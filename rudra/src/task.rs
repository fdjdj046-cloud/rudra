//! Задачи userspace (ring 3) и round-robin планировщик на PIT.
//!
//! Адресное пространство задачи: копия kernel half (индексы 1..512 таблицы L4)
//! + user-страницы в entry 0 (программа у USER_BASE, стек у USER_STACK_TOP,
//! страница аргумента у USER_ARG_PAGE).
//!
//! Переключение контекста — в обработчике таймера (asm `timer_entry`):
//! сохраняем все регистры на kernel-стеке текущей задачи, в Rust-коде
//! (timer_switch) меняем CR3/TSS/syscall-стек, возвращаем rsp следующей
//! задачи, asm восстанавливает регистры и делает iretq. Завершённые задачи
//! (Exited) планировщик пропускает; их слоты переиспользует spawn.

use alloc::boxed::Box;
use alloc::vec;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicIsize, AtomicU64, AtomicUsize, Ordering};
use spin::Mutex;
use x86_64::registers::control::{Cr3, Cr3Flags};
use x86_64::structures::paging::mapper::MapToError;
use x86_64::structures::paging::{
    FrameAllocator, Mapper, OffsetPageTable, Page, PageTable, PageTableFlags, PhysFrame,
    Size4KiB, Translate,
};
use x86_64::VirtAddr;

use crate::gdt;
use crate::memory::{active_level_4_table, BootInfoFrameAllocator};
use crate::{serial_println, syscall};

/// Минимальный парсер ELF64: заголовок + программные заголовки типа LOAD.
/// Руками вместо xmas-elf: меньше кода в ядре, ноль магии, ноль сюрпризов.
struct LoadSeg {
    offset: u64,
    vaddr: u64,
    file_size: u64,
    mem_size: u64,
}

fn rd32(b: &[u8], off: usize) -> u64 {
    u32::from_le_bytes(b[off..off + 4].try_into().unwrap()) as u64
}

fn rd64(b: &[u8], off: usize) -> u64 {
    u64::from_le_bytes(b[off..off + 8].try_into().unwrap())
}

/// (entry_point, сегменты LOAD) или None, если файл не похож на ELF64.
fn parse_elf64(elf: &[u8]) -> Option<(u64, Vec<LoadSeg>)> {
    if elf.len() < 64 || &elf[0..4] != b"\x7fELF" || elf[4] != 2 {
        return None;
    }
    let entry = rd64(elf, 24);
    let phoff = rd64(elf, 32) as usize;
    let phentsize = rd16(elf, 54) as usize;
    let phnum = rd16(elf, 56) as usize;
    if phentsize < 56 {
        return None;
    }
    let mut segs = Vec::new();
    for i in 0..phnum {
        let base = phoff + i * phentsize;
        if base + 56 > elf.len() {
            break;
        }
        if rd32(elf, base) == 1 {
            // PT_LOAD
            segs.push(LoadSeg {
                offset: rd64(elf, base + 8),
                vaddr: rd64(elf, base + 16),
                file_size: rd64(elf, base + 32),
                mem_size: rd64(elf, base + 40),
            });
        }
    }
    Some((entry, segs))
}

fn rd16(b: &[u8], off: usize) -> u16 {
    u16::from_le_bytes(b[off..off + 2].try_into().unwrap())
}

const USER_STACK_TOP: u64 = 0x80_0000;
const USER_STACK_SIZE: u64 = 64 * 1024; // 16 страниц: буферы shell'а (cat) лезут в стек
const USER_ARG_PAGE: u64 = 0x60_0000;
const KERNEL_STACK_SIZE: usize = 64 * 1024;

pub const MAX_TASKS: usize = 4;

/// User-программы, собранные крейтом `user` (build.sh собирает их до ядра).
/// После монтирования FS копируются в /bin и запускаются оттуда по пути.
static SHELL_ELF: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/shell.elf"));
static HELLO_ELF: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/hello.elf"));
static COUNTER_ELF: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/counter.elf"));
static FIZZ_ELF: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/fizzbuzz.elf"));

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum TaskState {
    Runnable,
    Exited,
}

pub struct Task {
    cr3: PhysFrame,
    /// Сохранённое значение kernel rsp (контекст для переключения).
    kernel_rsp: u64,
    /// Вершина kernel-стека задачи: для TSS (прерывания из ring 3) и syscall.
    kstack_top: u64,
    state: TaskState,
}

static TASKS: Mutex<[Option<Task>; MAX_TASKS]> = Mutex::new([None, None, None, None]);
static TASK_COUNT: AtomicUsize = AtomicUsize::new(0);
/// Индекс текущей задачи; -1 = boot-контекст (ядро до первого переключения).
static CURRENT: AtomicIsize = AtomicIsize::new(-1);
/// Сохранённый rsp boot-контекста (возврата в него не предусмотрено).
static BOOT_RSP: AtomicU64 = AtomicU64::new(0);
static SCHED_INITED: AtomicBool = AtomicBool::new(false);

/// Инициализация: кладём программы в /bin ramdisk'а, запускаем шелл оттуда
/// и включаем планировщик.
pub fn init() {
    const BINS: [(&str, &[u8]); 4] = [
        ("/bin/shell.elf", SHELL_ELF),
        ("/bin/hello.elf", HELLO_ELF),
        ("/bin/counter.elf", COUNTER_ELF),
        ("/bin/fizzbuzz.elf", FIZZ_ELF),
    ];
    for (name, elf) in BINS {
        if !elf.is_empty() {
            crate::fs::write_path(name.as_bytes(), elf);
        }
    }

    match spawn_path("/bin/shell.elf") {
        s if s != u64::MAX => {
            SCHED_INITED.store(true, Ordering::Release);
            serial_println!("[task] shell spawned (slot {}), round-robin on PIT", s);
        }
        _ => serial_println!("[task] failed to spawn shell"),
    }
}

/// Создать задачу из ELF-файла в ramdisk'е (путь, напр. "/bin/hello.elf").
/// Возвращает номер слота или u64::MAX.
pub fn spawn_path(name: &str) -> u64 {
    let size = crate::fs::size_path(name.as_bytes());
    if size <= 0 {
        serial_println!("[task] spawn_path: no such file: {}", name);
        return u64::MAX;
    }
    // Читаем ELF в выровненный буфер (копия утекает намеренно).
    let mut aligned: Box<[u64]> = vec![0u64; (size as usize + 7) / 8 + 1].into_boxed_slice();
    let elf_buf = unsafe {
        core::slice::from_raw_parts_mut(aligned.as_mut_ptr() as *mut u8, size as usize)
    };
    if crate::fs::read_path(name.as_bytes(), elf_buf) != size {
        serial_println!("[task] spawn_path: failed to read {}", name);
        return u64::MAX;
    }

    x86_64::instructions::interrupts::without_interrupts(|| {
        let slot = {
            let tasks = TASKS.lock();
            match (0..MAX_TASKS).find(|&i| match &tasks[i] {
                None => true,
                Some(t) => t.state == TaskState::Exited,
            }) {
                Some(s) => s,
                None => return u64::MAX,
            }
        };
        let built = crate::memory::with_frame_allocator(|fa| build_task(elf_buf, slot as u8, fa));
        match built {
            Ok(t) => {
                {
                    let mut tasks = TASKS.lock();
                    tasks[slot] = Some(t);
                }
                let count = TASK_COUNT.load(Ordering::Acquire);
                TASK_COUNT.store(count.max(slot + 1), Ordering::Release);
                serial_println!("[task] spawned {} in slot {}", name, slot);
                slot as u64
            }
            Err(e) => {
                serial_println!("[task] spawn {} failed: {:?}", name, e);
                u64::MAX
            }
        }
    })
}

/// Пометить текущую задачу завершённой. Планировщик больше в неё не вернётся.
pub fn exit_current() {
    x86_64::instructions::interrupts::without_interrupts(|| {
        let cur = CURRENT.load(Ordering::Relaxed);
        if cur >= 0 {
            let mut tasks = TASKS.lock();
            if let Some(t) = tasks[cur as usize].as_mut() {
                t.state = TaskState::Exited;
            }
        }
    });
}

/// Номер текущего слота (для отладки).
pub fn current_slot() -> isize {
    CURRENT.load(Ordering::Relaxed)
}

fn phys_offset() -> VirtAddr {
    VirtAddr::new(crate::PHYS_OFFSET.load(Ordering::Relaxed))
}

fn build_task(
    elf_bytes: &[u8],
    marker: u8,
    frame_allocator: &mut BootInfoFrameAllocator,
) -> Result<Task, MapToError<Size4KiB>> {
    let phys_offset = phys_offset();
    let (entry, segments) = match parse_elf64(elf_bytes) {
        Some(p) => p,
        None => {
            serial_println!("[task] bad ELF image");
            return Err(MapToError::FrameAllocationFailed);
        }
    };

    // 1) Своя L4-таблица для задачи.
    let l4_frame = frame_allocator
        .allocate_frame()
        .ok_or(MapToError::FrameAllocationFailed)?;
    let l4_virt = phys_offset + l4_frame.start_address().as_u64();
    unsafe { core::ptr::write_bytes(l4_virt.as_mut_ptr::<u8>(), 0, 4096) };
    let l4_table = unsafe { &mut *(l4_virt.as_mut_ptr::<PageTable>()) };

    // 2) Копируем все kernel-маппинги (индексы 1..512; kernel живёт в low-half
    //    индексов 2+, поэтому «верхняя половина» тут не подходит). Entry 0
    //    оставляем под пользовательские страницы.
    let kernel_l4 = unsafe { active_level_4_table(phys_offset) };
    for i in 1..512 {
        let e = &kernel_l4[i];
        l4_table[i].set_addr(e.addr(), e.flags());
    }

    let mut mapper = unsafe { OffsetPageTable::new(l4_table, phys_offset) };
    let user_flags =
        PageTableFlags::PRESENT | PageTableFlags::WRITABLE | PageTableFlags::USER_ACCESSIBLE;

    // 3) Маппим страницы ELF (сегменты могут делить страницы — сначала
    //    маппим все уникальные страницы, потом копируем данные).
    let mut mapped_pages: Vec<u64> = Vec::new();
    for seg in &segments {
        if seg.mem_size == 0 {
            continue;
        }
        let seg_end = seg.vaddr + seg.mem_size;
        let first_page = Page::<Size4KiB>::containing_address(VirtAddr::new(seg.vaddr));
        let last_page = Page::<Size4KiB>::containing_address(VirtAddr::new(seg_end - 1));
        for page in Page::range_inclusive(first_page, last_page) {
            let start = page.start_address().as_u64();
            if mapped_pages.contains(&start) {
                continue;
            }
            let frame = frame_allocator
                .allocate_frame()
                .ok_or(MapToError::FrameAllocationFailed)?;
            let frame_virt = phys_offset + frame.start_address().as_u64();
            unsafe { core::ptr::write_bytes(frame_virt.as_mut_ptr::<u8>(), 0, 4096) };
            unsafe { mapper.map_to(page, frame, user_flags, frame_allocator)?.flush() };
            mapped_pages.push(start);
        }
    }
    // Копируем данные сегментов в их страницы (фрейм находим через translate).
    for seg in &segments {
        if seg.file_size == 0 {
            continue;
        }
        let data = &elf_bytes[seg.offset as usize..(seg.offset + seg.file_size) as usize];
        let seg_end = seg.vaddr + seg.mem_size;
        let first_page = Page::<Size4KiB>::containing_address(VirtAddr::new(seg.vaddr));
        let last_page = Page::<Size4KiB>::containing_address(VirtAddr::new(seg_end - 1));
        for page in Page::range_inclusive(first_page, last_page) {
            let page_start = page.start_address().as_u64();
            let frame_phys = mapper
                .translate_addr(page.start_address())
                .ok_or(MapToError::FrameAllocationFailed)?;
            let frame_virt = phys_offset + frame_phys.as_u64();
            let copy_start = seg.vaddr.max(page_start);
            let copy_end = (seg.vaddr + data.len() as u64).min(page_start + 4096);
            if copy_start < copy_end {
                let src = &data
                    [(copy_start - seg.vaddr) as usize..(copy_end - seg.vaddr) as usize];
                let dst = (frame_virt.as_u64() + (copy_start - page_start)) as *mut u8;
                unsafe { core::ptr::copy_nonoverlapping(src.as_ptr(), dst, src.len()) };
            }
        }
    }

    // 4) Страница аргумента (индекс слота; программы могут использовать).
    map_zeroed(
        &mut mapper,
        Page::containing_address(VirtAddr::new(USER_ARG_PAGE)),
        frame_allocator,
        user_flags,
    )?;
    if let Some(arg_phys) = mapper.translate_addr(VirtAddr::new(USER_ARG_PAGE)) {
        let arg_frame_virt = phys_offset + arg_phys.as_u64();
        unsafe { core::ptr::write(arg_frame_virt.as_mut_ptr::<u8>(), marker) };
    }

    // 5) User-стек: USER_STACK_SIZE байт под USER_STACK_TOP.
    let stack_start = VirtAddr::new(USER_STACK_TOP - USER_STACK_SIZE);
    let stack_end = VirtAddr::new(USER_STACK_TOP - 1);
    let first_stack_page = Page::containing_address(stack_start);
    let last_stack_page = Page::containing_address(stack_end);
    for page in Page::range_inclusive(first_stack_page, last_stack_page) {
        map_zeroed(&mut mapper, page, frame_allocator, user_flags)?;
    }

    // 6) Kernel-стек задачи (в kernel-адресном пространстве, виден при любом CR3).
    let mut kstack: Box<[u8]> = vec![0u8; KERNEL_STACK_SIZE].into_boxed_slice();
    let kstack_top = kstack.as_mut_ptr() as u64 + KERNEL_STACK_SIZE as u64;
    core::mem::forget(kstack);

    // 7) Начальный «фрейм прерывания» на kernel-стеке: iretq в ring 3.
    //    Порядок слотов совпадает с pop-последовательностью timer_entry.
    const GPRS: usize = 15;
    let rsp = kstack_top - (GPRS as u64 + 5) * 8;
    let (user_data, user_code) = gdt::user_segments();
    unsafe {
        let f = rsp as *mut u64;
        // GPR-слоты (15 штук) — нули; потом iret-фрейм.
        core::ptr::write(f.add(GPRS + 0), entry); // rip
        core::ptr::write(f.add(GPRS + 1), u64::from(user_code.0)); // cs (0x30|3)
        core::ptr::write(f.add(GPRS + 2), 0x202); // rflags: IF
        core::ptr::write(f.add(GPRS + 3), USER_STACK_TOP); // user rsp
        core::ptr::write(f.add(GPRS + 4), u64::from(user_data.0)); // ss (0x28|3)
    }

    Ok(Task {
        cr3: l4_frame,
        kernel_rsp: rsp,
        kstack_top,
        state: TaskState::Runnable,
    })
}

fn map_zeroed(
    mapper: &mut OffsetPageTable,
    page: Page<Size4KiB>,
    frame_allocator: &mut BootInfoFrameAllocator,
    flags: PageTableFlags,
) -> Result<(), MapToError<Size4KiB>> {
    let frame = frame_allocator
        .allocate_frame()
        .ok_or(MapToError::FrameAllocationFailed)?;
    let frame_virt = phys_offset() + frame.start_address().as_u64();
    unsafe { core::ptr::write_bytes(frame_virt.as_mut_ptr::<u8>(), 0, 4096) };
    unsafe { mapper.map_to(page, frame, flags, frame_allocator)?.flush() };
    Ok(())
}

/// Переключение контекста из обработчика таймера (вызывается из asm).
/// Принимает rsp текущего контекста, возвращает rsp следующего.
#[no_mangle]
extern "C" fn timer_switch(current_rsp: u64) -> u64 {
    unsafe {
        crate::interrupts::PICS
            .lock()
            .notify_end_of_interrupt(crate::interrupts::InterruptIndex::Timer.as_u8());
    }

    if !SCHED_INITED.load(Ordering::Acquire) {
        return current_rsp;
    }
    let count = TASK_COUNT.load(Ordering::Acquire);
    if count == 0 {
        return current_rsp;
    }

    let prev = CURRENT.load(Ordering::Relaxed);

    let next = {
        let tasks = TASKS.lock();
        // Ищем следующую Runnable задачу, пропуская Exited и пустые слоты.
        let mut found = None;
        for k in 1..=count {
            let i = if prev < 0 {
                (k - 1) % count
            } else {
                (prev as usize + k) % count
            };
            if matches!(
                tasks[i].as_ref().map(|t| t.state),
                Some(TaskState::Runnable)
            ) {
                found = Some(i);
                break;
            }
        }
        found
    };

    let next = match next {
        Some(n) => n,
        None => return current_rsp, // некому переключаться
    };

    let (next_rsp, next_kstack_top, next_cr3);
    {
        let mut tasks = TASKS.lock();
        if prev >= 0 {
            if let Some(t) = tasks[prev as usize].as_mut() {
                t.kernel_rsp = current_rsp;
            }
        } else {
            BOOT_RSP.store(current_rsp, Ordering::Relaxed);
        }
        let task = tasks[next].as_ref().expect("runnable task disappeared");
        next_rsp = task.kernel_rsp;
        next_kstack_top = task.kstack_top;
        next_cr3 = task.cr3;
    }

    CURRENT.store(next as isize, Ordering::Relaxed);

    unsafe { Cr3::write(next_cr3, Cr3Flags::empty()) };
    gdt::set_kernel_stack(VirtAddr::new(next_kstack_top));
    syscall::set_current_kstack(next_kstack_top);

    next_rsp
}

core::arch::global_asm!(r#"
    .text
    .global timer_entry
timer_entry:
    push rax
    push rcx
    push rdx
    push rsi
    push rdi
    push r8
    push r9
    push r10
    push r11
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    mov rdi, rsp
    call timer_switch
    mov rsp, rax
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    pop r11
    pop r10
    pop r9
    pop r8
    pop rdi
    pop rsi
    pop rdx
    pop rcx
    pop rax
    iretq
"#);

extern "C" {
    fn timer_entry();
}

/// Адрес asm-обработчика таймера (для регистрации в IDT).
pub fn timer_handler_addr() -> u64 {
    let f: unsafe extern "C" fn() = timer_entry;
    f as u64
}
