//! Задачи userspace (ring 3) и round-robin планировщик на PIT.
//!
//! Адресное пространство задачи: копия kernel half (индексы 1..512 таблицы L4)
//! + user-страницы в entry 0 (программа у USER_BASE, стек у USER_STACK_TOP,
//! страница аргумента у USER_ARG_PAGE).
//!
//! Переключение контекста — в обработчике таймера (asm `timer_entry`):
//! сохраняем все регистры на kernel-стеке текущей задачи, в Rust-коде
//! (timer_switch) меняем CR3/TSS/syscall-стек, возвращаем rsp следующей
//! задачи, asm восстанавливает регистры и делает iretq в userland.

use alloc::boxed::Box;
use alloc::vec;
use core::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use spin::Mutex;
use x86_64::registers::control::Cr3;
use x86_64::structures::paging::mapper::MapToError;
use x86_64::structures::paging::{
    FrameAllocator, Mapper, OffsetPageTable, Page, PageTable, PageTableFlags, PhysFrame,
    Size4KiB, Translate,
};
use x86_64::VirtAddr;
use xmas_elf::program::Type;
use xmas_elf::ElfFile;

use crate::gdt;
use crate::memory::{active_level_4_table, BootInfoFrameAllocator};
use crate::{serial_println, syscall};

const USER_STACK_TOP: u64 = 0x80_0000;
const USER_ARG_PAGE: u64 = 0x60_0000;
const KERNEL_STACK_SIZE: usize = 64 * 1024;

/// User-программа, собранная крейтом `user` (build.sh собирает её до ядра).
static USER_PROGRAM: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/user.elf"));

pub struct Task {
    cr3: PhysFrame,
    /// Сохранённое значение kernel rsp (контекст для переключения).
    kernel_rsp: u64,
    /// Вершина kernel-стека задачи: для TSS (прерывания из ring 3) и syscall.
    kstack_top: u64,
}

static TASKS: Mutex<[Option<Task>; 2]> = Mutex::new([None, None]);
static TASK_COUNT: AtomicUsize = AtomicUsize::new(0);
/// Индекс текущей задачи; -1 = boot-контекст (ядро до первого переключения).
static CURRENT: core::sync::atomic::AtomicIsize = core::sync::atomic::AtomicIsize::new(-1);
/// Сохранённый rsp boot-контекста (возврата в него не предусмотрено).
static BOOT_RSP: AtomicU64 = AtomicU64::new(0);
static SCHED_INITED: AtomicBool = AtomicBool::new(false);

/// Создать две задачи из user ELF (маркеры 'A'/'B') и включить планировщик.
pub fn init() {
    if USER_PROGRAM.is_empty() {
        serial_println!("[task] user.elf not found, scheduler disabled");
        return;
    }

    // xmas-elf читает заголовки через ptr::read и требует выравнивания
    // буфера (u64-поля), а include_bytes даёт align(1) — копируем в
    // выровненный по 8 байт буфер.
    let mut aligned: Box<[u64]> = vec![0u64; (USER_PROGRAM.len() + 7) / 8 + 1].into_boxed_slice();
    let aligned_bytes = unsafe {
        core::slice::from_raw_parts_mut(aligned.as_mut_ptr() as *mut u8, USER_PROGRAM.len())
    };
    aligned_bytes.copy_from_slice(USER_PROGRAM);

    crate::memory::with_frame_allocator(|frame_allocator| {
        for (i, marker) in [b'A', b'B'].iter().enumerate() {
            let task = match build_task(aligned_bytes, *marker, frame_allocator) {
                Ok(t) => t,
                Err(e) => {
                    serial_println!("[task] failed to build task {}: {:?}", i, e);
                    return;
                }
            };
            TASKS.lock()[i] = Some(task);
            TASK_COUNT.store(i + 1, Ordering::Release);
        }
    });

    SCHED_INITED.store(true, Ordering::Release);
    serial_println!("[task] 2 user tasks ready, round-robin on PIT");
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
    let elf = ElfFile::new(elf_bytes).map_err(|_| MapToError::FrameAllocationFailed)?;
    let entry = elf.header.pt2.entry_point();

    // 1) Своя L4-таблица для задачи.
    let l4_frame = frame_allocator.allocate_frame().ok_or(MapToError::FrameAllocationFailed)?;
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
    let user_flags = PageTableFlags::PRESENT | PageTableFlags::WRITABLE | PageTableFlags::USER_ACCESSIBLE;

    // 3) Маппим страницы ELF (сегменты могут делить страницы — сначала
    //    маппим все уникальные страницы, потом копируем данные).
    let mut mapped_pages: alloc::vec::Vec<u64> = alloc::vec::Vec::new();
    for ph in elf.program_iter() {
        if ph.get_type() != Ok(Type::Load) || ph.mem_size() == 0 {
            continue;
        }
        let seg_end = ph.virtual_addr() + ph.mem_size();
        let first_page = Page::<Size4KiB>::containing_address(VirtAddr::new(ph.virtual_addr()));
        let last_page = Page::<Size4KiB>::containing_address(VirtAddr::new(seg_end - 1));
        for page in Page::range_inclusive(first_page, last_page) {
            let start = page.start_address().as_u64();
            if mapped_pages.contains(&start) {
                continue;
            }
            let frame =
                frame_allocator.allocate_frame().ok_or(MapToError::FrameAllocationFailed)?;
            let frame_virt = phys_offset + frame.start_address().as_u64();
            unsafe { core::ptr::write_bytes(frame_virt.as_mut_ptr::<u8>(), 0, 4096) };
            unsafe { mapper.map_to(page, frame, user_flags, frame_allocator)?.flush() };
            mapped_pages.push(start);
        }
    }
    // Копируем данные сегментов в их страницы (через physmap найдём фрейм).
    for ph in elf.program_iter() {
        if ph.get_type() != Ok(Type::Load) || ph.file_size() == 0 {
            continue;
        }
        let data: &[u8] = match ph {
            xmas_elf::program::ProgramHeader::Ph64(h) => h.raw_data(&elf),
            _ => continue,
        };
        let seg_end = ph.virtual_addr() + ph.mem_size();
        let first_page = Page::<Size4KiB>::containing_address(VirtAddr::new(ph.virtual_addr()));
        let last_page = Page::<Size4KiB>::containing_address(VirtAddr::new(seg_end - 1));
        for page in Page::range_inclusive(first_page, last_page) {
            let page_start = page.start_address().as_u64();
            let frame_phys = mapper
                .translate_addr(page.start_address())
                .ok_or(MapToError::FrameAllocationFailed)?;
            let frame_virt = phys_offset + frame_phys.as_u64();
            let copy_start = ph.virtual_addr().max(page_start);
            let copy_end = (ph.virtual_addr() + data.len() as u64).min(page_start + 4096);
            if copy_start < copy_end {
                let src = &data[(copy_start - ph.virtual_addr()) as usize
                    ..(copy_end - ph.virtual_addr()) as usize];
                let dst = (frame_virt.as_u64() + (copy_start - page_start)) as *mut u8;
                unsafe { core::ptr::copy_nonoverlapping(src.as_ptr(), dst, src.len()) };
            }
        }
    }

    // 4) Страница аргумента (маркер задачи).
    map_zeroed(
        &mut mapper,
        Page::containing_address(VirtAddr::new(USER_ARG_PAGE)),
        frame_allocator,
        user_flags,
    )?;
    let arg_frame_virt = phys_offset + task_frame_addr(&mapper, USER_ARG_PAGE);
    unsafe { core::ptr::write(arg_frame_virt.as_mut_ptr::<u8>(), marker) };

    // 5) User-стек: одна страница под USER_STACK_TOP.
    map_zeroed(
        &mut mapper,
        Page::containing_address(VirtAddr::new(USER_STACK_TOP - 1)),
        frame_allocator,
        user_flags,
    )?;

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
    })
}

fn map_zeroed(
    mapper: &mut OffsetPageTable,
    page: Page<Size4KiB>,
    frame_allocator: &mut BootInfoFrameAllocator,
    flags: PageTableFlags,
) -> Result<(), MapToError<Size4KiB>> {
    let frame = frame_allocator.allocate_frame().ok_or(MapToError::FrameAllocationFailed)?;
    let frame_virt = phys_offset() + frame.start_address().as_u64();
    unsafe { core::ptr::write_bytes(frame_virt.as_mut_ptr::<u8>(), 0, 4096) };
    unsafe { mapper.map_to(page, frame, flags, frame_allocator)?.flush() };
    Ok(())
}

/// Физический адрес фрейма, замапленного на user-адрес (через walk).
fn task_frame_addr(mapper: &OffsetPageTable, addr: u64) -> u64 {
    // USER_ARG_PAGE замаплен только что; читаем адрес через page table walk.
    // Упрощённо: переводим через OffsetPageTable::translate_addr.
    mapper
        .translate_addr(VirtAddr::new(addr))
        .map(|p| p.as_u64())
        .unwrap_or(0)
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
    let next = if prev < 0 {
        0
    } else {
        (prev as usize + 1) % count
    };
    CURRENT.store(next as isize, Ordering::Relaxed);

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
        let task = tasks[next].as_ref().expect("task disappeared");
        next_rsp = task.kernel_rsp;
        next_kstack_top = task.kstack_top;
        next_cr3 = task.cr3;
    }

    unsafe { Cr3::write(next_cr3, Cr3Flags::empty()) };
    gdt::set_kernel_stack(VirtAddr::new(next_kstack_top));
    syscall::set_current_kstack(next_kstack_top);

    next_rsp
}

use x86_64::registers::control::Cr3Flags;

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
    timer_entry as u64
}
