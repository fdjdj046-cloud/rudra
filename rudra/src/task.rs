//! Задачи userspace (ring 3), адресные пространства и round-robin планировщик.
//!
//! Адресное пространство (AddressSpace) — самостоятельная сущность с
//! refcount (Arc): несколько потоков одного процесса разделяют одно АП
//! (CLONE_VM), fork делает глубокую копию. Каждая задача имеет свой
//! kernel-стек; переключение — в обработчике таймера (asm `timer_entry`):
//! сохраняем регистры на kernel-стеке, в Rust-коде (timer_switch) меняем
//! CR3/TSS/syscall-стек/fs_base, возвращаем rsp следующей задачи.
//!
//! Раскладка userspace (всё в L4[0], 0..0x80_0000_0000):
//!   0x400000        ELF-образ (PT_LOAD)
//!   0x600000        резерв (раньше — страница аргумента)
//!   0x40000000      main-стек (растёт вниз от USER_STACK_TOP)
//!   0x10000000      brk-heap (растёт вверх до BRK_MAX)
//!   0x50000000      mmap-регион (bump вверх)
//!   0x70000000      стеки потоков (по 1 МиБ на поток)

use alloc::boxed::Box;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicIsize, AtomicU64, AtomicUsize, Ordering};
use spin::Mutex;
use x86_64::registers::control::{Cr3, Cr3Flags};
use x86_64::registers::model_specific::Msr;
use x86_64::structures::paging::mapper::MapToError;
use x86_64::structures::paging::{
    FrameAllocator, Mapper, OffsetPageTable, Page, PageTable, PageTableFlags, PhysFrame,
    Size4KiB, Translate,
};
use x86_64::VirtAddr;

use crate::gdt;
use crate::memory::{active_level_4_table, BootInfoFrameAllocator};
use crate::syscall::FRAME;
use crate::{serial_println, syscall};

pub const USER_STACK_TOP: u64 = 0x4000_0000;
pub const USER_STACK_SIZE: u64 = 256 * 1024;
pub const BRK_BASE: u64 = 0x1000_0000;
pub const BRK_MAX: u64 = 0x5000_0000;
pub const MMAP_BASE: u64 = 0x5000_0000;
pub const MMAP_TOP: u64 = 0x6000_0000;
pub const THREAD_STACK_BASE: u64 = 0x7000_0000;
pub const THREAD_STACK_SIZE: u64 = 1024 * 1024;
pub const MAX_THREADS_PER_PROC: u64 = 32;

const KERNEL_STACK_SIZE: usize = 64 * 1024;

pub const MAX_TASKS: usize = 32;

/// Результат загрузки ELF: точка входа и вершина user-стека (с argv/auxv).
pub struct LoadedImage {
    pub entry: u64,
    pub user_rsp: u64,
}

// ---- ELF64 ----

struct LoadSeg {
    offset: u64,
    vaddr: u64,
    file_size: u64,
    mem_size: u64,
}

fn rd16(b: &[u8], off: usize) -> u64 {
    u16::from_le_bytes(b[off..off + 2].try_into().unwrap()) as u64
}
fn rd32(b: &[u8], off: usize) -> u64 {
    u32::from_le_bytes(b[off..off + 4].try_into().unwrap()) as u64
}
fn rd64(b: &[u8], off: usize) -> u64 {
    u64::from_le_bytes(b[off..off + 8].try_into().unwrap())
}

/// (entry, phdr_vaddr, phnum, сегменты LOAD) или None, если не ELF64.
fn parse_elf64(elf: &[u8]) -> Option<(u64, u64, u64, Vec<LoadSeg>)> {
    if elf.len() < 64 || &elf[0..4] != b"\x7fELF" || elf[4] != 2 {
        return None;
    }
    if elf[16] != 2 || elf[18] != 62 {
        // ET_EXEC и EM_X86_64; динамические бинарники (ET_DYN/PIE) не грузим.
        return None;
    }
    let entry = rd64(elf, 24);
    let phoff = rd64(elf, 32);
    let phentsize = rd16(elf, 54) as usize;
    let phnum = rd16(elf, 56) as usize;
    if phentsize < 56 {
        return None;
    }
    let mut segs = Vec::new();
    let mut phdr_vaddr = 0u64;
    for i in 0..phnum {
        let base = (phoff as usize).checked_add(i * phentsize)?;
        if base + 56 > elf.len() {
            break;
        }
        let p_type = rd32(elf, base);
        if p_type == 3 {
            // PT_INTERP: динамический бинарник — у нас нет ld.so.
            return None;
        }
        if p_type == 1 {
            let seg = LoadSeg {
                offset: rd64(elf, base + 8),
                vaddr: rd64(elf, base + 16),
                file_size: rd64(elf, base + 32),
                mem_size: rd64(elf, base + 40),
            };
            // Программные заголовки лежат в этом сегменте → AT_PHDR.
            if phdr_vaddr == 0 && phoff >= seg.offset && phoff < seg.offset + seg.file_size {
                phdr_vaddr = seg.vaddr + (phoff - seg.offset);
            }
            segs.push(seg);
        }
    }
    Some((entry, phdr_vaddr, phnum as u64, segs))
}

// ---- Адресное пространство ----

/// Состояние userspace-части адресного пространства. l4 — физический фрейм
/// корневой таблицы. Данные (brk/mmap) мутируются под своим мьютексом;
/// маппинг выполняется через physmap (виден при любом CR3).
pub struct AddressSpace {
    pub l4: PhysFrame,
    pub brk_base: u64,
    pub brk: u64,
    pub mmap_next: u64,
    pub thread_stacks: u64,
}

impl AddressSpace {
    pub fn new_empty(frame_allocator: &mut BootInfoFrameAllocator) -> Option<Arc<Mutex<Self>>> {
        let l4 = alloc_l4(frame_allocator)?;
        Some(Arc::new(Mutex::new(AddressSpace {
            l4,
            brk_base: BRK_BASE,
            brk: BRK_BASE,
            mmap_next: MMAP_BASE,
            thread_stacks: 0,
        })))
    }
}

fn phys_offset() -> VirtAddr {
    VirtAddr::new(crate::PHYS_OFFSET.load(Ordering::Relaxed))
}

/// Свежая L4-таблица: kernel-маппинги (индексы 1..512) копируются,
/// entry 0 пуст под пользовательские страницы.
fn alloc_l4(frame_allocator: &mut BootInfoFrameAllocator) -> Option<PhysFrame> {
    let l4_frame = frame_allocator.allocate_frame()?;
    let l4_virt = phys_offset() + l4_frame.start_address().as_u64();
    unsafe { core::ptr::write_bytes(l4_virt.as_mut_ptr::<u8>(), 0, 4096) };
    let l4_table = unsafe { &mut *(l4_virt.as_mut_ptr::<PageTable>()) };
    let kernel_l4 = unsafe { active_level_4_table(phys_offset()) };
    for i in 1..512 {
        let e = &kernel_l4[i];
        l4_table[i].set_addr(e.addr(), e.flags());
    }
    Some(l4_frame)
}

unsafe fn mapper_for(l4: PhysFrame) -> OffsetPageTable<'static> {
    let l4_virt = phys_offset() + l4.start_address().as_u64();
    OffsetPageTable::new(&mut *(l4_virt.as_mut_ptr::<PageTable>()), phys_offset())
}

fn map_zeroed(
    l4: PhysFrame,
    page: Page<Size4KiB>,
    frame_allocator: &mut BootInfoFrameAllocator,
    flags: PageTableFlags,
) -> Result<(), MapToError<Size4KiB>> {
    let frame = frame_allocator
        .allocate_frame()
        .ok_or(MapToError::FrameAllocationFailed)?;
    let frame_virt = phys_offset() + frame.start_address().as_u64();
    unsafe { core::ptr::write_bytes(frame_virt.as_mut_ptr::<u8>(), 0, 4096) };
    let mut mapper = unsafe { mapper_for(l4) };
    unsafe { mapper.map_to(page, frame, flags, frame_allocator)?.flush() };
    Ok(())
}

/// Маппит диапазон страниц [start, end) нулями (end — адрес ПОСЛЕДНЕГО байта).
fn map_range_zeroed(
    l4: PhysFrame,
    start: VirtAddr,
    end_inclusive: VirtAddr,
    frame_allocator: &mut BootInfoFrameAllocator,
    flags: PageTableFlags,
) -> Result<(), MapToError<Size4KiB>> {
    let first = Page::<Size4KiB>::containing_address(start);
    let last = Page::<Size4KiB>::containing_address(end_inclusive);
    for page in Page::range_inclusive(first, last) {
        map_zeroed(l4, page, frame_allocator, flags)?;
    }
    Ok(())
}

const USER_FLAGS: PageTableFlags = PageTableFlags::from_bits_truncate(
    PageTableFlags::PRESENT.bits() | PageTableFlags::WRITABLE.bits() | PageTableFlags::USER_ACCESSIBLE.bits(),
);

/// Глубокая копия userspace-части АП (L4[0] целиком): все таблицы и страницы.
/// Только 4K-страницы (huge pages мы никогда не создаём).
fn copy_user_space(
    src_l4: PhysFrame,
    frame_allocator: &mut BootInfoFrameAllocator,
) -> Result<PhysFrame, MapToError<Size4KiB>> {
    fn copy_table(
        src_frame: PhysFrame,
        level: u8,
        frame_allocator: &mut BootInfoFrameAllocator,
    ) -> Result<PhysFrame, MapToError<Size4KiB>> {
        let dst_frame = frame_allocator
            .allocate_frame()
            .ok_or(MapToError::FrameAllocationFailed)?;
        let src_virt = (phys_offset() + src_frame.start_address().as_u64()).as_mut_ptr::<PageTable>();
        let dst_virt = (phys_offset() + dst_frame.start_address().as_u64()).as_mut_ptr::<PageTable>();
        unsafe { core::ptr::write_bytes(dst_virt as *mut u8, 0, 4096) };
        let src_table = unsafe { &*src_virt };
        let dst_table = unsafe { &mut *dst_virt };
        for i in 0..512 {
            let e = &src_table[i];
            if !e.flags().contains(PageTableFlags::PRESENT) {
                continue;
            }
            if e.flags().contains(PageTableFlags::HUGE_PAGE) {
                serial_println!("[task] copy_user_space: huge page unsupported");
                return Err(MapToError::FrameAllocationFailed);
            }
            if level == 1 {
                // Страница 4K: новый фрейм + копия данных.
                let new_page = frame_allocator
                    .allocate_frame()
                    .ok_or(MapToError::FrameAllocationFailed)?;
                unsafe {
                    core::ptr::copy_nonoverlapping(
                        (phys_offset() + e.addr().as_u64()).as_mut_ptr::<u8>(),
                        (phys_offset() + new_page.start_address().as_u64()).as_mut_ptr::<u8>(),
                        4096,
                    );
                }
                dst_table[i].set_addr(new_page.start_address(), e.flags());
            } else {
                let child = PhysFrame::from_start_address(e.addr())
                    .map_err(|_| MapToError::FrameAllocationFailed)?;
                let new_child = copy_table(child, level - 1, frame_allocator)?;
                dst_table[i].set_addr(new_child.start_address(), e.flags());
            }
        }
        Ok(dst_frame)
    }

    let new_l4 = alloc_l4(frame_allocator).ok_or(MapToError::FrameAllocationFailed)?;
    let src_l4_virt = phys_offset() + src_l4.start_address().as_u64();
    let src_l4_table = unsafe { &*(src_l4_virt.as_mut_ptr::<PageTable>()) };
    let e0 = &src_l4_table[0];
    if e0.flags().contains(PageTableFlags::PRESENT) {
        let src_l3 = PhysFrame::from_start_address(e0.addr())
            .map_err(|_| MapToError::FrameAllocationFailed)?;
        let new_l3 = copy_table(src_l3, 3, frame_allocator)?;
        let new_l4_virt = phys_offset() + new_l4.start_address().as_u64();
        let new_l4_table = unsafe { &mut *(new_l4_virt.as_mut_ptr::<PageTable>()) };
        new_l4_table[0].set_addr(new_l3.start_address(), e0.flags());
    }
    Ok(new_l4)
}

/// Писать байты в user-память АП `l4` через physmap.
///
/// `translate_addr` уже возвращает физический адрес байта, а не базы
/// страницы. Смещение прибавлять второй раз нельзя: запись уезжала в
/// следующий физический кадр (страница ELF сразу за вершиной стека) и
/// затирала GOT парой auxv `AT_BASE, 0`.
fn write_user(l4: PhysFrame, addr: u64, data: &[u8]) -> Result<(), MapToError<Size4KiB>> {
    let mapper = unsafe { mapper_for(l4) };
    let mut done = 0usize;
    while done < data.len() {
        let a = addr + done as u64;
        let phys = mapper
            .translate_addr(VirtAddr::new(a))
            .ok_or(MapToError::FrameAllocationFailed)?;
        let page_off = (a & 0xFFF) as usize;
        let n = (4096 - page_off).min(data.len() - done);
        let dst = (phys_offset().as_u64() + phys.as_u64()) as *mut u8;
        unsafe { core::ptr::copy_nonoverlapping(data.as_ptr().add(done), dst, n) };
        done += n;
    }
    Ok(())
}

// ---- Задачи ----

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum TaskState {
    Runnable,
    Exited,
}

pub struct Task {
    pub tid: u64,
    pub aspace: Arc<Mutex<AddressSpace>>,
    /// Кэш l4 (== aspace.lock().l4; продублирован для планировщика).
    pub cr3: PhysFrame,
    /// Сохранённое значение kernel rsp (контекст для переключения).
    pub kernel_rsp: u64,
    /// Вершина kernel-стека: для TSS (прерывания из ring 3) и syscall.
    pub kstack_top: u64,
    pub state: TaskState,
    pub exit_code: i64,
    /// Слот родителя (-1 = родитель не отслеживается).
    pub parent: isize,
    /// FS BASE (TLS) — восстанавливается планировщиком.
    pub fs_base: u64,
    /// Адрес для CLONE_CHILD_CLEARTID: при exit записать 0 и разбудить futex.
    pub clear_tid: u64,
    pub name: [u8; 24],
    pub fds: Arc<Mutex<Vec<Option<crate::linux::Fd>>>>,
    pub cwd: String,
    pub umask: u32,
    /// Сохранённые xmm/x87. Пустой образ = чистый FPU при первом входе.
    fx: crate::fpu::FxState,
}

static TASKS: Mutex<[Option<Task>; MAX_TASKS]> = Mutex::new([
    None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None,
    None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None,
]);
static TASK_COUNT: AtomicUsize = AtomicUsize::new(0);
static NEXT_TID: AtomicU64 = AtomicU64::new(1);
/// Индекс текущей задачи; -1 = boot-контекст (ядро до первого переключения).
static CURRENT: AtomicIsize = AtomicIsize::new(-1);
static SCHED_INITED: AtomicBool = AtomicBool::new(false);

/// User-программы, собранные крейтом `user` (build.sh собирает их до ядра).
/// После монтирования FS копируются в /bin и запускаются оттуда по пути.
static SHELL_ELF: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/shell.elf"));
static HELLO_ELF: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/hello.elf"));
static COUNTER_ELF: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/counter.elf"));
static FIZZ_ELF: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/fizzbuzz.elf"));
static THREADS_ELF: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/threads.elf"));

/// Инициализация: кладём программы в /bin ramdisk'а, запускаем шелл оттуда
/// и включаем планировщик.
pub fn init() {
    const BINS: [(&str, &[u8]); 5] = [
        ("/bin/shell.elf", SHELL_ELF),
        ("/bin/hello.elf", HELLO_ELF),
        ("/bin/counter.elf", COUNTER_ELF),
        ("/bin/fizzbuzz.elf", FIZZ_ELF),
        ("/bin/threads.elf", THREADS_ELF),
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

fn default_fds() -> Arc<Mutex<Vec<Option<crate::linux::Fd>>>> {
    Arc::new(Mutex::new(alloc::vec![
        Some(crate::linux::Fd::console(false)),
        Some(crate::linux::Fd::console(true)),
        Some(crate::linux::Fd::console(true)),
    ]))
}

fn alloc_slot(tasks: &mut [Option<Task>; MAX_TASKS]) -> Option<usize> {
    let count = TASK_COUNT.load(Ordering::Acquire);
    for i in 0..count.min(MAX_TASKS) {
        let free = match &tasks[i] {
            None => true,
            Some(t) => t.state == TaskState::Exited,
        };
        if free {
            return Some(i);
        }
    }
    if count < MAX_TASKS {
        return Some(count);
    }
    None
}

/// Создать задачу из ELF-файла в ramdisk'е (путь, напр. "/bin/hello.elf").
/// Возвращает tid или u64::MAX.
pub fn spawn_path(name: &str) -> u64 {
    let Some(elf) = crate::fs::read_canon(name) else {
        serial_println!("[task] spawn_path: no such file: {}", name);
        return u64::MAX;
    };
    let argv = alloc::vec![String::from(name)];
    x86_64::instructions::interrupts::without_interrupts(|| {
        let slot = {
            let mut tasks = TASKS.lock();
            match alloc_slot(&mut tasks) {
                Some(s) => s,
                None => return u64::MAX,
            }
        };
        let built = crate::memory::with_frame_allocator(|fa| build_task(&elf, &argv, &[], name, fa));
        match built {
            Ok(t) => {
                TASKS.lock()[slot] = Some(t);
                let count = TASK_COUNT.load(Ordering::Acquire);
                TASK_COUNT.store(count.max(slot + 1), Ordering::Release);
                serial_println!("[task] spawned {} in slot {}", name, slot);
                NEXT_TID.load(Ordering::Relaxed) - 1
            }
            Err(e) => {
                serial_println!("[task] spawn {} failed: {:?}", name, e);
                u64::MAX
            }
        }
    })
}

/// Собрать задачу из ELF-образа в свежем АП.
fn build_task(
    elf_bytes: &[u8],
    argv: &[String],
    envp: &[String],
    name: &str,
    frame_allocator: &mut BootInfoFrameAllocator,
) -> Result<Task, MapToError<Size4KiB>> {
    let aspace = match AddressSpace::new_empty(frame_allocator) {
        Some(a) => a,
        None => return Err(MapToError::FrameAllocationFailed),
    };
    let l4 = aspace.lock().l4;

    // Main-стек (маппим до загрузки ELF: строим argv на нём).
    let stack_start = VirtAddr::new(USER_STACK_TOP - USER_STACK_SIZE);
    map_range_zeroed(
        l4,
        stack_start,
        VirtAddr::new(USER_STACK_TOP - 1),
        frame_allocator,
        USER_FLAGS,
    )?;

    let img = load_elf_image(l4, elf_bytes, argv, envp, USER_STACK_TOP, frame_allocator)?;
    finish_task(aspace, img, name)
}

/// Загрузить ELF в АП l4 и построить начальный стек (argc/argv/envp/auxv).
/// Возвращает (entry, user_rsp).
pub fn load_elf_image(
    l4: PhysFrame,
    elf_bytes: &[u8],
    argv: &[String],
    envp: &[String],
    stack_top: u64,
    frame_allocator: &mut BootInfoFrameAllocator,
) -> Result<LoadedImage, MapToError<Size4KiB>> {
    let (entry, phdr_vaddr, phnum, segments) = match parse_elf64(elf_bytes) {
        Some(p) => p,
        None => {
            serial_println!("[task] bad ELF image (need static ET_EXEC x86_64)");
            return Err(MapToError::FrameAllocationFailed);
        }
    };

    // Маппим все уникальные страницы сегментов (сегменты могут делить
    // страницы — сначала маппинг, потом копия данных).
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
            map_zeroed(l4, page, frame_allocator, USER_FLAGS)?;
            mapped_pages.push(start);
        }
    }
    // Копируем данные сегментов в их страницы (фрейм находим через translate).
    let mut mapper = unsafe { mapper_for(l4) };
    for seg in &segments {
        if seg.file_size == 0 || seg.offset as usize + seg.file_size as usize > elf_bytes.len() {
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
            let frame_virt = phys_offset() + frame_phys.as_u64();
            let copy_start = seg.vaddr.max(page_start);
            let copy_end = (seg.vaddr + data.len() as u64).min(page_start + 4096);
            if copy_start < copy_end {
                let src = &data[(copy_start - seg.vaddr) as usize..(copy_end - seg.vaddr) as usize];
                let dst = (frame_virt.as_u64() + (copy_start - page_start)) as *mut u8;
                unsafe { core::ptr::copy_nonoverlapping(src.as_ptr(), dst, src.len()) };
            }
        }
    }

    // ---- Начальный стек ----
    // Все строки, потом (выравнивание 16) auxv, envp[], argv[], argc наверху.
    let mut sp = stack_top;
    let mut put = |l4: PhysFrame, bytes: &[u8], sp: &mut u64| -> Result<u64, MapToError<Size4KiB>> {
        *sp -= bytes.len() as u64;
        write_user(l4, *sp, bytes)?;
        Ok(*sp)
    };

    // Случайные 16 байт для AT_RANDOM.
    let seed = NEXT_TID.load(Ordering::Relaxed).wrapping_mul(0x9E37_79B9_7F4A_7C15)
        ^ x86_64::registers::control::Cr2::read().map(|a| a.as_u64()).unwrap_or(0x1234);
    let mut rnd = seed | 1;
    let mut random_bytes = [0u8; 16];
    for b in &mut random_bytes {
        rnd ^= rnd << 13;
        rnd ^= rnd >> 7;
        rnd ^= rnd << 17;
        *b = rnd as u8;
    }
    let random_ptr = put(l4, &random_bytes, &mut sp)?;

    // Строки argv (в обратном порядке записи — порядок указателей
    // восстановлен через argv_ptrs.reverse()).
    let mut argv_ptrs: Vec<u64> = Vec::new();
    for s in argv.iter().rev() {
        let mut bytes = s.clone().into_bytes();
        bytes.push(0);
        let p = put(l4, &bytes, &mut sp)?;
        argv_ptrs.push(p);
    }
    argv_ptrs.reverse();
    // AT_EXECFN указывает на argv[0]\0 (последняя записанная строка).
    let execfn_ptr = argv_ptrs.first().copied().unwrap_or(0);
    let mut envp_ptrs: Vec<u64> = Vec::new();
    for s in envp.iter().rev() {
        let mut bytes = s.clone().into_bytes();
        bytes.push(0);
        let p = put(l4, &bytes, &mut sp)?;
        envp_ptrs.push(p);
    }
    envp_ptrs.reverse();
    // Имя программы для AT_EXECFN: argv[0]\0 — последняя записанная строка.
    let execfn_ptr = argv_ptrs.first().copied().unwrap_or(0);

    sp &= !0xF; // выравнивание до 16 перед массивами указателей

    const AT_NULL: u64 = 0;
    const AT_PHDR: u64 = 3;
    const AT_PHENT: u64 = 4;
    const AT_PHNUM: u64 = 5;
    const AT_PAGESZ: u64 = 6;
    const AT_BASE: u64 = 7;
    const AT_FLAGS: u64 = 8;
    const AT_ENTRY: u64 = 9;
    const AT_UID: u64 = 11;
    const AT_EUID: u64 = 12;
    const AT_GID: u64 = 13;
    const AT_EGID: u64 = 14;
    const AT_HWCAP: u64 = 16;
    const AT_CLKTCK: u64 = 17;
    const AT_SECURE: u64 = 23;
    const AT_RANDOM: u64 = 25;
    const AT_HWCAP2: u64 = 26;
    const AT_EXECFN: u64 = 31;

    let auxv: [u64; 46] = [
        AT_PHDR, phdr_vaddr,
        AT_PHENT, 56,
        AT_PHNUM, phnum,
        AT_PAGESZ, 4096,
        AT_BASE, 0,
        AT_FLAGS, 0,
        AT_ENTRY, entry,
        AT_UID, 1000,
        AT_EUID, 1000,
        AT_GID, 1000,
        AT_EGID, 1000,
        AT_HWCAP, 0x078B_FBFF,
        AT_HWCAP2, 0,
        AT_CLKTCK, 100,
        AT_SECURE, 0,
        AT_RANDOM, random_ptr,
        AT_EXECFN, execfn_ptr,
        AT_NULL, 0,
        0, 0, // запас
        0, 0,
        0, 0,
        0, 0,
        0, 0,
    ];
    let auxv_len = 18 * 2; // до AT_NULL включительно
    let auxv_bytes: Vec<u8> = auxv[..auxv_len]
        .iter()
        .flat_map(|v| v.to_le_bytes())
        .collect();
    // На входе в _start %rsp обязан быть кратен 16 (psABI): первый call
    // тогда входит в функцию с (%rsp+8) кратным 16. Иначе glibc ловит #GP
    // на выровненных movaps. Все куски ниже кратны 8, так что хватает 0 или 8.
    let vectors = auxv_bytes.len()
        + (envp_ptrs.len() + 1) * 8
        + (argv_ptrs.len() + 1) * 8
        + 8;
    if sp.wrapping_sub(vectors as u64) & 0xF != 0 {
        sp -= 8;
    }
    sp -= auxv_bytes.len() as u64;
    write_user(l4, sp, &auxv_bytes)?;

    let mut push_ptrs = |l4: PhysFrame, ptrs: &[u64], sp: &mut u64| -> Result<(), MapToError<Size4KiB>> {
        let bytes: Vec<u8> = ptrs.iter().chain([0u64].iter()).flat_map(|v| v.to_le_bytes()).collect();
        *sp -= bytes.len() as u64;
        write_user(l4, *sp, &bytes)
    };
    push_ptrs(l4, &envp_ptrs, &mut sp)?;
    push_ptrs(l4, &argv_ptrs, &mut sp)?;
    sp -= 8;
    write_user(l4, sp, &argv.len().to_le_bytes())?;

    Ok(LoadedImage { entry, user_rsp: sp })
}

/// Завершает создание задачи: kernel-стек + начальный iret-фрейм.
fn finish_task(
    aspace: Arc<Mutex<AddressSpace>>,
    img: LoadedImage,
    name: &str,
) -> Result<Task, MapToError<Size4KiB>> {
    let l4 = aspace.lock().l4;
    let tid = NEXT_TID.fetch_add(1, Ordering::Relaxed);

    // Kernel-стек задачи (в kernel-адресном пространстве, виден при любом CR3).
    let mut kstack: Box<[u8]> = vec![0u8; KERNEL_STACK_SIZE].into_boxed_slice();
    let kstack_top = kstack.as_mut_ptr() as u64 + KERNEL_STACK_SIZE as u64;
    core::mem::forget(kstack);

    // Начальный «фрейм прерывания» на kernel-стеке: iretq в ring 3.
    // Порядок слотов совпадает с pop-последовательностью timer_entry.
    // ВАЖНО: фрейм лежит на 2 глубже вершины — первое же аппаратное
    // прерывание (CPU iret-фрейм + 15 пушей timer_entry) затирает верхние
    // ~160 байт стека; kernel_rsp должен указывать на нетронутую область.
    const GPRS: usize = 15;
    let rsp = kstack_top - 2 * (GPRS as u64 + 5) * 8;
    let (user_data, user_code) = gdt::user_segments();
    let mut name_buf = [0u8; 24];
    let nb = name.as_bytes();
    let n = nb.len().min(23);
    name_buf[..n].copy_from_slice(&nb[..n]);
    unsafe {
        let f = rsp as *mut u64;
        // GPR-слоты (15 штук) — нули; потом iret-фрейм.
        core::ptr::write(f.add(GPRS + 0), img.entry); // rip
        core::ptr::write(f.add(GPRS + 1), u64::from(user_code.0)); // cs (0x30|3)
        core::ptr::write(f.add(GPRS + 2), 0x202); // rflags: IF
        core::ptr::write(f.add(GPRS + 3), img.user_rsp); // user rsp
        core::ptr::write(f.add(GPRS + 4), u64::from(user_data.0)); // ss (0x28|3)
    }

    Ok(Task {
        tid,
        aspace,
        cr3: l4,
        kernel_rsp: rsp,
        kstack_top,
        state: TaskState::Runnable,
        exit_code: 0,
        parent: -1,
        fs_base: 0,
        clear_tid: 0,
        name: name_buf,
        fds: default_fds(),
        cwd: String::from("/"),
        umask: 0o022,
        fx: crate::fpu::FxState::new(),
    })
}

// ---- clone / fork / execve / wait (вызываются из linux.rs) ----

/// Номер текущего слота (для отладки).
pub fn current_slot() -> isize {
    CURRENT.load(Ordering::Relaxed)
}

pub fn current_tid() -> u64 {
    let cur = CURRENT.load(Ordering::Relaxed);
    if cur < 0 {
        return 0;
    }
    TASKS.lock()[cur as usize].as_ref().map(|t| t.tid).unwrap_or(0)
}

/// Доступ к текущей задаче под TASKS-локом.
pub fn with_current_task<R>(f: impl FnOnce(&mut Task) -> R) -> Option<R> {
    let cur = CURRENT.load(Ordering::Relaxed);
    if cur < 0 {
        return None;
    }
    let mut tasks = TASKS.lock();
    tasks[cur as usize].as_mut().map(f)
}

/// Доступ к любой задаче по tid.
pub fn with_task<R>(tid: u64, f: impl FnOnce(&mut Task) -> R) -> Option<R> {
    let mut tasks = TASKS.lock();
    tasks.iter_mut().flatten().find(|t| t.tid == tid).map(f)
}

/// Доступ к задаче по слоту (для getppid и отладки).
pub fn with_task_at<R>(slot: usize, f: impl FnOnce(&mut Task) -> R) -> Option<R> {
    let mut tasks = TASKS.lock();
    tasks.get_mut(slot).and_then(|t| t.as_mut()).map(f)
}

/// Найти завершившегося потомка tid'а (parent == tid). Возвращает
/// (child_tid, exit_code) и освобождает слот.
pub fn reap_child(parent_tid: u64, want: u64) -> Option<(u64, i64)> {
    let mut tasks = TASKS.lock();
    let count = TASK_COUNT.load(Ordering::Acquire);
    for i in 0..count.min(MAX_TASKS) {
        let matched = match &tasks[i] {
            Some(t) if t.state == TaskState::Exited => {
                let parent_ok = t.parent >= 0
                    && tasks
                        .get(t.parent as usize)
                        .and_then(|p| p.as_ref())
                        .map(|p| p.tid)
                        == Some(parent_tid);
                parent_ok && (want == 0 || want == u64::MAX || t.tid == want)
            }
            _ => false,
        };
        if matched {
            let t = tasks[i].take().expect("checked above");
            return Some((t.tid, t.exit_code));
        }
    }
    None
}

/// Количество живых потомков (для wait4 ECHILD).
pub fn has_children(parent_tid: u64) -> bool {
    let tasks = TASKS.lock();
    tasks.iter().flatten().any(|t| {
        t.parent >= 0
            && tasks[t.parent as usize]
                .as_ref()
                .map(|p| p.tid)
                .unwrap_or(u64::MAX)
                == parent_tid
    })
}

/// Создать поток/процесс (syscall clone). `frame` — сохранённый фрейм
/// родителя на его kernel-стеке (см. syscall::FRAME).
pub fn sys_clone(
    flags: u64,
    child_stack: u64,
    _ptid: u64,
    ctid: u64,
    tls: u64,
    frame: *const u64,
) -> u64 {
    const CLONE_VM: u64 = 0x100;
    const CLONE_FS: u64 = 0x200;
    const CLONE_FILES: u64 = 0x400;
    const CLONE_SETTLS: u64 = 0x80000;
    const CLONE_CHILD_CLEARTID: u64 = 0x200000;

    x86_64::instructions::interrupts::without_interrupts(|| {
        let cur = CURRENT.load(Ordering::Relaxed);
        if cur < 0 {
            return u64::MAX;
        }
        let slot = {
            let mut tasks = TASKS.lock();
            match alloc_slot(&mut tasks) {
                Some(s) => s,
                None => return u64::MAX,
            }
        };

        let (parent_as, parent_cr3, parent_fs, parent_cwd, parent_umask, parent_fds, parent_name, parent_tid);
        {
            let tasks = TASKS.lock();
            let p = tasks[cur as usize].as_ref().expect("current task vanished");
            parent_as = p.aspace.clone();
            parent_cr3 = p.cr3;
            parent_fs = p.fs_base;
            parent_cwd = p.cwd.clone();
            parent_umask = p.umask;
            parent_fds = p.fds.clone();
            parent_name = p.name;
            parent_tid = p.tid;
        }

        let child_as = if flags & CLONE_VM != 0 {
            parent_as.clone()
        } else {
            // fork: глубокая копия userspace.
            let copied = crate::memory::with_frame_allocator(|fa| {
                copy_user_space(parent_cr3, fa).and_then(|l4| {
                    let (brk_base, brk, mmap_next, thread_stacks) = {
                        let a = parent_as.lock();
                        (a.brk_base, a.brk, a.mmap_next, a.thread_stacks)
                    };
                    Ok(Arc::new(Mutex::new(AddressSpace {
                        l4,
                        brk_base,
                        brk,
                        mmap_next,
                        thread_stacks,
                    })))
                })
            });
            match copied {
                Ok(a) => a,
                Err(_) => return u64::MAX,
            }
        };

        let child_tid = NEXT_TID.fetch_add(1, Ordering::Relaxed);
        let child_l4 = child_as.lock().l4;

        // Kernel-стек ребёнка + контекст: копия фрейма родителя с rax=0.
        // Фрейм — на 2 глубже вершины: верхние ~160 байт стека затирает
        // первое же аппаратное прерывание (см. finish_task).
        let mut kstack: Box<[u8]> = vec![0u8; KERNEL_STACK_SIZE].into_boxed_slice();
        let kstack_top = kstack.as_mut_ptr() as u64 + KERNEL_STACK_SIZE as u64;
        core::mem::forget(kstack);
        let rsp = kstack_top - 2 * (15u64 + 5) * 8;
        let (user_data, user_code) = gdt::user_segments();
        unsafe {
            // Перекладка регистров: фрейм родителя в раскладке syscall_entry
            // (порядок push'ей entry), а timer_entry восстанавливает регистры
            // в СВОЁМ порядке (pop r15..rax). Слоты 0..5 совпадают, дальше —
            // явный remap. rax ребёнка = 0 (возврат из clone/fork).
            let f = rsp as *mut u64;
            *f.add(0) = *frame.add(0); // r15
            *f.add(1) = *frame.add(1); // r14
            *f.add(2) = *frame.add(2); // r13
            *f.add(3) = *frame.add(3); // r12
            *f.add(4) = *frame.add(4); // rbp
            *f.add(5) = *frame.add(5); // rbx
            *f.add(6) = *frame.add(12); // r11
            *f.add(7) = *frame.add(14); // r10 = user rsp
            *f.add(8) = *frame.add(6); // r9
            *f.add(9) = *frame.add(7); // r8
            *f.add(10) = *frame.add(10); // rdi
            *f.add(11) = *frame.add(9); // rsi
            *f.add(12) = *frame.add(8); // rdx
            *f.add(13) = *frame.add(13); // rcx
            *f.add(14) = 0; // rax: ребёнок получает 0 из clone
            let user_rsp = if flags & CLONE_VM != 0 && child_stack != 0 {
                child_stack // поток: свой стек
            } else {
                *frame.add(FRAME::RSP) // fork: общая копия стека родителя
            };
            let rip = *frame.add(FRAME::RIP);
            let rflags = *frame.add(FRAME::RFLAGS) | 0x200; // IF
            core::ptr::write(f.add(15), rip);
            core::ptr::write(f.add(16), u64::from(user_code.0));
            core::ptr::write(f.add(17), rflags);
            core::ptr::write(f.add(18), user_rsp);
            core::ptr::write(f.add(19), u64::from(user_data.0));
        }

        let fds = if flags & CLONE_FILES != 0 {
            parent_fds
        } else {
            let cloned: Vec<Option<crate::linux::Fd>> = parent_fds
                .lock()
                .iter()
                .map(|f| f.as_ref().map(|f| f.clone_fd()))
                .collect();
            Arc::new(Mutex::new(cloned))
        };

        let mut task = Task {
            tid: child_tid,
            aspace: child_as,
            cr3: child_l4,
            kernel_rsp: rsp,
            kstack_top,
            state: TaskState::Runnable,
            exit_code: 0,
            parent: cur as isize,
            fs_base: if flags & CLONE_SETTLS != 0 { tls } else { parent_fs },
            clear_tid: if flags & CLONE_CHILD_CLEARTID != 0 { ctid } else { 0 },
            name: parent_name,
            fds,
            cwd: if flags & CLONE_FS != 0 { parent_cwd } else { parent_cwd },
            umask: parent_umask,
            fx: crate::fpu::FxState::new(),
        };
        // Ребёнок должен увидеть те же xmm, что и родитель в точке clone.
        crate::fpu::save(&mut task.fx);
        unsafe {
            let f = rsp as *const u64;
            crate::serial_println!(
                "[clone] child frame: rip={:#x} rsp={:#x} rflags={:#x} rax={:#x}",
                *f.add(15), *f.add(18), *f.add(17), *f.add(14)
            );
        }
        let _ = parent_tid;

        TASKS.lock()[slot] = Some(task);
        let count = TASK_COUNT.load(Ordering::Acquire);
        TASK_COUNT.store(count.max(slot + 1), Ordering::Release);
        crate::serial_println!(
            "[clone] parent slot {} → child tid {} slot {} flags {:#x} cr3 {:?}",
            cur, child_tid, slot, flags, child_l4
        );
        child_tid
    })
}

/// Заменить образ текущей задачи (syscall execve).
/// path/argv/envp — указатели в user-памяти. Возвращает errno (-Exxx
/// как u64) или 0; при 0 фрейм syscall уже переписан под новый образ —
/// возврата в старый код не происходит.
pub fn sys_execve(path_ptr: u64, argv_ptr: u64, envp_ptr: u64, frame: *mut u64) -> u64 {
    use crate::linux::{E2BIG, EFAULT, EIO, ENOENT, ENOEXEC};

    // 1) Скопировать argv/envp в kernel до размонтирования старого АП.
    let argv = match copy_ptr_array(argv_ptr, 32) {
        Some(v) => v,
        None => return EFAULT,
    };
    let envp = match copy_ptr_array(envp_ptr, 64) {
        Some(v) => v,
        None => return EFAULT,
    };
    let path = match copy_user_cstr(path_ptr, 256) {
        Some(p) => p,
        None => return EFAULT,
    };
    crate::serial_println!("[execve] tid {} path '{}'", current_tid(), path);

    // 2) Разрешить путь и прочитать ELF.
    let canon = {
        let cwd = with_current_task(|t| t.cwd.clone()).unwrap_or_else(|| String::from("/"));
        match crate::fs::resolve(&cwd, &path) {
            Some(c) => c,
            None => return E2BIG,
        }
    };
    let elf = match crate::fs::read_canon(&canon) {
        Some(e) => e,
        None => {
            crate::serial_println!("[execve] '{}' not found (canon '{}')", path, canon);
            return ENOENT;
        }
    };

    // 3) Новое АП + загрузка.
    let built = crate::memory::with_frame_allocator(|fa| {
        let aspace = match AddressSpace::new_empty(fa) {
            Some(a) => a,
            None => return Err(MapToError::FrameAllocationFailed),
        };
        let l4 = aspace.lock().l4;
        map_range_zeroed(
            l4,
            VirtAddr::new(USER_STACK_TOP - USER_STACK_SIZE),
            VirtAddr::new(USER_STACK_TOP - 1),
            fa,
            USER_FLAGS,
        )?;
        let argv_full = if argv.is_empty() {
            alloc::vec![canon.clone()]
        } else {
            argv
        };
        let img = load_elf_image(l4, &elf, &argv_full, &envp, USER_STACK_TOP, fa)?;
        Ok((aspace, img))
    });
    let (aspace, img) = match built {
        Ok(v) => v,
        Err(_) => return ENOEXEC,
    };

    // 4) Переключиться на новое АП и переписать фрейм syscall:
    //    sysret уйдёт в точку входа нового образа.
    let l4 = aspace.lock().l4;
    with_current_task(|t| {
        t.aspace = aspace;
        t.cr3 = l4;
        t.fs_base = 0;
        let nb = canon.as_bytes();
        let n = nb.len().min(23);
        t.name = [0u8; 24];
        t.name[..n].copy_from_slice(&nb[..n]);
        // Старые xmm предыдущего образа новому процессу не принадлежат.
        crate::fpu::forget(&mut t.fx);
    });
    crate::fpu::reset_cpu();
    unsafe {
        Cr3::write(l4, Cr3Flags::empty());
        let f = frame;
        // ELF_PLAT_INIT: на входе в _start регистры нулевые. Иначе glibc
        // принимает rdx за rtld_fini и на exit зовёт мусор (часто адрес стека).
        *f.add(FRAME::R15) = 0;
        *f.add(FRAME::R14) = 0;
        *f.add(FRAME::R13) = 0;
        *f.add(FRAME::R12) = 0;
        *f.add(FRAME::RBP) = 0;
        *f.add(FRAME::RBX) = 0;
        *f.add(FRAME::R9) = 0;
        *f.add(FRAME::R8) = 0;
        *f.add(FRAME::RDX) = 0;
        *f.add(FRAME::RSI) = 0;
        *f.add(FRAME::RDI) = 0;
        *f.add(FRAME::RAX) = 0;
        *f.add(FRAME::RFLAGS) = 0x202;
        *f.add(FRAME::RIP) = img.entry;
        *f.add(FRAME::RSP) = img.user_rsp;
    }
    0
}

pub fn copy_user_cstr(ptr: u64, max: usize) -> Option<String> {
    if ptr == 0 {
        return Some(String::new());
    }
    let mut bytes = Vec::new();
    for i in 0..max {
        let b = unsafe { (ptr as *const u8).add(i).read() };
        if b == 0 {
            break;
        }
        bytes.push(b);
    }
    if bytes.len() >= max {
        return None;
    }
    Some(String::from_utf8_lossy(&bytes).into_owned())
}

fn copy_ptr_array(ptr: u64, max: usize) -> Option<Vec<String>> {
    if ptr == 0 {
        return Some(Vec::new());
    }
    let mut out = Vec::new();
    for i in 0..max {
        let p = unsafe { (ptr as *const u64).add(i).read() };
        if p == 0 {
            return Some(out);
        }
        out.push(copy_user_cstr(p, 1024)?);
    }
    None // нет завершающего NULL
}

/// sys_brk: вернуть/установить brk текущей задачи. addr=0 — запрос.
pub fn sys_brk(addr: u64) -> u64 {
    let cur = CURRENT.load(Ordering::Relaxed);
    if cur < 0 {
        return 0;
    }
    // brk в shared АП: мутируем под локом АП.
    let (l4, brk_base, old_brk);
    let aspace = {
        let tasks = TASKS.lock();
        tasks[cur as usize].as_ref().unwrap().aspace.clone()
    };
    {
        let mut a = aspace.lock();
        l4 = a.l4;
        brk_base = a.brk_base;
        old_brk = a.brk;
        if addr == 0 {
            return old_brk;
        }
        if addr < brk_base || addr > BRK_MAX {
            return old_brk;
        }
        a.brk = addr;
    }
    // Маппим недостающие страницы (сжатие не демаппим — фреймы текут).
    if addr > old_brk {
        let grow_start = (old_brk + 0xFFF) & !0xFFF;
        let grow_end = addr & !0xFFF;
        if grow_end >= grow_start {
            let r = crate::memory::with_frame_allocator(|fa| {
                map_range_zeroed(
                    l4,
                    VirtAddr::new(grow_start),
                    VirtAddr::new(grow_end),
                    fa,
                    USER_FLAGS,
                )
            });
            if r.is_err() {
                let mut a = aspace.lock();
                a.brk = old_brk;
                return old_brk;
            }
        }
    }
    addr
}

/// sys_mmap: анонимные приватные маппинги из бамп-региона АП.
pub fn sys_mmap(addr: u64, len: u64, _prot: u64, flags: u64, _fd: u64, _off: u64) -> u64 {
    use crate::linux::{ENOMEM, ENODEV};
    const MAP_ANONYMOUS: u64 = 0x20;
    const MAP_PRIVATE: u64 = 0x2;
    const MAP_FIXED: u64 = 0x10;
    if len == 0 || len > 256 * 1024 * 1024 {
        return ENOMEM;
    }
    if flags & MAP_ANONYMOUS == 0 {
        // Маппинг файлов пока не поддержан: busybox обходится без него.
        return ENODEV;
    }
    if flags & MAP_PRIVATE == 0 {
        return ENODEV;
    }
    let cur = CURRENT.load(Ordering::Relaxed);
    if cur < 0 {
        return ENOMEM;
    }
    let aspace = {
        let tasks = TASKS.lock();
        tasks[cur as usize].as_ref().unwrap().aspace.clone()
    };
    let pages = (len + 0xFFF) / 0x1000;
    let base = {
        let mut a = aspace.lock();
        let base = if MAP_FIXED != 0 && addr != 0 && (flags & MAP_FIXED) != 0 {
            addr & !0xFFF
        } else {
            a.mmap_next
        };
        a.mmap_next = base + pages * 0x1000;
        base
    };
    if base + pages * 0x1000 > MMAP_TOP {
        return ENOMEM;
    }
    let l4 = aspace.lock().l4;
    let r = crate::memory::with_frame_allocator(|fa| {
        map_range_zeroed(
            l4,
            VirtAddr::new(base),
            VirtAddr::new(base + pages * 0x1000 - 1),
            fa,
            USER_FLAGS,
        )
    });
    match r {
        Ok(()) => base,
        Err(_) => ENOMEM,
    }
}

/// sys_arch_prctl: установить/прочитать FS BASE текущей задачи.
pub fn sys_arch_prctl(code: u64, addr: u64) -> u64 {
    const ARCH_SET_FS: u64 = 0x1002;
    const ARCH_GET_FS: u64 = 0x1003;
    const ARCH_SET_GS: u64 = 0x1001;
    const ARCH_GET_GS: u64 = 0x1004;
    match code {
        ARCH_SET_FS => {
            with_current_task(|t| t.fs_base = addr);
            unsafe { Msr::new(0xC000_0100).write(addr) };
            0
        }
        ARCH_GET_FS => with_current_task(|t| t.fs_base).unwrap_or(0),
        ARCH_SET_GS => {
            unsafe { Msr::new(0xC000_0101).write(addr) };
            0
        }
        ARCH_GET_GS => unsafe { Msr::new(0xC000_0101).read() },
        _ => crate::linux::EINVAL,
    }
}

/// Выделить стек для нового потока в общем АП. Возвращает вершину стека.
pub fn alloc_thread_stack() -> Option<u64> {
    let cur = CURRENT.load(Ordering::Relaxed);
    if cur < 0 {
        return None;
    }
    let aspace = {
        let tasks = TASKS.lock();
        tasks[cur as usize].as_ref()?.aspace.clone()
    };
    let (l4, idx) = {
        let mut a = aspace.lock();
        if a.thread_stacks >= MAX_THREADS_PER_PROC {
            return None;
        }
        let idx = a.thread_stacks;
        a.thread_stacks += 1;
        (a.l4, idx)
    };
    let top = THREAD_STACK_BASE + idx * THREAD_STACK_SIZE + THREAD_STACK_SIZE / 2;
    let base = top - THREAD_STACK_SIZE / 2;
    let r = crate::memory::with_frame_allocator(|fa| {
        map_range_zeroed(
            l4,
            VirtAddr::new(base),
            VirtAddr::new(top - 1),
            fa,
            USER_FLAGS,
        )
    });
    r.ok().map(|_| top)
}

/// Пометить текущую задачу завершённой. Планировщик больше в неё не вернётся.
pub fn exit_current() {
    x86_64::instructions::interrupts::without_interrupts(|| {
        let cur = CURRENT.load(Ordering::Relaxed);
        if cur >= 0 {
            let mut tasks = TASKS.lock();
            // Детей отцепляем: слот родителя может достаться новой задаче.
            for t in tasks.iter_mut().flatten() {
                if t.parent == cur {
                    t.parent = -1;
                }
            }
            if let Some(t) = tasks[cur as usize].as_mut() {
                // CLONE_CHILD_CLEARTID: pthread join ждёт обнуления.
                if t.clear_tid != 0 {
                    let p = t.clear_tid as *mut u32;
                    unsafe { p.write_volatile(0) };
                }
                t.state = TaskState::Exited;
            }
        }
    });
}

/// sys_exit: код выхода → exit_code, дальше как exit_current.
pub fn sys_exit(code: u64) -> ! {
    with_current_task(|t| t.exit_code = code as i64);
    exit_current();
    serial_println!(
        "[task] tid {} exited with code {}",
        current_tid(),
        code as i64
    );
    // Планировщик больше не выберет эту задачу; тикаем hlt до конца таймсов.
    loop {
        x86_64::instructions::hlt();
    }
}

// ---- Планировщик ----

/// Дамп задач (serial + экран) для команды `ps`.
pub fn debug_dump() {
    let tasks = TASKS.lock();
    let count = TASK_COUNT.load(Ordering::Acquire);
    crate::serial_println!("  TID  SLOT STATE   PARENT NAME");
    crate::framebuffer::_print_screen(core::format_args!(
        "  TID  SLOT STATE   PARENT NAME\n"
    ));
    for i in 0..count.min(MAX_TASKS) {
        if let Some(t) = &tasks[i] {
            let state = match t.state {
                TaskState::Runnable => "run ",
                TaskState::Exited => "dead",
            };
            let name = core::str::from_utf8(&t.name).unwrap_or("?");
            crate::serial_println!(
                "  {:>3}  {:>4} {} {:>6} {}",
                t.tid,
                i,
                state,
                t.parent,
                name
            );
            crate::framebuffer::_print_screen(core::format_args!(
                "  {:>3}  {:>4} {} {:>6} {}\n",
                t.tid,
                i,
                state,
                t.parent,
                name
            ));
        }
    }
}

/// Переключение контекста из обработчика таймера (вызывается из asm).
/// Принимает rsp текущего контекста, возвращает rsp следующего.
#[no_mangle]
extern "C" fn timer_switch(current_rsp: u64) -> u64 {
    crate::interrupts::TICKS.fetch_add(1, Ordering::Relaxed);

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

    let (next_rsp, next_kstack_top, next_cr3, next_fs);
    {
        let mut tasks = TASKS.lock();
        if prev >= 0 {
            if let Some(t) = tasks[prev as usize].as_mut() {
                t.kernel_rsp = current_rsp;
                if prev as usize != next {
                    crate::fpu::save(&mut t.fx);
                }
            }
        }
        if prev < 0 || prev as usize != next {
            if let Some(t) = tasks[next].as_ref() {
                crate::fpu::restore(&t.fx);
            }
        }
        let task = tasks[next].as_ref().expect("runnable task disappeared");
        next_rsp = task.kernel_rsp;
        next_kstack_top = task.kstack_top;
        next_cr3 = task.cr3;
        next_fs = task.fs_base;
    }

    CURRENT.store(next as isize, Ordering::Relaxed);

    unsafe { Cr3::write(next_cr3, Cr3Flags::empty()) };
    unsafe { Msr::new(0xC000_0100).write(next_fs) };
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
    # Тот же контракт, что у syscall_entry: перед call выровнять rsp вниз
    # до 16, чтобы Rust вошёл с rsp ≡ 8 (mod 16). Сохранённый контекст — rbx,
    # он callee-saved и не входит в выравнивание.
    mov rbx, rsp
    mov rdi, rbx
    and rsp, -16
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
