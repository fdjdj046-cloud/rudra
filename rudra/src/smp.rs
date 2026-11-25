//! Старт application processors.
//!
//! AP поднимается SIPI в длинный режим, получает свой TSS и тик LAPIC
//! и исполняет задачи, у которых `Task::cpu` равен его индексу.
//! Кадр, застигнутый в ядре, на другой CPU не переносится.
//! IPI с вектором [`IPI_VECTOR`] считает попадания. Тот же вектор
//! сбрасывает TLB, если ядро попросило shootdown этого CR3.
//! Вектор [`MB_VECTOR`] — `membarrier GLOBAL`: барьер на каждом другом CPU.
//! TLB он не трогает и счётчик shootdown не двигает.

use bootloader_api::info::{MemoryRegion, MemoryRegionKind};
use core::sync::atomic::{AtomicU32, AtomicU64, AtomicU8, Ordering};
use spin::Mutex;
use x86_64::registers::control::Cr3;
use x86_64::structures::paging::{FrameAllocator, PageTable, PageTableFlags, PhysFrame};
use x86_64::PhysAddr;

use crate::cpu::MAX_CPUS;
use crate::memory::BootInfoFrameAllocator;
const PARAM_CR3: usize = 0xE0;
const PARAM_STACK: usize = 0xE8;
const PARAM_ENTRY: usize = 0xF0;
const PARAM_GDTR: usize = 0xF8;

static TRAMP: &[u8] = include_bytes!("ap_tramp.bin");

static CPU_COUNT: AtomicU32 = AtomicU32::new(0);
static ONLINE: AtomicU32 = AtomicU32::new(1);
static IPI_COUNT: AtomicU64 = AtomicU64::new(0);
/// Следующий индекс AP. BSP занимает 0. `lock xadd` в `ap_entry`.
#[no_mangle]
static AP_INDEX_ALLOC: AtomicU32 = AtomicU32::new(1);
/// Вершины простаивающих стеков. Индекс — номер CPU.
#[no_mangle]
static AP_IDLE_TOP: [AtomicU64; MAX_CPUS] = [
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
];
/// CR3 ядра этого CPU. Возврат в простой восстанавливает его, не CR3 BSP.
static KERNEL_CR3: [AtomicU64; MAX_CPUS] = [
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
];
/// Индекс CPU по id локального APIC. 0xFF — нет такого.
static APIC_INDEX: [AtomicU8; 256] = [const { AtomicU8::new(0xFF) }; 256];

const IDLE_STACK: usize = 32 * 1024;

#[repr(C, align(16))]
struct IdleMem([u8; IDLE_STACK]);

#[allow(static_mut_refs)]
static mut AP_IDLE_MEM: [IdleMem; MAX_CPUS] = [
    IdleMem([0; IDLE_STACK]),
    IdleMem([0; IDLE_STACK]),
    IdleMem([0; IDLE_STACK]),
    IdleMem([0; IDLE_STACK]),
    IdleMem([0; IDLE_STACK]),
    IdleMem([0; IDLE_STACK]),
    IdleMem([0; IDLE_STACK]),
    IdleMem([0; IDLE_STACK]),
];
static APIC_IDS: [AtomicU32; MAX_CPUS] = [
    AtomicU32::new(0),
    AtomicU32::new(0),
    AtomicU32::new(0),
    AtomicU32::new(0),
    AtomicU32::new(0),
    AtomicU32::new(0),
    AtomicU32::new(0),
    AtomicU32::new(0),
];

/// Вектор fixed-IPI. 48 занят таймером LAPIC, 32..=47 — PIC.
pub const IPI_VECTOR: u8 = 49;
/// `membarrier GLOBAL`. Отдельный вектор, чтобы не спутать с TLB.
pub const MB_VECTOR: u8 = 50;

pub fn cpu_count() -> u32 {
    let n = CPU_COUNT.load(Ordering::Relaxed);
    if n == 0 {
        1
    } else {
        n
    }
}

pub fn aps_online() -> u32 {
    ONLINE.load(Ordering::Acquire).saturating_sub(1)
}

pub fn ipi_seen() -> u64 {
    IPI_COUNT.load(Ordering::Acquire)
}

pub fn record_ipi() {
    IPI_COUNT.fetch_add(1, Ordering::Release);
}

/// Поколение shootdown. 0 — запроса ещё не было, обработчик только считает IPI.
static SHOOT_GEN: AtomicU64 = AtomicU64::new(0);
static SHOOT_CR3: AtomicU64 = AtomicU64::new(0);
static SHOOT_ACK: [AtomicU64; MAX_CPUS] = [const { AtomicU64::new(0) }; MAX_CPUS];
/// Ждёт ответа. Обработчик IPI его не берёт: иначе два CPU взаимно не ответят.
static SHOOT_LOCK: Mutex<()> = Mutex::new(());

fn cpu_registered(cpu: usize) -> bool {
    if cpu == 0 {
        return true;
    }
    if cpu >= MAX_CPUS {
        return false;
    }
    let id = APIC_IDS[cpu].load(Ordering::Relaxed);
    if id > 255 {
        return false;
    }
    APIC_INDEX[id as usize].load(Ordering::Acquire) == cpu as u8
}

fn flush_if_cr3(cr3: u64) {
    if cr3 == 0 {
        return;
    }
    let (frame, _) = Cr3::read();
    if frame.start_address().as_u64() == cr3 {
        x86_64::instructions::tlb::flush_all();
    }
}

/// IPI: счётчик для `ping_aps` и ответ на текущий shootdown.
/// Лок shootdown и аллокатор кадров здесь не берутся.
pub fn on_ipi() {
    record_ipi();
    let gen = SHOOT_GEN.load(Ordering::Acquire);
    if gen == 0 {
        return;
    }
    flush_if_cr3(SHOOT_CR3.load(Ordering::Acquire));
    let cpu = this_cpu();
    if cpu < MAX_CPUS {
        SHOOT_ACK[cpu].store(gen, Ordering::Release);
    }
}

/// Сбросить TLB `cr3` на каждом CPU, который его сейчас держит.
/// `false` — кто-то не ответил. Кадр после этого отдавать нельзя.
/// Ждущий не держит аллокатор кадров. Чужой IPI он принимает, если IF включён.
pub fn shootdown(cr3: u64) -> bool {
    let _guard = SHOOT_LOCK.lock();
    SHOOT_CR3.store(cr3, Ordering::Relaxed);
    let gen = SHOOT_GEN.fetch_add(1, Ordering::Release).wrapping_add(1);
    let me = this_cpu().min(MAX_CPUS - 1);
    let n = (cpu_count() as usize).min(MAX_CPUS);
    let mut wait = [false; MAX_CPUS];
    for cpu in 0..n {
        if cpu == me || !cpu_registered(cpu) {
            continue;
        }
        let id = APIC_IDS[cpu].load(Ordering::Relaxed);
        if !crate::apic::send_fixed(id, IPI_VECTOR) {
            crate::serial_println!("[smp] tlb ipi to {} failed", id);
            flush_if_cr3(cr3);
            return false;
        }
        wait[cpu] = true;
    }
    flush_if_cr3(cr3);
    let deadline = crate::time::monotonic_ns().saturating_add(50_000_000);
    loop {
        let mut done = true;
        for cpu in 0..n {
            if wait[cpu] && SHOOT_ACK[cpu].load(Ordering::Acquire) < gen {
                done = false;
                break;
            }
        }
        if done {
            return true;
        }
        if crate::time::monotonic_ns() > deadline {
            crate::serial_println!("[smp] tlb shootdown timeout gen {}", gen);
            return false;
        }
        core::hint::spin_loop();
    }
}

/// Поколение `membarrier`. 0 — запроса ещё не было.
static MB_GEN: AtomicU64 = AtomicU64::new(0);
static MB_ACK: [AtomicU64; MAX_CPUS] = [const { AtomicU64::new(0) }; MAX_CPUS];
/// Кого ждём в текущем поколении. Пишет только держатель `MB_LOCK`.
static MB_NEED: [AtomicU8; MAX_CPUS] = [const { AtomicU8::new(0) }; MAX_CPUS];
static MB_LOCK: Mutex<()> = Mutex::new(());
static MB_HITS: AtomicU64 = AtomicU64::new(0);

fn mb_done(gen: u64, n: usize) -> bool {
    for cpu in 0..n {
        if MB_NEED[cpu].load(Ordering::Relaxed) != 0
            && MB_ACK[cpu].load(Ordering::Acquire) < gen
        {
            return false;
        }
    }
    true
}

fn mb_wait(gen: u64, n: usize) -> bool {
    let deadline = crate::time::monotonic_ns().saturating_add(50_000_000);
    loop {
        if mb_done(gen, n) {
            return true;
        }
        if crate::time::monotonic_ns() > deadline {
            return false;
        }
        core::hint::spin_loop();
    }
}

/// IPI `GLOBAL`: барьер, затем ответ на текущее поколение.
/// Лок `membarrier` здесь не берётся.
pub fn on_membarrier_ipi() {
    core::sync::atomic::fence(Ordering::SeqCst);
    MB_HITS.fetch_add(1, Ordering::Release);
    let gen = MB_GEN.load(Ordering::Acquire);
    if gen == 0 {
        return;
    }
    let cpu = this_cpu();
    if cpu < MAX_CPUS {
        MB_ACK[cpu].store(gen, Ordering::Release);
    }
}

#[cfg(test)]
pub fn membarrier_hits() -> u64 {
    MB_HITS.load(Ordering::Acquire)
}

/// Барьер на этом CPU и на каждом другом поднятом. `false` — кто-то не ответил:
/// успехом это не считается. Новое поколение не начинается, пока предыдущие
/// IPI не доехали, иначе поздний ответ закрыл бы чужой барьер.
pub fn membarrier_global() -> bool {
    let _guard = MB_LOCK.lock();
    let n = (cpu_count() as usize).min(MAX_CPUS);
    let gen_now = MB_GEN.load(Ordering::Acquire);
    if gen_now != 0 && !mb_done(gen_now, n) && !mb_wait(gen_now, n) {
        return false;
    }
    core::sync::atomic::fence(Ordering::SeqCst);
    let gen = MB_GEN.fetch_add(1, Ordering::Release).wrapping_add(1);
    for cpu in 0..n {
        MB_NEED[cpu].store(0, Ordering::Relaxed);
    }
    let me = this_cpu().min(MAX_CPUS - 1);
    for cpu in 0..n {
        if cpu == me || !cpu_registered(cpu) {
            continue;
        }
        let id = APIC_IDS[cpu].load(Ordering::Relaxed);
        if !crate::apic::send_fixed(id, MB_VECTOR) {
            crate::serial_println!("[smp] membarrier ipi to {} failed", id);
            return false;
        }
        MB_NEED[cpu].store(1, Ordering::Relaxed);
    }
    if !mb_wait(gen, n) {
        crate::serial_println!("[smp] membarrier timeout gen {}", gen);
        return false;
    }
    core::sync::atomic::fence(Ordering::SeqCst);
    true
}

/// CPU, на котором выполняется этот код. До карты APIC и до регистрации — 0.
pub fn this_cpu() -> usize {
    if !crate::apic::mmio_ready() {
        return 0;
    }
    let id = crate::apic::local_id();
    if id > 255 {
        return 0;
    }
    let idx = APIC_INDEX[id as usize].load(Ordering::Relaxed);
    if idx == 0xFF {
        0
    } else {
        idx as usize
    }
}

pub fn kernel_cr3(cpu: usize) -> u64 {
    KERNEL_CR3[cpu.min(MAX_CPUS - 1)].load(Ordering::Relaxed)
}

/// Вершина простаивающего стека AP. У BSP запасной стек syscall, здесь 0.
pub fn idle_kstack(cpu: usize) -> u64 {
    if cpu == 0 || cpu >= MAX_CPUS {
        0
    } else {
        AP_IDLE_TOP[cpu].load(Ordering::Relaxed)
    }
}

#[allow(static_mut_refs)]
fn idle_stack_top(index: usize) -> u64 {
    let index = index.min(MAX_CPUS - 1);
    unsafe { core::ptr::addr_of!(AP_IDLE_MEM[index]) as u64 + IDLE_STACK as u64 }
}

/// Страница ниже 640 КиБ из свободной карты. Кадр потом не выдаёт аллокатор.
pub fn reserve_trampoline(regions: &[MemoryRegion]) -> Option<u64> {
    let mut best = None;
    for region in regions {
        if region.kind != MemoryRegionKind::Usable {
            continue;
        }
        let start = (region.start.max(0x1000) + 0xFFF) & !0xFFF;
        let end = region.end.min(0xA_0000);
        if start.saturating_add(4096) > end {
            continue;
        }
        let last = (end - 4096) & !0xFFF;
        if last >= start {
            best = Some(last);
        }
    }
    best
}

/// Разобрать MADT и поднять AP. `tramp` — страница из [`reserve_trampoline`].
pub fn start(tramp: Option<u64>, rsdp: Option<u64>) {
    let (kframe, _) = Cr3::read();
    KERNEL_CR3[0].store(kframe.start_address().as_u64(), Ordering::Relaxed);
    if crate::apic::mmio_ready() {
        let bsp = crate::apic::id();
        if bsp <= 255 {
            APIC_INDEX[bsp as usize].store(0, Ordering::Relaxed);
        }
    }
    if !crate::apic::mmio_ready() {
        crate::serial_println!("[smp] no xapic mmio, aps not started");
        return;
    }
    let Some(tramp) = tramp else {
        crate::serial_println!("[smp] no low page, aps not started");
        return;
    };
    let Some(rsdp) = rsdp else {
        crate::serial_println!("[smp] no rsdp, aps not started");
        return;
    };
    let mut ids = [0u32; MAX_CPUS];
    let n = match madt_ids(rsdp, &mut ids) {
        Some(n) if n > 0 => n,
        _ => {
            crate::serial_println!("[smp] madt has no local apics");
            return;
        }
    };
    let bsp = crate::apic::id();
    APIC_IDS[0].store(bsp, Ordering::Relaxed);
    let mut aps = [0u32; MAX_CPUS];
    let mut ap_n = 0usize;
    for i in 0..n {
        if ids[i] == bsp {
            continue;
        }
        if ap_n + 1 >= MAX_CPUS {
            crate::serial_println!("[smp] extra apic id {} skipped", ids[i]);
            continue;
        }
        aps[ap_n] = ids[i];
        ap_n += 1;
        APIC_IDS[ap_n].store(ids[i], Ordering::Relaxed);
    }
    CPU_COUNT.store((ap_n + 1) as u32, Ordering::Relaxed);
    for i in 1..=ap_n {
        AP_IDLE_TOP[i].store(idle_stack_top(i), Ordering::Release);
    }
    if ap_n == 0 {
        crate::serial_println!("[smp] madt {}, only bsp", n);
        return;
    }

    let stacks = match prepare(tramp, &aps[..ap_n]) {
        Some(s) => s,
        None => {
            crate::serial_println!("[smp] page tables failed");
            return;
        }
    };
    let vector = (tramp >> 12) as u8;
    for i in 0..ap_n {
        write_u64(tramp, PARAM_STACK, stacks[i]);
        core::sync::atomic::fence(Ordering::SeqCst);
        let id = aps[i];
        let seen = ONLINE.load(Ordering::Acquire);
        if !crate::apic::send_init(id) {
            crate::serial_println!("[smp] init ipi to {} failed", id);
            continue;
        }
        spin_ns(10_000_000);
        if !crate::apic::send_startup(id, vector) {
            crate::serial_println!("[smp] sipi to {} failed", id);
            continue;
        }
        spin_ns(200_000);
        let _ = crate::apic::send_startup(id, vector);
        let deadline = crate::time::monotonic_ns().saturating_add(50_000_000);
        while ONLINE.load(Ordering::Acquire) == seen {
            if crate::time::monotonic_ns() > deadline {
                crate::serial_println!("[smp] apic id {} did not come up", id);
                break;
            }
            core::hint::spin_loop();
        }
    }
    let woke = ping_aps(ap_n);
    crate::serial_println!(
        "[smp] madt {} online {} ipi {} (per-cpu tss, ap timer)",
        CPU_COUNT.load(Ordering::Relaxed),
        ONLINE.load(Ordering::Acquire),
        woke
    );
}

fn ping_aps(ap_n: usize) -> u64 {
    let before = IPI_COUNT.load(Ordering::Acquire);
    let expect = aps_online();
    for i in 1..=ap_n {
        let id = APIC_IDS[i as usize].load(Ordering::Relaxed);
        if !crate::apic::send_fixed(id, IPI_VECTOR) {
            crate::serial_println!("[smp] ipi to {} failed", id);
        }
    }
    let deadline = crate::time::monotonic_ns().saturating_add(20_000_000);
    while IPI_COUNT.load(Ordering::Acquire).wrapping_sub(before) < u64::from(expect) {
        if crate::time::monotonic_ns() > deadline {
            break;
        }
        core::hint::spin_loop();
    }
    IPI_COUNT.load(Ordering::Acquire).wrapping_sub(before)
}

fn prepare(tramp: u64, aps: &[u32]) -> Option<[u64; MAX_CPUS]> {
    unsafe {
        core::ptr::write_bytes(phys_mut(tramp), 0, 4096);
        core::ptr::copy_nonoverlapping(TRAMP.as_ptr(), phys_mut(tramp), TRAMP.len());
    }
    let mut gdtr = [0u8; 10];
    unsafe {
        core::arch::asm!(
            "sgdt [{}]",
            in(reg) gdtr.as_mut_ptr(),
            options(nostack, preserves_flags),
        );
    }
    unsafe {
        core::ptr::copy_nonoverlapping(gdtr.as_ptr(), phys_mut(tramp).add(PARAM_GDTR), 10);
    }
    let entry = ap_entry as *const () as u64;
    write_u64(tramp, PARAM_ENTRY, entry);

    let mut stacks = [0u64; MAX_CPUS];
    let cr3 = crate::memory::with_frame_allocator(|fa| -> Option<u64> {
        let l4 = copy_kernel_l4(fa)?;
        if !map_identity(l4, tramp, fa) {
            return None;
        }
        for (i, _) in aps.iter().enumerate() {
            let frame = fa.allocate_frame()?;
            let phys = frame.start_address().as_u64();
            unsafe { core::ptr::write_bytes(phys_mut(phys), 0, 4096) };
            let top = crate::PHYS_OFFSET.load(Ordering::Relaxed) + phys + 4096;
            stacks[i] = top - 8;
        }
        Some(l4)
    })?;
    write_u64(tramp, PARAM_CR3, cr3);
    Some(stacks)
}

extern "C" {
    fn ap_entry();
}

/// Уже на своём стеке 32 КиБ. Индекс выдал `ap_entry`.
#[no_mangle]
extern "C" fn ap_main(index: u64) -> ! {
    let index = index as usize;
    if index >= MAX_CPUS {
        // Кламп хуже остановки: два ядра на одном GS-слоте молча порушили
        // бы друг другу kstack-указатели. start() такое не шлёт — страховка.
        crate::serial_println!("[smp] ap index {} >= MAX_CPUS, halting", index);
        loop {
            x86_64::instructions::hlt();
        }
    }
    x86_64::instructions::interrupts::disable();
    crate::fpu::enable();
    let top = idle_stack_top(index);
    crate::gdt::load_ap(index, top);
    crate::interrupts::init_idt();
    crate::syscall::init();
    let id = crate::apic::local_id();
    if id <= 255 {
        APIC_INDEX[id as usize].store(index as u8, Ordering::Release);
    }
    let (frame, _) = Cr3::read();
    KERNEL_CR3[index].store(frame.start_address().as_u64(), Ordering::Relaxed);
    crate::apic::arm_ap_timer();
    // INIT-SIPI больше не нужны: переключаем этот AP на x2APIC (MSR-интерфейс).
    crate::apic::enable_x2apic();
    ONLINE.fetch_add(1, Ordering::Release);
    x86_64::instructions::interrupts::enable();
    loop {
        x86_64::instructions::hlt();
    }
}

core::arch::global_asm!(
    r#"
    .text
    .global ap_entry
ap_entry:
    # Трамплин оставил маленький стек. До Rust его меняем.
    mov eax, 1
    lock xadd dword ptr [rip + AP_INDEX_ALLOC], eax
    # Лишний AP (за пределами MAX_CPUS) останавливаем здесь, до Rust:
    # AP_IDLE_TOP короче, а кламп индекса алиасил бы GS-слот чужого ядра.
    cmp eax, 8
    jae 2f
    lea rcx, [rip + AP_IDLE_TOP]
    mov rsp, qword ptr [rcx + rax*8]
    mov rdi, rax
    call ap_main
2:
    cli
    hlt
    jmp 2b
"#
);

fn copy_kernel_l4(fa: &mut BootInfoFrameAllocator) -> Option<u64> {
    let src = Cr3::read().0.start_address().as_u64();
    let dst = alloc_zero(fa)?;
    unsafe {
        core::ptr::copy_nonoverlapping(phys_mut(src), phys_mut(dst), 4096);
        (&mut *(phys_mut(dst) as *mut PageTable))[0].set_unused();
    }
    Some(dst)
}

fn map_identity(l4: u64, phys: u64, fa: &mut BootInfoFrameAllocator) -> bool {
    let i4 = ((phys >> 39) & 0x1FF) as usize;
    let i3 = ((phys >> 30) & 0x1FF) as usize;
    let i2 = ((phys >> 21) & 0x1FF) as usize;
    let i1 = ((phys >> 12) & 0x1FF) as usize;
    let Some(l3) = next_table(l4, i4, fa) else {
        return false;
    };
    let Some(l2) = next_table(l3, i3, fa) else {
        return false;
    };
    let Some(l1) = next_table(l2, i2, fa) else {
        return false;
    };
    let flags = PageTableFlags::PRESENT | PageTableFlags::WRITABLE;
    unsafe {
        (&mut *(phys_mut(l1) as *mut PageTable))[i1].set_addr(PhysAddr::new(phys), flags);
    }
    true
}

fn next_table(parent: u64, index: usize, fa: &mut BootInfoFrameAllocator) -> Option<u64> {
    let existing = {
        let table = unsafe { &*(phys_mut(parent) as *const PageTable) };
        let entry = &table[index];
        if entry.flags().contains(PageTableFlags::HUGE_PAGE) {
            return None;
        }
        if entry.is_unused() {
            None
        } else {
            Some(entry.addr().as_u64())
        }
    };
    if let Some(phys) = existing {
        return Some(phys);
    }
    let phys = alloc_zero(fa)?;
    let flags = PageTableFlags::PRESENT | PageTableFlags::WRITABLE;
    unsafe {
        (&mut *(phys_mut(parent) as *mut PageTable))[index].set_addr(PhysAddr::new(phys), flags);
    }
    Some(phys)
}

fn alloc_zero(fa: &mut BootInfoFrameAllocator) -> Option<u64> {
    let frame: PhysFrame = fa.allocate_frame()?;
    let phys = frame.start_address().as_u64();
    unsafe { core::ptr::write_bytes(phys_mut(phys), 0, 4096) };
    Some(phys)
}

fn madt_ids(rsdp: u64, out: &mut [u32; MAX_CPUS]) -> Option<usize> {
    if !sig(rsdp, b"RSD PTR ") || sum(rsdp, 20) != 0 {
        crate::serial_println!("[smp] rsdp checksum failed");
        return None;
    }
    let rev = read_u8(rsdp + 15);
    let rsdt = u64::from(read_u32(rsdp + 16));
    let (root, wide) = if rev >= 2 {
        let len = read_u32(rsdp + 20) as usize;
        let xsdt = read_u64(rsdp + 24);
        if xsdt != 0 && (36..4096).contains(&len) && sum(rsdp, len) == 0 {
            (xsdt, true)
        } else {
            (rsdt, false)
        }
    } else {
        (rsdt, false)
    };
    if root == 0 || !sig(root, b"RSDT") && !sig(root, b"XSDT") {
        crate::serial_println!("[smp] bad rsdt {:#x}", root);
        return None;
    }
    let madt = find_sdt(root, wide, b"APIC")?;
    parse_madt(madt, out)
}

fn find_sdt(root: u64, wide: bool, want: &[u8; 4]) -> Option<u64> {
    let len = read_u32(root + 4) as usize;
    if !(36..1_048_576).contains(&len) {
        return None;
    }
    let stride = if wide { 8 } else { 4 };
    let mut off = 36usize;
    while off + stride <= len {
        let ptr = if wide {
            read_u64(root + off as u64)
        } else {
            u64::from(read_u32(root + off as u64))
        };
        if ptr != 0 && sig(ptr, want) {
            return Some(ptr);
        }
        off += stride;
    }
    None
}

fn parse_madt(madt: u64, out: &mut [u32; MAX_CPUS]) -> Option<usize> {
    let len = read_u32(madt + 4) as usize;
    if len < 44 || len > 1_048_576 {
        return None;
    }
    let mut off = 44usize;
    let mut n = 0usize;
    while off + 2 <= len {
        let kind = read_u8(madt + off as u64);
        let elen = read_u8(madt + off as u64 + 1) as usize;
        if elen < 2 || off + elen > len {
            break;
        }
        if kind == 0 && elen >= 8 {
            let id = u32::from(read_u8(madt + off as u64 + 3));
            let flags = read_u32(madt + off as u64 + 4);
            if flags & 1 != 0 {
                if n >= MAX_CPUS {
                    crate::serial_println!("[smp] madt id {} over cap", id);
                } else {
                    out[n] = id;
                    n += 1;
                }
            }
        }
        off += elen;
    }
    if n == 0 {
        None
    } else {
        Some(n)
    }
}

fn spin_ns(ns: u64) {
    let start = crate::time::monotonic_ns();
    while crate::time::monotonic_ns().wrapping_sub(start) < ns {
        core::hint::spin_loop();
    }
}

fn write_u64(tramp: u64, off: usize, value: u64) {
    unsafe {
        core::ptr::write_unaligned(phys_mut(tramp).add(off) as *mut u64, value);
    }
}

fn phys_mut(phys: u64) -> *mut u8 {
    (crate::PHYS_OFFSET.load(Ordering::Relaxed).wrapping_add(phys)) as *mut u8
}

fn read_u8(phys: u64) -> u8 {
    unsafe { core::ptr::read_volatile(phys_mut(phys)) }
}

fn read_u32(phys: u64) -> u32 {
    unsafe { core::ptr::read_unaligned(phys_mut(phys) as *const u32) }
}

fn read_u64(phys: u64) -> u64 {
    unsafe { core::ptr::read_unaligned(phys_mut(phys) as *const u64) }
}

fn sig(phys: u64, bytes: &[u8]) -> bool {
    bytes
        .iter()
        .enumerate()
        .all(|(i, b)| read_u8(phys + i as u64) == *b)
}

fn sum(phys: u64, len: usize) -> u8 {
    let mut s = 0u8;
    for i in 0..len {
        s = s.wrapping_add(read_u8(phys + i as u64));
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{serial_print, serial_println};

    #[test_case]
    fn aps_answer_ipi() {
        serial_print!("test aps_answer_ipi... ");
        assert!(
            cpu_count() >= 2,
            "madt cpus {}",
            cpu_count()
        );
        assert_eq!(
            aps_online(),
            cpu_count() - 1,
            "aps online {}",
            aps_online()
        );
        assert!(
            ipi_seen() >= u64::from(aps_online()),
            "ipi {}",
            ipi_seen()
        );
        serial_println!(
            "[ok] cpus {} ipi {}",
            cpu_count(),
            ipi_seen()
        );
    }
}
