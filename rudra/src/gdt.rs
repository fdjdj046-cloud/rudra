use core::mem::MaybeUninit;
use core::sync::atomic::{AtomicBool, Ordering};
use x86_64::structures::gdt::{Descriptor, GlobalDescriptorTable, SegmentSelector};
use x86_64::structures::tss::TaskStateSegment;
use x86_64::PrivilegeLevel;
use x86_64::VirtAddr;

pub const DOUBLE_FAULT_IST_INDEX: u16 = 0;

/// Селекторы сегментов. Порядок важен для syscall/sysret (см. `syscall::init`):
/// sysret CS = user_code (0x30), SS = user_data (0x28).
/// У каждого CPU своя таблица, но номера селекторов те же: лишний TSS
/// перед user-сегментами сдвинул бы STAR.
pub struct Selectors {
    pub code: SegmentSelector,
    pub data: SegmentSelector,
    pub tss: SegmentSelector,
    pub user_data: SegmentSelector,
    pub user_code: SegmentSelector,
}

const DOUBLE_FAULT_STACK_SIZE: usize = 4096 * 5;

#[repr(C, align(16))]
#[derive(Clone, Copy)]
struct DfStack([u8; DOUBLE_FAULT_STACK_SIZE]);

static mut DF_STACKS: [DfStack; crate::cpu::MAX_CPUS] =
    [DfStack([0; DOUBLE_FAULT_STACK_SIZE]); crate::cpu::MAX_CPUS];
static mut TSS: [TaskStateSegment; crate::cpu::MAX_CPUS] =
    [TaskStateSegment::new(); crate::cpu::MAX_CPUS];
static TSS_READY: [AtomicBool; crate::cpu::MAX_CPUS] = [
    AtomicBool::new(false),
    AtomicBool::new(false),
    AtomicBool::new(false),
    AtomicBool::new(false),
    AtomicBool::new(false),
    AtomicBool::new(false),
    AtomicBool::new(false),
    AtomicBool::new(false),
];

/// TSS этого CPU. privilege_stack_table[0] — стек прерывания из ring 3.
#[allow(static_mut_refs)]
fn tss_of(index: usize) -> &'static mut TaskStateSegment {
    let index = index.min(crate::cpu::MAX_CPUS - 1);
    unsafe {
        let tss = &mut TSS[index];
        if !TSS_READY[index].load(Ordering::Acquire) {
            *tss = TaskStateSegment::new();
            let base = core::ptr::addr_of!(DF_STACKS[index]) as u64;
            tss.interrupt_stack_table[DOUBLE_FAULT_IST_INDEX as usize] =
                VirtAddr::new(base + DOUBLE_FAULT_STACK_SIZE as u64);
            TSS_READY[index].store(true, Ordering::Release);
        }
        tss
    }
}

/// Kernel-стек прерываний из ring 3 на том CPU, который нас позвал.
pub fn set_kernel_stack(top: VirtAddr) {
    tss_of(crate::smp::this_cpu()).privilege_stack_table[0] = top;
}

use spin::Once;
pub(crate) static GDT: Once<(GlobalDescriptorTable, Selectors)> = Once::new();

pub fn init() {
    use x86_64::instructions::segmentation::{Segment, CS, DS, ES, SS};
    use x86_64::instructions::tables::load_tss;

    let gdt = GDT.call_once(|| {
        let mut gdt = GlobalDescriptorTable::new();
        let code = gdt.append(Descriptor::kernel_code_segment());
        let data = gdt.append(Descriptor::kernel_data_segment());
        let tss_sel = gdt.append(Descriptor::tss_segment(tss_of(0)));
        let user_data = gdt.append(Descriptor::user_data_segment());
        let user_code = gdt.append(Descriptor::user_code_segment());
        (
            gdt,
            Selectors {
                code,
                data,
                tss: tss_sel,
                user_data,
                user_code,
            },
        )
    });

    gdt.0.load();
    unsafe {
        // Без валидного data-сегмента в SS/DS любой hardware interrupt
        // (и IRET) ловит GPF: селекторы bootloader'а указывали бы на чужие дескрипторы.
        CS::set_reg(gdt.1.code);
        SS::set_reg(gdt.1.data);
        DS::set_reg(gdt.1.data);
        ES::set_reg(gdt.1.data);
        load_tss(gdt.1.tss);
    }
    // До первого прерывания: GS_BASE — слот BSP, не пользовательский GS.
    crate::cpu::bind(0);
}

static mut AP_GDT: [MaybeUninit<GlobalDescriptorTable>; crate::cpu::MAX_CPUS] =
    [const { MaybeUninit::uninit() }; crate::cpu::MAX_CPUS];

/// Свой GDT и TSS. Номера селекторов совпадают с BSP, иначе STAR и iret
/// уедут. `idle_top` — стек, пока на этом CPU нет задачи.
#[allow(static_mut_refs)]
pub fn load_ap(index: usize, idle_top: u64) {
    use x86_64::instructions::segmentation::{Segment, CS, DS, ES, SS};
    use x86_64::instructions::tables::load_tss;

    let index = index.min(crate::cpu::MAX_CPUS - 1);
    let tss = tss_of(index);
    tss.privilege_stack_table[0] = VirtAddr::new(idle_top);
    let gdt = unsafe { AP_GDT[index].write(GlobalDescriptorTable::new()) };
    let code = gdt.append(Descriptor::kernel_code_segment());
    let data = gdt.append(Descriptor::kernel_data_segment());
    let tss_sel = gdt.append(Descriptor::tss_segment(tss));
    let _user_data = gdt.append(Descriptor::user_data_segment());
    let _user_code = gdt.append(Descriptor::user_code_segment());
    let bsp = &GDT.get().expect("gdt not initialized").1;
    assert_eq!(code.0, bsp.code.0, "ap code selector");
    assert_eq!(data.0, bsp.data.0, "ap data selector");
    assert_eq!(tss_sel.0, bsp.tss.0, "ap tss selector");
    let loaded: &'static GlobalDescriptorTable = unsafe { &*(gdt as *const GlobalDescriptorTable) };
    loaded.load();
    unsafe {
        CS::set_reg(code);
        SS::set_reg(data);
        DS::set_reg(data);
        ES::set_reg(data);
        load_tss(tss_sel);
    }
    crate::cpu::bind(index);
    crate::cpu::set_kstack(index, idle_top);
}

/// Селекторы ring 3 (с RPL=3) — для iretq/sysret.
pub fn user_segments() -> (SegmentSelector, SegmentSelector) {
    let s = &GDT.get().expect("gdt not initialized").1;
    (
        SegmentSelector::new(s.user_data.index(), PrivilegeLevel::Ring3),
        SegmentSelector::new(s.user_code.index(), PrivilegeLevel::Ring3),
    )
}
