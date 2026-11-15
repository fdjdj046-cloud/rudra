use core::mem::MaybeUninit;
use core::sync::atomic::{AtomicBool, Ordering};
use x86_64::structures::gdt::{Descriptor, GlobalDescriptorTable, SegmentSelector};
use x86_64::structures::tss::TaskStateSegment;
use x86_64::PrivilegeLevel;
use x86_64::VirtAddr;

pub const DOUBLE_FAULT_IST_INDEX: u16 = 0;

/// Селекторы сегментов. Порядок важен для syscall/sysret (см. `syscall::init`):
/// sysret CS = user_code (0x30), SS = user_data (0x28).
pub struct Selectors {
    pub code: SegmentSelector,
    pub data: SegmentSelector,
    pub tss: SegmentSelector,
    pub user_data: SegmentSelector,
    pub user_code: SegmentSelector,
}

const DOUBLE_FAULT_STACK_SIZE: usize = 4096 * 5;
static mut DOUBLE_FAULT_STACK: [u8; DOUBLE_FAULT_STACK_SIZE] = [0; DOUBLE_FAULT_STACK_SIZE];

static mut TSS: MaybeUninit<TaskStateSegment> = MaybeUninit::uninit();
static TSS_INITED: AtomicBool = AtomicBool::new(false);

/// Доступ к TSS с отложенной однократной инициализацией.
/// privilege_stack_table[0] — kernel-стек для прерываний из ring 3,
/// обновляется планировщиком на каждое переключение задач.
#[allow(static_mut_refs)]
fn tss() -> &'static mut TaskStateSegment {
    if !TSS_INITED.load(Ordering::Acquire) {
        let mut tss = TaskStateSegment::new();
        tss.interrupt_stack_table[DOUBLE_FAULT_IST_INDEX as usize] = {
            let stack_start = VirtAddr::from_ptr(&raw const DOUBLE_FAULT_STACK);
            stack_start + DOUBLE_FAULT_STACK_SIZE as u64
        };
        unsafe {
            TSS.write(tss);
        }
        TSS_INITED.store(true, Ordering::Release);
    }
    unsafe { &mut *TSS.as_mut_ptr() }
}

/// Установить kernel-стек, используемый CPU при входе прерывания из ring 3.
pub fn set_kernel_stack(top: VirtAddr) {
    tss().privilege_stack_table[0] = top;
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
        let tss_sel = gdt.append(Descriptor::tss_segment(tss()));
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
}

/// Селекторы ring 3 (с RPL=3) — для iretq/sysret.
pub fn user_segments() -> (SegmentSelector, SegmentSelector) {
    let s = &GDT.get().expect("gdt not initialized").1;
    (
        SegmentSelector::new(s.user_data.index(), PrivilegeLevel::Ring3),
        SegmentSelector::new(s.user_code.index(), PrivilegeLevel::Ring3),
    )
}
