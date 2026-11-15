use lazy_static::lazy_static;
use x86_64::structures::gdt::{Descriptor, GlobalDescriptorTable, SegmentSelector};
use x86_64::structures::tss::TaskStateSegment;
use x86_64::VirtAddr;

pub const DOUBLE_FAULT_IST_INDEX: u16 = 0;

struct Selectors {
    code: SegmentSelector,
    data: SegmentSelector,
    tss: SegmentSelector,
}

lazy_static! {
    static ref TSS: TaskStateSegment = {
        let mut tss = TaskStateSegment::new();
        tss.interrupt_stack_table[DOUBLE_FAULT_IST_INDEX as usize] = {
            const STACK_SIZE: usize = 4096 * 5;
            // Статик-стек для double fault handler; .bss, zeroed, kernel-сегмент.
            static mut STACK: [u8; STACK_SIZE] = [0; STACK_SIZE];
            let stack_start = VirtAddr::from_ptr(&raw const STACK);
            stack_start + STACK_SIZE as u64
        };
        tss
    };
    static ref GDT: (GlobalDescriptorTable, Selectors) = {
        let mut gdt = GlobalDescriptorTable::new();
        let code = gdt.append(Descriptor::kernel_code_segment());
        let data = gdt.append(Descriptor::kernel_data_segment());
        let tss = gdt.append(Descriptor::tss_segment(&TSS));
        (gdt, Selectors { code, data, tss })
    };
}

pub fn init() {
    use x86_64::instructions::segmentation::{Segment, CS, DS, ES, SS};
    use x86_64::instructions::tables::load_tss;

    GDT.0.load();
    unsafe {
        // Без валидного data-сегмента в SS/DS любой hardware interrupt
        // (и IRET) ловит GPF: селекторы bootloader'а указывали бы на чужие дескрипторы.
        CS::set_reg(GDT.1.code);
        SS::set_reg(GDT.1.data);
        DS::set_reg(GDT.1.data);
        ES::set_reg(GDT.1.data);
        load_tss(GDT.1.tss);
    }
}
