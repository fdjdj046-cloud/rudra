#![no_std]
#![cfg_attr(test, no_main)]
#![feature(custom_test_frameworks)]
#![feature(abi_x86_interrupt)]
#![test_runner(crate::test_runner)]
#![reexport_test_harness_main = "test_main"]

extern crate alloc;

pub mod allocator;
pub mod gdt;
pub mod interrupts;
pub mod memory;
pub mod serial;
pub mod vga_buffer;

use bootloader_api::BootInfo;
use core::sync::atomic::{AtomicU64, Ordering};
use x86_64::VirtAddr;

/// Физическое смещение маппинга всей физической памяти (выставляется в `init`).
pub static PHYS_OFFSET: AtomicU64 = AtomicU64::new(0);

/// Общая инициализация ядра: GDT/TSS, IDT, пейджинг, куча.
pub fn init(boot_info: &'static mut BootInfo) {
    serial::init();
    gdt::init();
    interrupts::init_idt();

    let phys_offset = boot_info
        .physical_memory_offset
        .into_option()
        .expect("kernel requires physical memory mapping (bootloader config)");
    PHYS_OFFSET.store(phys_offset, Ordering::Relaxed);

    let mut mapper = unsafe { memory::init(VirtAddr::new(phys_offset)) };
    let mut frame_allocator = unsafe { memory::BootInfoFrameAllocator::init(&boot_info.memory_regions) };
    allocator::init_heap(&mut mapper, &mut frame_allocator).expect("heap initialization failed");
}

pub fn hlt_loop() -> ! {
    loop {
        x86_64::instructions::hlt();
    }
}

#[cfg(test)]
pub fn test_runner(tests: &[&dyn Fn()]) {
    serial_println!("Running {} tests", tests.len());
    for test in tests {
        test();
    }
    exit_qemu(QemuExitCode::Success);
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum QemuExitCode {
    Success = 0x10,
    Failed = 0x11,
}

pub fn exit_qemu(exit_code: QemuExitCode) -> ! {
    use x86_64::instructions::port::Port;

    unsafe {
        let mut port = Port::new(0xf4);
        port.write(exit_code as u32);
    }
    hlt_loop();
}

#[cfg(test)]
#[panic_handler]
fn panic(info: &core::panic::PanicInfo) -> ! {
    serial_println!("[failed]\n");
    serial_println!("Error: {}\n", info);
    exit_qemu(QemuExitCode::Failed);
}
