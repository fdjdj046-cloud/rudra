#![no_std]
#![cfg_attr(test, no_main)]
#![feature(custom_test_frameworks)]
#![feature(abi_x86_interrupt)]
#![test_runner(crate::test_runner)]
#![reexport_test_harness_main = "test_main"]

extern crate alloc;

pub mod allocator;
pub mod apic;
pub mod block;
pub mod ext2;
pub mod framebuffer;
pub mod fpu;
pub mod fs;
pub mod gdt;
pub mod input;
pub mod interrupts;
pub mod linux;
pub mod memory;
pub mod pci;
pub mod serial;
pub mod syscall;
pub mod task;
pub mod time;
pub mod virtio_blk;

use bootloader_api::BootInfo;
use core::sync::atomic::{AtomicU64, Ordering};
use x86_64::VirtAddr;

/// Физическое смещение маппинга всей физической памяти (выставляется в `init`).
pub static PHYS_OFFSET: AtomicU64 = AtomicU64::new(0);

/// Общая инициализация ядра: serial, GDT/TSS, IDT, framebuffer, пейджинг, куча, PIC.
pub fn init(boot_info: &mut BootInfo) {
    serial::init();
    gdt::init();
    fpu::enable();
    time::init();
    syscall::init();
    interrupts::init_idt();

    if let Some(fb) = boot_info.framebuffer.take() {
        framebuffer::init(fb);
    }

    let phys_offset = boot_info
        .physical_memory_offset
        .into_option()
        .expect("kernel requires physical memory mapping (bootloader config)");
    PHYS_OFFSET.store(phys_offset, Ordering::Relaxed);

    let mut mapper = unsafe { memory::init(VirtAddr::new(phys_offset)) };
    memory::init_frame_allocator(&boot_info.memory_regions);
    memory::with_frame_allocator(|fa| {
        apic::init(&mut mapper, fa);
        allocator::init_heap(&mut mapper, fa).expect("heap initialization failed");
    });

    unsafe {
        interrupts::init_pics();
    }
    x86_64::instructions::interrupts::enable();
    time::finish();
    apic::start_timer();

    // Ramdisk из rootfs (после кучи: нужен 256 KiB буфер).
    fs::init();
    pci::scan();
    block::init();
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
    serial_println!("[all tests passed]");
    exit_qemu(QemuExitCode::Success);
}

/// Точка входа test-бинарника ядра (cargo test --lib).
/// entry_point! встраивает секцию .bootloader-config, без которой
/// bootloader 0.11 не загрузит kernel.
#[cfg(test)]
static BOOTLOADER_CONFIG: bootloader_api::BootloaderConfig = {
    let mut config = bootloader_api::BootloaderConfig::new_default();
    config.mappings.physical_memory = Some(bootloader_api::config::Mapping::Dynamic);
    config
};

#[cfg(test)]
bootloader_api::entry_point!(kernel_test_main, config = &BOOTLOADER_CONFIG);

#[cfg(test)]
fn kernel_test_main(boot_info: &'static mut BootInfo) -> ! {
    init(boot_info);
    test_main();
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
