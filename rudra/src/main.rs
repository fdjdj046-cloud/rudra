#![no_std]
#![no_main]

extern crate alloc;

use bootloader_api::config::Mapping;
use bootloader_api::{entry_point, BootInfo, BootloaderConfig};
use core::panic::PanicInfo;
use rudra::serial_println;

static BOOTLOADER_CONFIG: BootloaderConfig = {
    let mut config = BootloaderConfig::new_default();
    // Маппим всю физическую память по динамическому смещению —
    // так ядру доступны page tables и MMIO.
    config.mappings.physical_memory = Some(Mapping::Dynamic);
    config
};

entry_point!(kernel_main, config = &BOOTLOADER_CONFIG);

fn kernel_main(boot_info: &'static mut BootInfo) -> ! {
    rudra::serial::init();
    serial_println!("rudra: early serial up");
    rudra::init(boot_info);

    rudra::println!("rudra kernel v1.0.1");
    rudra::println!("subsystems: gdt/idt, paging, heap, framebuffer: ok");
    rudra::println!("features: Linux ABI (static glibc/musl bins), threads (CLONE_VM+futex),");
    rudra::println!("          fork/execve/wait4, pipe/poll, ext2 root on virtio-blk");
    serial_println!("rudra: serial output alive");

    // Пользовательский шелл ring 3 + планировщик.
    rudra::task::init();

    rudra::println!("It did not crash!");
    serial_println!("rudra: entering hlt loop, scheduler on");
    rudra::hlt_loop()
}

#[cfg(not(test))]
#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    serial_println!("PANIC: {}", info);
    rudra::hlt_loop()
}
