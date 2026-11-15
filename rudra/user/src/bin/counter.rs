#![no_std]
#![no_main]

//! Счётчик: печатает 1..=5 с паузами и завершается (демо exit и слотов).

use core::panic::PanicInfo;

#[no_mangle]
pub extern "C" fn _start() -> ! {
    for i in 1u32..=5 {
        user::write("tick ");
        let mut b = [0u8; 4];
        let s = {
            // itoa руками: числа до 5
            b[0] = b'0' + i as u8;
            &b[..1]
        };
        user::write(core::str::from_utf8(s).unwrap_or("?"));
        user::write("\n");
        for _ in 0..40_000_000 {
            core::hint::spin_loop();
        }
    }
    user::write("counter done\n");
    user::exit(0)
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    user::write("counter panic\n");
    user::exit(1)
}
