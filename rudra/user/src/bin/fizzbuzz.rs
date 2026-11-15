#![no_std]
#![no_main]

//! FizzBuzz 1..=30 — длинная задача, на которой видно вытеснение
//! планировщиком (шелл остаётся отзывчивым).

use core::panic::PanicInfo;

fn print_u32(n: u32) {
    let mut b = [0u8; 10];
    let mut i = b.len();
    let mut v = n;
    loop {
        i -= 1;
        b[i] = b'0' + (v % 10) as u8;
        v /= 10;
        if v == 0 {
            break;
        }
    }
    user::write(core::str::from_utf8(&b[i..]).unwrap_or("?"));
}

#[no_mangle]
pub extern "C" fn _start() -> ! {
    for i in 1u32..=30 {
        if i % 15 == 0 {
            user::write("fizzbuzz\n");
        } else if i % 3 == 0 {
            user::write("fizz\n");
        } else if i % 5 == 0 {
            user::write("buzz\n");
        } else {
            print_u32(i);
            user::write("\n");
        }
        for _ in 0..6_000_000 {
            core::hint::spin_loop();
        }
    }
    user::write("fizzbuzz done\n");
    user::exit(0)
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    user::write("fizzbuzz panic\n");
    user::exit(1)
}
