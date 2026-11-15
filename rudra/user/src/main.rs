#![no_std]
#![no_main]

//! User-программа для rudra: печатает маркер задачи (ядро кладёт 'A'/'B'
//! по адресу ARG_PAGE) и крутится в цикле, демонстрируя вытесняющее
//! планирование: вывод двух задач перемешивается.

use core::panic::PanicInfo;

const ARG_PAGE: *const u8 = 0x60_0000 as *const u8;

const SYS_WRITE: u64 = 1;
const SYS_EXIT: u64 = 2;

unsafe fn syscall3(nr: u64, a1: u64, a2: u64, a3: u64) -> u64 {
    let ret: u64;
    core::arch::asm!(
        "syscall",
        inlateout("rax") nr => ret,
        in("rdi") a1,
        in("rsi") a2,
        in("rdx") a3,
        lateout("rcx") _,
        lateout("r11") _,
        options(nostack, preserves_flags)
    );
    ret
}

fn write(s: &str) {
    unsafe { syscall3(SYS_WRITE, s.as_ptr() as u64, s.len() as u64, 0) };
}

fn exit(code: u64) -> ! {
    unsafe { syscall3(SYS_EXIT, code, 0, 0) };
    loop {
        core::hint::spin_loop();
    }
}

#[no_mangle]
pub extern "C" fn _start() -> ! {
    let marker = unsafe { *ARG_PAGE };

    let mut m = [0u8; 4];
    let mlen = encode_char(marker, &mut m);

    write("user task ");
    write(core::str::from_utf8(&m[..mlen]).unwrap_or("?"));
    write(": hello from ring 3!\n");

    loop {
        // Печатаем маркер периодически; таймер ядра (PIT) вытесняет задачу.
        for _ in 0..20_000_000 {
            core::hint::spin_loop();
        }
        write(core::str::from_utf8(&m[..mlen]).unwrap_or("?"));
        write("\n");
    }
}

fn encode_char(c: u8, buf: &mut [u8; 4]) -> usize {
    // Маркеры — ASCII (b'A' / b'B'), но на всякий случай кодируем через char.
    let ch = c as char;
    ch.encode_utf8(buf).len()
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    write("user panic\n");
    exit(1)
}
