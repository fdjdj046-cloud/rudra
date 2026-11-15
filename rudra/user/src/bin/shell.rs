#![no_std]
#![no_main]

//! Интерактивный шелл rudra: читает строку с клавиатуры, запускает
//! встроенные программы через spawn.

use core::panic::PanicInfo;

fn read_line(buf: &mut [u8]) -> usize {
    let mut len = 0;
    while len < buf.len() {
        let mut c = [0u8; 1];
        let n = user::read(&mut c);
        if n == 0 {
            user::r#yield();
            continue;
        }
        let ch = c[0];
        if ch == b'\n' {
            user::write("\n");
            break;
        }
        if ch == 0x08 || ch == 0x7f {
            // Backspace
            if len > 0 {
                len -= 1;
                user::write("\u{8} \u{8}");
            }
            continue;
        }
        buf[len] = ch;
        len += 1;
        // Эхо символа
        user::write(core::str::from_utf8(&c[..1]).unwrap_or("?"));
    }
    len
}

#[no_mangle]
pub extern "C" fn _start() -> ! {
    user::write("rudra shell v0.4 (type 'help')\n");
    let mut line = [0u8; 64];

    loop {
        user::write("rudra> ");
        let len = read_line(&mut line);
        let cmd = core::str::from_utf8(&line[..len]).unwrap_or("").trim();

        match cmd {
            "" => {}
            "help" => user::write("commands: hello counter ps clear exit\n"),
            "hello" => {
                if user::spawn(user::PROG_HELLO) == u64::MAX {
                    user::write("spawn failed: no free task slots\n");
                }
            }
            "counter" => {
                if user::spawn(user::PROG_COUNTER) == u64::MAX {
                    user::write("spawn failed: no free task slots\n");
                }
            }
            "ps" => user::write("tasks: shell (this), spawned children print above\n"),
            "clear" => user::write("\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n"),
            "exit" => user::exit(0),
            _ => {
                user::write("unknown command: ");
                user::write(cmd);
                user::write("\n");
            }
        }
    }
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    user::write("shell panic\n");
    user::exit(1)
}
