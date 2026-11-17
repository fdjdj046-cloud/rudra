//! PID1. Не читает консоль и не печатает приглашение.
//! Поднимает шелл и в цикле забирает завершившихся детей, включая осиротевших.

#![no_std]
#![no_main]

use rudra::{execve, exit, fork, sleep_ms, wait4};

fn main() {
    let pid = fork();
    if pid == 0 {
        // execve сам ставит argv[0] = путь. Лишний аргумент дал бы второй argv.
        execve("/bin/shell.elf", &[]);
        exit(127);
    }
    if pid == u64::MAX {
        exit(1);
    }
    let echild = (-10i64) as u64;
    loop {
        let (w, _) = wait4(u64::MAX);
        if w == echild {
            sleep_ms(50);
        }
    }
}

rudra::entry!(main);
