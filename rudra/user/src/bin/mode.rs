//! Режим нового файла и каталога: umask, chmod, fchmod, stat.
//! Проверки доступа нет. Повторный запуск, если /mode.txt уже 0640 и содержит
//! keep, печатает mode-kept и файл не трогает.

#![no_std]
#![no_main]

use rudra::{exit, println, syscall6};

const FILE: &[u8] = b"/mode.txt\0";
const DIR: &[u8] = b"/mode-dir\0";
const MISSING: &[u8] = b"/no-such-mode\0";

fn bad(what: &str) -> ! {
    println!("mode-bad {}", what);
    exit(1);
}

/// Биты 0777 из struct stat. Чтение буфера в той же функции, что и syscall.
fn perm_of(path: *const u8) -> u32 {
    let mut st = [0u8; 144];
    let rc = unsafe { syscall6(4, path as u64, st.as_mut_ptr() as u64, 0, 0, 0, 0) };
    if rc != 0 {
        return !0;
    }
    u32::from_le_bytes([st[24], st[25], st[26], st[27]]) & 0o777
}

fn is_keep(path: *const u8) -> bool {
    let fd = unsafe { syscall6(2, path as u64, 0, 0, 0, 0, 0) };
    if (fd as i64) < 0 {
        return false;
    }
    let mut buf = [0u8; 4];
    let n = unsafe { syscall6(0, fd, buf.as_mut_ptr() as u64, 4, 0, 0, 0) };
    unsafe { syscall6(3, fd, 0, 0, 0, 0, 0) };
    n == 4 && &buf == b"keep"
}

fn main() {
    if perm_of(FILE.as_ptr()) == 0o640 && is_keep(FILE.as_ptr()) {
        println!("mode-kept");
        exit(0);
    }

    unsafe { syscall6(87, FILE.as_ptr() as u64, 0, 0, 0, 0, 0) };
    unsafe { syscall6(84, DIR.as_ptr() as u64, 0, 0, 0, 0, 0) };
    let old = unsafe { syscall6(95, 0, 0, 0, 0, 0, 0) };
    if old > 0o777 {
        bad("umask");
    }

    let fd = unsafe { syscall6(2, FILE.as_ptr() as u64, 0x242, 0o755, 0, 0, 0) };
    if (fd as i64) < 0 {
        bad("open");
    }
    let msg = b"keep";
    let n = unsafe { syscall6(1, fd, msg.as_ptr() as u64, 4, 0, 0, 0) };
    if n != 4 {
        bad("write");
    }
    if unsafe { syscall6(3, fd, 0, 0, 0, 0, 0) } != 0 {
        bad("close");
    }
    if perm_of(FILE.as_ptr()) != 0o755 {
        bad("creat");
    }
    if unsafe { syscall6(90, FILE.as_ptr() as u64, 0o640, 0, 0, 0, 0) } != 0 {
        bad("chmod");
    }
    if perm_of(FILE.as_ptr()) != 0o640 {
        bad("chmod-stat");
    }

    let fd = unsafe { syscall6(2, FILE.as_ptr() as u64, 2, 0, 0, 0, 0) };
    if (fd as i64) < 0 {
        bad("reopen");
    }
    if unsafe { syscall6(91, fd, 0o604, 0, 0, 0, 0) } != 0 {
        bad("fchmod");
    }
    unsafe { syscall6(3, fd, 0, 0, 0, 0, 0) };
    if perm_of(FILE.as_ptr()) != 0o604 {
        bad("fchmod-stat");
    }
    if unsafe { syscall6(90, FILE.as_ptr() as u64, 0o640, 0, 0, 0, 0) } != 0 {
        bad("chmod-back");
    }
    if perm_of(FILE.as_ptr()) != 0o640 || !is_keep(FILE.as_ptr()) {
        bad("keep");
    }

    unsafe { syscall6(95, 0o077, 0, 0, 0, 0, 0) };
    let mk = unsafe { syscall6(83, DIR.as_ptr() as u64, 0o777, 0, 0, 0, 0) };
    if mk != 0 {
        bad("mkdir");
    }
    if perm_of(DIR.as_ptr()) != 0o700 {
        bad("mkdir-mode");
    }
    if unsafe { syscall6(84, DIR.as_ptr() as u64, 0, 0, 0, 0, 0) } != 0 {
        bad("rmdir");
    }
    let miss = unsafe { syscall6(90, MISSING.as_ptr() as u64, 0o644, 0, 0, 0, 0) };
    if (miss as i64) != -2 {
        bad("missing");
    }
    unsafe { syscall6(95, 0o022, 0, 0, 0, 0, 0) };
    println!("mode-ok");
}

rudra::entry!(main);
