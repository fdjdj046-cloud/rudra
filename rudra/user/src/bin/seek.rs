//! lseek возвращает позицию. pread читает по смещению и курсор не двигает.
//! pwrite пишет по смещению. Повторный write без O_TRUNC сохраняет хвост.

#![no_std]
#![no_main]

use rudra::{close, exit, open, println, syscall6, O_CREAT, O_RDWR, O_TRUNC};

fn bad(what: &str, rc: u64) -> ! {
    println!("seek-bad {} {:#x}", what, rc);
    exit(1);
}

fn lseek(fd: u64, off: i64, whence: u64) -> u64 {
    unsafe { syscall6(8, fd, off as u64, whence, 0, 0, 0) }
}

fn eq_at(fd: u64, pos: u64, expect: &[u8]) -> bool {
    let mut buf = [0u8; 16];
    let n = unsafe { syscall6(17, fd, buf.as_mut_ptr() as u64, expect.len() as u64, pos, 0, 0) };
    if n == expect.len() as u64 && &buf[..expect.len()] == expect {
        return true;
    }
    println!("seek-bad pread {:#x} {}", n, buf[0]);
    false
}

fn read_eq(fd: u64, expect: &[u8]) -> bool {
    let mut buf = [0u8; 16];
    let n = unsafe { syscall6(0, fd, buf.as_mut_ptr() as u64, expect.len() as u64, 0, 0, 0) };
    if n == expect.len() as u64 && &buf[..expect.len()] == expect {
        return true;
    }
    println!("seek-bad read {:#x} {}", n, buf[0]);
    false
}

fn main() {
    let fd = open("/seek.txt", O_RDWR | O_CREAT | O_TRUNC);
    if fd < 0 {
        bad("open", fd as u64);
    }
    let fd = fd as u64;
    let msg = *b"abcdefghij";
    let n = unsafe { syscall6(1, fd, msg.as_ptr() as u64, 10, 0, 0, 0) };
    if n != 10 {
        bad("write", n);
    }
    let at = lseek(fd, 3, 0);
    if at != 3 {
        bad("set", at);
    }
    if !read_eq(fd, b"de") {
        exit(1);
    }
    let cur = lseek(fd, 0, 1);
    if cur != 5 {
        bad("cur", cur);
    }
    let end = lseek(fd, -2, 2);
    if end != 8 {
        bad("end", end);
    }
    if !eq_at(fd, 2, b"cde") {
        exit(1);
    }
    let still = lseek(fd, 0, 1);
    if still != 8 {
        bad("pread-moved", still);
    }
    let xy = *b"XY";
    let n = unsafe { syscall6(18, fd, xy.as_ptr() as u64, 2, 1, 0, 0) };
    if n != 2 {
        bad("pwrite", n);
    }
    let still = lseek(fd, 0, 1);
    if still != 8 {
        bad("pwrite-moved", still);
    }
    if !eq_at(fd, 0, b"aXYd") {
        exit(1);
    }
    let neg = lseek(fd, -1, 0);
    if neg as i64 != -22 {
        bad("einval", neg);
    }
    let still = lseek(fd, 0, 1);
    if still != 8 {
        bad("einval-moved", still);
    }
    close(fd);

    let fd = open("/seek.txt", O_RDWR);
    if fd < 0 {
        bad("reopen", fd as u64);
    }
    let fd = fd as u64;
    let z = *b"Z";
    let n = unsafe { syscall6(1, fd, z.as_ptr() as u64, 1, 0, 0, 0) };
    if n != 1 {
        bad("patch", n);
    }
    close(fd);

    let fd = open("/seek.txt", 0);
    if fd < 0 {
        bad("readopen", fd as u64);
    }
    if !read_eq(fd as u64, b"ZXYdefghij") {
        exit(1);
    }
    close(fd as u64);
    println!("seek-ok");
}

rudra::entry!(main);
