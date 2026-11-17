//! Петля TCP на 127.0.0.1: bind, listen, connect, accept, обмен, EOF.
//! Адрес не из 127.0.0.0/8 обязан вернуть ENETUNREACH. IPv6 и listen на UDP — ошибка.

#![no_std]
#![no_main]

use rudra::{exit, println, syscall6};

fn sa(port: u16, ip: u32) -> [u8; 16] {
    let mut a = [0u8; 16];
    a[0..2].copy_from_slice(&2u16.to_le_bytes());
    a[2..4].copy_from_slice(&port.to_be_bytes());
    a[4..8].copy_from_slice(&ip.to_be_bytes());
    a
}

fn bad(what: &str, rc: u64) -> ! {
    println!("tcp-bad {} {:#x}", what, rc);
    exit(1);
}

/// Сравнение в той же функции, что и syscall: иначе rustc выкидывает чтение буфера.
fn got(fd: u64, expect: &[u8]) -> bool {
    let mut buf = [0u8; 8];
    let n = unsafe { syscall6(0, fd, buf.as_mut_ptr() as u64, expect.len() as u64, 0, 0, 0) };
    if n == expect.len() as u64 && &buf[..expect.len()] == expect {
        return true;
    }
    println!("tcp-bad bytes {:#x} {}", n, buf[0]);
    false
}

fn main() {
    let v6 = unsafe { syscall6(41, 10, 1, 0, 0, 0, 0) };
    if v6 as i64 != -97 {
        bad("v6", v6);
    }

    let udp = unsafe { syscall6(41, 2, 2, 0, 0, 0, 0) };
    if (udp as i64) < 0 {
        bad("udp", udp);
    }
    let lrc = unsafe { syscall6(50, udp, 1, 0, 0, 0, 0) };
    if lrc as i64 != -95 {
        bad("udp-listen", lrc);
    }
    unsafe { syscall6(3, udp, 0, 0, 0, 0, 0) };

    let lst = unsafe { syscall6(41, 2, 1, 0, 0, 0, 0) };
    if (lst as i64) < 0 {
        bad("socket", lst);
    }
    let addr = sa(19011, 0x7f00_0001);
    let rc = unsafe { syscall6(49, lst, addr.as_ptr() as u64, 16, 0, 0, 0) };
    if rc != 0 {
        bad("bind", rc);
    }
    let rc = unsafe { syscall6(50, lst, 1, 0, 0, 0, 0) };
    if rc != 0 {
        bad("listen", rc);
    }

    let cli = unsafe { syscall6(41, 2, 1, 0, 0, 0, 0) };
    if (cli as i64) < 0 {
        bad("client", cli);
    }
    let wire = sa(19011, 0x0a00_0202);
    let rc = unsafe { syscall6(42, cli, wire.as_ptr() as u64, 16, 0, 0, 0) };
    if rc as i64 != -101 {
        bad("wire", rc);
    }
    let miss = sa(9, 0x7f00_0001);
    let rc = unsafe { syscall6(42, cli, miss.as_ptr() as u64, 16, 0, 0, 0) };
    if rc as i64 != -111 {
        bad("refused", rc);
    }
    let ok = sa(19011, 0x7f00_0001);
    let rc = unsafe { syscall6(42, cli, ok.as_ptr() as u64, 16, 0, 0, 0) };
    if rc != 0 {
        bad("connect", rc);
    }

    let acc = unsafe { syscall6(43, lst, 0, 0, 0, 0, 0) };
    if (acc as i64) < 0 {
        bad("accept", acc);
    }

    let msg = *b"ping";
    let n = unsafe { syscall6(1, cli, msg.as_ptr() as u64, 4, 0, 0, 0) };
    if n != 4 {
        bad("send", n);
    }
    if !got(acc, b"ping") {
        exit(1);
    }
    let reply = *b"pong";
    let n = unsafe { syscall6(1, acc, reply.as_ptr() as u64, 4, 0, 0, 0) };
    if n != 4 {
        bad("reply", n);
    }
    if !got(cli, b"pong") {
        exit(1);
    }

    unsafe { syscall6(3, cli, 0, 0, 0, 0, 0) };
    let mut end = [0u8; 1];
    let n = unsafe { syscall6(0, acc, end.as_mut_ptr() as u64, 1, 0, 0, 0) };
    if n != 0 {
        bad("eof", n);
    }
    let _ = end[0];
    println!("tcp-ok");
}

rudra::entry!(main);
