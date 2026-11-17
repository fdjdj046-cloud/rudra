//! `/proc/<pid>` для живой задачи: status, cmdline и имя в каталоге `/proc`.
//! Чужого pid нет. cmdline — путь exec и NUL, не полный argv.

#![no_std]
#![no_main]

use rudra::{close, exit, open, println, read, syscall6};

fn bad(what: &str, rc: u64) -> ! {
    println!("proc-bad {} {:#x}", what, rc);
    exit(1);
}

fn write_u64(buf: &mut [u8], mut n: u64) -> usize {
    if n == 0 {
        buf[0] = b'0';
        return 1;
    }
    let mut tmp = [0u8; 20];
    let mut i = 0;
    while n > 0 {
        tmp[i] = b'0' + (n % 10) as u8;
        n /= 10;
        i += 1;
    }
    for j in 0..i {
        buf[j] = tmp[i - 1 - j];
    }
    i
}

fn proc_path(pid: u64, suffix: &[u8], out: &mut [u8]) -> usize {
    let pre = b"/proc/";
    out[..pre.len()].copy_from_slice(pre);
    let mut n = pre.len();
    n += write_u64(&mut out[n..], pid);
    out[n..n + suffix.len()].copy_from_slice(suffix);
    n + suffix.len()
}

fn contains(hay: &[u8], needle: &[u8]) -> bool {
    hay.windows(needle.len()).any(|w| w == needle)
}

fn dents_have(fd: u64, pid_text: &[u8]) -> bool {
    let mut saw_pid = false;
    let mut saw_self = false;
    loop {
        let mut buf = [0u8; 512];
        let n = unsafe { syscall6(78, fd, buf.as_mut_ptr() as u64, buf.len() as u64, 0, 0, 0) };
        if n == 0 {
            break;
        }
        if (n as i64) < 0 {
            println!("proc-bad dents {:#x}", n);
            return false;
        }
        let n = n as usize;
        let mut off = 0usize;
        while off + 19 < n {
            let reclen = u16::from_le_bytes([buf[off + 16], buf[off + 17]]) as usize;
            if reclen < 20 || off + reclen > n {
                break;
            }
            let start = off + 19;
            let mut end = start;
            while end < off + reclen && buf[end] != 0 {
                end += 1;
            }
            let name = &buf[start..end];
            if name == pid_text {
                saw_pid = true;
            }
            if name == b"self" {
                saw_self = true;
            }
            off += reclen;
        }
        if saw_pid && saw_self {
            return true;
        }
    }
    saw_pid && saw_self
}

fn main() {
    let pid = unsafe { syscall6(39, 0, 0, 0, 0, 0, 0) };
    let ppid = unsafe { syscall6(110, 0, 0, 0, 0, 0, 0) };
    if pid == 0 || ppid == 0 {
        bad("ids", pid);
    }

    let mut raw = [0u8; 32];
    let n = proc_path(pid, b"/status", &mut raw);
    let path = core::str::from_utf8(&raw[..n]).unwrap();
    let fd = open(path, 0);
    if fd < 0 {
        bad("status", fd as u64);
    }
    let mut body = [0u8; 256];
    let got = read(fd as u64, &mut body);
    close(fd as u64);
    if got < 0 {
        bad("read", got as u64);
    }
    let body = &body[..got as usize];
    let mut pid_line = [0u8; 24];
    let mut i = 0;
    pid_line[i..i + 5].copy_from_slice(b"Pid:\t");
    i += 5;
    i += write_u64(&mut pid_line[i..], pid);
    pid_line[i] = b'\n';
    i += 1;
    if !contains(body, &pid_line[..i]) {
        bad("pid-line", pid);
    }
    let mut ppid_line = [0u8; 24];
    let mut j = 0;
    ppid_line[j..j + 6].copy_from_slice(b"PPid:\t");
    j += 6;
    j += write_u64(&mut ppid_line[j..], ppid);
    ppid_line[j] = b'\n';
    j += 1;
    if !contains(body, &ppid_line[..j]) || !contains(body, b"State:\tR\n") {
        bad("ppid", ppid);
    }
    if !contains(body, b"Name:\t/bin/proc.elf\n") {
        bad("name", pid);
    }

    let n = proc_path(pid, b"/cmdline", &mut raw);
    let path = core::str::from_utf8(&raw[..n]).unwrap();
    let fd = open(path, 0);
    if fd < 0 {
        bad("cmdline", fd as u64);
    }
    let mut cmd = [0u8; 32];
    let got = read(fd as u64, &mut cmd);
    close(fd as u64);
    if got < 13 || &cmd[..13] != b"/bin/proc.elf" {
        bad("cmd", got as u64);
    }

    let miss = open("/proc/999999/status", 0);
    if miss >= 0 {
        bad("ghost", miss as u64);
    }

    let root = open("/proc", 0);
    if root < 0 {
        bad("proc", root as u64);
    }
    let mut digits = [0u8; 20];
    let dn = write_u64(&mut digits, pid);
    if !dents_have(root as u64, &digits[..dn]) {
        close(root as u64);
        bad("list", pid);
    }
    close(root as u64);
    println!("proc-ok");
}

rudra::entry!(main);
