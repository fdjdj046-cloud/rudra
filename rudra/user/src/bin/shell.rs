//! Интерактивный шелл rudra (ring 3).
//!
//! Билтины: help, ls, cat, echo, pwd, cd, rm, mkdir, ps, uname, clear,
//! run, exit. Всё остальное — execve: сначала как путь, потом /bin/<cmd>,
//! потом /bin/<cmd>.elf, и финально fallback на busybox-апплет
//! (execve /bin/busybox busybox <cmd> ...) — настоящая Linux-утилита.

#![no_std]
#![no_main]

use rudra::{print, println};

const BB_PATH: &str = "/bin/busybox";

fn main() {
    println!("rudra shell v0.6 (Linux ABI). 'help' — список команд.");
    let motd_buf = &mut [0u8; 512];
    let n = rudra::read_file("/motd.txt", motd_buf);
    if n > 0 {
        if let Ok(s) = core::str::from_utf8(&motd_buf[..n as usize]) {
            print!("{}", s);
        }
    }
    println!();

    loop {
        let line = rudra::readline("rudra:/$ ");
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        run_command(line);
    }
}

/// Разбить строку на слова (пробелы). Возвращает число слов.
fn split<'a>(line: &'a str, words: &mut [&'a str]) -> usize {
    let mut n = 0;
    for w in line.split(' ').filter(|w| !w.is_empty()) {
        if n >= words.len() {
            break;
        }
        words[n] = w;
        n += 1;
    }
    n
}

fn run_command(line: &str) {
    let mut words = [""; 16];
    let n = split(line, &mut words);
    if n == 0 {
        return;
    }
    let cmd = words[0];
    let args = &words[1..n];

    match cmd {
        "help" => {
            println!("Билтины: help ls cat echo pwd cd rm mkdir ps uname clear run exit");
            println!("Любая другая команда — execve: /bin/<cmd>, /bin/<cmd>.elf,");
            println!("затем busybox-апплет (ls, cat, echo, wc, true, yes...).");
            println!("Примеры: ls / | run /bin/hello.elf | echo привет > x.txt | cat x.txt");
        }
        "exit" => {
            println!("bye");
            rudra::exit(0);
        }
        "clear" => {
            print!("\x1b[2J\x1b[H"); // ANSI: ядро рисует по-своему, но serial чистим
            for _ in 0..40 {
                println!();
            }
        }
        "pwd" => {
            let mut buf = [0u8; 128];
            let n = rudra::read_file("/dev/null", &mut buf);
            let _ = (buf, n);
            // getcwd через syscall 79
            let mut cwd = [0u8; 128];
            let len = unsafe {
                rudra::syscall6(79, cwd.as_mut_ptr() as u64, cwd.len() as u64, 0, 0, 0, 0)
            };
            if len > 0 {
                println!("{}", core::str::from_utf8(&cwd[..(len - 1) as usize]).unwrap_or("/"));
            } else {
                println!("/");
            }
        }
        "cd" => {
            let dir = args.first().copied().unwrap_or("/");
            let mut p = [0u8; 128];
            let pb = dir.as_bytes();
            if pb.len() >= p.len() {
                println!("cd: слишком длинный путь");
                return;
            }
            p[..pb.len()].copy_from_slice(pb);
            p[pb.len()] = 0;
            let r = unsafe { rudra::syscall6(80, p.as_ptr() as u64, 0, 0, 0, 0, 0) };
            if r != 0 {
                println!("cd: {}: нет такого каталога ({})", dir, r as i64);
            }
        }
        "ls" => {
            ls(args.first().copied().unwrap_or("."));
        }
        "cat" => {
            if args.is_empty() {
                println!("cat: нужен файл");
                return;
            }
            cat(args[0]);
        }
        "echo" => {
            echo(args);
        }
        "rm" => {
            if args.is_empty() {
                println!("rm: нужен файл");
                return;
            }
            for f in args {
                if !rudra::delete(f) {
                    println!("rm: {}: нет такого файла", f);
                }
            }
        }
        "mkdir" => {
            if args.is_empty() {
                println!("mkdir: нужен каталог");
                return;
            }
            for d in args {
                let r = rudra::mkdir(d);
                if r != 0 {
                    println!("mkdir: {}: {}", d, r);
                }
            }
        }
        "ps" => {
            unsafe { rudra::syscall6(rudra::SYS_DEBUG_TASKS, 0, 0, 0, 0, 0, 0) };
        }
        "uname" => {
            let mut buf = [0u8; 6 * 65];
            unsafe { rudra::syscall6(rudra::SYS_UNAME, buf.as_mut_ptr() as u64, 0, 0, 0, 0, 0) };
            let fields = [
                core::str::from_utf8(&buf[0..65]).unwrap_or("?"),
                core::str::from_utf8(&buf[65..130]).unwrap_or("?"),
                core::str::from_utf8(&buf[130..195]).unwrap_or("?"),
                core::str::from_utf8(&buf[195..260]).unwrap_or("?"),
                core::str::from_utf8(&buf[260..325]).unwrap_or("?"),
            ];
            println!(
                "{} {} {} {} {} x86_64",
                fields[0], fields[1], fields[2], fields[3], fields[4]
            );
        }
        "run" => {
            if args.is_empty() {
                println!("run: нужен путь");
                return;
            }
            let path = args[0];
            let code = rudra::run_and_wait(path, &[]);
            println!("[exit {}]", code);
        }
        _ => {
            // Внешняя команда: execve с fallback'ами.
            external(cmd, args);
        }
    }
}

fn ls(path: &str) {
    let fd = rudra::open(path, rudra::O_RDONLY | rudra::O_DIRECTORY);
    if fd < 0 {
        // Может, это файл?
        let mut buf = [0u8; 64];
        if rudra::read_file(path, &mut buf) >= 0 {
            println!("{}", path);
            return;
        }
        println!("ls: {}: нет такого каталога", path);
        return;
    }
    let mut buf = [0u8; 4096];
    loop {
        let n = unsafe {
            rudra::syscall6(rudra::SYS_GETDENTS64, fd as u64, buf.as_mut_ptr() as u64, buf.len() as u64, 0, 0, 0)
        };
        if n <= 0 {
            break;
        }
        let mut off = 0usize;
        while off < n as usize {
            let p = unsafe { buf.as_ptr().add(off) };
            let reclen = unsafe { (p.add(16) as *const u16).read() } as usize;
            if reclen == 0 {
                break;
            }
            let name_len = (0..64)
                .find(|&i| unsafe { *p.add(19 + i) } == 0)
                .unwrap_or(0);
            let name = core::str::from_utf8(unsafe { core::slice::from_raw_parts(p.add(19), name_len) })
                .unwrap_or("?");
            let d_type = unsafe { *p.add(18) };
            if d_type == 4 {
                println!("{}/", name);
            } else {
                println!("{}", name);
            }
            off += reclen;
        }
    }
    rudra::close(fd as u64);
}

fn cat(path: &str) {
    let fd = rudra::open(path, rudra::O_RDONLY);
    if fd < 0 {
        println!("cat: {}: нет такого файла", path);
        return;
    }
    let mut buf = [0u8; 512];
    loop {
        let n = rudra::read(fd as u64, &mut buf);
        if n <= 0 {
            break;
        }
        rudra::write_str(core::str::from_utf8(&buf[..n as usize]).unwrap_or("?"));
    }
    rudra::close(fd as u64);
}

/// echo [текст] [> файл]
fn echo(args: &[&str]) {
    let mut text_end = args.len();
    let mut redirect: Option<&str> = None;
    for (i, a) in args.iter().enumerate() {
        if *a == ">" {
            text_end = i;
            redirect = args.get(i + 1).copied();
            break;
        }
    }
    let mut line = [0u8; 256];
    let mut len = 0usize;
    for (i, w) in args[..text_end].iter().enumerate() {
        if i > 0 && len < line.len() - 1 {
            line[len] = b' ';
            len += 1;
        }
        let b = w.as_bytes();
        let n = b.len().min(line.len() - 1 - len);
        line[len..len + n].copy_from_slice(&b[..n]);
        len += n;
    }
    line[len] = 0;
    let text = core::str::from_utf8(&line[..len]).unwrap_or("");
    match redirect {
        Some(path) => {
            rudra::write_file(path, text.as_bytes());
        }
        None => {
            println!("{}", text);
        }
    }
}

/// Внешняя команда: пробуем execve варианты в child-процессе.
fn external(cmd: &str, args: &[&str]) {
    let pid = rudra::fork();
    if pid == 0 {
        // Ребёнок: последовательные попытки execve.
        // 1) как путь (если содержит '/')
        if cmd.contains('/') {
            let mut argv: [&str; 16] = [""; 16];
            argv[0] = cmd;
            for (i, a) in args.iter().take(14).enumerate() {
                argv[i + 1] = a;
            }
            let r = rudra::execve(cmd, &argv[..args.len().min(14) + 1]);
            if r != 0 && r != u64::MAX {
                rudra::write_err("rudra: exec format error\n");
            } else {
                rudra::write_err("rudra: not found\n");
            }
            rudra::exit(127);
        }
        // 2) /bin/<cmd>, 3) /bin/<cmd>.elf, 4) /bin/busybox <cmd>
        let mut pbuf = [0u8; 64];
        let full: &'static str = {
            let b = cmd.as_bytes();
            let pre = b"/bin/";
            if pre.len() + b.len() + 4 < pbuf.len() {
                pbuf[..pre.len()].copy_from_slice(pre);
                pbuf[pre.len()..pre.len() + b.len()].copy_from_slice(b);
                pbuf[pre.len() + b.len()] = 0;
                let full_len = pre.len() + b.len();
                leak_str(core::str::from_utf8(&pbuf[..full_len]).unwrap_or(""))
            } else {
                rudra::write_err("rudra: имя слишком длинное\n");
                rudra::exit(127);
            }
        };
        let mut argv: [&str; 16] = [""; 16];
        argv[0] = full;
        for (i, a) in args.iter().take(14).enumerate() {
            argv[i + 1] = a;
        }
        let r1 = rudra::execve(full, &argv[..args.len().min(14) + 1]);
        if r1 == 0 {
            rudra::exit(0); // не достигается
        }
        // .elf вариант
        let elf: &'static str = {
            let b = full.as_bytes();
            if b.len() + 4 < pbuf.len() {
                pbuf[..b.len()].copy_from_slice(b);
                pbuf[b.len()..b.len() + 4].copy_from_slice(b".elf");
                pbuf[b.len() + 4] = 0;
                leak_str(core::str::from_utf8(&pbuf[..b.len() + 4]).unwrap_or(""))
            } else {
                ""
            }
        };
        if !elf.is_empty() {
            let mut argv2: [&str; 16] = [""; 16];
            argv2[0] = elf;
            for (i, a) in args.iter().take(14).enumerate() {
                argv2[i + 1] = a;
            }
            let r2 = rudra::execve(elf, &argv2[..args.len().min(14) + 1]);
            if r2 == 0 {
                rudra::exit(0);
            }
        }
        // busybox fallback
        let mut argv3: [&str; 16] = [""; 16];
        argv3[0] = BB_PATH;
        argv3[1] = "busybox";
        argv3[2] = cmd;
        for (i, a) in args.iter().take(12).enumerate() {
            argv3[i + 3] = a;
        }
        let r3 = rudra::execve(BB_PATH, &argv3[..args.len().min(12) + 3]);
        if r3 != 0 {
            let msg = if r3 == (-2i64) as u64 {
                "rudra: command not found\n"
            } else {
                "rudra: busybox exec failed\n"
            };
            rudra::write_err(msg);
        }
        rudra::exit(127);
    }
    if pid == u64::MAX {
        println!("fork failed");
        return;
    }
    let (tid, _) = rudra::wait4(pid);
    let _ = tid;
}

// Копия строки в статический буфер-пул (шелл без alloc).
static mut LEAK_BUF: [u8; 1024] = [0u8; 1024];
static mut LEAK_POS: usize = 0;

fn leak_str(s: &str) -> &'static str {
    unsafe {
        let start = LEAK_POS;
        let b = s.as_bytes();
        if start + b.len() + 1 > LEAK_BUF.len() {
            return "";
        }
        LEAK_BUF[start..start + b.len()].copy_from_slice(b);
        LEAK_BUF[start + b.len()] = 0;
        LEAK_POS = start + b.len() + 1;
        core::str::from_utf8_unchecked(core::slice::from_raw_parts(
            LEAK_BUF.as_ptr().add(start),
            b.len(),
        ))
    }
}

rudra::entry!(main);
