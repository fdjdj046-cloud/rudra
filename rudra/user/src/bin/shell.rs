#![no_std]
#![no_main]

//! Интерактивный шелл rudra (ring 3).
//!
//! Команды:
//!   ls [path]        — список файлов ramdisk'а
//!   cat <path>       — напечатать файл
//!   echo <text>      — напечатать текст
//!   echo <text> > <path> — записать текст в файл
//!   run <prog>       — запустить /bin/<prog>.elf
//!   rm <path>        — удалить файл
//!   uname            — информация о системе
//!   pwd              — текущий каталог (всегда "/")
//!   help             — эта справка
//!   clear            — очистить экран
//!   exit             — завершить шелл

use core::panic::PanicInfo;

fn read_line(buf: &mut [u8]) -> usize {
    let mut len = 0;
    while len < buf.len() {
        let mut c = [0u8; 1];
        if user::read(&mut c) == 0 {
            user::r#yield();
            continue;
        }
        let ch = c[0];
        if ch == b'\n' {
            user::write("\n");
            break;
        }
        if ch == 0x08 || ch == 0x7f {
            if len > 0 {
                len -= 1;
                user::write("\u{8} \u{8}");
            }
            continue;
        }
        buf[len] = ch;
        len += 1;
        user::write(core::str::from_utf8(&c[..1]).unwrap_or("?"));
    }
    len
}

/// Разбить строку на токены по пробелам. Возвращает число токенов.
fn tokenize<'a>(line: &'a [u8], tokens: &mut [&'a str]) -> usize {
    let s = core::str::from_utf8(line).unwrap_or("");
    let mut n = 0;
    for t in s.split(' ') {
        let t = t.trim();
        if t.is_empty() {
            continue;
        }
        if n < tokens.len() {
            tokens[n] = t;
            n += 1;
        }
    }
    n
}

fn cmd_ls(arg: &str) {
    let mut name = [0u8; 32];
    let filter = arg.trim_start_matches('/');
    let mut i: u64 = 0;
    loop {
        let n = user::list(i, &mut name);
        if n <= 0 {
            break;
        }
        let entry = core::str::from_utf8(&name[..n as usize]).unwrap_or("?");
        if !filter.is_empty() && entry.trim_start_matches('/') != filter {
            i += 1;
            continue;
        }
        user::write(entry);
        user::write("\n");
        i += 1;
    }
}

fn cmd_cat(path: &str) {
    if path.is_empty() {
        user::write("usage: cat <file>\n");
        return;
    }
    let mut buf = [0u8; user::FS_BUF_SIZE];
    let n = user::read_file(path, &mut buf);
    if n < 0 {
        user::write("cat: no such file: ");
        user::write(path);
        user::write("\n");
        return;
    }
    user::write(core::str::from_utf8(&buf[..n as usize]).unwrap_or("<binary>"));
    user::write("\n");
}

fn cmd_echo(tokens: &[&str], n: usize) {
    // echo text... [> file]
    let mut redirect: Option<&str> = None;
    let mut text_end = n;
    for i in 1..n {
        if tokens[i] == ">" && i + 1 < n {
            redirect = Some(tokens[i + 1]);
            text_end = i;
            break;
        }
    }
    let mut text_buf = [0u8; 256];
    let text = {
        let mut s = heapless::Str::new(&mut text_buf);
        for (k, t) in tokens[1..text_end].iter().enumerate() {
            if k > 0 {
                s.push(" ");
            }
            s.push(t);
        }
        s.into_str()
    };
    match redirect {
        Some(path) => {
            if user::write_file(path, text.as_bytes()) < 0 {
                user::write("echo: write failed (disk full or bad name)\n");
            }
        }
        None => {
            user::write(text);
            user::write("\n");
        }
    }
}

fn cmd_run(name: &str) {
    if name.is_empty() {
        user::write("usage: run <program>   (see: ls /bin)\n");
        return;
    }
    let mut path_buf = [0u8; 40];
    let path = {
        let mut s = heapless::Str::new(&mut path_buf);
        s.push("/bin/").push(name).push(".elf");
        s.into_str()
    };
    if user::spawn_path(path) == u64::MAX {
        user::write("run: program not found or no free slots\n");
    }
}

fn execute(tokens: &[&str], n: usize) {
    if n == 0 {
        return;
    }
    match tokens[0] {
        "help" => user::write(
            "commands: ls cat echo run rm uname pwd help clear exit\n\
             examples: ls\n\
                       cat /motd.txt\n\
                       echo hello > note.txt && cat note.txt\n\
                       run fizzbuzz\n",
        ),
        "ls" => cmd_ls(if n > 1 { tokens[1] } else { "" }),
        "cat" => cmd_cat(if n > 1 { tokens[1] } else { "" }),
        "echo" => cmd_echo(tokens, n),
        "run" => cmd_run(if n > 1 { tokens[1] } else { "" }),
        "rm" => {
            if n > 1 {
                if !user::delete(tokens[1]) {
                    user::write("rm: no such file\n");
                }
            } else {
                user::write("usage: rm <file>\n");
            }
        }
        "uname" => user::write("rudra 0.5.0 x86_64 (hobby OS, rust nightly)\n"),
        "pwd" => user::write("/\n"),
        "clear" => user::write("\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n"),
        "exit" => user::exit(0),
        _ => {
            user::write("unknown command: ");
            user::write(tokens[0]);
            user::write(" (try 'help')\n");
        }
    }
}

/// Крошечная строка поверх буфера (без alloc).
mod heapless {
    pub struct Str<'a> {
        buf: &'a mut [u8],
        len: usize,
    }
    impl<'a> Str<'a> {
        pub fn new(buf: &'a mut [u8]) -> Self {
            Str { buf, len: 0 }
        }
        pub fn push(&mut self, s: &str) -> &mut Self {
            let n = s.len().min(self.buf.len() - self.len);
            self.buf[self.len..self.len + n].copy_from_slice(&s.as_bytes()[..n]);
            self.len += n;
            self
        }
        /// Отдать собранную строку с лайфтаймом буфера.
        pub fn into_str(self) -> &'a str {
            let len = self.len;
            let buf = self.buf;
            core::str::from_utf8(&buf[..len]).unwrap_or("")
        }
    }
}

#[no_mangle]
pub extern "C" fn _start() -> ! {
    user::write("rudra shell v0.5 (type 'help')\n");
    let mut line = [0u8; 96];

    loop {
        user::write("rudra> ");
        let len = read_line(&mut line);
        let mut tokens = [""; 12];
        let n = tokenize(&line[..len], &mut tokens);
        execute(&tokens, n);
    }
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    user::write("shell panic\n");
    user::exit(1)
}
