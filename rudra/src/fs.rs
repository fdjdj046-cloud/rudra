//! Ramdisk-файловая система rudra (RFS2).
//!
//! Плоское хранилище полных путей ("/bin/shell.elf"), каталоги эмулируются
//! синтетически: "/bin" — это префикс имён. Запись — create-or-replace с
//! bump-аллокацией (старые данные текут, это учебная FS).
//!
//! Регион живёт в kernel heap (Box утекает), поэтому FS доступна при любом
//! CR3 задач. Все операции под глобальным мьютексом, короткие.

use alloc::boxed::Box;
use alloc::format;
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;
use spin::{Mutex, Once};

const MAGIC: u32 = 0x3253_4652; // "RFS2"
const MAX_FILES: usize = 192;
const NAME_LEN: usize = 64;
const ENTRY_SIZE: usize = 72; // name[64] + offset u32 + size u32
const TABLE_OFF: usize = 12; // magic + num_files + data_used
const DATA_OFF: usize = 16 * 1024;
pub const DISK_SIZE: usize = 8 * 1024 * 1024;

/// Базовый образ ramdisk, собранный pack_rfs.py из rootfs при сборке ядра.
static BASE_IMAGE: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/rfs.img"));

pub struct RamFs {
    storage: Box<[u8]>,
}

static FS: Once<Mutex<RamFs>> = Once::new();

fn rd32(buf: &[u8], off: usize) -> u32 {
    u32::from_le_bytes(buf[off..off + 4].try_into().unwrap())
}

fn wr32(buf: &mut [u8], off: usize, v: u32) {
    buf[off..off + 4].copy_from_slice(&v.to_le_bytes());
}

/// Смонтировать ramdisk, скопировав базовый образ (из rootfs, собранный
/// pack_rfs.py на хосте). Вызывать один раз, до запуска задач.
pub fn init() {
    init_from(BASE_IMAGE);
}

pub fn init_from(base_image: &[u8]) {
    let mut storage: Box<[u8]> = vec![0u8; DISK_SIZE].into_boxed_slice();
    let n = base_image.len().min(DISK_SIZE);
    storage[..n].copy_from_slice(&base_image[..n]);
    if rd32(&storage, 0) != MAGIC {
        // Образ битый или пустой — стартуем с чистого диска.
        for b in &mut storage[..] {
            *b = 0;
        }
        wr32(&mut storage, 0, MAGIC);
    }
    let _ = FS.call_once(|| Mutex::new(RamFs { storage }));
}

fn fs() -> spin::MutexGuard<'static, RamFs> {
    FS.get().expect("fs not mounted").lock()
}

/// Прямой доступ к FS под локом (для linux.rs: is_dir/list_dir/size_of).
pub fn fs_lock() -> spin::MutexGuard<'static, RamFs> {
    fs()
}

impl RamFs {
    fn num_files(&self) -> usize {
        rd32(&self.storage, 4) as usize
    }

    fn data_used(&self) -> usize {
        rd32(&self.storage, 8) as usize
    }

    fn set_num_files(&mut self, n: usize) {
        wr32(&mut self.storage, 4, n as u32);
    }

    fn set_data_used(&mut self, n: usize) {
        wr32(&mut self.storage, 8, n as u32);
    }

    /// Имя записи (пустая строка для удалённых).
    fn entry_name(&self, slot: usize) -> &str {
        let base = TABLE_OFF + slot * ENTRY_SIZE;
        let raw = &self.storage[base..base + NAME_LEN];
        let len = raw.iter().position(|&b| b == 0).unwrap_or(NAME_LEN);
        core::str::from_utf8(&raw[..len]).unwrap_or("")
    }

    /// Слот записи: None, если не найдена.
    fn find_slot(&self, name: &str) -> Option<usize> {
        let count = self.num_files().min(MAX_FILES);
        for i in 0..count {
            let base = TABLE_OFF + i * ENTRY_SIZE;
            if self.storage[base] == 0 {
                continue; // удалённая запись
            }
            if self.entry_name(i) == name {
                return Some(i);
            }
        }
        None
    }

    fn entry(&self, slot: usize) -> (u32, u32) {
        let base = TABLE_OFF + slot * ENTRY_SIZE;
        (rd32(&self.storage, base + NAME_LEN), rd32(&self.storage, base + NAME_LEN + 4))
    }

    pub fn read(&self, name: &str, buf: &mut [u8]) -> isize {
        self.read_at(name, 0, buf)
    }

    /// Прочитать `buf.len()` байт с позиции `offset`.
    pub fn read_at(&self, name: &str, offset: u64, buf: &mut [u8]) -> isize {
        if name.is_empty() || name.len() >= NAME_LEN {
            return -1;
        }
        let slot = match self.find_slot(name) {
            Some(s) => s,
            None => return -1,
        };
        let (off, size) = self.entry(slot);
        if offset >= size as u64 {
            return 0;
        }
        let start = DATA_OFF + off as usize + offset as usize;
        let n = ((size as u64 - offset) as usize).min(buf.len());
        buf[..n].copy_from_slice(&self.storage[start..start + n]);
        n as isize
    }

    /// Создать или заменить файл. Возвращает размер или -1.
    pub fn write(&mut self, name: &str, data: &[u8]) -> isize {
        if name.is_empty() || name.len() >= NAME_LEN || name == "/" {
            return -1;
        }
        let count = self.num_files().min(MAX_FILES);
        let slot = match self.find_slot(name) {
            Some(s) => s,
            None => {
                if count >= MAX_FILES {
                    return -1;
                }
                count // новый слот
            }
        };
        let used = self.data_used();
        if DATA_OFF + used + data.len() > DISK_SIZE {
            return -1; // не хватает места
        }
        // Имя
        let base = TABLE_OFF + slot * ENTRY_SIZE;
        for b in &mut self.storage[base..base + NAME_LEN] {
            *b = 0;
        }
        self.storage[base..base + name.len()].copy_from_slice(name.as_bytes());
        // Данные
        let start = DATA_OFF + used;
        self.storage[start..start + data.len()].copy_from_slice(data);
        wr32(&mut self.storage, base + NAME_LEN, used as u32);
        wr32(&mut self.storage, base + NAME_LEN + 4, data.len() as u32);
        if slot >= count {
            self.set_num_files(count + 1);
        }
        self.set_data_used(used + data.len());
        data.len() as isize
    }

    pub fn delete(&mut self, name: &str) -> bool {
        match self.find_slot(name) {
            Some(slot) => {
                let base = TABLE_OFF + slot * ENTRY_SIZE;
                self.storage[base] = 0;
                true
            }
            None => false,
        }
    }

    /// Имя i-го живого файла (для ls). Возвращает длину имени или -1.
    pub fn list(&self, index: usize, buf: &mut [u8]) -> isize {
        let count = self.num_files().min(MAX_FILES);
        let mut live = 0;
        for i in 0..count {
            let base = TABLE_OFF + i * ENTRY_SIZE;
            if self.storage[base] == 0 {
                continue;
            }
            if live == index {
                let name = self.entry_name(i);
                let n = name.len().min(buf.len());
                buf[..n].copy_from_slice(&name.as_bytes()[..n]);
                return n as isize;
            }
            live += 1;
        }
        -1
    }

    /// Размер файла (для ls -l).
    pub fn size_of(&self, name: &str) -> isize {
        match self.find_slot(name) {
            Some(slot) => self.entry(slot).1 as isize,
            None => -1,
        }
    }

    pub fn exists(&self, name: &str) -> bool {
        self.find_slot(name).is_some()
    }

    /// Каталог ли путь (корень или префикс существующих файлов).
    pub fn is_dir(&self, name: &str) -> bool {
        if name == "/" {
            return true;
        }
        let prefix = format!("{}/", name);
        let count = self.num_files().min(MAX_FILES);
        for i in 0..count {
            let base = TABLE_OFF + i * ENTRY_SIZE;
            if self.storage[base] == 0 {
                continue;
            }
            if self.entry_name(i).starts_with(&prefix) {
                return true;
            }
        }
        false
    }

    /// Прямые дети каталога (без вложенных компонентов).
    pub fn list_dir(&self, name: &str) -> Vec<String> {
        let mut out: Vec<String> = Vec::new();
        let count = self.num_files().min(MAX_FILES);
        for i in 0..count {
            let base = TABLE_OFF + i * ENTRY_SIZE;
            if self.storage[base] == 0 {
                continue;
            }
            let full = self.entry_name(i);
            let rest = if name == "/" {
                full.strip_prefix('/')
            } else {
                full.strip_prefix(name).and_then(|s| s.strip_prefix('/'))
            };
            if let Some(rest) = rest {
                let child = match rest.find('/') {
                    Some(p) => &rest[..p],
                    None => rest,
                };
                if !child.is_empty() && !out.iter().any(|c| c == child) {
                    out.push(String::from(child));
                }
            }
        }
        out
    }
}

/// Привести путь к каноническому виду "/a/b" (убирает ".", "..", "//").
/// Возвращает None, если результат не влезает в NAME_LEN.
fn canon(path: &str, buf: &mut [u8; NAME_LEN]) -> Option<usize> {
    let p = path.trim_end_matches('\0').trim_matches(' ');
    let mut comps: Vec<&str> = Vec::new();
    for part in p.split('/') {
        match part {
            "" | "." => {}
            ".." => {
                comps.pop();
            }
            other => comps.push(other),
        }
    }
    let full: String = if comps.is_empty() {
        String::from("/")
    } else {
        let mut s = String::new();
        for c in comps {
            s.push('/');
            s.push_str(c);
        }
        s
    };
    if full.len() >= NAME_LEN {
        return None;
    }
    buf[..full.len()].copy_from_slice(full.as_bytes());
    Some(full.len())
}

/// Разрешить путь относительно cwd в каноническое имя FS.
pub fn resolve(cwd: &str, path: &str) -> Option<String> {
    let joined = if path.starts_with('/') {
        String::from(path)
    } else if cwd == "/" {
        let mut s = String::from("/");
        s.push_str(path);
        s
    } else {
        let mut s = String::from(cwd);
        s.push('/');
        s.push_str(path);
        s
    };
    let mut buf = [0u8; NAME_LEN];
    match canon(&joined, &mut buf) {
        Some(len) => Some(String::from(
            core::str::from_utf8(&buf[..len]).unwrap_or("/"),
        )),
        None => None,
    }
}

fn with_name<R>(path: &[u8], f: impl FnOnce(&str) -> R, default: R) -> R {
    let s = match core::str::from_utf8(path) {
        Ok(s) => s,
        Err(_) => return default,
    };
    let mut buf = [0u8; NAME_LEN];
    match canon(s, &mut buf) {
        Some(len) => f(core::str::from_utf8(&buf[..len]).unwrap_or("")),
        None => default,
    }
}

/// Прочитать файл (путь из user/kernel памяти, игнорирует cwd).
pub fn read_path(path: &[u8], buf: &mut [u8]) -> isize {
    with_name(path, |n| fs().read(n, buf), -1)
}

pub fn write_path(path: &[u8], data: &[u8]) -> isize {
    with_name(path, |n| fs().write(n, data), -1)
}

pub fn delete_path(path: &[u8]) -> bool {
    with_name(path, |n| fs().delete(n), false)
}

pub fn list_index(index: usize, buf: &mut [u8]) -> isize {
    fs().list(index, buf)
}

/// Размер файла по пути (для execve/spawn).
pub fn size_path(path: &[u8]) -> isize {
    with_name(path, |n| fs().size_of(n), -1)
}

pub fn read_file_to_vec(path: &[u8]) -> Option<Vec<u8>> {
    let size = size_path(path);
    if size <= 0 {
        return None;
    }
    let mut v = vec![0u8; size as usize];
    match read_path(path, &mut v) {
        n if n == size => Some(v),
        _ => None,
    }
}

/// Прочитать файл по каноническому имени в Vec (для execve).
pub fn read_canon(name: &str) -> Option<Vec<u8>> {
    let size = fs().size_of(name);
    if size <= 0 {
        return None;
    }
    let mut v = vec![0u8; size as usize];
    match fs().read(name, &mut v) {
        n if n == size => Some(v),
        _ => None,
    }
}

/// Удалить файл по каноническому имени.
pub fn delete_canon(name: &str) -> bool {
    fs().delete(name)
}

/// Создать/перезаписать файл по каноническому имени.
pub fn write_canon(name: &str, data: &[u8]) -> isize {
    fs().write(name, data)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{serial_print, serial_println};

    #[test_case]
    fn ramfs_roundtrip() {
        serial_print!("test ramfs_roundtrip... ");
        assert!(write_path(b"/test.txt", b"hello fs") > 0);
        let mut buf = [0u8; 32];
        let n = read_path(b"/test.txt", &mut buf) as usize;
        assert_eq!(&buf[..n], b"hello fs");
        // read_at с позиции
        assert_eq!(fs().read_at("/test.txt", 6, &mut buf), 2);
        assert_eq!(&buf[..2], b"fs");
        assert!(delete_path(b"/test.txt"));
        assert_eq!(read_path(b"/test.txt", &mut buf), -1);
        serial_println!("[ok]");
    }

    #[test_case]
    fn ramfs_dirs() {
        serial_print!("test ramfs_dirs... ");
        assert!(fs().is_dir("/"));
        write_path(b"/a/b/f.txt", b"x");
        assert!(fs().is_dir("/a"));
        assert!(fs().is_dir("/a/b"));
        assert!(!fs().is_dir("/a/b/f.txt"));
        let kids = fs().list_dir("/a");
        assert_eq!(kids.len(), 1);
        assert_eq!(kids[0], "b");
        let kids = fs().list_dir("/a/b");
        assert_eq!(kids.len(), 1);
        assert_eq!(kids[0], "f.txt");
        delete_path(b"/a/b/f.txt");
        serial_println!("[ok]");
    }

    #[test_case]
    fn path_resolve() {
        serial_print!("test path_resolve... ");
        assert_eq!(resolve("/", "/bin//ls").unwrap(), "/bin/ls");
        assert_eq!(resolve("/bin", "ls").unwrap(), "/bin/ls");
        assert_eq!(resolve("/bin", "../etc/x").unwrap(), "/etc/x");
        assert_eq!(resolve("/bin", "..").unwrap(), "/");
        assert_eq!(resolve("/", ".").unwrap(), "/");
        assert_eq!(resolve("/a/b", "../../c").unwrap(), "/c");
        serial_println!("[ok]");
    }
}
