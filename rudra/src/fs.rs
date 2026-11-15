//! Ramdisk-файловая система rudra (RFS2).
//!
//! Каждая запись — полный путь ("/bin/busybox" или "/bin"). Каталог — отдельная
//! запись: старший бит `offset` установлен, данных нет. Префикс файла каталогом
//! не считается. Новый файл можно создать только в существующем каталоге.
//! Запись файла — create-or-replace с bump-аллокацией (старые данные текут).
//!
//! При монтировании недостающие родители уже лежащих в образе файлов
//! достраиваются один раз: старый образ без записей каталогов продолжает
//! грузиться. Дальше `mkdir` / `rmdir` обязательны.
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
const PATH_MAX: usize = 256;
const ENTRY_SIZE: usize = 72; // name[64] + offset u32 + size u32
const TABLE_OFF: usize = 12; // magic + num_files + data_used
const DATA_OFF: usize = 16 * 1024;
pub const DISK_SIZE: usize = 8 * 1024 * 1024;
/// Старший бит offset: запись — каталог, поле size не используется.
const DIR_BIT: u32 = 0x8000_0000;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FsError {
    NoEnt,
    Exist,
    NotDir,
    IsDir,
    NotEmpty,
    NoSpc,
    Inval,
    Perm,
    Io,
}

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
    let mut ram = RamFs { storage };
    ram.materialize_parents();
    let _ = FS.call_once(|| Mutex::new(ram));
}

/// Родитель канонического пути. У `"/"` и у `"foo"` родитель — `"/"`.
pub fn parent(path: &str) -> &str {
    match path.rfind('/') {
        Some(0) | None => "/",
        Some(i) => &path[..i],
    }
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

    fn is_dir_slot(&self, slot: usize) -> bool {
        self.entry(slot).0 & DIR_BIT != 0
    }

    fn set_name(&mut self, slot: usize, name: &str) {
        let base = TABLE_OFF + slot * ENTRY_SIZE;
        for b in &mut self.storage[base..base + NAME_LEN] {
            *b = 0;
        }
        self.storage[base..base + name.len()].copy_from_slice(name.as_bytes());
    }

    fn clear_slot(&mut self, slot: usize) {
        let base = TABLE_OFF + slot * ENTRY_SIZE;
        self.storage[base] = 0;
    }

    /// Свободный слот: дырка от удаления или новый в конце таблицы.
    fn alloc_slot(&mut self) -> Result<usize, FsError> {
        let count = self.num_files().min(MAX_FILES);
        for i in 0..count {
            if self.storage[TABLE_OFF + i * ENTRY_SIZE] == 0 {
                return Ok(i);
            }
        }
        if count >= MAX_FILES {
            return Err(FsError::NoSpc);
        }
        self.set_num_files(count + 1);
        Ok(count)
    }

    pub fn parent_ok(&self, name: &str) -> Result<(), FsError> {
        let parent = parent(name);
        if self.is_dir(parent) {
            Ok(())
        } else if self.find_slot(parent).is_some() {
            Err(FsError::NotDir)
        } else {
            Err(FsError::NoEnt)
        }
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
        if self.is_dir_slot(slot) {
            return -1;
        }
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
        let slot = match self.find_slot(name) {
            Some(s) if self.is_dir_slot(s) => return -1,
            Some(s) => s,
            None => {
                if self.parent_ok(name).is_err() {
                    return -1;
                }
                match self.alloc_slot() {
                    Ok(s) => s,
                    Err(_) => return -1,
                }
            }
        };
        let used = self.data_used();
        if DATA_OFF + used + data.len() > DISK_SIZE {
            return -1; // не хватает места
        }
        self.set_name(slot, name);
        let base = TABLE_OFF + slot * ENTRY_SIZE;
        let start = DATA_OFF + used;
        self.storage[start..start + data.len()].copy_from_slice(data);
        wr32(&mut self.storage, base + NAME_LEN, used as u32);
        wr32(&mut self.storage, base + NAME_LEN + 4, data.len() as u32);
        self.set_data_used(used + data.len());
        data.len() as isize
    }

    /// Удалить файл. Каталог не трогает.
    pub fn delete(&mut self, name: &str) -> bool {
        self.unlink(name).is_ok()
    }

    /// unlink(2): каталог — ошибка, а не тихое «нет файла».
    pub fn unlink(&mut self, name: &str) -> Result<(), FsError> {
        match self.find_slot(name) {
            Some(slot) if self.is_dir_slot(slot) => Err(FsError::IsDir),
            Some(slot) => {
                self.clear_slot(slot);
                Ok(())
            }
            None => Err(FsError::NoEnt),
        }
    }

    /// Создать каталог. Родитель должен уже существовать.
    pub fn mkdir(&mut self, name: &str) -> Result<(), FsError> {
        if name.is_empty() || name == "/" || name.len() >= NAME_LEN || name.contains('\0') {
            return Err(FsError::Inval);
        }
        if self.find_slot(name).is_some() {
            return Err(FsError::Exist);
        }
        self.parent_ok(name)?;
        let slot = self.alloc_slot()?;
        self.set_name(slot, name);
        let base = TABLE_OFF + slot * ENTRY_SIZE;
        wr32(&mut self.storage, base + NAME_LEN, DIR_BIT);
        wr32(&mut self.storage, base + NAME_LEN + 4, 0);
        Ok(())
    }

    /// Удалить пустой каталог. Корень удалить нельзя.
    pub fn rmdir(&mut self, name: &str) -> Result<(), FsError> {
        if name == "/" {
            return Err(FsError::Perm);
        }
        let slot = match self.find_slot(name) {
            Some(s) if self.is_dir_slot(s) => s,
            Some(_) => return Err(FsError::NotDir),
            None => return Err(FsError::NoEnt),
        };
        if !self.list_dir(name).is_empty() {
            return Err(FsError::NotEmpty);
        }
        self.clear_slot(slot);
        Ok(())
    }

    /// Переименовать файл или каталог вместе с потомками. Данные не копируются.
    pub fn rename(&mut self, old: &str, new: &str) -> Result<(), FsError> {
        if old == new {
            return Ok(());
        }
        if old == "/" || new == "/" || new.len() >= NAME_LEN || old.is_empty() {
            return Err(FsError::Inval);
        }
        let old_slot = self.find_slot(old).ok_or(FsError::NoEnt)?;
        let old_is_dir = self.is_dir_slot(old_slot);
        self.parent_ok(new)?;
        let mut kids: Vec<(usize, String)> = Vec::new();
        if old_is_dir {
            let prefix = format!("{}/", old);
            if new.starts_with(&prefix) {
                return Err(FsError::Inval);
            }
            let count = self.num_files().min(MAX_FILES);
            for i in 0..count {
                if self.storage[TABLE_OFF + i * ENTRY_SIZE] == 0 {
                    continue;
                }
                let n = self.entry_name(i);
                if n.starts_with(&prefix) {
                    let renamed = format!("{}{}", new, &n[old.len()..]);
                    if renamed.len() >= NAME_LEN {
                        return Err(FsError::Inval);
                    }
                    kids.push((i, renamed));
                }
            }
        }
        if let Some(dest) = self.find_slot(new) {
            let dest_dir = self.is_dir_slot(dest);
            if dest_dir && !old_is_dir {
                return Err(FsError::IsDir);
            }
            if !dest_dir && old_is_dir {
                return Err(FsError::NotDir);
            }
            if dest_dir && !self.list_dir(new).is_empty() {
                return Err(FsError::NotEmpty);
            }
            self.clear_slot(dest);
        }
        for (i, renamed) in kids {
            self.set_name(i, &renamed);
        }
        self.set_name(old_slot, new);
        Ok(())
    }

    /// Достроить каталоги-родители для записей, уже лежащих в образе.
    fn materialize_parents(&mut self) {
        let count = self.num_files().min(MAX_FILES);
        let mut names: Vec<String> = Vec::new();
        for i in 0..count {
            if self.storage[TABLE_OFF + i * ENTRY_SIZE] == 0 {
                continue;
            }
            names.push(String::from(self.entry_name(i)));
        }
        for name in names {
            let mut missing: Vec<String> = Vec::new();
            let mut cur = String::from(parent(&name));
            while cur != "/" && !self.is_dir(&cur) {
                if self.find_slot(&cur).is_some() {
                    break;
                }
                let next = String::from(parent(&cur));
                missing.push(cur);
                cur = next;
            }
            for dir in missing.iter().rev() {
                let _ = self.mkdir(dir);
            }
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
            Some(slot) if !self.is_dir_slot(slot) => self.entry(slot).1 as isize,
            _ => -1,
        }
    }

    pub fn exists(&self, name: &str) -> bool {
        self.find_slot(name).is_some()
    }

    /// Каталог ли путь. Корень есть всегда. Префикс чужого имени — не каталог.
    pub fn is_dir(&self, name: &str) -> bool {
        if name == "/" {
            return true;
        }
        self.find_slot(name)
            .map(|s| self.is_dir_slot(s))
            .unwrap_or(false)
    }

    /// Прямые дети каталога: только реальные записи, ровно на один компонент глубже.
    pub fn list_dir(&self, name: &str) -> Vec<String> {
        let mut out: Vec<String> = Vec::new();
        if name != "/" && !self.is_dir(name) {
            return out;
        }
        let count = self.num_files().min(MAX_FILES);
        for i in 0..count {
            let base = TABLE_OFF + i * ENTRY_SIZE;
            if self.storage[base] == 0 {
                continue;
            }
            let full = self.entry_name(i);
            if parent(full) != name {
                continue;
            }
            let child = match full.rfind('/') {
                Some(pos) => &full[pos + 1..],
                None => full,
            };
            if !child.is_empty() && !out.iter().any(|c| c == child) {
                out.push(String::from(child));
            }
        }
        out
    }
}

/// Привести путь к каноническому виду "/a/b" (убирает ".", "..", "//").
/// Возвращает None, если результат не влезает в NAME_LEN.
fn canon(path: &str, buf: &mut [u8; PATH_MAX]) -> Option<usize> {
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
    if full.len() >= PATH_MAX {
        return None;
    }
    buf[..full.len()].copy_from_slice(full.as_bytes());
    Some(full.len())
}

fn ext2_on() -> bool {
    crate::ext2::mounted()
}

/// Синтетический `/proc`. Не пишется на диск: и при ext2, и на ramdisk.
fn proc_root(name: &str) -> bool {
    name == "/proc"
}

fn proc_body(name: &str) -> Option<String> {
    match name {
        "/proc/uptime" => {
            let ns = crate::time::monotonic_ns();
            let sec = ns / 1_000_000_000;
            let cent = (ns / 10_000_000) % 100;
            // Второе поле Linux — idle. Мы его не считаем, поэтому ноль.
            Some(format!("{}.{:02} 0.00\n", sec, cent))
        }
        "/proc/cpuinfo" => Some(format!(
            "processor\t: 0\nsiblings\t: {}\n",
            crate::smp::cpu_count()
        )),
        _ => None,
    }
}

fn proc_mut(name: &str) -> bool {
    proc_root(name) || name.starts_with("/proc/")
}

pub fn is_dir(name: &str) -> bool {
    if proc_root(name) {
        return true;
    }
    if proc_body(name).is_some() {
        return false;
    }
    if ext2_on() {
        crate::ext2::is_dir(name)
    } else {
        fs().is_dir(name)
    }
}

pub fn exists(name: &str) -> bool {
    if proc_root(name) || proc_body(name).is_some() {
        return true;
    }
    if ext2_on() {
        crate::ext2::exists(name)
    } else {
        fs().exists(name)
    }
}

pub fn size_of(name: &str) -> isize {
    if let Some(text) = proc_body(name) {
        return text.len() as isize;
    }
    if proc_root(name) {
        return 0;
    }
    if ext2_on() {
        crate::ext2::size_of(name)
    } else {
        fs().size_of(name)
    }
}

pub fn nlink_of(name: &str) -> u64 {
    if proc_root(name) {
        return 2;
    }
    if proc_body(name).is_some() {
        return 1;
    }
    if ext2_on() {
        crate::ext2::nlink_of(name)
    } else if fs().is_dir(name) {
        2
    } else {
        1
    }
}

pub fn read_at(name: &str, offset: u64, buf: &mut [u8]) -> isize {
    if let Some(text) = proc_body(name) {
        let bytes = text.as_bytes();
        let start = offset as usize;
        if start >= bytes.len() {
            return 0;
        }
        let n = (bytes.len() - start).min(buf.len());
        buf[..n].copy_from_slice(&bytes[start..start + n]);
        return n as isize;
    }
    if ext2_on() {
        crate::ext2::read_at(name, offset, buf)
    } else {
        fs().read_at(name, offset, buf)
    }
}

pub fn list_dir(name: &str) -> Vec<String> {
    if proc_root(name) {
        return vec!["cpuinfo".into(), "uptime".into()];
    }
    let mut names = if ext2_on() {
        crate::ext2::list_dir(name)
    } else {
        fs().list_dir(name)
    };
    if name == "/" && !names.iter().any(|n| n == "proc") {
        names.push("proc".into());
    }
    names
}

pub fn parent_ok(name: &str) -> Result<(), FsError> {
    if ext2_on() {
        crate::ext2::parent_ok(name)
    } else {
        fs().parent_ok(name)
    }
}

pub fn mkdir(name: &str) -> Result<(), FsError> {
    if proc_mut(name) {
        return Err(if proc_root(name) { FsError::Exist } else { FsError::Perm });
    }
    if ext2_on() {
        crate::ext2::mkdir(name)
    } else {
        fs().mkdir(name)
    }
}

pub fn rmdir(name: &str) -> Result<(), FsError> {
    if proc_root(name) {
        return Err(FsError::NotEmpty);
    }
    if proc_mut(name) {
        return Err(FsError::NotDir);
    }
    if ext2_on() {
        crate::ext2::rmdir(name)
    } else {
        fs().rmdir(name)
    }
}

pub fn unlink(name: &str) -> Result<(), FsError> {
    if proc_mut(name) {
        return Err(FsError::Perm);
    }
    if ext2_on() {
        crate::ext2::unlink(name)
    } else {
        fs().unlink(name)
    }
}

pub fn rename(old: &str, new: &str) -> Result<(), FsError> {
    if proc_mut(old) || proc_mut(new) {
        return Err(FsError::Perm);
    }
    if ext2_on() {
        crate::ext2::rename(old, new)
    } else {
        fs().rename(old, new)
    }
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
    let mut buf = [0u8; PATH_MAX];
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
    let mut buf = [0u8; PATH_MAX];
    match canon(s, &mut buf) {
        Some(len) => f(core::str::from_utf8(&buf[..len]).unwrap_or("")),
        None => default,
    }
}

/// Прочитать файл (путь из user/kernel памяти, игнорирует cwd).
pub fn read_path(path: &[u8], buf: &mut [u8]) -> isize {
    with_name(path, |n| read_at(n, 0, buf), -1)
}

pub fn write_path(path: &[u8], data: &[u8]) -> isize {
    with_name(path, |n| write_canon(n, data), -1)
}

pub fn delete_path(path: &[u8]) -> bool {
    with_name(path, |n| unlink(n).is_ok(), false)
}

pub fn list_index(index: usize, buf: &mut [u8]) -> isize {
    fs().list(index, buf)
}

/// Размер файла по пути (для execve/spawn).
pub fn size_path(path: &[u8]) -> isize {
    with_name(path, |n| size_of(n), -1)
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
    if let Some(text) = proc_body(name) {
        return Some(text.into_bytes());
    }
    if ext2_on() {
        return crate::ext2::read_file(name);
    }
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
    unlink(name).is_ok()
}

/// Создать/перезаписать файл по каноническому имени.
pub fn write_canon(name: &str, data: &[u8]) -> isize {
    if proc_mut(name) {
        return -1;
    }
    if ext2_on() {
        crate::ext2::write_file(name, data)
    } else {
        fs().write(name, data)
    }
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
        // Файл без родителей не создаёт каталоги и сам не появляется.
        assert!(write_path(b"/zd/orphan.txt", b"no") < 0);
        assert!(!fs().is_dir("/zd"));
        assert!(fs().mkdir("/zd").is_ok());
        assert!(fs().mkdir("/zd/sub").is_ok());
        assert_eq!(fs().mkdir("/zd/sub"), Err(FsError::Exist));
        assert!(write_path(b"/zd/sub/f.txt", b"x") > 0);
        assert!(fs().is_dir("/zd"));
        assert!(fs().is_dir("/zd/sub"));
        assert!(!fs().is_dir("/zd/sub/f.txt"));
        let kids = fs().list_dir("/zd");
        assert_eq!(kids.len(), 1);
        assert_eq!(kids[0], "sub");
        let kids = fs().list_dir("/zd/sub");
        assert_eq!(kids.len(), 1);
        assert_eq!(kids[0], "f.txt");
        // Непустой каталог не удаляется. Файл — не каталог.
        assert_eq!(fs().rmdir("/zd"), Err(FsError::NotEmpty));
        assert_eq!(fs().rmdir("/zd/sub/f.txt"), Err(FsError::NotDir));
        assert!(fs().rename("/zd/sub/f.txt", "/zd/g.txt").is_ok());
        assert!(fs().list_dir("/zd/sub").is_empty());
        assert_eq!(fs().list_dir("/zd").len(), 2);
        assert!(delete_path(b"/zd/g.txt"));
        assert!(fs().rmdir("/zd/sub").is_ok());
        assert!(fs().rmdir("/zd").is_ok());
        assert!(!fs().is_dir("/zd"));
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

    #[test_case]
    fn proc_uptime_is_readable() {
        serial_print!("test proc_uptime_is_readable... ");
        assert!(is_dir("/proc"));
        assert!(exists("/proc/uptime"));
        assert!(!is_dir("/proc/uptime"));
        let names = list_dir("/proc");
        assert!(names.iter().any(|n| n == "uptime"));
        assert!(names.iter().any(|n| n == "cpuinfo"));
        assert!(list_dir("/").iter().any(|n| n == "proc"));
        let mut buf = [0u8; 64];
        let n = read_at("/proc/uptime", 0, &mut buf);
        assert!(n > 2, "n {}", n);
        assert!(buf[0].is_ascii_digit());
        assert!(buf[..n as usize].contains(&b' '));
        assert!(read_at("/proc/cpuinfo", 0, &mut buf) > 0);
        assert_eq!(unlink("/proc/uptime"), Err(FsError::Perm));
        assert!(write_canon("/proc/uptime", b"x") < 0);
        serial_println!("[ok]");
    }
}
