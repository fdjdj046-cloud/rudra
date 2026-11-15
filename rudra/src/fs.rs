//! Ramdisk-файловая система rudra (RFS1).
//!
//! Плоское пространство имён ("/имя"), файлы хранятся непрерывно,
//! запись — create-or-replace с bump-аллокацией (старые данные текут,
//! это учебная FS). Таблица в начале региона, данные — с DATA_OFF.
//!
//! Регион живёт в kernel heap (Box утекает), поэтому FS доступна при любом
//! CR3 задач. Все операции под глобальным мьютексом, короткие.

use alloc::boxed::Box;
use alloc::vec;
use spin::{Mutex, Once};

const MAGIC: u32 = 0x3153_4652; // "RFS1"
const MAX_FILES: usize = 64;
const NAME_LEN: usize = 24;
const ENTRY_SIZE: usize = 32; // name[24] + offset u32 + size u32
const TABLE_OFF: usize = 12; // magic + num_files + data_used
const DATA_OFF: usize = 4096;
pub const DISK_SIZE: usize = 256 * 1024;

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

    /// Слот записи: None, если не найдена.
    fn find_slot(&self, name: &str) -> Option<usize> {
        let count = self.num_files().min(MAX_FILES);
        for i in 0..count {
            let base = TABLE_OFF + i * ENTRY_SIZE;
            if self.storage[base] == 0 {
                continue; // удалённая запись
            }
            let entry_name = core::str::from_utf8(&self.storage[base..base + NAME_LEN])
                .unwrap_or("")
                .trim_end_matches('\0');
            if entry_name == name {
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
        if name.is_empty() || name.len() >= NAME_LEN {
            return -1;
        }
        let slot = match self.find_slot(name) {
            Some(s) => s,
            None => return -1,
        };
        let (off, size) = self.entry(slot);
        let start = DATA_OFF + off as usize;
        let n = (size as usize).min(buf.len());
        buf[..n].copy_from_slice(&self.storage[start..start + n]);
        n as isize
    }

    /// Создать или заменить файл. Возвращает размер или -1.
    pub fn write(&mut self, name: &str, data: &[u8]) -> isize {
        if name.is_empty() || name.len() >= NAME_LEN {
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
                let name = &self.storage[base..base + NAME_LEN];
                let len = name.iter().position(|&b| b == 0).unwrap_or(NAME_LEN);
                let n = len.min(buf.len());
                buf[..n].copy_from_slice(&name[..n]);
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
}

/// Привести путь к каноническому виду "/name" в буфере.
/// Возвращает длину канонического имени или None.
fn canon(path: &str, buf: &mut [u8; 32]) -> Option<usize> {
    let p = path.trim_end_matches('\0');
    let full_len = if p.starts_with('/') { p.len() } else { p.len() + 1 };
    if p.is_empty() || full_len >= NAME_LEN {
        return None;
    }
    if p.starts_with('/') {
        buf[..p.len()].copy_from_slice(p.as_bytes());
    } else {
        buf[0] = b'/';
        buf[1..1 + p.len()].copy_from_slice(p.as_bytes());
    }
    Some(full_len)
}

fn with_name<R>(path: &[u8], f: impl FnOnce(&str) -> R, default: R) -> R {
    let s = match core::str::from_utf8(path) {
        Ok(s) => s,
        Err(_) => return default,
    };
    let mut buf = [0u8; 32];
    match canon(s, &mut buf) {
        Some(len) => f(core::str::from_utf8(&buf[..len]).unwrap_or("")),
        None => default,
    }
}

/// Прочитать файл (путь из user/kernel памяти).
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

/// Размер файла по пути (для spawn_path).
pub fn size_path(path: &[u8]) -> isize {
    with_name(path, |n| fs().size_of(n), -1)
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
        assert!(delete_path(b"/test.txt"));
        assert_eq!(read_path(b"/test.txt", &mut buf), -1);
        serial_println!("[ok]");
    }
}
