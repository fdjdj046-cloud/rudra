//! ext2 только на чтение, поверх блочного слоя.
//!
//! Образ собирает `scripts/mk_ext2.py`: блоки по 1024 байта, одна группа,
//! revision 0 (inode 128 байт, в каталоге `name_len` — это u16). Косвенные
//! блоки не читаем: хватает двенадцати прямых.

use alloc::boxed::Box;
use alloc::vec;
use alloc::vec::Vec;

use crate::block;

const SUPER_OFF: u64 = 1024;
const MAGIC: u16 = 0xEF53;
const INODE_SIZE: usize = 128;
const ROOT_INO: u32 = 2;

struct Super {
    block_size: usize,
    inodes_per_group: u32,
    inode_table: u32,
}

enum ExtError {
    Io,
    Magic,
    Name,
}

pub fn probe() {
    if !block::present() {
        return;
    }
    match Super::load() {
        Ok(sb) => {
            crate::serial_println!(
                "[ext2] magic ok block {} inode-table {}",
                sb.block_size,
                sb.inode_table
            );
            match sb.list_dir(ROOT_INO) {
                Ok(names) => {
                    for name in &names {
                        crate::serial_println!("[ext2] /{}", name);
                    }
                }
                Err(_) => crate::serial_println!("[ext2] root unreadable"),
            }
            match sb.read_path("/hello.txt") {
                Ok(data) => {
                    let text = core::str::from_utf8(&data).unwrap_or("?");
                    crate::serial_println!("[ext2] /hello.txt: {}", text);
                }
                Err(_) => crate::serial_println!("[ext2] /hello.txt missing"),
            }
        }
        Err(ExtError::Magic) => crate::serial_println!("[ext2] no superblock"),
        Err(_) => crate::serial_println!("[ext2] read error"),
    }
}

impl Super {
    fn load() -> Result<Self, ExtError> {
        let mut raw = [0u8; 1024];
        read_at(SUPER_OFF, &mut raw)?;
        let magic = u16_at(&raw, 56);
        if magic != MAGIC {
            return Err(ExtError::Magic);
        }
        let log_block = u32_at(&raw, 24);
        if log_block > 2 {
            return Err(ExtError::Magic);
        }
        let block_size = 1024usize << log_block;
        // Дескриптор группы — сразу после суперблока, в блоке 2 при размере 1024.
        let gdt_off = if block_size == 1024 {
            2048u64
        } else {
            block_size as u64
        };
        let mut gd = [0u8; 32];
        read_at(gdt_off, &mut gd)?;
        let inode_table = u32_at(&gd, 8);
        let inodes_per_group = u32_at(&raw, 40);
        if inodes_per_group == 0 || block_size < 1024 {
            return Err(ExtError::Magic);
        }
        Ok(Super {
            block_size,
            inodes_per_group,
            inode_table,
        })
    }

    fn read_inode(&self, ino: u32) -> Result<Vec<u8>, ExtError> {
        if ino == 0 {
            return Err(ExtError::Name);
        }
        let index = (ino - 1) as usize;
        let group = index / self.inodes_per_group as usize;
        let index_in_group = index % self.inodes_per_group as usize;
        let table = self.inode_table as usize + group * self.inodes_per_group as usize * INODE_SIZE / self.block_size;
        let byte_off = index_in_group * INODE_SIZE;
        let block = table + byte_off / self.block_size;
        let inner = byte_off % self.block_size;
        let mut blk = vec![0u8; self.block_size];
        self.read_fs_block(block as u32, &mut blk)?;
        Ok(blk[inner..inner + INODE_SIZE].to_vec())
    }

    fn read_fs_block(&self, block: u32, buf: &mut [u8]) -> Result<(), ExtError> {
        if buf.len() < self.block_size {
            return Err(ExtError::Io);
        }
        let lba = (block as u64) * (self.block_size as u64 / 512);
        block::read_blocks(lba, &mut buf[..self.block_size]).map_err(|_| ExtError::Io)
    }

    fn list_dir(&self, ino: u32) -> Result<Vec<&'static str>, ExtError> {
        // Имена копируем в статическое хранилище, чтобы не тащить String в лог.
        let data = self.read_file_inode(ino)?;
        let mut names = Vec::new();
        let mut off = 0usize;
        while off + 8 <= data.len() {
            let rec_len = u16_at(&data, off + 4) as usize;
            let name_len = u16_at(&data, off + 6) as usize;
            if rec_len < 8 || off + rec_len > data.len() {
                break;
            }
            if name_len > 0 && off + 8 + name_len <= data.len() {
                let raw = &data[off + 8..off + 8 + name_len];
                if raw != b"." && raw != b".." {
                    if let Ok(s) = core::str::from_utf8(raw) {
                        names.push(leak(s));
                    }
                }
            }
            off += rec_len;
        }
        Ok(names)
    }

    fn read_path(&self, path: &str) -> Result<Vec<u8>, ExtError> {
        let name = path.trim_start_matches('/');
        if name.is_empty() || name.contains('/') {
            return Err(ExtError::Name);
        }
        let root = self.read_file_inode(ROOT_INO)?;
        let mut off = 0usize;
        while off + 8 <= root.len() {
            let file_ino = u32_at(&root, off);
            let rec_len = u16_at(&root, off + 4) as usize;
            let name_len = u16_at(&root, off + 6) as usize;
            if rec_len < 8 || off + rec_len > root.len() {
                break;
            }
            if file_ino != 0 && name_len == name.len() && off + 8 + name_len <= root.len() {
                if &root[off + 8..off + 8 + name_len] == name.as_bytes() {
                    return self.read_file_inode(file_ino);
                }
            }
            off += rec_len;
        }
        Err(ExtError::Name)
    }

    fn read_file_inode(&self, ino: u32) -> Result<Vec<u8>, ExtError> {
        let inode = self.read_inode(ino)?;
        let size = u32_at(&inode, 4) as usize;
        let mut out = vec![0u8; size];
        let mut filled = 0usize;
        for i in 0..12 {
            if filled >= size {
                break;
            }
            let block = u32_at(&inode, 40 + i * 4);
            if block == 0 {
                break;
            }
            let mut blk = vec![0u8; self.block_size];
            self.read_fs_block(block, &mut blk)?;
            let n = (size - filled).min(self.block_size);
            out[filled..filled + n].copy_from_slice(&blk[..n]);
            filled += n;
        }
        Ok(out)
    }
}

fn read_at(offset: u64, buf: &mut [u8]) -> Result<(), ExtError> {
    if buf.is_empty() {
        return Ok(());
    }
    let start = offset / 512;
    let skip = (offset % 512) as usize;
    let need = skip + buf.len();
    let sectors = (need + 511) / 512;
    let mut tmp = vec![0u8; sectors * 512];
    block::read_blocks(start, &mut tmp).map_err(|_| ExtError::Io)?;
    buf.copy_from_slice(&tmp[skip..skip + buf.len()]);
    Ok(())
}

fn u16_at(buf: &[u8], off: usize) -> u16 {
    u16::from_le_bytes([buf[off], buf[off + 1]])
}

fn u32_at(buf: &[u8], off: usize) -> u32 {
    u32::from_le_bytes([buf[off], buf[off + 1], buf[off + 2], buf[off + 3]])
}

fn leak(s: &str) -> &'static str {
    let mut owned = alloc::string::String::from(s);
    owned.push('\0');
    let p = Box::leak(owned.into_boxed_str());
    &p[..p.len() - 1]
}
