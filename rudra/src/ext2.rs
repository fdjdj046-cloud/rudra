//! ext2 чтение и запись поверх блочного слоя.
//!
//! Релизный образ: первые 16 МиБ — загрузчик и ядро, дальше файловая система.
//! Отдельный диск, у которого суперблок в байте 1024, тоже монтируется.
//! Одна группа, блоки до 4096, inode 128 или 256, прямой и один косвенный блок.
//! `RFS2` остаётся recovery, если ext2 не найден.

use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;
use spin::Mutex;

use crate::fs::{parent, FsError};

/// Смещение ext2 в общем raw-образе `rudra-1.0.0.img`.
pub const EMBED_OFF: u64 = 16 * 1024 * 1024;

const FILETYPE: u32 = 0x2;
const EXT2_FT_REG: u8 = 1;
const EXT2_FT_DIR: u8 = 2;
const ROOT_INO: u32 = 2;

struct Vol {
    off: u64,
    block_size: usize,
    blocks_count: u32,
    inodes_count: u32,
    free_blocks: u32,
    free_inodes: u32,
    _blocks_per_group: u32,
    _inodes_per_group: u32,
    inode_size: usize,
    first_ino: u32,
    filetype: bool,
    block_bitmap: u32,
    inode_bitmap: u32,
    inode_table: u32,
    used_dirs: u16,
    bb: Vec<u8>,
    ib: Vec<u8>,
    sb: Vec<u8>,
    gd: Vec<u8>,
}

static EXT2: Mutex<Option<Vol>> = Mutex::new(None);

pub fn mounted() -> bool {
    EXT2.lock().is_some()
}

pub fn sync() {
    let _ = with_vol(|v| v.flush());
}

/// Найти суперблок и проверить, что запись блока не задевает соседний.
pub fn mount() {
    let bytes = crate::block::sector_count().saturating_mul(512);
    let mut last_err = "no superblock";
    for off in [EMBED_OFF, 0u64] {
        if off != 0 && off + 4096 > bytes {
            continue;
        }
        match Vol::open(off, bytes) {
            Ok(vol) => {
                let max_file = (12 + vol.block_size / 4) * vol.block_size;
                crate::serial_println!(
                    "[ext2] mounted off {:#x} block {} blocks {} inodes {} free {} file-max {}",
                    vol.off,
                    vol.block_size,
                    vol.blocks_count,
                    vol.inodes_count,
                    vol.free_blocks,
                    max_file
                );
                *EXT2.lock() = Some(vol);
                crate::serial_println!("[root] ext2 on virtio-blk");
                return;
            }
            Err(e) => last_err = e,
        }
    }
    crate::serial_println!("[ext2] {}", last_err);
    crate::serial_println!("[root] recovery ramdisk");
}

fn with_vol<R>(f: impl FnOnce(&mut Vol) -> R) -> Option<R> {
    x86_64::instructions::interrupts::without_interrupts(|| {
        let mut g = EXT2.lock();
        g.as_mut().map(f)
    })
}

pub fn is_dir(path: &str) -> bool {
    with_vol(|v| match v.lookup(path) {
        Ok(ino) => v.is_dir_ino(ino).unwrap_or(false),
        Err(_) => false,
    })
    .unwrap_or(false)
}

pub fn exists(path: &str) -> bool {
    with_vol(|v| v.lookup(path).is_ok()).unwrap_or(false)
}

pub fn size_of(path: &str) -> isize {
    with_vol(|v| {
        let ino = v.lookup(path).ok()?;
        if v.is_dir_ino(ino).unwrap_or(true) {
            return None;
        }
        let inode = v.read_inode(ino).ok()?;
        Some(get_u32(&inode, 4) as isize)
    })
    .flatten()
    .unwrap_or(-1)
}

pub fn nlink_of(path: &str) -> u64 {
    with_vol(|v| {
        let ino = v.lookup(path).ok()?;
        let inode = v.read_inode(ino).ok()?;
        Some(get_u16(&inode, 26) as u64)
    })
    .flatten()
    .unwrap_or(1)
}

pub fn read_at(path: &str, offset: u64, buf: &mut [u8]) -> isize {
    match with_vol(|v| v.read_path(path, offset, buf)) {
        Some(Ok(n)) => n as isize,
        _ => -1,
    }
}

pub fn read_file(path: &str) -> Option<Vec<u8>> {
    with_vol(|v| {
        let ino = v.lookup(path).ok()?;
        if v.is_dir_ino(ino).unwrap_or(true) {
            return None;
        }
        let inode = v.read_inode(ino).ok()?;
        let size = get_u32(&inode, 4) as usize;
        let mut buf = vec![0u8; size];
        if size == 0 {
            return Some(buf);
        }
        match v.read_ino(ino, 0, &mut buf) {
            Ok(n) if n == size => Some(buf),
            _ => None,
        }
    })
    .flatten()
}

pub fn write_file(path: &str, data: &[u8]) -> isize {
    match with_vol(|v| v.write_file_at(path, data)) {
        Some(Ok(())) => data.len() as isize,
        Some(Err(e)) => {
            crate::serial_println!("[ext2] write {} failed ({:?})", path, e);
            -1
        }
        None => -1,
    }
}

pub fn list_dir(path: &str) -> Vec<String> {
    with_vol(|v| v.list(path).unwrap_or_default()).unwrap_or_default()
}

pub fn parent_ok(path: &str) -> Result<(), FsError> {
    with_vol(|v| v.parent_ok(path)).unwrap_or(Err(FsError::Io))
}

pub fn mkdir(path: &str) -> Result<(), FsError> {
    with_vol(|v| v.mkdir_at(path)).unwrap_or(Err(FsError::Io))
}

pub fn rmdir(path: &str) -> Result<(), FsError> {
    with_vol(|v| v.rmdir_at(path)).unwrap_or(Err(FsError::Io))
}

pub fn unlink(path: &str) -> Result<(), FsError> {
    with_vol(|v| v.unlink_at(path)).unwrap_or(Err(FsError::Io))
}

pub fn rename(old: &str, new: &str) -> Result<(), FsError> {
    with_vol(|v| v.rename_at(old, new)).unwrap_or(Err(FsError::Io))
}

impl Vol {
    fn open(off: u64, disk_bytes: u64) -> Result<Self, &'static str> {
        let mut sb = vec![0u8; 1024];
        read_abs(off + 1024, &mut sb).map_err(|_| "super read")?;
        if get_u16(&sb, 56) != 0xEF53 {
            return Err("no superblock");
        }
        let log_block = get_u32(&sb, 24);
        if log_block > 2 {
            return Err("block size");
        }
        let block_size = 1024usize << log_block;
        let blocks_count = get_u32(&sb, 4);
        let inodes_count = get_u32(&sb, 0);
        let blocks_per_group = get_u32(&sb, 32);
        let inodes_per_group = get_u32(&sb, 40);
        if blocks_count == 0 || inodes_count == 0 || blocks_per_group == 0 || inodes_per_group == 0
        {
            return Err("empty fs");
        }
        let fs_bytes = blocks_count as u64 * block_size as u64;
        if off.saturating_add(fs_bytes) > disk_bytes {
            return Err("fs past disk");
        }
        let rev = get_u32(&sb, 76);
        if rev > 1 {
            return Err("rev");
        }
        let (inode_size, first_ino) = if rev == 0 {
            (128usize, 11u32)
        } else {
            (get_u16(&sb, 88) as usize, get_u32(&sb, 84))
        };
        if inode_size < 128 || inode_size > 256 || inode_size % 4 != 0 {
            return Err("inode size");
        }
        let incompat = get_u32(&sb, 96);
        if incompat & !FILETYPE != 0 {
            return Err("incompat feature");
        }
        if get_u32(&sb, 100) != 0 {
            return Err("ro feature");
        }
        let groups = blocks_count.div_ceil(blocks_per_group);
        let igroups = inodes_count.div_ceil(inodes_per_group);
        if groups != 1 || igroups != 1 {
            return Err("only one group");
        }
        let mut gd = vec![0u8; 32];
        // 1024: суперблок — блок 1, таблица групп — блок 2.
        // 2048 и 4096: суперблок внутри блока 0, таблица групп — следующий блок.
        read_abs(gdt_byte(off, block_size), &mut gd).map_err(|_| "gdt read")?;
        let block_bitmap = get_u32(&gd, 0);
        let inode_bitmap = get_u32(&gd, 4);
        let inode_table = get_u32(&gd, 8);
        if block_bitmap == 0 || inode_bitmap == 0 || inode_table == 0 {
            return Err("group desc");
        }
        let mut bb = vec![0u8; block_size];
        let mut ib = vec![0u8; block_size];
        read_abs(off + block_bitmap as u64 * block_size as u64, &mut bb).map_err(|_| "bitmap")?;
        read_abs(off + inode_bitmap as u64 * block_size as u64, &mut ib).map_err(|_| "ibitmap")?;
        let mut vol = Vol {
            off,
            block_size,
            blocks_count,
            inodes_count,
            free_blocks: 0,
            free_inodes: 0,
            _blocks_per_group: blocks_per_group,
            _inodes_per_group: inodes_per_group,
            inode_size,
            first_ino,
            filetype: incompat & FILETYPE != 0,
            block_bitmap,
            inode_bitmap,
            inode_table,
            used_dirs: get_u16(&gd, 16),
            bb,
            ib,
            sb,
            gd,
        };
        vol.recount();
        vol.write_check().map_err(|_| "write check")?;
        Ok(vol)
    }

    fn recount(&mut self) {
        let mut blocks = 0u32;
        for b in 0..self.blocks_count {
            if !bit(&self.bb, b) {
                blocks += 1;
            }
        }
        let mut inodes = 0u32;
        for i in 0..self.inodes_count {
            if !bit(&self.ib, i) {
                inodes += 1;
            }
        }
        self.free_blocks = blocks;
        self.free_inodes = inodes;
    }

    fn ptrs(&self) -> u32 {
        (self.block_size / 4) as u32
    }

    fn read_block(&self, block: u32, buf: &mut [u8]) -> Result<(), FsError> {
        if block >= self.blocks_count || buf.len() < self.block_size {
            return Err(FsError::Io);
        }
        let byte = self.off + block as u64 * self.block_size as u64;
        read_abs(byte, &mut buf[..self.block_size])
    }

    fn write_block(&self, block: u32, buf: &[u8]) -> Result<(), FsError> {
        if block >= self.blocks_count || buf.len() < self.block_size {
            return Err(FsError::Io);
        }
        let byte = self.off + block as u64 * self.block_size as u64;
        write_abs(byte, &buf[..self.block_size])
    }

    fn write_check(&mut self) -> Result<(), FsError> {
        let bb = self.bb.clone();
        let ib = self.ib.clone();
        let free = self.free_blocks;
        let b = self.alloc_block()?;
        let neighbor = b.saturating_add(1);
        let mut nb = vec![0u8; self.block_size];
        let have_neighbor = neighbor < self.blocks_count;
        if have_neighbor {
            self.read_block(neighbor, &mut nb)?;
        }
        let mut pat = vec![0u8; self.block_size];
        for (i, p) in pat.iter_mut().enumerate() {
            *p = (i as u8).wrapping_mul(17).wrapping_add(0xA5);
        }
        self.write_block(b, &pat)?;
        let mut got = vec![0u8; self.block_size];
        self.read_block(b, &mut got)?;
        if got != pat {
            return Err(FsError::Io);
        }
        if have_neighbor {
            let mut after = vec![0u8; self.block_size];
            self.read_block(neighbor, &mut after)?;
            if after != nb {
                return Err(FsError::Io);
            }
        }
        self.free_block(b);
        if self.bb != bb || self.ib != ib || self.free_blocks != free {
            return Err(FsError::Io);
        }
        self.flush()?;
        crate::serial_println!("[ext2] block write check ok");
        Ok(())
    }

    fn flush(&mut self) -> Result<(), FsError> {
        put_u32(&mut self.sb, 12, self.free_blocks);
        put_u32(&mut self.sb, 16, self.free_inodes);
        put_u16(&mut self.sb, 58, 1);
        put_u16(&mut self.gd, 12, self.free_blocks as u16);
        put_u16(&mut self.gd, 14, self.free_inodes as u16);
        put_u16(&mut self.gd, 16, self.used_dirs);
        write_abs(self.off + 1024, &self.sb)?;
        write_abs(gdt_byte(self.off, self.block_size), &self.gd)?;
        self.write_block(self.block_bitmap, &self.bb)?;
        self.write_block(self.inode_bitmap, &self.ib)?;
        Ok(())
    }

    fn alloc_block(&mut self) -> Result<u32, FsError> {
        for b in 0..self.blocks_count {
            if !bit(&self.bb, b) {
                set_bit(&mut self.bb, b, true);
                self.free_blocks = self.free_blocks.saturating_sub(1);
                return Ok(b);
            }
        }
        Err(FsError::NoSpc)
    }

    fn free_block(&mut self, b: u32) {
        if b == 0 || b >= self.blocks_count {
            return;
        }
        if bit(&self.bb, b) {
            set_bit(&mut self.bb, b, false);
            self.free_blocks = self.free_blocks.saturating_add(1);
        }
    }

    fn alloc_ino(&mut self) -> Result<u32, FsError> {
        let start = self.first_ino.max(1);
        for ino in start..=self.inodes_count {
            let bit_i = ino - 1;
            if !bit(&self.ib, bit_i) {
                set_bit(&mut self.ib, bit_i, true);
                self.free_inodes = self.free_inodes.saturating_sub(1);
                return Ok(ino);
            }
        }
        Err(FsError::NoSpc)
    }

    fn free_ino(&mut self, ino: u32) {
        if ino < self.first_ino || ino > self.inodes_count {
            return;
        }
        let bit_i = ino - 1;
        if bit(&self.ib, bit_i) {
            set_bit(&mut self.ib, bit_i, false);
            self.free_inodes = self.free_inodes.saturating_add(1);
        }
    }

    fn read_inode(&self, ino: u32) -> Result<Vec<u8>, FsError> {
        if ino == 0 || ino > self.inodes_count {
            return Err(FsError::NoEnt);
        }
        let index = (ino - 1) as usize;
        let per = self.block_size / self.inode_size;
        if per == 0 {
            return Err(FsError::Io);
        }
        let block = self.inode_table as usize + index / per;
        let inner = (index % per) * self.inode_size;
        let mut blk = vec![0u8; self.block_size];
        self.read_block(block as u32, &mut blk)?;
        let mut out = vec![0u8; 128];
        let n = 128.min(self.inode_size);
        out[..n].copy_from_slice(&blk[inner..inner + n]);
        Ok(out)
    }

    fn write_inode(&self, ino: u32, inode: &[u8]) -> Result<(), FsError> {
        if ino == 0 || ino > self.inodes_count || inode.len() < 128 {
            return Err(FsError::Io);
        }
        let index = (ino - 1) as usize;
        let per = self.block_size / self.inode_size;
        let block = self.inode_table as usize + index / per;
        let inner = (index % per) * self.inode_size;
        let mut blk = vec![0u8; self.block_size];
        self.read_block(block as u32, &mut blk)?;
        let n = 128.min(self.inode_size);
        blk[inner..inner + n].copy_from_slice(&inode[..n]);
        self.write_block(block as u32, &blk)
    }

    fn is_dir_ino(&self, ino: u32) -> Result<bool, FsError> {
        let inode = self.read_inode(ino)?;
        Ok(get_u16(&inode, 0) & 0xF000 == 0x4000)
    }

    fn map_block(&self, inode: &[u8], iblock: u32) -> Result<u32, FsError> {
        if iblock < 12 {
            return Ok(get_u32(inode, 40 + iblock as usize * 4));
        }
        let idx = iblock - 12;
        if idx >= self.ptrs() {
            return Err(FsError::NoSpc);
        }
        let sib = get_u32(inode, 40 + 48);
        if sib == 0 {
            return Ok(0);
        }
        let mut blk = vec![0u8; self.block_size];
        self.read_block(sib, &mut blk)?;
        Ok(get_u32(&blk, idx as usize * 4))
    }

    fn read_ino(&self, ino: u32, offset: u64, buf: &mut [u8]) -> Result<usize, FsError> {
        let inode = self.read_inode(ino)?;
        let size = get_u32(&inode, 4) as u64;
        if offset >= size || buf.is_empty() {
            return Ok(0);
        }
        let want = ((size - offset) as usize).min(buf.len());
        let mut sib_cache: Option<(u32, Vec<u8>)> = None;
        let mut done = 0usize;
        while done < want {
            let pos = offset + done as u64;
            let iblock = (pos / self.block_size as u64) as u32;
            let inner = (pos % self.block_size as u64) as usize;
            let disk = self.map_cached(&inode, iblock, &mut sib_cache)?;
            let n = (self.block_size - inner).min(want - done);
            if disk == 0 {
                buf[done..done + n].fill(0);
            } else {
                let mut blk = vec![0u8; self.block_size];
                self.read_block(disk, &mut blk)?;
                buf[done..done + n].copy_from_slice(&blk[inner..inner + n]);
            }
            done += n;
        }
        Ok(done)
    }

    fn map_cached(
        &self,
        inode: &[u8],
        iblock: u32,
        cache: &mut Option<(u32, Vec<u8>)>,
    ) -> Result<u32, FsError> {
        if iblock < 12 {
            return Ok(get_u32(inode, 40 + iblock as usize * 4));
        }
        let idx = iblock - 12;
        if idx >= self.ptrs() {
            return Err(FsError::NoSpc);
        }
        let sib = get_u32(inode, 40 + 48);
        if sib == 0 {
            return Ok(0);
        }
        if cache.as_ref().map(|(n, _)| *n) != Some(sib) {
            let mut blk = vec![0u8; self.block_size];
            self.read_block(sib, &mut blk)?;
            *cache = Some((sib, blk));
        }
        let buf = &cache.as_ref().unwrap().1;
        Ok(get_u32(buf, idx as usize * 4))
    }

    fn read_path(&self, path: &str, offset: u64, buf: &mut [u8]) -> Result<usize, FsError> {
        let ino = self.lookup(path)?;
        if self.is_dir_ino(ino)? {
            return Err(FsError::IsDir);
        }
        self.read_ino(ino, offset, buf)
    }

    fn lookup(&self, path: &str) -> Result<u32, FsError> {
        if path.is_empty() {
            return Err(FsError::NoEnt);
        }
        if path == "/" {
            return Ok(ROOT_INO);
        }
        let mut ino = ROOT_INO;
        for comp in path.split('/').filter(|c| !c.is_empty()) {
            if !self.is_dir_ino(ino)? {
                return Err(FsError::NotDir);
            }
            ino = self.find_in_dir(ino, comp)?.ok_or(FsError::NoEnt)?;
        }
        Ok(ino)
    }

    fn parent_ok(&self, path: &str) -> Result<(), FsError> {
        if path == "/" {
            return Ok(());
        }
        let (dir, name) = split(path)?;
        if name.is_empty() {
            return Err(FsError::Inval);
        }
        match self.lookup(dir) {
            Ok(ino) if self.is_dir_ino(ino)? => Ok(()),
            Ok(_) => Err(FsError::NotDir),
            Err(FsError::NoEnt) => Err(FsError::NoEnt),
            Err(e) => Err(e),
        }
    }

    fn name_len(&self, block: &[u8], off: usize) -> usize {
        if self.filetype {
            block[off + 6] as usize
        } else {
            get_u16(block, off + 6) as usize
        }
    }

    fn walk_dir(
        &self,
        dir: u32,
        mut f: impl FnMut(&[u8], usize, usize, u32) -> Result<bool, FsError>,
    ) -> Result<(), FsError> {
        let inode = self.read_inode(dir)?;
        let size = get_u32(&inode, 4) as usize;
        let mut off = 0usize;
        while off + 8 <= size {
            let ib = (off / self.block_size) as u32;
            let disk = self.map_block(&inode, ib)?;
            if disk == 0 {
                return Err(FsError::Io);
            }
            let mut block = vec![0u8; self.block_size];
            self.read_block(disk, &mut block)?;
            let base = ib as usize * self.block_size;
            let mut local = off % self.block_size;
            while local + 8 <= self.block_size {
                let rec = get_u16(&block, local + 4) as usize;
                if rec < 8 || local + rec > self.block_size {
                    return Err(FsError::Io);
                }
                let ino = get_u32(&block, local);
                if f(&block, local, rec, ino)? {
                    return Ok(());
                }
                local += rec;
                off = base + local;
                if off >= size {
                    return Ok(());
                }
            }
        }
        Ok(())
    }

    fn find_in_dir(&self, dir: u32, name: &str) -> Result<Option<u32>, FsError> {
        let mut found = None;
        self.walk_dir(dir, |block, local, rec, ino| {
            if ino == 0 {
                return Ok(false);
            }
            let nl = self.name_len(block, local).min(rec.saturating_sub(8));
            if local + 8 + nl > block.len() {
                return Err(FsError::Io);
            }
            if &block[local + 8..local + 8 + nl] == name.as_bytes() {
                found = Some(ino);
                return Ok(true);
            }
            Ok(false)
        })?;
        Ok(found)
    }

    fn list(&self, path: &str) -> Result<Vec<String>, FsError> {
        let ino = self.lookup(path)?;
        if !self.is_dir_ino(ino)? {
            return Ok(Vec::new());
        }
        let mut names = Vec::new();
        self.walk_dir(ino, |block, local, rec, child| {
            if child == 0 {
                return Ok(false);
            }
            let nl = self.name_len(block, local).min(rec.saturating_sub(8));
            if local + 8 + nl > block.len() {
                return Ok(false);
            }
            let raw = &block[local + 8..local + 8 + nl];
            if raw != b"." && raw != b".." {
                if let Ok(s) = core::str::from_utf8(raw) {
                    names.push(String::from(s));
                }
            }
            Ok(false)
        })?;
        Ok(names)
    }

    fn dir_empty(&self, dir: u32) -> Result<bool, FsError> {
        let mut empty = true;
        self.walk_dir(dir, |block, local, rec, ino| {
            if ino == 0 {
                return Ok(false);
            }
            let nl = self.name_len(block, local).min(rec.saturating_sub(8));
            let raw = &block[local + 8..local + 8 + nl];
            if raw != b"." && raw != b".." {
                empty = false;
                return Ok(true);
            }
            Ok(false)
        })?;
        Ok(empty)
    }

    fn store_dirent(&self, block: &mut [u8], off: usize, rec: usize, ino: u32, name: &str, ft: u8) {
        put_u32(block, off, ino);
        put_u16(block, off + 4, rec as u16);
        let nb = name.as_bytes();
        if self.filetype {
            block[off + 6] = nb.len() as u8;
            block[off + 7] = ft;
        } else {
            put_u16(block, off + 6, nb.len() as u16);
        }
        let start = off + 8;
        block[start..start + nb.len()].copy_from_slice(nb);
        for b in &mut block[start + nb.len()..off + rec] {
            *b = 0;
        }
    }

    fn add_dirent(&mut self, dir: u32, child: u32, name: &str, ft: u8) -> Result<(), FsError> {
        let need = (8 + name.len() + 3) & !3;
        let mut inode = self.read_inode(dir)?;
        let size = get_u32(&inode, 4) as usize;
        let mut off = 0usize;
        while off + 8 <= size {
            let ib = (off / self.block_size) as u32;
            let disk = self.map_block(&inode, ib)?;
            if disk == 0 {
                return Err(FsError::Io);
            }
            let mut block = vec![0u8; self.block_size];
            self.read_block(disk, &mut block)?;
            let base = ib as usize * self.block_size;
            let mut local = off % self.block_size;
            while local + 8 <= self.block_size {
                let rec = get_u16(&block, local + 4) as usize;
                if rec < 8 || local + rec > self.block_size {
                    return Err(FsError::Io);
                }
                let ino = get_u32(&block, local);
                let nl = self.name_len(&block, local).min(rec.saturating_sub(8));
                let ideal = (8 + nl + 3) & !3;
                if ino == 0 && rec >= need {
                    self.store_dirent(&mut block, local, rec, child, name, ft);
                    return self.write_block(disk, &block);
                }
                if ino != 0 && rec >= ideal + need {
                    put_u16(&mut block, local + 4, ideal as u16);
                    self.store_dirent(&mut block, local + ideal, rec - ideal, child, name, ft);
                    return self.write_block(disk, &block);
                }
                local += rec;
                off = base + local;
                if off >= size {
                    break;
                }
            }
        }
        let ib = (size / self.block_size) as u32;
        if ib >= 12 {
            return Err(FsError::NoSpc);
        }
        let b = self.alloc_block()?;
        let mut block = vec![0u8; self.block_size];
        self.store_dirent(&mut block, 0, self.block_size, child, name, ft);
        self.write_block(b, &block)?;
        put_u32(&mut inode, 40 + ib as usize * 4, b);
        put_u32(&mut inode, 4, (size + self.block_size) as u32);
        let sectors = get_u32(&inode, 28) + (self.block_size / 512) as u32;
        put_u32(&mut inode, 28, sectors);
        self.write_inode(dir, &inode)
    }

    fn remove_dirent(&mut self, dir: u32, name: &str) -> Result<(), FsError> {
        let inode = self.read_inode(dir)?;
        let size = get_u32(&inode, 4) as usize;
        let mut off = 0usize;
        while off + 8 <= size {
            let ib = (off / self.block_size) as u32;
            let disk = self.map_block(&inode, ib)?;
            let mut block = vec![0u8; self.block_size];
            self.read_block(disk, &mut block)?;
            let base = ib as usize * self.block_size;
            let mut local = off % self.block_size;
            let mut prev: Option<usize> = None;
            while local + 8 <= self.block_size {
                let rec = get_u16(&block, local + 4) as usize;
                if rec < 8 || local + rec > self.block_size {
                    return Err(FsError::Io);
                }
                let ino = get_u32(&block, local);
                let nl = self.name_len(&block, local).min(rec.saturating_sub(8));
                let raw = if ino != 0 && local + 8 + nl <= block.len() {
                    &block[local + 8..local + 8 + nl]
                } else {
                    &[]
                };
                if ino != 0 && raw == name.as_bytes() {
                    if let Some(p) = prev {
                        let pr = get_u16(&block, p + 4) as usize;
                        put_u16(&mut block, p + 4, (pr + rec) as u16);
                    } else {
                        put_u32(&mut block, local, 0);
                    }
                    return self.write_block(disk, &block);
                }
                prev = Some(local);
                local += rec;
                off = base + local;
                if off >= size {
                    break;
                }
            }
        }
        Err(FsError::NoEnt)
    }

    fn free_tree(&mut self, inode: &mut [u8]) -> Result<(), FsError> {
        for i in 0..12 {
            let b = get_u32(inode, 40 + i * 4);
            if b != 0 {
                self.free_block(b);
                put_u32(inode, 40 + i * 4, 0);
            }
        }
        let sib = get_u32(inode, 40 + 48);
        if sib != 0 {
            let mut blk = vec![0u8; self.block_size];
            self.read_block(sib, &mut blk)?;
            let n = self.ptrs() as usize;
            for i in 0..n {
                let b = get_u32(&blk, i * 4);
                if b != 0 {
                    self.free_block(b);
                }
            }
            self.free_block(sib);
            put_u32(inode, 40 + 48, 0);
        }
        let dib = get_u32(inode, 40 + 52);
        if dib != 0 {
            let mut top = vec![0u8; self.block_size];
            self.read_block(dib, &mut top)?;
            let n = self.ptrs() as usize;
            for i in 0..n {
                let sib = get_u32(&top, i * 4);
                if sib == 0 {
                    continue;
                }
                let mut blk = vec![0u8; self.block_size];
                self.read_block(sib, &mut blk)?;
                for j in 0..n {
                    let b = get_u32(&blk, j * 4);
                    if b != 0 {
                        self.free_block(b);
                    }
                }
                self.free_block(sib);
            }
            self.free_block(dib);
            put_u32(inode, 40 + 52, 0);
        }
        Ok(())
    }

    fn write_data(&mut self, ino: u32, data: &[u8]) -> Result<(), FsError> {
        let mut inode = self.read_inode(ino)?;
        self.free_tree(&mut inode)?;
        let bs = self.block_size;
        let nblocks = if data.is_empty() {
            0
        } else {
            (data.len() + bs - 1) / bs
        };
        if nblocks > 12 + self.ptrs() as usize {
            self.write_inode(ino, &inode)?;
            return Err(FsError::NoSpc);
        }
        let mut indirect: Option<(u32, Vec<u8>)> = None;
        let mut allocated = 0u32;
        for i in 0..nblocks {
            let b = match self.alloc_block() {
                Ok(b) => b,
                Err(e) => {
                    self.free_tree(&mut inode)?;
                    put_u32(&mut inode, 4, 0);
                    put_u32(&mut inode, 28, 0);
                    self.write_inode(ino, &inode)?;
                    return Err(e);
                }
            };
            allocated += 1;
            let mut blk = vec![0u8; bs];
            let start = i * bs;
            let end = (start + bs).min(data.len());
            blk[..end - start].copy_from_slice(&data[start..end]);
            self.write_block(b, &blk)?;
            if i < 12 {
                put_u32(&mut inode, 40 + i * 4, b);
            } else if indirect.is_none() {
                let ib = match self.alloc_block() {
                    Ok(ib) => ib,
                    Err(e) => {
                        self.free_tree(&mut inode)?;
                        self.free_block(b);
                        put_u32(&mut inode, 4, 0);
                        put_u32(&mut inode, 28, 0);
                        self.write_inode(ino, &inode)?;
                        return Err(e);
                    }
                };
                allocated += 1;
                put_u32(&mut inode, 40 + 48, ib);
                let mut buf = vec![0u8; bs];
                put_u32(&mut buf, (i - 12) * 4, b);
                indirect = Some((ib, buf));
            } else if let Some((_, buf)) = indirect.as_mut() {
                put_u32(buf, (i - 12) * 4, b);
            }
        }
        if let Some((ib, buf)) = indirect {
            self.write_block(ib, &buf)?;
        }
        put_u32(&mut inode, 4, data.len() as u32);
        put_u32(&mut inode, 28, allocated * (bs as u32 / 512));
        if get_u16(&inode, 0) == 0 {
            put_u16(&mut inode, 0, 0x81A4);
        }
        if get_u16(&inode, 26) == 0 {
            put_u16(&mut inode, 26, 1);
        }
        put_u32(&mut inode, 20, 0);
        self.write_inode(ino, &inode)
    }

    fn write_file_at(&mut self, path: &str, data: &[u8]) -> Result<(), FsError> {
        if path == "/" {
            return Err(FsError::IsDir);
        }
        let (dir, name) = split(path)?;
        let pino = self.lookup(dir)?;
        if !self.is_dir_ino(pino)? {
            return Err(FsError::NotDir);
        }
        let ino = if let Some(ino) = self.find_in_dir(pino, name)? {
            if self.is_dir_ino(ino)? {
                return Err(FsError::IsDir);
            }
            ino
        } else {
            let ino = self.alloc_ino()?;
            let mut fresh = vec![0u8; 128];
            put_u16(&mut fresh, 0, 0x81A4);
            put_u16(&mut fresh, 26, 1);
            self.write_inode(ino, &fresh)?;
            if let Err(e) = self.add_dirent(pino, ino, name, EXT2_FT_REG) {
                self.free_ino(ino);
                return Err(e);
            }
            ino
        };
        self.write_data(ino, data)?;
        self.flush()
    }

    fn mkdir_at(&mut self, path: &str) -> Result<(), FsError> {
        if path.is_empty() || path == "/" {
            return Err(FsError::Inval);
        }
        let (dir, name) = split(path)?;
        if name == "." || name == ".." {
            return Err(FsError::Inval);
        }
        let pino = self.lookup(dir)?;
        if !self.is_dir_ino(pino)? {
            return Err(FsError::NotDir);
        }
        if self.find_in_dir(pino, name)?.is_some() {
            return Err(FsError::Exist);
        }
        let ino = self.alloc_ino()?;
        let block = self.alloc_block()?;
        let mut db = vec![0u8; self.block_size];
        let dot = (8 + 1 + 3) & !3;
        self.store_dirent(&mut db, 0, dot, ino, ".", EXT2_FT_DIR);
        self.store_dirent(
            &mut db,
            dot,
            self.block_size - dot,
            pino,
            "..",
            EXT2_FT_DIR,
        );
        self.write_block(block, &db)?;
        let mut inode = vec![0u8; 128];
        put_u16(&mut inode, 0, 0x41ED);
        put_u32(&mut inode, 4, self.block_size as u32);
        put_u16(&mut inode, 26, 2);
        put_u32(&mut inode, 28, (self.block_size / 512) as u32);
        put_u32(&mut inode, 40, block);
        self.write_inode(ino, &inode)?;
        if let Err(e) = self.add_dirent(pino, ino, name, EXT2_FT_DIR) {
            self.free_block(block);
            self.free_ino(ino);
            return Err(e);
        }
        self.bump_links(pino, 1)?;
        self.used_dirs = self.used_dirs.saturating_add(1);
        self.flush()
    }

    fn bump_links(&mut self, ino: u32, delta: i32) -> Result<(), FsError> {
        let mut inode = self.read_inode(ino)?;
        let mut n = get_u16(&inode, 26) as i32 + delta;
        if n < 0 {
            n = 0;
        }
        put_u16(&mut inode, 26, n as u16);
        self.write_inode(ino, &inode)
    }

    fn unlink_at(&mut self, path: &str) -> Result<(), FsError> {
        if path == "/" {
            return Err(FsError::Perm);
        }
        let (dir, name) = split(path)?;
        if name == "." || name == ".." {
            return Err(FsError::Inval);
        }
        let pino = self.lookup(dir)?;
        let ino = self.find_in_dir(pino, name)?.ok_or(FsError::NoEnt)?;
        if self.is_dir_ino(ino)? {
            return Err(FsError::IsDir);
        }
        self.remove_dirent(pino, name)?;
        let mut inode = self.read_inode(ino)?;
        let mut links = get_u16(&inode, 26);
        if links > 0 {
            links -= 1;
        }
        put_u16(&mut inode, 26, links);
        if links == 0 {
            self.free_tree(&mut inode)?;
            for b in inode.iter_mut() {
                *b = 0;
            }
            put_u32(&mut inode, 20, 1);
            self.write_inode(ino, &inode)?;
            self.free_ino(ino);
        } else {
            self.write_inode(ino, &inode)?;
        }
        self.flush()
    }

    fn rmdir_at(&mut self, path: &str) -> Result<(), FsError> {
        if path == "/" {
            return Err(FsError::Perm);
        }
        let (dir, name) = split(path)?;
        if name == "." || name == ".." {
            return Err(FsError::Inval);
        }
        let pino = self.lookup(dir)?;
        let Some(ino) = self.find_in_dir(pino, name)? else {
            return Err(FsError::NoEnt);
        };
        if !self.is_dir_ino(ino)? {
            return Err(FsError::NotDir);
        }
        if !self.dir_empty(ino)? {
            return Err(FsError::NotEmpty);
        }
        self.remove_dirent(pino, name)?;
        let mut inode = self.read_inode(ino)?;
        self.free_tree(&mut inode)?;
        for b in inode.iter_mut() {
            *b = 0;
        }
        put_u32(&mut inode, 20, 1);
        self.write_inode(ino, &inode)?;
        self.free_ino(ino);
        self.bump_links(pino, -1)?;
        self.used_dirs = self.used_dirs.saturating_sub(1);
        self.flush()
    }

    fn set_dotdot(&mut self, dir: u32, parent: u32) -> Result<(), FsError> {
        let inode = self.read_inode(dir)?;
        let disk = self.map_block(&inode, 0)?;
        if disk == 0 {
            return Err(FsError::Io);
        }
        let mut block = vec![0u8; self.block_size];
        self.read_block(disk, &mut block)?;
        let mut local = 0usize;
        while local + 8 <= self.block_size {
            let rec = get_u16(&block, local + 4) as usize;
            if rec < 8 || local + rec > self.block_size {
                break;
            }
            let nl = self.name_len(&block, local).min(rec.saturating_sub(8));
            if &block[local + 8..local + 8 + nl] == b".." {
                put_u32(&mut block, local, parent);
                return self.write_block(disk, &block);
            }
            local += rec;
        }
        Err(FsError::Io)
    }

    fn rename_at(&mut self, old: &str, new: &str) -> Result<(), FsError> {
        if old == new {
            return Ok(());
        }
        if old == "/" || new == "/" || old.is_empty() || new.is_empty() {
            return Err(FsError::Inval);
        }
        let (op, oname) = split(old)?;
        let (np, nname) = split(new)?;
        if matches!(oname, "." | "..") || matches!(nname, "." | "..") {
            return Err(FsError::Inval);
        }
        let old_ino = self.lookup(old)?;
        let old_dir = self.is_dir_ino(old_ino)?;
        if old_dir && (new == old || new.starts_with(&alloc::format!("{}/", old))) {
            return Err(FsError::Inval);
        }
        let npino = self.lookup(np)?;
        if !self.is_dir_ino(npino)? {
            return Err(FsError::NotDir);
        }
        let opino = self.lookup(op)?;
        if let Some(dest) = self.find_in_dir(npino, nname)? {
            if dest == old_ino {
                return Ok(());
            }
            let dest_dir = self.is_dir_ino(dest)?;
            if dest_dir && !old_dir {
                return Err(FsError::IsDir);
            }
            if !dest_dir && old_dir {
                return Err(FsError::NotDir);
            }
            if dest_dir {
                self.rmdir_at(new)?;
            } else {
                self.unlink_at(new)?;
            }
        }
        if old_dir && opino != npino {
            self.set_dotdot(old_ino, npino)?;
            self.bump_links(opino, -1)?;
            self.bump_links(npino, 1)?;
        }
        let ft = if old_dir { EXT2_FT_DIR } else { EXT2_FT_REG };
        self.remove_dirent(opino, oname)?;
        self.add_dirent(npino, old_ino, nname, ft)?;
        self.flush()
    }
}

fn gdt_byte(fs_off: u64, block_size: usize) -> u64 {
    if block_size <= 1024 {
        fs_off + 2048
    } else {
        fs_off + block_size as u64
    }
}

fn split(path: &str) -> Result<(&str, &str), FsError> {
    if path.is_empty() || path == "/" {
        return Err(FsError::Inval);
    }
    let name = match path.rfind('/') {
        Some(i) => &path[i + 1..],
        None => path,
    };
    if name.is_empty() || name.len() > 255 || name.contains('\0') {
        return Err(FsError::Inval);
    }
    Ok((parent(path), name))
}

fn read_abs(byte: u64, buf: &mut [u8]) -> Result<(), FsError> {
    if buf.is_empty() {
        return Ok(());
    }
    let start = byte & !511;
    let skip = (byte - start) as usize;
    let need = skip + buf.len();
    let sectors = (need + 511) / 512;
    let mut tmp = vec![0u8; sectors * 512];
    crate::block::read_blocks(start / 512, &mut tmp).map_err(|_| FsError::Io)?;
    buf.copy_from_slice(&tmp[skip..skip + buf.len()]);
    Ok(())
}

fn write_abs(byte: u64, data: &[u8]) -> Result<(), FsError> {
    if data.is_empty() {
        return Ok(());
    }
    if byte % 512 == 0 && data.len() % 512 == 0 {
        return crate::block::write_blocks(byte / 512, data).map_err(|_| FsError::Io);
    }
    let start = byte & !511;
    let skip = (byte - start) as usize;
    let need = skip + data.len();
    let sectors = (need + 511) / 512;
    let mut tmp = vec![0u8; sectors * 512];
    crate::block::read_blocks(start / 512, &mut tmp).map_err(|_| FsError::Io)?;
    tmp[skip..skip + data.len()].copy_from_slice(data);
    crate::block::write_blocks(start / 512, &tmp).map_err(|_| FsError::Io)
}

fn bit(bm: &[u8], i: u32) -> bool {
    let i = i as usize;
    if i / 8 >= bm.len() {
        return true;
    }
    bm[i / 8] & (1 << (i % 8)) != 0
}

fn set_bit(bm: &mut [u8], i: u32, on: bool) {
    let i = i as usize;
    if i / 8 >= bm.len() {
        return;
    }
    if on {
        bm[i / 8] |= 1 << (i % 8);
    } else {
        bm[i / 8] &= !(1 << (i % 8));
    }
}

fn get_u16(buf: &[u8], off: usize) -> u16 {
    u16::from_le_bytes([buf[off], buf[off + 1]])
}

fn get_u32(buf: &[u8], off: usize) -> u32 {
    u32::from_le_bytes([buf[off], buf[off + 1], buf[off + 2], buf[off + 3]])
}

fn put_u16(buf: &mut [u8], off: usize, v: u16) {
    buf[off..off + 2].copy_from_slice(&v.to_le_bytes());
}

fn put_u32(buf: &mut [u8], off: usize, v: u32) {
    buf[off..off + 4].copy_from_slice(&v.to_le_bytes());
}
