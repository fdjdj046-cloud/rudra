//! ext2 чтение и запись и чтение ext4 поверх блочного слоя.
//!
//! Релизный образ: первые 16 МиБ — загрузчик и ядро, дальше файловая система.
//! Отдельный диск, у которого суперблок в байте 1024, тоже монтируется.
//! ext2: одна группа, блоки до 4096, inode 128 или 256, прямой и один косвенный
//! блок. ext4 монтируется только на чтение, если в incompat нет ничего, кроме
//! filetype, extents, flex_bg, 64bit, metadata_csum_seed и RECOVER. Дескриптор группы — `s_desc_size`
//! (степень двойки от 64 до размера блока), номер inode-таблицы собирается
//! из младшей и старшей половин. Число блоков тоже 64-битное. Дерево extent
//! (корень в inode, глубина до 5) отдаёт физический блок до 48 бит; дыра и
//! unwritten читаются нулями. Каталог с htree читается по логическим блокам:
//! индекс не разбирается как имена, листья — обычные записи. Короткая ссылка
//! (меньше 60 байт и без блоков) лежит в `i_block`. `metadata_csum` проверяется
//! crc32c (суперблок, дескриптор группы, inode, блок каталога, блок extent).
//! Старый `gdt_csum` без `metadata_csum` проверяет дескриптор группы crc16.
//! Запись такого тома — `EROFS`. Журнал с `RECOVER` проигрывается в память
//! и диск не меняет: суперблок jbd2 v2, revoke, 64bit и csum v3. `s_start == 0`
//! значит, что журнал чистый. Иной журнал отвергает монтирование. `RFS2`
//! остаётся recovery, если суперблок не подошёл.

use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;
use spin::Mutex;

use crate::fs::{parent, FsError};

/// Смещение ext2 в общем raw-образе `rudra-1.0.0.img`.
pub const EMBED_OFF: u64 = 16 * 1024 * 1024;

const FILETYPE: u32 = 0x2;
/// ext4 `EXT4_FEATURE_INCOMPAT_RECOVER`. Журнал есть и его надо проиграть.
const RECOVER: u32 = 0x4;
const BIT64: u32 = 0x80;
/// Зерно crc32c лежит в суперблоке (`s_checksum_seed`), а не считается из UUID.
const CSUM_SEED: u32 = 0x2000;
const METADATA_CSUM: u32 = 0x400;
/// Старая сумма дескриптора группы. Вместе с `metadata_csum` не считается:
/// тогда дескриптор проверяет crc32c.
const GDT_CSUM: u32 = 0x10;
const INLINE_DATA_FL: u32 = 0x10000000;
const FT_DIR_CSUM: u8 = 0xDE;
const EXTENTS_FL: u32 = 0x80000;
const HUGE_FL: u32 = 0x40000;
const EXTENT_MAGIC: u16 = 0xF30A;
const EXT2_FT_REG: u8 = 1;
const EXT2_FT_DIR: u8 = 2;
const ROOT_INO: u32 = 2;

struct Vol {
    off: u64,
    block_size: usize,
    blocks_count: u64,
    inodes_count: u32,
    free_blocks: u32,
    free_inodes: u32,
    inode_size: usize,
    first_ino: u32,
    filetype: bool,
    /// ext4 с extent: метаданные не переписываем, мутации возвращают `RoFs`.
    readonly: bool,
    /// ro_compat `metadata_csum`. Считаем crc32c, как Linux `ext4_chksum`.
    metadata_csum: bool,
    /// Старый `gdt_csum` и нет `metadata_csum`. Дескриптор группы — crc16.
    gdt_crc16: bool,
    /// Зерно crc32c: `s_checksum_seed` либо `crc32c(~0, UUID)`.
    csum_seed: u32,
    /// Сумма inode только у создателя Linux: поле лежит в osd2.
    csum_inodes: bool,
    blocks_per_group: u32,
    inodes_per_group: u32,
    /// 32 у ext2. У ext4 с 64bit — `s_desc_size`, от 64 и степень двойки.
    desc_size: usize,
    block_bitmap: u32,
    inode_bitmap: u32,
    inode_table: u64,
    used_dirs: u16,
    bb: Vec<u8>,
    ib: Vec<u8>,
    sb: Vec<u8>,
    gd: Vec<u8>,
    /// Блоки журнала, перекрывшие диск в памяти. Ключ — номер блока ФС.
    /// Пусто, если журнала нет или он чистый. На диск это не пишется.
    replay: Vec<(u64, Vec<u8>)>,
}

static EXT2: Mutex<Option<Vol>> = Mutex::new(None);

pub fn mounted() -> bool {
    EXT2.lock().is_some()
}

pub fn sync() {
    let _ = with_vol(|v| {
        if v.readonly {
            return Ok(());
        }
        v.flush()
    });
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
                if vol.readonly {
                    crate::serial_println!(
                        "[ext4] read-only off {:#x} block {} blocks {} inodes {} replay {}",
                        vol.off,
                        vol.block_size,
                        vol.blocks_count,
                        vol.inodes_count,
                        vol.replay.len()
                    );
                    *EXT2.lock() = Some(vol);
                    crate::serial_println!("[root] ext4 on virtio-blk");
                    return;
                }
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
        let sz = inode_bytes(&inode);
        if sz > isize::MAX as u64 {
            return None;
        }
        Some(sz as isize)
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
        let size = inode_bytes(&inode);
        if size > isize::MAX as u64 {
            return None;
        }
        let size = size as usize;
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

pub fn write_file(path: &str, data: &[u8]) -> Result<(), FsError> {
    match with_vol(|v| v.write_file_at(path, data)) {
        Some(Err(e)) => {
            crate::serial_println!("[ext2] write {} failed ({:?})", path, e);
            Err(e)
        }
        Some(Ok(())) => Ok(()),
        None => Err(FsError::Io),
    }
}

pub fn list_dir(path: &str) -> Vec<String> {
    with_vol(|v| v.list(path).unwrap_or_default()).unwrap_or_default()
}

pub fn parent_ok(path: &str) -> Result<(), FsError> {
    with_vol(|v| v.parent_ok(path)).unwrap_or(Err(FsError::Io))
}

pub fn mkdir(path: &str) -> Result<(), FsError> {
    mkdir_mode(path, 0o755)
}

/// `perm` — биты 0777 после umask. Тип каталога — 0x4000. Владелец — euid/egid
/// создавшей задачи: uid lo@2 hi@120, gid lo@24 hi@122 (rev 1, inode 128 B).
pub fn mkdir_mode(path: &str, perm: u16) -> Result<(), FsError> {
    let uid = crate::task::cred_euid() as u32;
    let gid = crate::task::cred_egid() as u32;
    with_vol(|v| v.mkdir_at(path, perm, uid, gid)).unwrap_or(Err(FsError::Io))
}

pub fn mode_of(path: &str) -> Option<u32> {
    with_vol(|v| {
        let ino = v.lookup(path).ok()?;
        let inode = v.read_inode(ino).ok()?;
        Some(get_u16(&inode, 0) as u32)
    })
    .flatten()
}

/// Пишет биты 07777. Старшая тетрада типа остаётся.
pub fn chmod(path: &str, perm: u16) -> Result<(), FsError> {
    with_vol(|v| v.chmod_at(path, perm)).unwrap_or(Err(FsError::Io))
}

/// Пустой новый обычный файл. Существующий путь не трогает. Владелец —
/// euid/egid создавшей задачи.
pub fn create_file(path: &str, perm: u16) -> Result<(), FsError> {
    let uid = crate::task::cred_euid() as u32;
    let gid = crate::task::cred_egid() as u32;
    with_vol(|v| v.create_reg(path, perm, uid, gid)).unwrap_or(Err(FsError::Io))
}

/// Владелец (uid, gid) из inode. Нет пути — None.
pub fn owner_of(path: &str) -> Option<(u32, u32)> {
    with_vol(|v| {
        let ino = v.lookup(path).ok()?;
        let inode = v.read_inode(ino).ok()?;
        let uid = get_u16(&inode, 2) as u32 | ((get_u16(&inode, 120) as u32) << 16);
        let gid = get_u16(&inode, 24) as u32 | ((get_u16(&inode, 122) as u32) << 16);
        Some((uid, gid))
    })
    .flatten()
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
        let blocks_lo = get_u32(&sb, 4);
        let inodes_count = get_u32(&sb, 0);
        let blocks_per_group = get_u32(&sb, 32);
        let inodes_per_group = get_u32(&sb, 40);
        if inodes_count == 0 || blocks_per_group == 0 || inodes_per_group == 0 {
            return Err("empty fs");
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
        let ro_compat = get_u32(&sb, 100);
        let readonly = features(incompat, ro_compat)?;
        let metadata_csum = ro_compat & METADATA_CSUM != 0;
        let gdt_crc16 = ro_compat & GDT_CSUM != 0 && !metadata_csum;
        let (csum_seed, csum_inodes) = if metadata_csum {
            // s_checksum_type @ 0x173: ext4 пишет 1 (crc32c). Иное — не наш алгоритм.
            if sb.len() < 1024 || sb[0x173] != 1 || !super_csum_ok(&sb) {
                return Err(if sb.len() < 1024 || sb[0x173] != 1 {
                    "checksum type"
                } else {
                    "checksum"
                });
            }
            let seed = if incompat & CSUM_SEED != 0 {
                get_u32(&sb, 0x270)
            } else {
                crc32c(!0, &sb[104..120])
            };
            (seed, get_u32(&sb, 72) == 1)
        } else {
            (0, false)
        };
        let bit64 = incompat & BIT64 != 0;
        let blocks_hi = if sb.len() >= 340 { get_u32(&sb, 336) } else { 0 };
        if blocks_hi != 0 && !bit64 {
            return Err("64bit blocks");
        }
        let blocks_count = (blocks_lo as u64) | ((blocks_hi as u64) << 32);
        if blocks_count == 0 {
            return Err("empty fs");
        }
        let fs_bytes = match blocks_count.checked_mul(block_size as u64) {
            Some(n) => n,
            None => return Err("fs size"),
        };
        if off.saturating_add(fs_bytes) > disk_bytes {
            return Err("fs past disk");
        }
        let desc_size = desc_len(&sb, block_size, bit64)?;
        let groups = blocks_count.div_ceil(blocks_per_group as u64);
        let igroups = inodes_count.div_ceil(inodes_per_group);
        if !readonly && (groups != 1 || igroups != 1) {
            return Err("only one group");
        }
        let mut gd = vec![0u8; desc_size];
        // 1024: суперблок — блок 1, таблица групп — блок 2.
        // 2048 и 4096: суперблок внутри блока 0, таблица групп — следующий блок.
        read_abs(gdt_byte(off, block_size), &mut gd).map_err(|_| "gdt read")?;
        if metadata_csum && !gd_csum_ok(csum_seed, 0, &gd) {
            return Err("checksum");
        }
        if gdt_crc16 && !gd_crc16_ok(&sb[104..120], 0, &gd) {
            return Err("checksum");
        }
        let block_bitmap = get_u32(&gd, 0);
        let inode_bitmap = get_u32(&gd, 4);
        let inode_table = gd_inode_table(&gd).map_err(|_| "group desc")?;
        if !readonly && (block_bitmap == 0 || inode_bitmap == 0) {
            return Err("group desc");
        }
        let (bb, ib) = if readonly {
            (Vec::new(), Vec::new())
        } else {
            let mut bb = vec![0u8; block_size];
            let mut ib = vec![0u8; block_size];
            read_abs(off + block_bitmap as u64 * block_size as u64, &mut bb)
                .map_err(|_| "bitmap")?;
            read_abs(off + inode_bitmap as u64 * block_size as u64, &mut ib)
                .map_err(|_| "ibitmap")?;
            (bb, ib)
        };
        let mut vol = Vol {
            off,
            block_size,
            blocks_count,
            inodes_count,
            free_blocks: 0,
            free_inodes: 0,
            inode_size,
            first_ino,
            filetype: incompat & FILETYPE != 0,
            readonly,
            metadata_csum,
            gdt_crc16,
            csum_seed,
            csum_inodes,
            blocks_per_group,
            inodes_per_group,
            desc_size,
            block_bitmap,
            inode_bitmap,
            inode_table,
            used_dirs: get_u16(&gd, 16),
            bb,
            ib,
            sb,
            gd,
            replay: Vec::new(),
        };
        if incompat & RECOVER != 0 {
            vol.recover_journal()?;
        }
        if readonly {
            return Ok(vol);
        }
        vol.recount();
        vol.write_check().map_err(|_| "write check")?;
        Ok(vol)
    }

    fn ro(&self) -> Result<(), FsError> {
        if self.readonly {
            Err(FsError::RoFs)
        } else {
            Ok(())
        }
    }

    fn recount(&mut self) {
        let mut blocks = 0u32;
        let nblocks = self.blocks_count.min(u32::MAX as u64) as u32;
        for b in 0..nblocks {
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

    fn read_block(&self, block: impl Into<u64>, buf: &mut [u8]) -> Result<(), FsError> {
        let block = block.into();
        if block >= self.blocks_count || buf.len() < self.block_size {
            return Err(FsError::Io);
        }
        if let Ok(i) = self.replay.binary_search_by_key(&block, |e| e.0) {
            let src = &self.replay[i].1;
            if src.len() < self.block_size {
                return Err(FsError::Io);
            }
            buf[..self.block_size].copy_from_slice(&src[..self.block_size]);
            return Ok(());
        }
        let byte = match block.checked_mul(self.block_size as u64) {
            Some(n) => self.off.saturating_add(n),
            None => return Err(FsError::Io),
        };
        read_abs(byte, &mut buf[..self.block_size])
    }

    fn write_block(&self, block: impl Into<u64>, buf: &[u8]) -> Result<(), FsError> {
        let block = block.into();
        if block >= self.blocks_count || buf.len() < self.block_size {
            return Err(FsError::Io);
        }
        let byte = match block.checked_mul(self.block_size as u64) {
            Some(n) => self.off.saturating_add(n),
            None => return Err(FsError::Io),
        };
        write_abs(byte, &buf[..self.block_size])
    }

    fn write_check(&mut self) -> Result<(), FsError> {
        let bb = self.bb.clone();
        let ib = self.ib.clone();
        let free = self.free_blocks;
        let b = self.alloc_block()?;
        let neighbor = b.saturating_add(1);
        let mut nb = vec![0u8; self.block_size];
        let have_neighbor = (neighbor as u64) < self.blocks_count;
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
        let nblocks = self.blocks_count.min(u32::MAX as u64) as u32;
        for b in 0..nblocks {
            if !bit(&self.bb, b) {
                set_bit(&mut self.bb, b, true);
                self.free_blocks = self.free_blocks.saturating_sub(1);
                return Ok(b);
            }
        }
        Err(FsError::NoSpc)
    }

    fn free_block(&mut self, b: u32) {
        if b == 0 || b as u64 >= self.blocks_count {
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

    fn read_group_desc(&self, group: u32) -> Result<Vec<u8>, FsError> {
        let groups = self.blocks_count.div_ceil(self.blocks_per_group as u64);
        if group as u64 >= groups {
            return Err(FsError::Io);
        }
        let gdt = if self.block_size <= 1024 {
            2048u64
        } else {
            self.block_size as u64
        };
        let byte = gdt + group as u64 * self.desc_size as u64;
        let block = byte / self.block_size as u64;
        let inner = (byte % self.block_size as u64) as usize;
        if inner.saturating_add(self.desc_size) > self.block_size {
            return Err(FsError::Io);
        }
        let mut blk = vec![0u8; self.block_size];
        self.read_block(block, &mut blk)?;
        Ok(blk[inner..inner + self.desc_size].to_vec())
    }

    fn inode_table_of(&self, ino: u32) -> Result<u64, FsError> {
        let group = (ino - 1) / self.inodes_per_group;
        if !self.readonly {
            return Ok(self.inode_table);
        }
        let gd = self.read_group_desc(group)?;
        if self.metadata_csum && !gd_csum_ok(self.csum_seed, group, &gd) {
            return Err(FsError::Io);
        }
        if self.gdt_crc16 && !gd_crc16_ok(&self.sb[104..120], group, &gd) {
            return Err(FsError::Io);
        }
        gd_inode_table(&gd)
    }

    /// Проиграть внутренний журнал в `replay`. Диск не пишется, флаг RECOVER
    /// на диске остаётся. Инода журнала читается до проигрыша: так же делает Linux.
    fn recover_journal(&mut self) -> Result<(), &'static str> {
        if self.sb.len() < 0xE4 {
            return Err("journal");
        }
        let inum = get_u32(&self.sb, 0xE0);
        if inum == 0 || inum > self.inodes_count {
            return Err("journal");
        }
        let inode = self.read_inode(inum).map_err(|_| "journal")?;
        if self.block_size == 0 {
            return Err("journal");
        }
        let size = inode_bytes(&inode);
        if size == 0 || size % self.block_size as u64 != 0 {
            return Err("journal");
        }
        let nblocks_u = size / self.block_size as u64;
        if nblocks_u > u32::MAX as u64 {
            return Err("journal");
        }
        let nblocks = nblocks_u as u32;
        let bs = self.block_size;
        let replay = replay_journal_blocks(bs, nblocks, &mut |log| {
            let phys = self.map_block(inum, &inode, log).map_err(|_| "journal")?;
            if phys == 0 {
                return Err("journal");
            }
            let mut buf = vec![0u8; bs];
            self.read_block(phys, &mut buf).map_err(|_| "journal")?;
            Ok(buf)
        })?;
        for (block, data) in &replay {
            if *block >= self.blocks_count || data.len() != self.block_size {
                return Err("journal");
            }
        }
        crate::serial_println!("[ext4] journal replay {} blocks", replay.len());
        self.replay = replay;
        let gd = self.read_group_desc(0).map_err(|_| "journal")?;
        if self.metadata_csum && !gd_csum_ok(self.csum_seed, 0, &gd) {
            return Err("checksum");
        }
        if self.gdt_crc16 && !gd_crc16_ok(&self.sb[104..120], 0, &gd) {
            return Err("checksum");
        }
        self.inode_table = gd_inode_table(&gd).map_err(|_| "journal")?;
        self.gd = gd;
        Ok(())
    }

    fn read_inode(&self, ino: u32) -> Result<Vec<u8>, FsError> {
        if ino == 0 || ino > self.inodes_count {
            return Err(FsError::NoEnt);
        }
        let per = self.block_size / self.inode_size;
        if per == 0 {
            return Err(FsError::Io);
        }
        let table = self.inode_table_of(ino)?;
        let index = (ino - 1) as usize % self.inodes_per_group as usize;
        let block = table + (index / per) as u64;
        let inner = (index % per) * self.inode_size;
        let mut blk = vec![0u8; self.block_size];
        self.read_block(block, &mut blk)?;
        let n = if self.csum_inodes {
            self.inode_size
        } else {
            128.min(self.inode_size)
        };
        if inner + n > blk.len() {
            return Err(FsError::Io);
        }
        let mut out = vec![0u8; n];
        out.copy_from_slice(&blk[inner..inner + n]);
        if self.csum_inodes {
            let seed = inode_csum_seed(self.csum_seed, ino, get_u32(&out, 100));
            if !inode_csum_ok(seed, &out) {
                return Err(FsError::Io);
            }
        }
        Ok(out)
    }

    fn write_inode(&self, ino: u32, inode: &[u8]) -> Result<(), FsError> {
        if ino == 0 || ino > self.inodes_count || inode.len() < 128 {
            return Err(FsError::Io);
        }
        let per = self.block_size / self.inode_size;
        let table = self.inode_table_of(ino)?;
        let index = (ino - 1) as usize % self.inodes_per_group as usize;
        let block = table + (index / per) as u64;
        let inner = (index % per) * self.inode_size;
        let mut blk = vec![0u8; self.block_size];
        self.read_block(block, &mut blk)?;
        let n = 128.min(self.inode_size);
        blk[inner..inner + n].copy_from_slice(&inode[..n]);
        self.write_block(block, &blk)
    }

    fn is_dir_ino(&self, ino: u32) -> Result<bool, FsError> {
        let inode = self.read_inode(ino)?;
        Ok(get_u16(&inode, 0) & 0xF000 == 0x4000)
    }

    fn map_block(&self, ino: u32, inode: &[u8], iblock: u32) -> Result<u64, FsError> {
        if inode.len() >= 100 && get_u32(inode, 32) & EXTENTS_FL != 0 {
            return extent_map(&inode[40..100], iblock, &mut |b| {
                let mut blk = vec![0u8; self.block_size];
                self.read_block(b, &mut blk)?;
                if self.metadata_csum {
                    let seed = inode_csum_seed(self.csum_seed, ino, get_u32(inode, 100));
                    if !extent_csum_ok(seed, &blk) {
                        return Err(FsError::Io);
                    }
                }
                Ok(blk)
            });
        }
        if iblock < 12 {
            return Ok(get_u32(inode, 40 + iblock as usize * 4) as u64);
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
        Ok(get_u32(&blk, idx as usize * 4) as u64)
    }

    fn read_ino(&self, ino: u32, offset: u64, buf: &mut [u8]) -> Result<usize, FsError> {
        let inode = self.read_inode(ino)?;
        let size = inode_bytes(&inode);
        if offset >= size || buf.is_empty() {
            return Ok(0);
        }
        if let Some(src) = inline_symlink(&inode) {
            let start = offset as usize;
            if start >= src.len() {
                return Ok(0);
            }
            let n = (src.len() - start).min(buf.len());
            buf[..n].copy_from_slice(&src[start..start + n]);
            return Ok(n);
        }
        let want = ((size - offset) as usize).min(buf.len());
        let mut sib_cache: Option<(u32, Vec<u8>)> = None;
        let mut done = 0usize;
        while done < want {
            let pos = offset + done as u64;
            let iblock = (pos / self.block_size as u64) as u32;
            let inner = (pos % self.block_size as u64) as usize;
            let disk = self.map_cached(ino, &inode, iblock, &mut sib_cache)?;
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
        ino: u32,
        inode: &[u8],
        iblock: u32,
        cache: &mut Option<(u32, Vec<u8>)>,
    ) -> Result<u64, FsError> {
        if inode.len() >= 100 && get_u32(inode, 32) & EXTENTS_FL != 0 {
            return self.map_block(ino, inode, iblock);
        }
        if iblock < 12 {
            return Ok(get_u32(inode, 40 + iblock as usize * 4) as u64);
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
        Ok(get_u32(buf, idx as usize * 4) as u64)
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
        // htree (`EXT4_INDEX_FL`) — это индекс поверх тех же логических блоков.
        // Блок 0 закрывает индекс длиной `..`, внутренний узел — одной пустой
        // записью на весь блок. Имена лежат в листьях и находятся линейным
        // обходом, без хеша: версия хеша, включая siphash, на поиск не влияет.
        let size = inode_bytes(&inode) as usize;
        let mut off = 0usize;
        while off + 8 <= size {
            let ib = (off / self.block_size) as u32;
            let disk = self.map_block(dir, &inode, ib)?;
            if disk == 0 {
                return Err(FsError::Io);
            }
            let mut block = vec![0u8; self.block_size];
            self.read_block(disk, &mut block)?;
            self.check_dir_block(dir, &inode, &block)?;
            let base = ib as usize * self.block_size;
            let limit = self.block_size.min(size - base);
            if scan_dirents(&block, self.filetype, limit, &mut f)? {
                return Ok(());
            }
            if limit < self.block_size {
                return Ok(());
            }
            off = base + self.block_size;
        }
        Ok(())
    }

    fn check_dir_block(&self, dir: u32, inode: &[u8], block: &[u8]) -> Result<(), FsError> {
        if !self.metadata_csum {
            return Ok(());
        }
        let seed = inode_csum_seed(self.csum_seed, dir, get_u32(inode, 100));
        let ok = match dx_kind(block) {
            Some(kind) => dx_csum_ok(seed, block, kind),
            None => dir_tail_csum_ok(seed, block),
        };
        if ok {
            Ok(())
        } else {
            Err(FsError::Io)
        }
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
            let disk = self.map_block(dir, &inode, ib)?;
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
            let disk = self.map_block(dir, &inode, ib)?;
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
        self.ro()?;
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

    fn mkdir_at(&mut self, path: &str, perm: u16, uid: u32, gid: u32) -> Result<(), FsError> {
        self.ro()?;
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
        put_u16(&mut inode, 0, 0x4000 | (perm & 0o777));
        put_u16(&mut inode, 2, uid as u16);
        put_u16(&mut inode, 24, gid as u16);
        put_u16(&mut inode, 120, (uid >> 16) as u16);
        put_u16(&mut inode, 122, (gid >> 16) as u16);
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

    fn chmod_at(&mut self, path: &str, perm: u16) -> Result<(), FsError> {
        self.ro()?;
        let ino = self.lookup(path)?;
        let mut inode = self.read_inode(ino)?;
        let old = get_u16(&inode, 0);
        let typ = old & 0xF000;
        if typ == 0 {
            return Err(FsError::Io);
        }
        put_u16(&mut inode, 0, typ | (perm & 0o7777));
        self.write_inode(ino, &inode)
    }

    fn create_reg(&mut self, path: &str, perm: u16, uid: u32, gid: u32) -> Result<(), FsError> {
        self.ro()?;
        if path.is_empty() || path == "/" {
            return Err(FsError::Inval);
        }
        let (dir, name) = split(path)?;
        if name.is_empty() || name == "." || name == ".." {
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
        let mut fresh = vec![0u8; 128];
        put_u16(&mut fresh, 0, 0x8000 | (perm & 0o777));
        put_u16(&mut fresh, 2, uid as u16);
        put_u16(&mut fresh, 24, gid as u16);
        put_u16(&mut fresh, 120, (uid >> 16) as u16);
        put_u16(&mut fresh, 122, (gid >> 16) as u16);
        put_u16(&mut fresh, 26, 1);
        self.write_inode(ino, &fresh)?;
        if let Err(e) = self.add_dirent(pino, ino, name, EXT2_FT_REG) {
            self.free_ino(ino);
            return Err(e);
        }
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
        self.ro()?;
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
        self.ro()?;
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
        let disk = self.map_block(dir, &inode, 0)?;
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
        self.ro()?;
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

/// Размер файла. `HUGE_FILE` добавляет старшую половину с offset 108.
fn inode_bytes(inode: &[u8]) -> u64 {
    let lo = get_u32(inode, 4) as u64;
    if inode.len() >= 112 && get_u32(inode, 32) & HUGE_FL != 0 {
        lo | ((get_u32(inode, 108) as u64) << 32)
    } else {
        lo
    }
}

/// Обход записей одного блока каталога. Хвост `metadata_csum` (inode 0,
/// `file_type` 0xDE) пропускается. `limit` — до какого смещения запись ещё
/// начинается: у каталога это конец файла, если он разрезал блок.
fn scan_dirents(
    block: &[u8],
    filetype: bool,
    limit: usize,
    f: &mut impl FnMut(&[u8], usize, usize, u32) -> Result<bool, FsError>,
) -> Result<bool, FsError> {
    let limit = limit.min(block.len());
    let mut local = 0usize;
    while local + 8 <= limit {
        let rec = get_u16(block, local + 4) as usize;
        if rec < 8 || local + rec > block.len() {
            return Err(FsError::Io);
        }
        let ino = get_u32(block, local);
        let tail = filetype && ino == 0 && block[local + 6] == 0 && block[local + 7] == FT_DIR_CSUM;
        if !tail && f(block, local, rec, ino)? {
            return Ok(true);
        }
        local += rec;
    }
    Ok(false)
}

/// Корень htree: `..` занимает остаток блока и `info_length == 8`.
/// Внутренний узел: первая запись длиной в блок.
fn dx_kind(block: &[u8]) -> Option<DxKind> {
    if block.len() < 8 {
        return None;
    }
    let rec0 = get_u16(block, 4) as usize;
    if rec0 == block.len() {
        return Some(DxKind::Node);
    }
    if rec0 == 12 && block.len() >= 32 {
        let rec1 = get_u16(block, 16) as usize;
        if rec1 == block.len() - 12 && get_u32(block, 24) == 0 && block[29] == 8 {
            return Some(DxKind::Root);
        }
    }
    None
}

enum DxKind {
    Root,
    Node,
}

/// CRC-32C в соглашении Linux `crc32c`: `crc` уже содержит зерно (`!0` для
/// нового расчёта), конечного xor нет. `crc32c(crc32c(!0, a), b)` равен
/// `crc32c(!0, a || b)`. Значение из Википедии `0xE3069283` для «123456789» —
/// это `crc32c(!0, data) ^ !0`.
fn crc32c(mut crc: u32, data: &[u8]) -> u32 {
    for &b in data {
        crc ^= u32::from(b);
        for _ in 0..8 {
            let mask = (crc & 1).wrapping_neg();
            crc = (crc >> 1) ^ (0x82F63B78 & mask);
        }
    }
    crc
}

fn super_csum_ok(sb: &[u8]) -> bool {
    sb.len() >= 1024 && crc32c(!0, &sb[..1020]) == get_u32(sb, 1020)
}

/// CRC-16/ARC, как Linux `crc16`: полином `0x8005` отражённый, конечного xor нет.
/// `crc16(0, b"123456789") == 0xBB3D`, `crc16(0xFFFF, …) == 0x4B37`.
fn crc16(mut crc: u16, data: &[u8]) -> u16 {
    for &b in data {
        crc ^= u16::from(b);
        for _ in 0..8 {
            let mask = (crc & 1).wrapping_neg();
            crc = (crc >> 1) ^ (0xA001 & mask);
        }
    }
    crc
}

/// Старый `gdt_csum`: `crc16(~0, UUID || номер группы || дескриптор)`.
/// Два байта суммы пропускаются, а не зануляются. Хвост длиннее 32 байт
/// входит в счёт: без 64bit дескриптор короче и хвоста нет.
fn gd_crc16_ok(uuid: &[u8], group: u32, gd: &[u8]) -> bool {
    if uuid.len() != 16 || gd.len() < 32 {
        return false;
    }
    let mut c = crc16(0xFFFF, uuid);
    c = crc16(c, &group.to_le_bytes());
    c = crc16(c, &gd[..30]);
    if gd.len() > 32 {
        c = crc16(c, &gd[32..]);
    }
    c == get_u16(gd, 30)
}

fn gd_csum_ok(seed: u32, group: u32, gd: &[u8]) -> bool {
    if gd.len() < 32 {
        return false;
    }
    let mut c = crc32c(seed, &group.to_le_bytes());
    c = crc32c(c, &gd[..30]);
    c = crc32c(c, &[0, 0]);
    if gd.len() > 32 {
        c = crc32c(c, &gd[32..]);
    }
    c as u16 == get_u16(gd, 30)
}

fn inode_csum_seed(fs_seed: u32, ino: u32, generation: u32) -> u32 {
    let c = crc32c(fs_seed, &ino.to_le_bytes());
    crc32c(c, &generation.to_le_bytes())
}

/// Сумма inode: `i_checksum_lo` @ 124 и, если `i_extra_isize` покрывает его,
/// `i_checksum_hi` @ 130. Поля на время счёта — нули.
fn inode_csum_ok(seed: u32, raw: &[u8]) -> bool {
    if raw.len() < 128 {
        return false;
    }
    let mut c = crc32c(seed, &raw[..124]);
    c = crc32c(c, &[0, 0]);
    c = crc32c(c, &raw[126..128]);
    let mut provided = u32::from(get_u16(raw, 124));
    let mut full = false;
    if raw.len() > 128 {
        let up = 130.min(raw.len());
        c = crc32c(c, &raw[128..up]);
        let extra = if raw.len() >= 130 {
            get_u16(raw, 128) as usize
        } else {
            0
        };
        if extra >= 4 && raw.len() >= 132 {
            c = crc32c(c, &[0, 0]);
            c = crc32c(c, &raw[132..]);
            provided |= u32::from(get_u16(raw, 130)) << 16;
            full = true;
        } else if up < raw.len() {
            c = crc32c(c, &raw[up..]);
        }
    }
    if !full {
        c &= 0xFFFF;
    }
    c == provided
}

fn dx_csum_ok(seed: u32, block: &[u8], kind: DxKind) -> bool {
    let count_off = match kind {
        DxKind::Root => 32,
        DxKind::Node => 8,
    };
    if count_off + 4 > block.len() {
        return false;
    }
    let limit = get_u16(block, count_off) as usize;
    let count = get_u16(block, count_off + 2) as usize;
    if count == 0 || limit == 0 || count > limit {
        return false;
    }
    let tail = count_off.saturating_add(limit.saturating_mul(8));
    if tail + 8 > block.len() {
        return false;
    }
    let covered = count_off + count * 8;
    if covered > tail {
        return false;
    }
    let mut c = crc32c(seed, &block[..covered]);
    c = crc32c(c, &block[tail..tail + 4]);
    c = crc32c(c, &[0, 0, 0, 0]);
    c == get_u32(block, tail + 4)
}

fn dir_tail_csum_ok(seed: u32, block: &[u8]) -> bool {
    if block.len() < 12 {
        return false;
    }
    let off = block.len() - 12;
    if get_u32(block, off) != 0
        || get_u16(block, off + 4) != 12
        || block[off + 6] != 0
        || block[off + 7] != FT_DIR_CSUM
    {
        return false;
    }
    crc32c(seed, &block[..off]) == get_u32(block, off + 8)
}

/// Хвост блока extent стоит после `eh_max` записей. В самом inode хвоста нет.
fn extent_csum_ok(seed: u32, block: &[u8]) -> bool {
    if block.len() < 12 || get_u16(block, 0) != EXTENT_MAGIC {
        return false;
    }
    let max = get_u16(block, 4) as usize;
    let tail = 12usize.saturating_add(max.saturating_mul(12));
    if tail + 4 > block.len() {
        return false;
    }
    crc32c(seed, &block[..tail]) == get_u32(block, tail)
}

/// Цель короткой ссылки лежит в `i_block` (60 байт), а не в блоках.
/// Extent и `INLINE_DATA` читаются как обычный файл.
fn inline_symlink(inode: &[u8]) -> Option<&[u8]> {
    if inode.len() < 100 {
        return None;
    }
    if get_u16(inode, 0) & 0xF000 != 0xA000 {
        return None;
    }
    let flags = get_u32(inode, 32);
    if flags & (EXTENTS_FL | INLINE_DATA_FL) != 0 {
        return None;
    }
    let size = inode_bytes(inode);
    if size >= 60 {
        return None;
    }
    let blocks_hi = if inode.len() >= 118 {
        u64::from(get_u16(inode, 116)) << 32
    } else {
        0
    };
    if u64::from(get_u32(inode, 28)) | blocks_hi != 0 {
        return None;
    }
    let n = size as usize;
    Some(&inode[40..40 + n])
}

/// Проигрыш jbd2 в память. Функция только читает `read_log` и ничего не пишет.
///
/// `s_start == 0` — журнал чисто размонтирован (`jbd2_journal_recover`):
/// применять нечего. Поддержаны revoke, 64bit и csum v3. v1-сумма, csum v2,
/// async и fast commit отвергаются, как и ненулевой `s_errno`. Сумма тега
/// считается по байтам журнала до снятия escape. Revoke с номером `R` гасит
/// запись транзакции `T`, если не `tid_gt(T, R)`: равные номера тоже гасятся.
/// Битая сумма внутри зафиксированного диапазона отвергает монтирование.
/// Более старый commit (метка времени меньше предыдущей) обрывает журнал.
/// Больше 16 МиБ проигранных блоков или 65536 revoke — отказ, а не обрезка.
const J_MAGIC: u32 = 0xC03B3998;
const J_DESCRIPTOR: u32 = 1;
const J_COMMIT: u32 = 2;
const J_SUPER_V2: u32 = 4;
const J_REVOKE: u32 = 5;
const J_ESCAPE: u32 = 1;
const J_SAME_UUID: u32 = 2;
const J_LAST_TAG: u32 = 8;
const J_FEAT_REVOKE: u32 = 0x1;
const J_FEAT_64BIT: u32 = 0x2;
const J_FEAT_CSUM3: u32 = 0x10;
const J_FEAT_OK: u32 = J_FEAT_REVOKE | J_FEAT_64BIT | J_FEAT_CSUM3;
const J_MIN_BLOCKS: u32 = 1024;
const J_REPLAY_MAX: usize = 16 * 1024 * 1024;
const J_REVOKE_MAX: usize = 65536;

#[derive(Clone, Copy, PartialEq, Eq)]
enum JPass {
    Scan,
    Revoke,
    Replay,
}

struct Jbd {
    block_size: usize,
    maxlen: u32,
    first: u32,
    sequence: u32,
    start: u32,
    csum: bool,
    bit64: bool,
    seed: u32,
}

fn replay_journal_blocks(
    block_size: usize,
    nblocks: u32,
    read_log: &mut dyn FnMut(u32) -> Result<Vec<u8>, &'static str>,
) -> Result<Vec<(u64, Vec<u8>)>, &'static str> {
    if block_size != 1024 && block_size != 2048 && block_size != 4096 {
        return Err("journal");
    }
    let sb = read_log(0)?;
    if sb.len() != block_size {
        return Err("journal");
    }
    let j = parse_jbd(&sb, block_size, nblocks)?;
    if j.start == 0 {
        return Ok(Vec::new());
    }
    let end = jbd_pass(
        &j,
        JPass::Scan,
        0,
        &mut Vec::new(),
        &mut Vec::new(),
        read_log,
    )?;
    let mut revokes = Vec::new();
    jbd_pass(
        &j,
        JPass::Revoke,
        end,
        &mut revokes,
        &mut Vec::new(),
        read_log,
    )?;
    let mut overlay = Vec::new();
    jbd_pass(
        &j,
        JPass::Replay,
        end,
        &mut revokes,
        &mut overlay,
        read_log,
    )?;
    Ok(overlay)
}

fn parse_jbd(sb: &[u8], block_size: usize, nblocks: u32) -> Result<Jbd, &'static str> {
    if sb.len() < 1024 {
        return Err("journal");
    }
    let magic = get_be32(sb, 0).ok_or("journal")?;
    let kind = get_be32(sb, 4).ok_or("journal")?;
    if magic != J_MAGIC || kind != J_SUPER_V2 {
        return Err("journal");
    }
    let bsize = get_be32(sb, 0x0C).ok_or("journal")?;
    if bsize as usize != block_size {
        return Err("journal");
    }
    let maxlen = get_be32(sb, 0x10).ok_or("journal")?;
    let first = get_be32(sb, 0x14).ok_or("journal")?;
    let sequence = get_be32(sb, 0x18).ok_or("journal")?;
    let start = get_be32(sb, 0x1C).ok_or("journal")?;
    let errno = get_be32(sb, 0x20).ok_or("journal")?;
    let compat = get_be32(sb, 0x24).ok_or("journal")?;
    let incompat = get_be32(sb, 0x28).ok_or("journal")?;
    let ro = get_be32(sb, 0x2C).ok_or("journal")?;
    if errno != 0 || compat != 0 || ro != 0 || incompat & !J_FEAT_OK != 0 {
        return Err("journal");
    }
    if maxlen < J_MIN_BLOCKS || maxlen > nblocks || first == 0 || first >= maxlen {
        return Err("journal");
    }
    if start != 0 && (start < first || start >= maxlen) {
        return Err("journal");
    }
    let csum = incompat & J_FEAT_CSUM3 != 0;
    let mut seed = 0u32;
    if csum {
        if sb[0x50] != 4 || !j_super_ok(sb) {
            return Err("journal checksum");
        }
        seed = crc32c(!0, &sb[0x30..0x40]);
    }
    Ok(Jbd {
        block_size,
        maxlen,
        first,
        sequence,
        start,
        csum,
        bit64: incompat & J_FEAT_64BIT != 0,
        seed,
    })
}

fn jbd_pass(
    j: &Jbd,
    goal: JPass,
    end_txn: u32,
    revokes: &mut Vec<(u64, u32)>,
    overlay: &mut Vec<(u64, Vec<u8>)>,
    read_log: &mut dyn FnMut(u32) -> Result<Vec<u8>, &'static str>,
) -> Result<u32, &'static str> {
    let mut next_id = j.sequence;
    let mut next_log = j.start;
    let mut need_time = false;
    let mut last_time = 0u64;
    let mut steps = 0u32;
    let mut overlay_bytes = 0usize;
    loop {
        if goal != JPass::Scan && tid_geq(next_id, end_txn) {
            break;
        }
        steps = steps.saturating_add(1);
        if steps > j.maxlen {
            return Err("journal");
        }
        let buf = read_log(next_log)?;
        if buf.len() != j.block_size {
            return Err("journal");
        }
        next_log = j_wrap(j, next_log)?;
        let magic = get_be32(&buf, 0).ok_or("journal")?;
        if magic != J_MAGIC {
            break;
        }
        let kind = get_be32(&buf, 4).ok_or("journal")?;
        let seq = get_be32(&buf, 8).ok_or("journal")?;
        if seq != next_id {
            break;
        }
        match kind {
            J_DESCRIPTOR => {
                if j.csum && !j_tail_ok(j.seed, &buf) {
                    if goal != JPass::Scan {
                        return Err("journal checksum");
                    }
                    need_time = true;
                }
                if goal != JPass::Replay {
                    let n = count_jtags(j, &buf)?;
                    next_log = j_skip(j, next_log, n)?;
                    continue;
                }
                j_replay_desc(
                    j,
                    &buf,
                    next_id,
                    &mut next_log,
                    revokes,
                    overlay,
                    &mut overlay_bytes,
                    read_log,
                )?;
            }
            J_COMMIT => {
                if goal != JPass::Scan {
                    next_id = next_id.wrapping_add(1);
                    continue;
                }
                let commit_time = get_be64(&buf, 48).unwrap_or(0);
                if need_time {
                    if commit_time >= last_time {
                        return Err("journal checksum");
                    }
                    break;
                }
                if j.csum && !j_commit_ok(j.seed, &buf) && !j_commit_partial_ok(j.seed, &buf) {
                    if commit_time < last_time {
                        break;
                    }
                    return Err("journal checksum");
                }
                last_time = commit_time;
                need_time = false;
                next_id = next_id.wrapping_add(1);
            }
            J_REVOKE => {
                if goal == JPass::Replay {
                    continue;
                }
                if goal == JPass::Scan && j.csum && !j_tail_ok(j.seed, &buf) {
                    need_time = true;
                }
                j_take_revoke(j, &buf, next_id, revokes, goal == JPass::Revoke)?;
            }
            _ => break,
        }
    }
    if goal == JPass::Scan {
        Ok(next_id)
    } else if next_id != end_txn {
        Err("journal")
    } else {
        Ok(next_id)
    }
}

fn j_replay_desc(
    j: &Jbd,
    buf: &[u8],
    seq: u32,
    next_log: &mut u32,
    revokes: &[(u64, u32)],
    overlay: &mut Vec<(u64, Vec<u8>)>,
    overlay_bytes: &mut usize,
    read_log: &mut dyn FnMut(u32) -> Result<Vec<u8>, &'static str>,
) -> Result<(), &'static str> {
    j_each_tag(j, buf, |tag, flags| {
        let fsblock = j_tag_block(tag, j.bit64)?;
        let at = *next_log;
        *next_log = j_wrap(j, *next_log)?;
        let mut data = read_log(at)?;
        if data.len() != j.block_size {
            return Err("journal");
        }
        if j_revoked(revokes, fsblock, seq) {
            return Ok(());
        }
        if j.csum && !j_tag_ok(j.seed, seq, &data, tag) {
            return Err("journal checksum");
        }
        if flags & J_ESCAPE != 0 {
            put_be32(&mut data, 0, J_MAGIC);
        }
        j_overlay_put(overlay, overlay_bytes, fsblock, data)
    })
}

fn j_each_tag(
    j: &Jbd,
    buf: &[u8],
    mut f: impl FnMut(&[u8], u32) -> Result<(), &'static str>,
) -> Result<(), &'static str> {
    let tb = j_tag_bytes(j);
    let mut limit = buf.len();
    if j.csum {
        limit = limit.saturating_sub(4);
    }
    let mut tagp = 12usize;
    while tagp + tb <= limit {
        let flags = u32::from(get_be16(buf, tagp + 6).ok_or("journal")?);
        f(&buf[tagp..tagp + tb], flags)?;
        tagp += tb;
        if flags & J_SAME_UUID == 0 {
            tagp = tagp.saturating_add(16);
        }
        if flags & J_LAST_TAG != 0 {
            break;
        }
    }
    Ok(())
}

fn count_jtags(j: &Jbd, buf: &[u8]) -> Result<u32, &'static str> {
    let mut n = 0u32;
    j_each_tag(j, buf, |_, _| {
        n = n.saturating_add(1);
        Ok(())
    })?;
    Ok(n)
}

fn j_tag_bytes(j: &Jbd) -> usize {
    if j.csum {
        16
    } else if j.bit64 {
        12
    } else {
        8
    }
}

fn j_tag_block(tag: &[u8], bit64: bool) -> Result<u64, &'static str> {
    let lo = u64::from(get_be32(tag, 0).ok_or("journal")?);
    if !bit64 {
        return Ok(lo);
    }
    let hi = u64::from(get_be32(tag, 8).ok_or("journal")?);
    Ok((hi << 32) | lo)
}

fn j_wrap(j: &Jbd, block: u32) -> Result<u32, &'static str> {
    let n = block.checked_add(1).ok_or("journal")?;
    if n >= j.maxlen {
        if j.first == 0 || j.first >= j.maxlen {
            return Err("journal");
        }
        Ok(j.first)
    } else {
        Ok(n)
    }
}

fn j_skip(j: &Jbd, mut block: u32, n: u32) -> Result<u32, &'static str> {
    let mut left = n;
    while left > 0 {
        block = j_wrap(j, block)?;
        left -= 1;
    }
    Ok(block)
}

/// Как Linux `tid_gt`: разность в кольце `u32`, старший бит — «не больше».
fn tid_gt(x: u32, y: u32) -> bool {
    x.wrapping_sub(y) as i32 > 0
}

fn tid_geq(x: u32, y: u32) -> bool {
    x.wrapping_sub(y) as i32 >= 0
}

fn j_revoked(table: &[(u64, u32)], block: u64, seq: u32) -> bool {
    table.iter().any(|(b, s)| *b == block && !tid_gt(seq, *s))
}

fn j_set_revoke(table: &mut Vec<(u64, u32)>, block: u64, seq: u32) -> Result<(), &'static str> {
    if let Some(slot) = table.iter_mut().find(|e| e.0 == block) {
        if tid_gt(seq, slot.1) {
            slot.1 = seq;
        }
        return Ok(());
    }
    if table.len() >= J_REVOKE_MAX {
        return Err("journal");
    }
    table.push((block, seq));
    Ok(())
}

fn j_take_revoke(
    j: &Jbd,
    buf: &[u8],
    seq: u32,
    table: &mut Vec<(u64, u32)>,
    record: bool,
) -> Result<(), &'static str> {
    let tail = if j.csum { 4 } else { 0 };
    let rcount = get_be32(buf, 12).ok_or("journal")? as usize;
    if rcount > j.block_size.saturating_sub(tail) {
        return Err("journal");
    }
    if !record {
        return Ok(());
    }
    let rec = if j.bit64 { 8 } else { 4 };
    let mut off = 16usize;
    while off + rec <= rcount {
        let block = if rec == 4 {
            u64::from(get_be32(buf, off).ok_or("journal")?)
        } else {
            get_be64(buf, off).ok_or("journal")?
        };
        off += rec;
        j_set_revoke(table, block, seq)?;
    }
    Ok(())
}

fn j_overlay_put(
    map: &mut Vec<(u64, Vec<u8>)>,
    used: &mut usize,
    block: u64,
    data: Vec<u8>,
) -> Result<(), &'static str> {
    match map.binary_search_by_key(&block, |e| e.0) {
        Ok(i) => map[i].1 = data,
        Err(i) => {
            if used.saturating_add(data.len()) > J_REPLAY_MAX {
                return Err("journal");
            }
            *used += data.len();
            map.insert(i, (block, data));
        }
    }
    Ok(())
}

fn j_super_ok(sb: &[u8]) -> bool {
    if sb.len() < 1024 {
        return false;
    }
    let provided = match get_be32(sb, 0xFC) {
        Some(v) => v,
        None => return false,
    };
    let mut tmp = sb[..1024].to_vec();
    tmp[0xFC..0x100].fill(0);
    crc32c(!0, &tmp) == provided
}

fn j_tail_ok(seed: u32, buf: &[u8]) -> bool {
    if buf.len() < 4 {
        return false;
    }
    let n = buf.len();
    let provided = match get_be32(buf, n - 4) {
        Some(v) => v,
        None => return false,
    };
    let mut tmp = buf.to_vec();
    tmp[n - 4..].fill(0);
    crc32c(seed, &tmp) == provided
}

fn j_commit_ok(seed: u32, buf: &[u8]) -> bool {
    if buf.len() < 20 {
        return false;
    }
    let provided = match get_be32(buf, 16) {
        Some(v) => v,
        None => return false,
    };
    let mut tmp = buf.to_vec();
    tmp[16..20].fill(0);
    crc32c(seed, &tmp) == provided
}

fn j_commit_partial_ok(seed: u32, buf: &[u8]) -> bool {
    if buf.len() < 60 {
        return false;
    }
    let provided = match get_be32(buf, 16) {
        Some(v) => v,
        None => return false,
    };
    let mut tmp = vec![0u8; buf.len()];
    tmp[..60].copy_from_slice(&buf[..60]);
    tmp[16..20].fill(0);
    crc32c(seed, &tmp) == provided
}

fn j_tag_ok(seed: u32, seq: u32, data: &[u8], tag: &[u8]) -> bool {
    let provided = match get_be32(tag, 12) {
        Some(v) => v,
        None => return false,
    };
    let c = crc32c(seed, &seq.to_be_bytes());
    crc32c(c, data) == provided
}

fn get_be16(buf: &[u8], off: usize) -> Option<u16> {
    let end = off.checked_add(2)?;
    if end > buf.len() {
        return None;
    }
    Some(u16::from_be_bytes([buf[off], buf[off + 1]]))
}

fn get_be32(buf: &[u8], off: usize) -> Option<u32> {
    let end = off.checked_add(4)?;
    if end > buf.len() {
        return None;
    }
    Some(u32::from_be_bytes([
        buf[off],
        buf[off + 1],
        buf[off + 2],
        buf[off + 3],
    ]))
}

fn get_be64(buf: &[u8], off: usize) -> Option<u64> {
    let end = off.checked_add(8)?;
    if end > buf.len() {
        return None;
    }
    let mut raw = [0u8; 8];
    raw.copy_from_slice(&buf[off..end]);
    Some(u64::from_be_bytes(raw))
}

fn put_be32(buf: &mut [u8], off: usize, v: u32) {
    buf[off..off + 4].copy_from_slice(&v.to_be_bytes());
}

/// `Ok(true)` — монтировать только на чтение. `Ok(false)` — обычный ext2.
/// `RECOVER` принимается только вместе с extents: журнал проигрывается в память.
/// meta_bg, encrypt и прочие incompat отвергаются.
/// `64bit` и `metadata_csum_seed` принимаются только вместе с extents.
fn features(incompat: u32, ro: u32) -> Result<bool, &'static str> {
    const EXTENTS: u32 = 0x40;
    const FLEX_BG: u32 = 0x200;
    const OK: u32 = FILETYPE | EXTENTS | FLEX_BG | BIT64 | CSUM_SEED | RECOVER;
    // sparse_super, large_file, huge_file, gdt_csum, dir_nlink, extra_isize,
    // metadata_csum. crc32c проверяет open, если стоит metadata_csum.
    // gdt_csum без metadata_csum проверяет дескриптор crc16.
    const RO_OK: u32 = 0x1 | 0x2 | 0x8 | 0x10 | 0x20 | 0x40 | 0x400;
    if incompat & !OK != 0 {
        return Err("incompat feature");
    }
    let extents = incompat & EXTENTS != 0;
    if (incompat & (FLEX_BG | BIT64 | CSUM_SEED | RECOVER)) != 0 && !extents {
        return Err("incompat feature");
    }
    if extents {
        if ro & !RO_OK != 0 {
            return Err("ro feature");
        }
        return Ok(true);
    }
    if ro != 0 {
        return Err("ro feature");
    }
    Ok(false)
}

/// Длина дескриптора группы. Без 64bit это 32 байта. С 64bit — `s_desc_size`
/// по смещению 254: не меньше 64, не больше блока, степень двойки.
fn desc_len(sb: &[u8], block_size: usize, bit64: bool) -> Result<usize, &'static str> {
    if !bit64 {
        return Ok(32);
    }
    if sb.len() < 256 {
        return Err("desc size");
    }
    let d = get_u16(sb, 254) as usize;
    if d < 64 || d > block_size || !d.is_power_of_two() {
        return Err("desc size");
    }
    Ok(d)
}

/// Номер блока inode-таблицы. Старшая половина лежит по смещению 0x28
/// и есть только в дескрипторе длиннее 32 байт.
fn gd_inode_table(gd: &[u8]) -> Result<u64, FsError> {
    if gd.len() < 12 {
        return Err(FsError::Io);
    }
    let lo = get_u32(gd, 8) as u64;
    let hi = if gd.len() >= 44 {
        get_u32(gd, 40) as u64
    } else {
        0
    };
    let table = (hi << 32) | lo;
    if table == 0 {
        Err(FsError::Io)
    } else {
        Ok(table)
    }
}

/// Логический блок → физический. `0` — дыра или unwritten (читать нулями).
/// Индексный узел: берётся запись с наибольшим `ei_block` не больше логического.
/// Старшие 16 бит номера блока (`ee_start_hi` / `ei_leaf_hi`) входят в адрес.
fn extent_map(
    node: &[u8],
    logical: u32,
    fetch: &mut dyn FnMut(u64) -> Result<Vec<u8>, FsError>,
) -> Result<u64, FsError> {
    extent_walk(node, logical, 5, fetch)
}

fn extent_walk(
    node: &[u8],
    logical: u32,
    left: u8,
    fetch: &mut dyn FnMut(u64) -> Result<Vec<u8>, FsError>,
) -> Result<u64, FsError> {
    if node.len() < 12 || get_u16(node, 0) != EXTENT_MAGIC {
        return Err(FsError::Io);
    }
    let entries = get_u16(node, 2) as usize;
    let max = get_u16(node, 4) as usize;
    let depth = get_u16(node, 6);
    if entries > max || 12 + entries * 12 > node.len() {
        return Err(FsError::Io);
    }
    if entries == 0 {
        return Ok(0);
    }
    if depth == 0 {
        for i in 0..entries {
            let off = 12 + i * 12;
            let ee_block = get_u32(node, off);
            let raw = get_u16(node, off + 4);
            let start_hi = get_u16(node, off + 6) as u64;
            let start_lo = get_u32(node, off + 8) as u64;
            let len = (raw & 0x7FFF) as u32;
            if len == 0 {
                return Err(FsError::Io);
            }
            let start = (start_hi << 32) | start_lo;
            if logical >= ee_block && logical - ee_block < len {
                if raw & 0x8000 != 0 || start == 0 {
                    return Ok(0);
                }
                return start
                    .checked_add((logical - ee_block) as u64)
                    .ok_or(FsError::Io);
            }
        }
        return Ok(0);
    }
    if left == 0 {
        return Err(FsError::Io);
    }
    let mut best_at = 0u32;
    let mut best_leaf = 0u64;
    let mut found = false;
    for i in 0..entries {
        let off = 12 + i * 12;
        let ei_block = get_u32(node, off);
        let leaf = ((get_u16(node, off + 8) as u64) << 32) | get_u32(node, off + 4) as u64;
        if ei_block <= logical && leaf == 0 {
            return Err(FsError::Io);
        }
        if ei_block <= logical && (!found || ei_block >= best_at) {
            found = true;
            best_at = ei_block;
            best_leaf = leaf;
        }
    }
    if !found {
        return Ok(0);
    }
    let child = fetch(best_leaf)?;
    extent_walk(&child, logical, left - 1, fetch)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{serial_print, serial_println};

    fn hdr(buf: &mut [u8], entries: u16, max: u16, depth: u16) {
        put_u16(buf, 0, EXTENT_MAGIC);
        put_u16(buf, 2, entries);
        put_u16(buf, 4, max);
        put_u16(buf, 6, depth);
    }

    fn leaf_at(buf: &mut [u8], i: usize, block: u32, len: u16, start: u32) {
        let off = 12 + i * 12;
        put_u32(buf, off, block);
        put_u16(buf, off + 4, len);
        put_u16(buf, off + 6, 0);
        put_u32(buf, off + 8, start);
    }

    fn idx_at(buf: &mut [u8], i: usize, block: u32, leaf: u32) {
        let off = 12 + i * 12;
        put_u32(buf, off, block);
        put_u32(buf, off + 4, leaf);
        put_u16(buf, off + 8, 0);
    }

    #[test_case]
    fn extent_tree_maps_leaves_holes_and_indexes() {
        serial_print!("test extent_tree_maps_leaves_holes_and_indexes... ");
        let mut node = [0u8; 60];
        hdr(&mut node, 2, 4, 0);
        leaf_at(&mut node, 0, 0, 2, 100);
        leaf_at(&mut node, 1, 10, 1, 50);
        let map = |node: &[u8], logical| extent_map(node, logical, &mut |_| Err(FsError::Io));
        assert_eq!(map(&node, 0).unwrap(), 100);
        assert_eq!(map(&node, 1).unwrap(), 101);
        assert_eq!(map(&node, 2).unwrap(), 0);
        assert_eq!(map(&node, 9).unwrap(), 0);
        assert_eq!(map(&node, 10).unwrap(), 50);
        assert_eq!(map(&node, 11).unwrap(), 0);

        leaf_at(&mut node, 0, 0, 0x8003, 10);
        assert_eq!(map(&node, 1).unwrap(), 0, "unwritten reads as a hole");

        leaf_at(&mut node, 0, 0, 1, 10);
        put_u16(&mut node, 12 + 6, 1);
        assert_eq!(map(&node, 0).unwrap(), (1u64 << 32) | 10);

        hdr(&mut node, 1, 4, 0);
        leaf_at(&mut node, 0, 0, 0, 10);
        assert!(extent_map(&node, 0, &mut |_| Err(FsError::Io)).is_err());

        node[0] = 0;
        assert!(extent_map(&node, 0, &mut |_| Err(FsError::Io)).is_err());

        let mut root = [0u8; 60];
        hdr(&mut root, 2, 4, 1);
        idx_at(&mut root, 0, 0, 7);
        idx_at(&mut root, 1, 100, 8);
        let mut leaf7 = [0u8; 60];
        hdr(&mut leaf7, 1, 4, 0);
        leaf_at(&mut leaf7, 0, 0, 4, 200);
        let mut leaf8 = [0u8; 60];
        hdr(&mut leaf8, 1, 4, 0);
        leaf_at(&mut leaf8, 0, 100, 2, 300);
        let phys = |logical: u32| {
            extent_map(&root, logical, &mut |b| match b {
                7 => Ok(leaf7.to_vec()),
                8 => Ok(leaf8.to_vec()),
                _ => Err(FsError::Io),
            })
        };
        assert_eq!(phys(3).unwrap(), 203);
        assert_eq!(phys(4).unwrap(), 0);
        assert_eq!(phys(100).unwrap(), 300);
        assert_eq!(phys(101).unwrap(), 301);
        assert!(phys(99).unwrap() == 0);

        let mut looped = [0u8; 60];
        hdr(&mut looped, 1, 4, 1);
        idx_at(&mut looped, 0, 0, 1);
        let mut fetches = 0u32;
        let cyc = extent_map(&looped, 0, &mut |b| {
            fetches += 1;
            assert_eq!(b, 1);
            Ok(looped.to_vec())
        });
        assert!(cyc.is_err());
        assert!(fetches <= 5);
        serial_println!("[ok]");
    }

    #[test_case]
    fn ext4_feature_mask_is_read_only() {
        serial_print!("test ext4_feature_mask_is_read_only... ");
        assert_eq!(features(0, 0).unwrap(), false);
        assert_eq!(features(FILETYPE, 0).unwrap(), false);
        assert!(features(FILETYPE, 0x1).is_err());
        assert_eq!(features(FILETYPE | 0x40, 0).unwrap(), true);
        assert_eq!(features(FILETYPE | 0x40 | 0x200, 0x400).unwrap(), true);
        assert_eq!(features(FILETYPE | 0x40 | BIT64 | 0x200, 0x1 | 0x2 | 0x400).unwrap(), true);
        // mke2fs 1.47 ext4: filetype, extent, flex_bg, 64bit, csum_seed
        // и ro sparse, large, huge, dir_nlink, extra_isize, metadata_csum.
        let mke2fs = FILETYPE | 0x40 | 0x200 | BIT64 | CSUM_SEED;
        let mke2fs_ro = 0x1 | 0x2 | 0x8 | 0x20 | 0x40 | 0x400;
        assert_eq!(features(mke2fs, mke2fs_ro).unwrap(), true);
        assert_eq!(
            features(0x40 | RECOVER, 0).unwrap(),
            true,
            "journal recovers read-only"
        );
        assert!(features(RECOVER, 0).is_err(), "recover without extents");
        assert!(features(BIT64, 0).is_err(), "64bit without extents");
        assert!(features(CSUM_SEED, 0).is_err(), "csum seed without extents");
        assert!(features(0x200, 0).is_err(), "flex_bg without extents");
        assert!(features(0x40, 0x200).is_err(), "bigalloc");
        let mut sb = [0u8; 1024];
        assert_eq!(desc_len(&sb, 4096, false).unwrap(), 32);
        put_u16(&mut sb, 254, 64);
        assert_eq!(desc_len(&sb, 4096, true).unwrap(), 64);
        put_u16(&mut sb, 254, 32);
        assert!(desc_len(&sb, 4096, true).is_err(), "desc shorter than 64");
        put_u16(&mut sb, 254, 48);
        assert!(desc_len(&sb, 4096, true).is_err(), "desc not a power of two");
        let mut gd = [0u8; 64];
        put_u32(&mut gd, 8, 0x11);
        put_u32(&mut gd, 40, 0x2);
        assert_eq!(gd_inode_table(&gd).unwrap(), (0x2u64 << 32) | 0x11);
        assert_eq!(gd_inode_table(&gd[..32]).unwrap(), 0x11);
        gd[8] = 0;
        gd[9] = 0;
        gd[10] = 0;
        gd[11] = 0;
        assert!(gd_inode_table(&gd[..32]).is_err());
        let mut inode = [0u8; 128];
        put_u32(&mut inode, 4, 0x1000);
        put_u32(&mut inode, 32, HUGE_FL);
        put_u32(&mut inode, 108, 2);
        assert_eq!(inode_bytes(&inode), (2u64 << 32) | 0x1000);
        serial_println!("[ok]");
    }

    fn replay_parts(parts: &[(u32, Vec<u8>)]) -> Result<Vec<(u64, Vec<u8>)>, &'static str> {
        replay_journal_blocks(1024, J_MIN_BLOCKS, &mut |i| {
            match parts.iter().find(|(n, _)| *n == i) {
                Some((_, b)) => Ok(b.clone()),
                None => Err("missing"),
            }
        })
    }

    fn jbd_super(
        start: u32,
        seq: u32,
        incompat: u32,
        compat: u32,
        errno: u32,
        csum: bool,
    ) -> Vec<u8> {
        let mut b = vec![0u8; 1024];
        put_be32(&mut b, 0, J_MAGIC);
        put_be32(&mut b, 4, J_SUPER_V2);
        put_be32(&mut b, 0x0C, 1024);
        put_be32(&mut b, 0x10, J_MIN_BLOCKS);
        put_be32(&mut b, 0x14, 1);
        put_be32(&mut b, 0x18, seq);
        put_be32(&mut b, 0x1C, start);
        put_be32(&mut b, 0x20, errno);
        put_be32(&mut b, 0x24, compat);
        put_be32(&mut b, 0x28, incompat);
        b[0x30..0x40].copy_from_slice(b"rudra-journal-uu");
        if csum {
            b[0x50] = 4;
            let sum = crc32c(!0, &b[..1024]);
            put_be32(&mut b, 0xFC, sum);
        }
        b
    }

    fn fill(byte: u8) -> Vec<u8> {
        vec![byte; 1024]
    }

    fn descr_plain(seq: u32, block: u32, flags: u16) -> Vec<u8> {
        let mut b = vec![0u8; 1024];
        put_be32(&mut b, 0, J_MAGIC);
        put_be32(&mut b, 4, J_DESCRIPTOR);
        put_be32(&mut b, 8, seq);
        put_be32(&mut b, 12, block);
        b[18..20].copy_from_slice(&flags.to_be_bytes());
        b
    }

    fn commit_block(seq: u32, time: u64, seed: Option<u32>) -> Vec<u8> {
        let mut b = vec![0u8; 1024];
        put_be32(&mut b, 0, J_MAGIC);
        put_be32(&mut b, 4, J_COMMIT);
        put_be32(&mut b, 8, seq);
        b[48..56].copy_from_slice(&time.to_be_bytes());
        if let Some(seed) = seed {
            let sum = crc32c(seed, &b);
            put_be32(&mut b, 16, sum);
        }
        b
    }

    fn revoke_block(seq: u32, blocks: &[u32]) -> Vec<u8> {
        let mut b = vec![0u8; 1024];
        put_be32(&mut b, 0, J_MAGIC);
        put_be32(&mut b, 4, J_REVOKE);
        put_be32(&mut b, 8, seq);
        let mut off = 16usize;
        for blk in blocks {
            put_be32(&mut b, off, *blk);
            off += 4;
        }
        put_be32(&mut b, 12, off as u32);
        b
    }

    fn descr_csum(seq: u32, block: u64, flags: u32, tag_sum: u32, seed: u32) -> Vec<u8> {
        let mut b = vec![0u8; 1024];
        put_be32(&mut b, 0, J_MAGIC);
        put_be32(&mut b, 4, J_DESCRIPTOR);
        put_be32(&mut b, 8, seq);
        put_be32(&mut b, 12, block as u32);
        put_be32(&mut b, 16, flags);
        put_be32(&mut b, 20, (block >> 32) as u32);
        put_be32(&mut b, 24, tag_sum);
        let sum = crc32c(seed, &b);
        let tail = b.len() - 4;
        put_be32(&mut b, tail, sum);
        b
    }

    fn tag_sum(seed: u32, seq: u32, data: &[u8]) -> u32 {
        crc32c(crc32c(seed, &seq.to_be_bytes()), data)
    }

    fn one(map: &[(u64, Vec<u8>)], block: u64) -> &[u8] {
        map.iter().find(|e| e.0 == block).expect("block").1.as_slice()
    }

    #[test_case]
    fn journal_replay_applies_only_a_committed_block() {
        serial_print!("test journal_replay_applies_only_a_committed_block... ");
        let feat = J_FEAT_REVOKE;
        let sb = jbd_super(1, 1, feat, 0, 0, false);
        let data = fill(0x5A);
        // scan читает блок после commit. Нулевой блок кончает журнал, дыра — ошибка ввода.
        let committed = replay_parts(&[
            (0, sb.clone()),
            (1, descr_plain(1, 40, J_LAST_TAG as u16)),
            (2, data.clone()),
            (3, commit_block(1, 10, None)),
            (4, vec![0u8; 1024]),
        ])
        .unwrap();
        assert_eq!(committed.len(), 1);
        assert_eq!(one(&committed, 40), data.as_slice());

        let open_end = replay_parts(&[
            (0, sb.clone()),
            (1, descr_plain(1, 40, J_LAST_TAG as u16)),
            (2, data.clone()),
            (3, vec![0u8; 1024]),
        ])
        .unwrap();
        assert!(open_end.is_empty(), "no commit means nothing applied");
        assert!(
            replay_parts(&[
                (0, sb.clone()),
                (1, descr_plain(1, 40, J_LAST_TAG as u16)),
                (2, data.clone()),
            ])
            .is_err(),
            "a missing log block is an IO error"
        );

        let mut two = descr_plain(1, 3, 0);
        put_be32(&mut two, 36, 4);
        let both = (J_SAME_UUID | J_LAST_TAG) as u16;
        two[42..44].copy_from_slice(&both.to_be_bytes());
        let pair = replay_parts(&[
            (0, sb.clone()),
            (1, two),
            (2, fill(0x31)),
            (3, fill(0x32)),
            (4, commit_block(1, 4, None)),
            (5, vec![0u8; 1024]),
        ])
        .unwrap();
        assert_eq!(pair.len(), 2, "uuid is not a log block");
        assert_eq!(one(&pair, 3)[0], 0x31);
        assert_eq!(one(&pair, 4)[0], 0x32);

        let newer = replay_parts(&[
            (0, sb.clone()),
            (1, descr_plain(1, 6, J_LAST_TAG as u16)),
            (2, fill(0x11)),
            (3, commit_block(1, 1, None)),
            (4, descr_plain(2, 6, J_LAST_TAG as u16)),
            (5, fill(0x22)),
            (6, commit_block(2, 2, None)),
            (7, vec![0u8; 1024]),
        ])
        .unwrap();
        assert_eq!(newer.len(), 1);
        assert_eq!(one(&newer, 6)[0], 0x22);

        let tail = replay_parts(&[
            (0, sb.clone()),
            (1, descr_plain(1, 4, J_LAST_TAG as u16)),
            (2, fill(0x11)),
            (3, commit_block(1, 1, None)),
            (4, descr_plain(2, 4, J_LAST_TAG as u16)),
            (5, fill(0x22)),
            (6, vec![0u8; 1024]),
        ])
        .unwrap();
        assert_eq!(tail.len(), 1);
        assert_eq!(one(&tail, 4)[0], 0x11, "uncommitted tail is dropped");

        let wrong_seq = replay_parts(&[
            (0, sb.clone()),
            (1, descr_plain(1, 4, J_LAST_TAG as u16)),
            (2, fill(0x11)),
            (3, commit_block(2, 1, None)),
        ])
        .unwrap();
        assert!(wrong_seq.is_empty(), "commit sequence must match");

        let same = replay_parts(&[
            (0, sb.clone()),
            (1, descr_plain(1, 15, J_LAST_TAG as u16)),
            (2, fill(0xAB)),
            (3, revoke_block(1, &[15])),
            (4, commit_block(1, 3, None)),
            (5, vec![0u8; 1024]),
        ])
        .unwrap();
        assert!(same.is_empty(), "revoke in the same transaction drops the write");

        let later = replay_parts(&[
            (0, sb.clone()),
            (1, descr_plain(1, 15, J_LAST_TAG as u16)),
            (2, fill(0xAB)),
            (3, revoke_block(1, &[15])),
            (4, commit_block(1, 3, None)),
            (5, descr_plain(2, 15, J_LAST_TAG as u16)),
            (6, fill(0xCD)),
            (7, commit_block(2, 4, None)),
            (8, vec![0u8; 1024]),
        ])
        .unwrap();
        assert_eq!(one(&later, 15)[0], 0xCD, "a write after revoke stays");

        let dropped = replay_parts(&[
            (0, sb.clone()),
            (1, descr_plain(1, 21, J_LAST_TAG as u16)),
            (2, fill(0x11)),
            (3, commit_block(1, 1, None)),
            (4, revoke_block(2, &[21])),
            (5, commit_block(2, 2, None)),
            (6, vec![0u8; 1024]),
        ])
        .unwrap();
        assert!(dropped.is_empty(), "later revoke drops the earlier write");

        let wrapped = replay_parts(&[
            (0, jbd_super(1023, 1, feat, 0, 0, false)),
            (1023, descr_plain(1, 7, J_LAST_TAG as u16)),
            (1, fill(0x11)),
            (2, commit_block(1, 8, None)),
            (3, vec![0u8; 1024]),
        ])
        .unwrap();
        assert_eq!(one(&wrapped, 7)[0], 0x11, "log wraps to s_first");

        let wide = (1u64 << 32) | 9;
        let high = replay_parts(&[
            (0, jbd_super(1, 1, feat | J_FEAT_64BIT, 0, 0, false)),
            (1, {
                let mut b = vec![0u8; 1024];
                put_be32(&mut b, 0, J_MAGIC);
                put_be32(&mut b, 4, J_DESCRIPTOR);
                put_be32(&mut b, 8, 1);
                put_be32(&mut b, 12, wide as u32);
                b[18..20].copy_from_slice(&(J_LAST_TAG as u16).to_be_bytes());
                put_be32(&mut b, 20, (wide >> 32) as u32);
                b
            }),
            (2, fill(0x44)),
            (3, commit_block(1, 1, None)),
            (4, vec![0u8; 1024]),
        ])
        .unwrap();
        assert_eq!(one(&high, wide)[0], 0x44, "64bit tag keeps the high half");
        let mut revoked_wide = replay_parts(&[
            (0, jbd_super(1, 1, feat | J_FEAT_64BIT, 0, 0, false)),
            (1, {
                let mut b = vec![0u8; 1024];
                put_be32(&mut b, 0, J_MAGIC);
                put_be32(&mut b, 4, J_DESCRIPTOR);
                put_be32(&mut b, 8, 1);
                put_be32(&mut b, 12, wide as u32);
                b[18..20].copy_from_slice(&(J_LAST_TAG as u16).to_be_bytes());
                put_be32(&mut b, 20, (wide >> 32) as u32);
                b
            }),
            (2, fill(0x44)),
            (3, commit_block(1, 1, None)),
            (4, {
                let mut b = vec![0u8; 1024];
                put_be32(&mut b, 0, J_MAGIC);
                put_be32(&mut b, 4, J_REVOKE);
                put_be32(&mut b, 8, 2);
                b[16..24].copy_from_slice(&wide.to_be_bytes());
                put_be32(&mut b, 12, 24);
                b
            }),
            (5, commit_block(2, 2, None)),
            (6, vec![0u8; 1024]),
        ])
        .unwrap();
        assert!(revoked_wide.is_empty(), "64bit revoke matches the full block");
        revoked_wide.clear();

        let seed = crc32c(!0, b"rudra-journal-uu");
        let csum_feat = feat | J_FEAT_CSUM3;
        let mut escaped = fill(0x22);
        escaped[..4].fill(0);
        let escape_flags = J_ESCAPE | J_LAST_TAG;
        let escaped_log = replay_parts(&[
            (0, jbd_super(1, 1, csum_feat, 0, 0, true)),
            (
                1,
                descr_csum(1, 12, escape_flags, tag_sum(seed, 1, &escaped), seed),
            ),
            (2, escaped.clone()),
            (3, commit_block(1, 9, Some(seed))),
            (4, vec![0u8; 1024]),
        ])
        .unwrap();
        assert_eq!(&one(&escaped_log, 12)[..4], &J_MAGIC.to_be_bytes());
        assert!(one(&escaped_log, 12)[4..].iter().all(|b| *b == 0x22));

        let payload = fill(0x77);
        let partial = {
            let mut header = vec![0u8; 1024];
            put_be32(&mut header, 0, J_MAGIC);
            put_be32(&mut header, 4, J_COMMIT);
            put_be32(&mut header, 8, 1);
            header[48..56].copy_from_slice(&9u64.to_be_bytes());
            let sum = crc32c(seed, &header);
            let mut b = vec![0xFFu8; 1024];
            b[..60].copy_from_slice(&header[..60]);
            put_be32(&mut b, 16, sum);
            b
        };
        let partial_log = replay_parts(&[
            (0, jbd_super(1, 1, csum_feat, 0, 0, true)),
            (1, descr_csum(1, 8, J_LAST_TAG, tag_sum(seed, 1, &payload), seed)),
            (2, payload.clone()),
            (3, partial),
            (4, vec![0u8; 1024]),
        ])
        .unwrap();
        assert_eq!(one(&partial_log, 8), payload.as_slice(), "partial commit counts");

        assert!(
            replay_parts(&[
                (0, jbd_super(1, 1, csum_feat, 0, 0, true)),
                (1, descr_csum(1, 8, J_LAST_TAG, 0xDEAD, seed)),
                (2, payload.clone()),
                (3, commit_block(1, 9, Some(seed))),
                (4, vec![0u8; 1024]),
            ])
            .is_err(),
            "bad tag checksum refuses"
        );
        let revoked_bad = replay_parts(&[
            (0, jbd_super(1, 1, csum_feat, 0, 0, true)),
            (1, descr_csum(1, 8, J_LAST_TAG, 0xDEAD, seed)),
            (2, payload.clone()),
            (3, {
                let mut b = revoke_block(1, &[8]);
                let sum = crc32c(seed, &b);
                let tail = b.len() - 4;
                put_be32(&mut b, tail, sum);
                b
            }),
            (4, commit_block(1, 9, Some(seed))),
            (5, vec![0u8; 1024]),
        ])
        .unwrap();
        assert!(
            revoked_bad.is_empty(),
            "revoked block skips the tag checksum"
        );

        let mut bad_tail = descr_csum(2, 4, J_LAST_TAG, tag_sum(seed, 2, &payload), seed);
        let last = bad_tail.len() - 1;
        bad_tail[last] ^= 0xFF;
        assert!(
            replay_parts(&[
                (0, jbd_super(1, 1, csum_feat, 0, 0, true)),
                (1, descr_csum(1, 4, J_LAST_TAG, tag_sum(seed, 1, &fill(0x11)), seed)),
                (2, fill(0x11)),
                (3, commit_block(1, 5000, Some(seed))),
                (4, bad_tail.clone()),
                (5, payload.clone()),
                (6, commit_block(2, 6000, Some(seed))),
            ])
            .is_err(),
            "newer commit after a bad descriptor refuses"
        );
        let stale = replay_parts(&[
            (0, jbd_super(1, 1, csum_feat, 0, 0, true)),
            (1, descr_csum(1, 4, J_LAST_TAG, tag_sum(seed, 1, &fill(0x11)), seed)),
            (2, fill(0x11)),
            (3, commit_block(1, 5000, Some(seed))),
            (4, bad_tail),
            (5, payload.clone()),
            (6, commit_block(2, 1, Some(seed))),
        ])
        .unwrap();
        assert_eq!(stale.len(), 1);
        assert_eq!(one(&stale, 4)[0], 0x11, "older commit time ends the log");

        let mut reads = 0u32;
        let clean = jbd_super(0, 1, csum_feat, 0, 0, true);
        let empty = replay_journal_blocks(1024, J_MIN_BLOCKS, &mut |i| {
            reads += 1;
            if i == 0 {
                Ok(clean.clone())
            } else {
                Err("missing")
            }
        })
        .unwrap();
        assert!(empty.is_empty());
        assert_eq!(reads, 1, "clean journal reads only the superblock");
        let mut flipped = clean.clone();
        flipped[0xFC] ^= 0xFF;
        assert!(replay_parts(&[(0, flipped)]).is_err(), "superblock checksum");

        let mut typed = jbd_super(0, 1, csum_feat, 0, 0, false);
        typed[0x50] = 1;
        let sum = crc32c(!0, &typed[..1024]);
        put_be32(&mut typed, 0xFC, sum);
        assert!(replay_parts(&[(0, typed)]).is_err(), "checksum type");
        assert!(replay_parts(&[(0, jbd_super(0, 1, 0x20, 0, 0, false))]).is_err(), "fast commit");
        assert!(replay_parts(&[(0, jbd_super(0, 1, feat, 1, 0, false))]).is_err(), "v1 checksum");
        assert!(replay_parts(&[(0, jbd_super(0, 1, feat, 0, 5, false))]).is_err(), "s_errno");
        let mut v1 = jbd_super(0, 1, feat, 0, 0, false);
        put_be32(&mut v1, 4, 3);
        assert!(replay_parts(&[(0, v1)]).is_err(), "v1 superblock");
        let mut short = jbd_super(0, 1, feat, 0, 0, false);
        put_be32(&mut short, 0x10, 100);
        assert!(replay_parts(&[(0, short)]).is_err(), "short journal");
        let mut magic = jbd_super(0, 1, feat, 0, 0, false);
        put_be32(&mut magic, 0, 0);
        assert!(replay_parts(&[(0, magic)]).is_err(), "magic");
        serial_println!("[ok]");
    }

    fn put_dirent(block: &mut [u8], off: usize, rec: usize, ino: u32, name: &[u8], ft: u8) {
        put_u32(block, off, ino);
        put_u16(block, off + 4, rec as u16);
        block[off + 6] = name.len() as u8;
        block[off + 7] = ft;
        block[off + 8..off + 8 + name.len()].copy_from_slice(name);
    }

    fn dir_names(block: &[u8]) -> Result<Vec<String>, FsError> {
        let mut names = Vec::new();
        scan_dirents(block, true, block.len(), &mut |b, local, rec, ino| {
            if ino == 0 {
                return Ok(false);
            }
            let nl = (b[local + 6] as usize).min(rec.saturating_sub(8));
            let raw = &b[local + 8..local + 8 + nl];
            if let Ok(s) = core::str::from_utf8(raw) {
                names.push(String::from(s));
            }
            Ok(false)
        })?;
        Ok(names)
    }

    #[test_case]
    fn ext4_htree_and_fast_symlink_read() {
        serial_print!("test ext4_htree_and_fast_symlink_read... ");
        // Корень htree: «..» закрывает индекс. Мусор дальше именами не становится.
        let mut root = [0xABu8; 128];
        put_dirent(&mut root, 0, 12, 2, b".", 2);
        put_dirent(&mut root, 12, 116, 2, b"..", 2);
        root[24..28].fill(0);
        root[28] = 1; // half_md4
        root[29] = 8; // info_length
        assert!(matches!(dx_kind(&root), Some(DxKind::Root)));
        assert_eq!(
            dir_names(&root).unwrap(),
            vec![String::from("."), String::from("..")]
        );

        // Внутренний узел — одна пустая запись на весь блок.
        let mut node = [0xABu8; 128];
        put_u32(&mut node, 0, 0);
        put_u16(&mut node, 4, 128);
        node[6] = 0;
        node[7] = 0;
        assert!(matches!(dx_kind(&node), Some(DxKind::Node)));
        assert!(dir_names(&node).unwrap().is_empty());

        // Лист: имя и хвост суммы. Хвост в список не попадает.
        let mut leaf = [0u8; 128];
        put_dirent(&mut leaf, 0, 116, 11, b"foo", 1);
        put_u16(&mut leaf, 116 + 4, 12);
        leaf[116 + 7] = FT_DIR_CSUM;
        assert!(dx_kind(&leaf).is_none());
        assert_eq!(dir_names(&leaf).unwrap(), vec![String::from("foo")]);

        let mut link = [0u8; 128];
        put_u16(&mut link, 0, 0xA1FF);
        put_u32(&mut link, 4, 4);
        link[40..44].copy_from_slice(b"/bin");
        assert_eq!(inline_symlink(&link), Some(&b"/bin"[..]));
        put_u32(&mut link, 32, EXTENTS_FL);
        assert!(inline_symlink(&link).is_none());
        put_u32(&mut link, 32, 0);
        put_u32(&mut link, 28, 8);
        assert!(inline_symlink(&link).is_none(), "blocks mean a real file");
        serial_println!("[ok]");
    }

    #[test_case]
    fn ext4_metadata_csum_matches_crc32c() {
        serial_print!("test ext4_metadata_csum_matches_crc32c... ");
        let sample = b"123456789";
        let raw = crc32c(!0, sample);
        assert_eq!(raw, 0x1cf9_6d7c, "linux crc32c register");
        assert_eq!(raw ^ !0, 0xE306_9283);
        assert_eq!(crc32c(crc32c(!0, &sample[..4]), &sample[4..]), raw);

        let mut sb = [0u8; 1024];
        sb[104..120].copy_from_slice(b"rudra-uuid-bytes");
        sb[0x173] = 1;
        let seed = crc32c(!0, &sb[104..120]);
        let sb_sum = crc32c(!0, &sb[..1020]);
        put_u32(&mut sb, 1020, sb_sum);
        assert!(super_csum_ok(&sb));
        sb[10] ^= 1;
        assert!(!super_csum_ok(&sb));

        let mut gd = [0u8; 64];
        put_u32(&mut gd, 8, 40);
        let mut c = crc32c(seed, &0u32.to_le_bytes());
        c = crc32c(c, &gd[..30]);
        c = crc32c(c, &[0, 0]);
        c = crc32c(c, &gd[32..]);
        put_u16(&mut gd, 30, c as u16);
        assert!(gd_csum_ok(seed, 0, &gd));
        gd[8] ^= 1;
        assert!(!gd_csum_ok(seed, 0, &gd));

        let mut inode = [0u8; 256];
        put_u16(&mut inode, 0, 0x81A4);
        put_u32(&mut inode, 100, 7);
        put_u16(&mut inode, 128, 32);
        let iseed = inode_csum_seed(seed, 12, 7);
        let mut ic = crc32c(iseed, &inode[..124]);
        ic = crc32c(ic, &[0, 0]);
        ic = crc32c(ic, &inode[126..128]);
        ic = crc32c(ic, &inode[128..130]);
        ic = crc32c(ic, &[0, 0]);
        ic = crc32c(ic, &inode[132..]);
        put_u16(&mut inode, 124, ic as u16);
        put_u16(&mut inode, 130, (ic >> 16) as u16);
        assert!(inode_csum_ok(iseed, &inode));
        inode[4] ^= 1;
        assert!(!inode_csum_ok(iseed, &inode));

        let mut leaf = [0u8; 128];
        put_dirent(&mut leaf, 0, 116, 11, b"foo", 1);
        put_u16(&mut leaf, 120, 12);
        leaf[123] = FT_DIR_CSUM;
        let dseed = inode_csum_seed(seed, 2, 9);
        let leaf_sum = crc32c(dseed, &leaf[..116]);
        put_u32(&mut leaf, 124, leaf_sum);
        assert!(dir_tail_csum_ok(dseed, &leaf));
        leaf[8] ^= 1;
        assert!(!dir_tail_csum_ok(dseed, &leaf));

        let mut dx = [0u8; 128];
        put_dirent(&mut dx, 0, 12, 2, b".", 2);
        put_dirent(&mut dx, 12, 116, 2, b"..", 2);
        dx[29] = 8;
        let limit = 11u16;
        put_u16(&mut dx, 32, limit);
        put_u16(&mut dx, 34, 1);
        put_u32(&mut dx, 36, 1);
        let tail = 32 + limit as usize * 8;
        let mut xc = crc32c(dseed, &dx[..32 + 8]);
        xc = crc32c(xc, &dx[tail..tail + 4]);
        xc = crc32c(xc, &[0, 0, 0, 0]);
        put_u32(&mut dx, tail + 4, xc);
        assert!(dx_csum_ok(dseed, &dx, DxKind::Root));
        dx[36] ^= 1;
        assert!(!dx_csum_ok(dseed, &dx, DxKind::Root));

        let mut ext = [0u8; 128];
        put_u16(&mut ext, 0, EXTENT_MAGIC);
        put_u16(&mut ext, 2, 1);
        let max = 9u16;
        put_u16(&mut ext, 4, max);
        let et = 12 + max as usize * 12;
        let ext_sum = crc32c(dseed, &ext[..et]);
        put_u32(&mut ext, et, ext_sum);
        assert!(extent_csum_ok(dseed, &ext));
        ext[12] ^= 1;
        assert!(!extent_csum_ok(dseed, &ext));
        serial_println!("[ok]");
    }

    #[test_case]
    fn ext4_gdt_csum_matches_crc16() {
        serial_print!("test ext4_gdt_csum_matches_crc16... ");
        assert_eq!(crc16(0, b"123456789"), 0xBB3D, "crc-16/arc");
        assert_eq!(crc16(0xFFFF, b"123456789"), 0x4B37, "crc-16/modbus");
        let uuid = b"rudra-uuid-bytes";
        let mut gd = [0u8; 32];
        put_u32(&mut gd, 8, 40);
        let mut c = crc16(0xFFFF, uuid);
        c = crc16(c, &7u32.to_le_bytes());
        c = crc16(c, &gd[..30]);
        put_u16(&mut gd, 30, c);
        assert!(gd_crc16_ok(uuid, 7, &gd));
        gd[8] ^= 1;
        assert!(!gd_crc16_ok(uuid, 7, &gd));

        // Хвост 64bit входит в сумму, а уже записанное поле суммы — нет.
        let mut wide = [0xA5u8; 64];
        let mut c = crc16(0xFFFF, uuid);
        c = crc16(c, &1u32.to_le_bytes());
        c = crc16(c, &wide[..30]);
        c = crc16(c, &wide[32..]);
        put_u16(&mut wide, 30, c);
        assert!(gd_crc16_ok(uuid, 1, &wide));
        wide[40] ^= 1;
        assert!(!gd_crc16_ok(uuid, 1, &wide));
        serial_println!("[ok]");
    }
}
