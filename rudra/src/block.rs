//! Блочный слой поверх virtio-blk. Сектор — 512 байт.
//!
//! `read_blocks` / `write_blocks` режут запрос на куски по 4 КиБ: столько
//! влезает в одну DMA-страницу и одну цепочку из трёх дескрипторов.
//!
//! Кэш чтения — 16 слотов по 4 КиБ. Ключ — LBA первого сектора. В кэш
//! попадает только кусок ровно 4096 байт с LBA, кратным 8. Запись слот
//! не обновляет: пересекающийся диапазон его сбрасывает, следующее чтение
//! идёт в устройство. Проверка записи ext2 поэтому не проходит по копии.
//! Это не page cache.

use spin::Mutex;

const SECTOR: usize = 512;
const CHUNK: usize = 4096;
const CACHE_SLOTS: usize = 16;
const SECTORS_PER_SLOT: u64 = (CHUNK / SECTOR) as u64;

#[derive(Clone, Copy)]
struct Slot {
    used: bool,
    lba: u64,
    data: [u8; CHUNK],
}

struct ReadCache {
    next: usize,
    slots: [Slot; CACHE_SLOTS],
}

impl ReadCache {
    const fn empty() -> Self {
        const BLANK: Slot = Slot {
            used: false,
            lba: 0,
            data: [0; CHUNK],
        };
        Self {
            next: 0,
            slots: [BLANK; CACHE_SLOTS],
        }
    }
}

static CACHE: Mutex<ReadCache> = Mutex::new(ReadCache::empty());

fn cache_copy_out(lba: u64, dst: &mut [u8]) -> bool {
    let c = CACHE.lock();
    let Some(s) = c.slots.iter().find(|s| s.used && s.lba == lba) else {
        return false;
    };
    dst.copy_from_slice(&s.data);
    true
}

fn cache_store(lba: u64, data: &[u8]) {
    let mut c = CACHE.lock();
    if let Some(s) = c.slots.iter_mut().find(|s| s.used && s.lba == lba) {
        s.data.copy_from_slice(data);
        return;
    }
    let i = c.next % CACHE_SLOTS;
    c.next = (c.next + 1) % CACHE_SLOTS;
    c.slots[i].used = true;
    c.slots[i].lba = lba;
    c.slots[i].data.copy_from_slice(data);
}

/// Сбросить слоты, чей диапазон секторов пересекается с `[lba, lba+nsectors)`.
fn cache_invalidate(lba: u64, nsectors: u64) {
    if nsectors == 0 {
        return;
    }
    let end = lba.saturating_add(nsectors);
    let mut c = CACHE.lock();
    for s in &mut c.slots {
        if !s.used {
            continue;
        }
        let s1 = s.lba.saturating_add(SECTORS_PER_SLOT);
        if s.lba < end && lba < s1 {
            s.used = false;
        }
    }
}

#[cfg(test)]
fn cache_reset() {
    let mut c = CACHE.lock();
    c.next = 0;
    for s in &mut c.slots {
        s.used = false;
        s.lba = 0;
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BlockError {
    NoDevice,
    Align,
    Range,
    Io,
}

pub fn present() -> bool {
    crate::virtio_blk::present()
}

pub fn sector_count() -> u64 {
    crate::virtio_blk::capacity().unwrap_or(0)
}

pub fn init() {
    if crate::virtio_blk::init().is_err() {
        crate::serial_println!("[virtio-blk] no device");
        crate::serial_println!("[root] recovery ramdisk");
        return;
    }
    // Не пишем в LBA 0.. : на общем образе там загрузчик.
    // Проверка записи — внутри свободного блока ext2.
    crate::ext2::mount();
}

pub fn read_blocks(lba: u64, buf: &mut [u8]) -> Result<(), BlockError> {
    if buf.is_empty() || buf.len() % SECTOR != 0 {
        return Err(BlockError::Align);
    }
    if !present() {
        return Err(BlockError::NoDevice);
    }
    let mut done = 0usize;
    let mut at = lba;
    while done < buf.len() {
        let n = (buf.len() - done).min(CHUNK);
        if n == CHUNK && at % SECTORS_PER_SLOT == 0 && cache_copy_out(at, &mut buf[done..done + n])
        {
            done += n;
            at += SECTORS_PER_SLOT;
            continue;
        }
        crate::virtio_blk::read_sectors(at, &mut buf[done..done + n]).map_err(map_err)?;
        if n == CHUNK && at % SECTORS_PER_SLOT == 0 {
            cache_store(at, &buf[done..done + n]);
        }
        done += n;
        at += (n / SECTOR) as u64;
    }
    Ok(())
}

pub fn write_blocks(lba: u64, buf: &[u8]) -> Result<(), BlockError> {
    if buf.is_empty() || buf.len() % SECTOR != 0 {
        return Err(BlockError::Align);
    }
    if !present() {
        return Err(BlockError::NoDevice);
    }
    let mut done = 0usize;
    let mut at = lba;
    while done < buf.len() {
        let n = (buf.len() - done).min(CHUNK);
        crate::virtio_blk::write_sectors(at, &buf[done..done + n]).map_err(map_err)?;
        // После успешной записи. Неудача оставляет старый слот: устройство не изменилось.
        cache_invalidate(at, (n / SECTOR) as u64);
        done += n;
        at += (n / SECTOR) as u64;
    }
    Ok(())
}

fn map_err(e: &str) -> BlockError {
    match e {
        "range" => BlockError::Range,
        "len" => BlockError::Align,
        "no dev" => BlockError::NoDevice,
        _ => BlockError::Io,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{serial_print, serial_println};

    #[test_case]
    fn block_read_cache_evicts_and_invalidates() {
        serial_print!("test block_read_cache_evicts_and_invalidates... ");
        cache_reset();
        let mut page = alloc::vec![0u8; CHUNK];
        let mut out = alloc::vec![0u8; CHUNK];
        page[0] = 0xAB;
        cache_store(0, &page);
        assert!(cache_copy_out(0, &mut out));
        assert_eq!(out[0], 0xAB);
        page[0] = 0xCD;
        cache_store(0, &page);
        assert!(cache_copy_out(0, &mut out));
        assert_eq!(out[0], 0xCD);
        for i in 1..=16 {
            page[0] = i as u8;
            cache_store((i as u64) * 8, &page);
        }
        assert!(!cache_copy_out(0, &mut out), "first slot was not evicted");
        assert!(cache_copy_out(8, &mut out));
        assert_eq!(out[0], 1);
        assert!(cache_copy_out(128, &mut out));
        assert_eq!(out[0], 16);

        cache_reset();
        cache_store(64, &page);
        cache_invalidate(68, 1);
        assert!(!cache_copy_out(64, &mut out), "sector inside the slot");
        cache_store(64, &page);
        cache_invalidate(80, 8);
        assert!(cache_copy_out(64, &mut out), "disjoint write dropped the slot");
        cache_invalidate(63, 2);
        assert!(!cache_copy_out(64, &mut out), "partial overlap at the start");
        cache_store(64, &page);
        cache_invalidate(64, 0);
        assert!(cache_copy_out(64, &mut out));
        serial_println!("[ok]");
    }
}
