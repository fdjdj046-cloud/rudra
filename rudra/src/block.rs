//! Блочный слой поверх virtio-blk. Сектор — 512 байт.
//!
//! `read_blocks` / `write_blocks` режут запрос на куски по 4 КиБ: столько
//! влезает в одну DMA-страницу и одну цепочку из трёх дескрипторов.

const SECTOR: usize = 512;
const CHUNK: usize = 4096;

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
        crate::virtio_blk::read_sectors(at, &mut buf[done..done + n]).map_err(map_err)?;
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
