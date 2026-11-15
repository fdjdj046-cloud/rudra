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
        return;
    }
    if let Err(e) = read_lba0() {
        crate::serial_println!("[virtio-blk] LBA0 failed ({:?})", e);
        return;
    }
    match self_test() {
        Ok(()) => crate::serial_println!("[block] write/read LBA 200: ok"),
        Err(e) => crate::serial_println!("[block] write/read LBA 200 failed ({:?})", e),
    }
    crate::ext2::probe();
}

fn read_lba0() -> Result<(), BlockError> {
    let mut sec = [0u8; SECTOR];
    read_blocks(0, &mut sec)?;
    if &sec[..10] == b"RUDRA-DISK" {
        crate::serial_println!("[virtio-blk] LBA0: RUDRA-DISK");
    } else {
        crate::serial_println!(
            "[virtio-blk] LBA0 {:02x}{:02x}{:02x}{:02x} {:02x}{:02x}{:02x}{:02x}",
            sec[0], sec[1], sec[2], sec[3], sec[4], sec[5], sec[6], sec[7]
        );
    }
    Ok(())
}

/// Записать сектор далеко за ext2-томом и прочитать обратно.
fn self_test() -> Result<(), BlockError> {
    if sector_count() <= 200 {
        return Err(BlockError::Range);
    }
    let mut src = [0u8; SECTOR];
    src[..8].copy_from_slice(b"BLKWRITE");
    src[8] = 0xA5;
    write_blocks(200, &src)?;
    let mut dst = [0u8; SECTOR];
    read_blocks(200, &mut dst)?;
    if dst[..9] != src[..9] {
        return Err(BlockError::Io);
    }
    Ok(())
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
