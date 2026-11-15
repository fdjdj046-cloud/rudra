use bootloader_api::info::{MemoryRegion, MemoryRegionKind};
use core::sync::atomic::Ordering;
use spin::{Mutex, Once};

/// Глобальный frame allocator: единственный инстанс, чтобы не выдать
/// одни и те же фреймы дважды (kernel heap, page tables, user tasks).
static FRAME_ALLOCATOR: Once<Mutex<BootInfoFrameAllocator>> = Once::new();

pub fn init_frame_allocator(memory_regions: &[MemoryRegion]) {
    FRAME_ALLOCATOR.call_once(|| Mutex::new(BootInfoFrameAllocator::init(memory_regions)));
}

/// Выполнить `f` с mutable-доступом к глобальному allocator'у.
pub fn with_frame_allocator<R>(f: impl FnOnce(&mut BootInfoFrameAllocator) -> R) -> R {
    // syscall_entry включает прерывания. Лок берём с выключенным IF:
    // обработчик, который тоже возьмёт allocator, иначе крутит его вечно.
    x86_64::instructions::interrupts::without_interrupts(|| {
        let mut guard = FRAME_ALLOCATOR
            .get()
            .expect("frame allocator not initialized")
            .lock();
        f(&mut guard)
    })
}
use x86_64::registers::control::Cr3;
use x86_64::structures::paging::{
    FrameAllocator, OffsetPageTable, PageTable, PhysFrame, Size4KiB,
};
use x86_64::{PhysAddr, VirtAddr};

/// Возвращает mutable-ссылку на активную P4-таблицу страниц.
///
/// # Safety
/// `phys_offset` должен указывать на корректное маппие всей физической памяти,
/// иначе UB.
pub unsafe fn active_level_4_table(phys_offset: VirtAddr) -> &'static mut PageTable {
    let (level_4_table_frame, _) = Cr3::read();
    let phys = level_4_table_frame.start_address();
    let virt = phys_offset + phys.as_u64();
    &mut *virt.as_mut_ptr()
}

/// Инициализирует OffsetPageTable поверх активной таблицы страниц.
///
/// # Safety
/// Требуется корректный маппинг всей физпамяти по `phys_offset` (загрузчик
/// обязан его предоставить — см. конфиг `mappings.physical_memory`).
pub unsafe fn init(phys_offset: VirtAddr) -> OffsetPageTable<'static> {
    OffsetPageTable::new(active_level_4_table(phys_offset), phys_offset)
}

const MAX_REGIONS: usize = 64;
/// Пустой свободный список. 1 не выровнен на страницу, поэтому не адрес кадра.
const FREE_EMPTY: u64 = 1;

/// Frame allocator по карте памяти загрузчика.
///
/// Свободные кадры лежат во вторгающемся списке: в первом слове страницы
/// (через physmap) записан физический адрес следующего. Выдача сначала
/// снимает кадр со списка, иначе сдвигает курсор на один кадр вперёд.
/// Курсор не перебирает `nth` на каждой выдаче.
///
/// `alloc_contiguous` курсор только двигает и не берёт кадры из списка:
/// список не гарантирует соседство. Брошенные префиксы возвращаются в список.
pub struct BootInfoFrameAllocator {
    memory_regions: [MemoryRegion; MAX_REGIONS],
    region_count: usize,
    cursor_region: usize,
    cursor: u64,
    free_head: u64,
    bump_count: usize,
}

fn align4k(addr: u64) -> u64 {
    (addr + 4095) & !4095
}

impl BootInfoFrameAllocator {
    pub fn init(memory_regions: &[MemoryRegion]) -> Self {
        let mut regions = [MemoryRegion {
            start: 0,
            end: 0,
            kind: MemoryRegionKind::Bootloader,
        }; MAX_REGIONS];
        let count = memory_regions.len().min(MAX_REGIONS);
        regions[..count].copy_from_slice(&memory_regions[..count]);
        let mut alloc = BootInfoFrameAllocator {
            memory_regions: regions,
            region_count: count,
            cursor_region: 0,
            cursor: 0,
            free_head: FREE_EMPTY,
            bump_count: 0,
        };
        alloc.skip_to_frame();
        alloc
    }

    /// Сколько кадров выдано с курсора, не из свободного списка.
    pub fn bump_count(&self) -> usize {
        self.bump_count
    }

    fn skip_to_frame(&mut self) {
        while self.cursor_region < self.region_count {
            let region = self.memory_regions[self.cursor_region];
            if region.kind == MemoryRegionKind::Usable {
                let start = if self.cursor < region.start {
                    align4k(region.start)
                } else {
                    self.cursor
                };
                if start.saturating_add(4096) <= region.end {
                    self.cursor = start;
                    return;
                }
            }
            self.cursor_region += 1;
            self.cursor = 0;
        }
    }

    /// Следующий кадр строго с курсора. Свободный список не трогает.
    pub fn bump_frame(&mut self) -> Option<PhysFrame> {
        if self.cursor_region >= self.region_count {
            return None;
        }
        let addr = self.cursor;
        let frame = PhysFrame::from_start_address(PhysAddr::new(addr)).ok()?;
        self.bump_count += 1;
        self.cursor = addr.saturating_add(4096);
        let region_end = self.memory_regions[self.cursor_region].end;
        if self.cursor.saturating_add(4096) > region_end {
            self.cursor_region += 1;
            self.cursor = 0;
            self.skip_to_frame();
        }
        Some(frame)
    }

    /// Вернуть кадр. Страница больше не должна быть в таблицах и в куче.
    pub fn deallocate_frame(&mut self, frame: PhysFrame) {
        let phys = frame.start_address().as_u64();
        if phys & 0xFFF != 0 {
            return;
        }
        let virt = crate::PHYS_OFFSET.load(Ordering::Relaxed).wrapping_add(phys);
        unsafe {
            core::ptr::write_volatile(virt as *mut u64, self.free_head);
        }
        self.free_head = phys;
    }
}

unsafe impl FrameAllocator<Size4KiB> for BootInfoFrameAllocator {
    fn allocate_frame(&mut self) -> Option<PhysFrame> {
        if self.free_head != FREE_EMPTY {
            let phys = self.free_head;
            let virt = crate::PHYS_OFFSET.load(Ordering::Relaxed).wrapping_add(phys);
            let next = unsafe { core::ptr::read_volatile(virt as *const u64) };
            self.free_head = next;
            return PhysFrame::from_start_address(PhysAddr::new(phys)).ok();
        }
        self.bump_frame()
    }
}

/// Несколько подряд идущих кадров. Нужны virtqueue и DMA: устройство видит
/// гостевой физический адрес и не умеет разрозненные страницы в одной очереди.
pub fn alloc_contiguous(pages: usize) -> Option<u64> {
    if pages == 0 {
        return None;
    }
    with_frame_allocator(|fa| {
        const MAX_DISCARD: usize = 256;
        let mut discarded = [0u64; MAX_DISCARD];
        let mut discarded_n = 0usize;
        let mut run_start = 0u64;
        let mut run_len = 0usize;
        for _ in 0..(pages + 64) {
            let Some(frame) = fa.bump_frame() else {
                free_run(fa, run_start, run_len);
                free_discarded(fa, &discarded, discarded_n);
                return None;
            };
            let addr = frame.start_address().as_u64();
            if run_len > 0 && addr == run_start + (run_len as u64) * 4096 {
                run_len += 1;
            } else {
                push_discard(&mut discarded, &mut discarded_n, fa, run_start, run_len);
                run_start = addr;
                run_len = 1;
            }
            if run_len == pages {
                free_discarded(fa, &discarded, discarded_n);
                return Some(run_start);
            }
        }
        free_run(fa, run_start, run_len);
        free_discarded(fa, &discarded, discarded_n);
        None
    })
}

fn push_discard(
    discarded: &mut [u64; 256],
    n: &mut usize,
    fa: &mut BootInfoFrameAllocator,
    start: u64,
    len: usize,
) {
    for i in 0..len {
        let addr = start + (i as u64) * 4096;
        if *n < discarded.len() {
            discarded[*n] = addr;
            *n += 1;
        } else if let Ok(frame) = PhysFrame::from_start_address(PhysAddr::new(addr)) {
            fa.deallocate_frame(frame);
        }
    }
}

fn free_discarded(fa: &mut BootInfoFrameAllocator, discarded: &[u64], n: usize) {
    for i in 0..n {
        if let Ok(frame) = PhysFrame::from_start_address(PhysAddr::new(discarded[i])) {
            fa.deallocate_frame(frame);
        }
    }
}

fn free_run(fa: &mut BootInfoFrameAllocator, start: u64, len: usize) {
    for i in 0..len {
        let addr = start + (i as u64) * 4096;
        if let Ok(frame) = PhysFrame::from_start_address(PhysAddr::new(addr)) {
            fa.deallocate_frame(frame);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{serial_print, serial_println};

    #[test_case]
    fn frame_free_does_not_advance_bump() {
        serial_print!("test frame_free_does_not_advance_bump... ");
        x86_64::instructions::interrupts::without_interrupts(|| {
            with_frame_allocator(|fa| {
                let mut frames = [None; 64];
                for slot in &mut frames {
                    *slot = fa.allocate_frame();
                    assert!(slot.is_some());
                }
                let mid = fa.bump_count();
                for frame in frames.into_iter().flatten() {
                    fa.deallocate_frame(frame);
                }
                for _ in 0..64 {
                    assert!(fa.allocate_frame().is_some());
                }
                assert_eq!(fa.bump_count(), mid);
            });
        });
        serial_println!("[ok]");
    }
}
