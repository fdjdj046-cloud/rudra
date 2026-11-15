use bootloader_api::info::{MemoryRegion, MemoryRegionKind};
use spin::{Mutex, Once};

/// Глобальный frame allocator: единственный инстанс, чтобы не выдать
/// одни и те же фреймы дважды (kernel heap, page tables, user tasks).
static FRAME_ALLOCATOR: Once<Mutex<BootInfoFrameAllocator>> = Once::new();

pub fn init_frame_allocator(memory_regions: &[MemoryRegion]) {
    FRAME_ALLOCATOR.call_once(|| Mutex::new(BootInfoFrameAllocator::init(memory_regions)));
}

/// Выполнить `f` с mutable-доступом к глобальному allocator'у.
pub fn with_frame_allocator<R>(f: impl FnOnce(&mut BootInfoFrameAllocator) -> R) -> R {
    let mut guard = FRAME_ALLOCATOR
        .get()
        .expect("frame allocator not initialized")
        .lock();
    f(&mut guard)
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

/// Frame allocator, итерирующий usable-регионы карты памяти.
/// Владеет копией карты в фиксированном массиве — работает и до
/// инициализации кучи (поэтому не Vec).
pub struct BootInfoFrameAllocator {
    memory_regions: [MemoryRegion; MAX_REGIONS],
    region_count: usize,
    next: usize,
}

impl BootInfoFrameAllocator {
    pub fn init(memory_regions: &[MemoryRegion]) -> Self {
        let mut regions = [MemoryRegion {
            start: 0,
            end: 0,
            kind: MemoryRegionKind::Bootloader, // любой не-Usable
        }; MAX_REGIONS];
        let count = memory_regions.len().min(MAX_REGIONS);
        regions[..count].copy_from_slice(&memory_regions[..count]);
        BootInfoFrameAllocator {
            memory_regions: regions,
            region_count: count,
            next: 0,
        }
    }

    fn usable_frames(&self) -> impl Iterator<Item = PhysFrame> + '_ {
        let regions = self.memory_regions[..self.region_count].iter();
        let usable = regions.filter(|r| r.kind == MemoryRegionKind::Usable);
        let addr_ranges = usable.map(|r| r.start..r.end);
        let frame_addrs = addr_ranges.flat_map(|r| r.step_by(4096));
        frame_addrs.map(|addr| PhysFrame::containing_address(PhysAddr::new(addr)))
    }
}

unsafe impl FrameAllocator<Size4KiB> for BootInfoFrameAllocator {
    fn allocate_frame(&mut self) -> Option<PhysFrame> {
        let frame = self.usable_frames().nth(self.next);
        self.next += 1;
        frame
    }
}
