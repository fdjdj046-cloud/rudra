use alloc::alloc::{GlobalAlloc, Layout};
use core::ptr::null_mut;
use spin::Mutex;
use x86_64::structures::paging::mapper::MapToError;
use x86_64::structures::paging::{
    FrameAllocator, Mapper, Page, PageTableFlags, Size4KiB,
};
use x86_64::VirtAddr;

pub const HEAP_START: usize = 0x_4444_4444_0000;
pub const HEAP_SIZE: usize = 48 * 1024 * 1024; // 48 MiB: ramdisk 8M + busybox-буферы + стеки задач

const MIN_BLOCK: usize = 16;

/// Куча со свободным списком. Блок не меньше 16 байт, указатель пользователя
/// совпадает с началом блока. Соседние свободные блоки сливаются по адресу.
pub struct HeapAllocator {
    heap_start: usize,
    heap_end: usize,
    next: usize,
    free_head: usize,
}

impl HeapAllocator {
    pub const fn new() -> Self {
        HeapAllocator {
            heap_start: 0,
            heap_end: 0,
            next: 0,
            free_head: 0,
        }
    }

    pub unsafe fn init(&mut self, heap_start: usize, heap_size: usize) {
        self.heap_start = heap_start;
        self.heap_end = heap_start + heap_size;
        self.next = heap_start;
        self.free_head = 0;
    }

    fn alloc_inner(&mut self, layout: Layout) -> *mut u8 {
        if layout.size() == 0 {
            return layout.align() as *mut u8;
        }
        let (size, align) = block_size(layout);
        if let Some(ptr) = self.take_free(size, align) {
            return ptr;
        }
        let start = align_up(self.next, align);
        let end = match start.checked_add(size) {
            Some(end) if end <= self.heap_end => end,
            _ => return null_mut(),
        };
        let front = start - self.next;
        if front >= MIN_BLOCK {
            self.insert_free(self.next, front);
        }
        self.next = end;
        start as *mut u8
    }

    fn dealloc_inner(&mut self, ptr: *mut u8, layout: Layout) {
        if ptr.is_null() || layout.size() == 0 {
            return;
        }
        let (size, _) = block_size(layout);
        let addr = ptr as usize;
        if addr < self.heap_start || addr.saturating_add(size) > self.heap_end {
            return;
        }
        self.insert_free(addr, size);
    }

    fn take_free(&mut self, size: usize, align: usize) -> Option<*mut u8> {
        let mut prev = 0usize;
        let mut cur = self.free_head;
        while cur != 0 {
            let cur_size = unsafe { core::ptr::read_volatile(cur as *const u64) } as usize;
            let cur_next = unsafe { core::ptr::read_volatile((cur + 8) as *const u64) } as usize;
            let aligned = align_up(cur, align);
            let front = aligned - cur;
            if front + size <= cur_size {
                let back = cur_size - front - size;
                if (front == 0 || front >= MIN_BLOCK) && (back == 0 || back >= MIN_BLOCK) {
                    if prev == 0 {
                        self.free_head = cur_next;
                    } else {
                        unsafe {
                            core::ptr::write_volatile((prev + 8) as *mut u64, cur_next as u64);
                        }
                    }
                    if front >= MIN_BLOCK {
                        self.insert_free(cur, front);
                    }
                    if back >= MIN_BLOCK {
                        self.insert_free(aligned + size, back);
                    }
                    return Some(aligned as *mut u8);
                }
            }
            prev = cur;
            cur = cur_next;
        }
        None
    }

    /// Вставить блок в список по возрастанию адреса и слить соседей.
    fn insert_free(&mut self, addr: usize, size: usize) {
        let mut prev = 0usize;
        let mut cur = self.free_head;
        while cur != 0 && cur < addr {
            prev = cur;
            cur = unsafe { core::ptr::read_volatile((cur + 8) as *const u64) } as usize;
        }
        let mut size = size;
        let mut next = cur;
        if cur != 0 && addr + size == cur {
            let cur_size = unsafe { core::ptr::read_volatile(cur as *const u64) } as usize;
            size += cur_size;
            next = unsafe { core::ptr::read_volatile((cur + 8) as *const u64) } as usize;
        }
        if prev != 0 {
            let prev_size = unsafe { core::ptr::read_volatile(prev as *const u64) } as usize;
            if prev + prev_size == addr {
                unsafe {
                    core::ptr::write_volatile(prev as *mut u64, (prev_size + size) as u64);
                    core::ptr::write_volatile((prev + 8) as *mut u64, next as u64);
                }
                return;
            }
            unsafe {
                core::ptr::write_volatile((prev + 8) as *mut u64, addr as u64);
            }
        } else {
            self.free_head = addr;
        }
        unsafe {
            core::ptr::write_volatile(addr as *mut u64, size as u64);
            core::ptr::write_volatile((addr + 8) as *mut u64, next as u64);
        }
    }
}

fn block_size(layout: Layout) -> (usize, usize) {
    let align = layout.align().max(MIN_BLOCK);
    let size = align_up(layout.size(), align).max(MIN_BLOCK);
    (size, align)
}

unsafe impl GlobalAlloc for Locked<HeapAllocator> {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        // Прерывание не должно аллоцировать, пока syscall держит кучу.
        x86_64::instructions::interrupts::without_interrupts(|| self.lock().alloc_inner(layout))
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        x86_64::instructions::interrupts::without_interrupts(|| {
            self.lock().dealloc_inner(ptr, layout);
        })
    }
}

pub struct Locked<A> {
    inner: Mutex<A>,
}

impl<A> Locked<A> {
    pub const fn new(inner: A) -> Self {
        Locked {
            inner: Mutex::new(inner),
        }
    }

    pub fn lock(&self) -> spin::MutexGuard<'_, A> {
        self.inner.lock()
    }
}

fn align_up(addr: usize, align: usize) -> usize {
    (addr + align - 1) & !(align - 1)
}

#[global_allocator]
static ALLOCATOR: Locked<HeapAllocator> = Locked::new(HeapAllocator::new());

/// Маппит страницы кучи и инициализирует глобальный аллокатор.
pub fn init_heap(
    mapper: &mut impl Mapper<Size4KiB>,
    frame_allocator: &mut impl FrameAllocator<Size4KiB>,
) -> Result<(), MapToError<Size4KiB>> {
    let page_range = {
        let heap_start = VirtAddr::new(HEAP_START as u64);
        let heap_end = heap_start + HEAP_SIZE as u64 - 1u64;
        let heap_start_page = Page::containing_address(heap_start);
        let heap_end_page = Page::containing_address(heap_end);
        Page::range_inclusive(heap_start_page, heap_end_page)
    };

    for page in page_range {
        let frame = frame_allocator
            .allocate_frame()
            .ok_or(MapToError::FrameAllocationFailed)?;
        let flags = PageTableFlags::PRESENT | PageTableFlags::WRITABLE;
        unsafe {
            mapper.map_to(page, frame, flags, frame_allocator)?.flush();
        }
    }

    unsafe {
        x86_64::instructions::interrupts::without_interrupts(|| {
            ALLOCATOR.lock().init(HEAP_START, HEAP_SIZE);
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{serial_print, serial_println};
    use alloc::alloc::{alloc, dealloc};

    #[test_case]
    fn heap_free_fills_again() {
        serial_print!("test heap_free_fills_again... ");
        let layout = Layout::from_size_align(64 * 1024, 16).unwrap();
        let mut ptrs = [null_mut::<u8>(); 640];
        let mut n = 0usize;
        while n < ptrs.len() {
            let p = unsafe { alloc(layout) };
            if p.is_null() {
                break;
            }
            unsafe { p.write(0xAB) };
            ptrs[n] = p;
            n += 1;
        }
        assert!(n > 200, "heap allocated only {}", n);
        for i in 0..n {
            unsafe { dealloc(ptrs[i], layout) };
        }
        for i in 0..n {
            let p = unsafe { alloc(layout) };
            assert!(!p.is_null(), "reclaim failed at {} of {}", i, n);
            unsafe { p.write(0xCD) };
            ptrs[i] = p;
        }
        for i in 0..n {
            unsafe { dealloc(ptrs[i], layout) };
        }
        serial_println!("[ok] {} x 64KiB", n);
    }
}
