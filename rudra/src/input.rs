use spin::Mutex;

/// Кольцевой буфер клавиатурного ввода: keyboard handler кладёт
/// декодированные символы, syscall read забирает.
const QUEUE_SIZE: usize = 256;

pub struct InputQueue {
    buf: [u8; QUEUE_SIZE],
    head: usize,
    len: usize,
}

impl InputQueue {
    const fn new() -> Self {
        InputQueue {
            buf: [0; QUEUE_SIZE],
            head: 0,
            len: 0,
        }
    }

    pub fn push(&mut self, byte: u8) {
        if self.len == QUEUE_SIZE {
            return; // переполнение: дропаем
        }
        let tail = (self.head + self.len) % QUEUE_SIZE;
        self.buf[tail] = byte;
        self.len += 1;
    }

    pub fn pop(&mut self) -> Option<u8> {
        if self.len == 0 {
            return None;
        }
        let b = self.buf[self.head];
        self.head = (self.head + 1) % QUEUE_SIZE;
        self.len -= 1;
        Some(b)
    }

    pub fn len(&self) -> usize {
        self.len
    }
}

pub static INPUT_QUEUE: Mutex<InputQueue> = Mutex::new(InputQueue::new());
