//! Вывод на экран через framebuffer bootloader'а.
//!
//! Бэкенд для print!/println!: пишем одновременно в serial и сюда.
//! Растеризация — embedded-graphics + встроенный bitmap-шрифт 8x13.

use bootloader_api::info::{FrameBuffer, FrameBufferInfo, PixelFormat};
use core::fmt;
use embedded_graphics::pixelcolor::Bgr888;
use embedded_graphics::prelude::*;
use embedded_graphics::mono_font::{ascii::FONT_8X13, MonoTextStyle};
use embedded_graphics::text::Text;
use spin::{Mutex, Once};

pub static WRITER: Once<Mutex<FramebufferWriter>> = Once::new();

pub fn init(framebuffer: FrameBuffer) {
    WRITER.call_once(|| Mutex::new(FramebufferWriter::new(framebuffer)));
}

/// Вывод строки во все доступные бэкенды (serial + framebuffer).
#[doc(hidden)]
pub fn _print(args: fmt::Arguments) {
    crate::serial::_print(args);
    _print_screen(args);
}

/// Вывод только на экран (serial не трогаем) — для sys_write,
/// который сам управляет serial-выводом.
#[doc(hidden)]
pub fn _print_screen(args: fmt::Arguments) {
    use core::fmt::Write;
    if let Some(writer) = WRITER.get() {
        // Тот же риск, что у serial: лок нельзя оставлять вытесненному контексту.
        x86_64::instructions::interrupts::without_interrupts(|| {
            writer.lock().write_fmt(args).ok();
        });
    }
}

#[macro_export]
macro_rules! print {
    ($($arg:tt)*) => ($crate::framebuffer::_print(format_args!($($arg)*)));
}

#[macro_export]
macro_rules! println {
    () => ($crate::print!("\n"));
    ($fmt:expr) => ($crate::print!(concat!($fmt, "\n")));
    ($fmt:expr, $($arg:tt)*) => ($crate::print!(concat!($fmt, "\n"), $($arg)*));
}

/// DrawTarget поверх raw framebuffer (поддерживает Bgr888, 3–4 байта/пиксель).
struct FbTarget {
    buffer: &'static mut [u8],
    info: FrameBufferInfo,
}

impl FbTarget {
    fn write_pixel(&mut self, x: usize, y: usize, color: Bgr888) {
        let bpp = self.info.bytes_per_pixel;
        let offset = (y * self.info.stride + x) * bpp;
        if offset + bpp > self.buffer.len() {
            return;
        }
        let [r, g, b] = [color.r(), color.g(), color.b()];
        let px = &mut self.buffer[offset..offset + bpp];
        match self.info.pixel_format {
            PixelFormat::Bgr => {
                px[0] = b;
                px[1] = g;
                px[2] = r;
            }
            PixelFormat::Rgb => {
                px[0] = r;
                px[1] = g;
                px[2] = b;
            }
            _ => { /* остальные форматы (U8 и пр.) не поддерживаются */ }
        }
        if bpp == 4 {
            px[3] = 0xff;
        }
    }
}

impl OriginDimensions for FbTarget {
    fn size(&self) -> Size {
        Size::new(self.info.width as u32, self.info.height as u32)
    }
}

impl DrawTarget for FbTarget {
    type Color = Bgr888;
    type Error = ();

    fn draw_iter<I>(&mut self, pixels: I) -> Result<(), Self::Error>
    where
        I: IntoIterator<Item = Pixel<Self::Color>>,
    {
        for pixel in pixels {
            let (x, y) = (pixel.0.x, pixel.0.y);
            if x >= 0 && y >= 0 {
                self.write_pixel(x as usize, y as usize, pixel.1);
            }
        }
        Ok(())
    }
}

pub struct FramebufferWriter {
    target: FbTarget,
    style: MonoTextStyle<'static, Bgr888>,
    x: usize, // позиция в символах
    y: usize,
    char_w: usize,
    char_h: usize,
    cols: usize,
    rows: usize,
}

impl FramebufferWriter {
    pub fn new(framebuffer: FrameBuffer) -> Self {
        let info = framebuffer.info();
        let buffer = framebuffer.into_buffer();
        let char_w = FONT_8X13.character_size.width as usize;
        let char_h = FONT_8X13.character_size.height as usize;
        let mut writer = FramebufferWriter {
            target: FbTarget { buffer, info },
            style: MonoTextStyle::new(&FONT_8X13, Bgr888::WHITE),
            x: 0,
            y: 0,
            char_w,
            char_h,
            cols: info.width / char_w,
            rows: info.height / char_h,
        };
        writer.clear();
        writer
    }

    fn clear(&mut self) {
        let len = self.target.buffer.len();
        for byte in &mut self.target.buffer[..len] {
            *byte = 0;
        }
        self.x = 0;
        self.y = 0;
    }

    /// Сдвиг экрана вверх на одну строку шрифта.
    fn scroll(&mut self) {
        let stride = self.target.info.stride;
        let bpp = self.target.info.bytes_per_pixel;
        let row_bytes = stride * bpp;
        let height = self.target.info.height;
        let shift = self.char_h;

        unsafe {
            let base = self.target.buffer.as_mut_ptr();
            for y in shift..height {
                core::ptr::copy(base.add(y * row_bytes), base.add((y - shift) * row_bytes), row_bytes);
            }
            // Чистим нижние `shift` строк.
            core::ptr::write_bytes(base.add((height - shift) * row_bytes), 0, shift * row_bytes);
        }
        self.y = self.rows - 1;
    }

    fn newline(&mut self) {
        self.x = 0;
        self.y += 1;
        if self.y >= self.rows {
            self.scroll();
        }
    }

    fn put_char(&mut self, c: char) {
        if c == '\n' {
            self.newline();
            return;
        }
        if self.x >= self.cols {
            self.newline();
        }
        let px = (self.x * self.char_w) as i32;
        // ВАЖНО: point.y у Text — это baseline, а не верх глифа.
        // Глифы занимают примерно [baseline-8, baseline+2], поэтому baseline
        // ставим на (верх ячейки + char_h - 3): текст целиком внутри ячейки.
        let py = (self.y * self.char_h) as i32 + (self.char_h as i32 - 2);
        let mut buf = [0u8; 4];
        let s: &str = c.encode_utf8(&mut buf);
        Text::new(s, Point::new(px, py), self.style)
            .draw(&mut self.target)
            .ok();
        self.x += 1;
    }
}

impl fmt::Write for FramebufferWriter {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        for c in s.chars() {
            self.put_char(c);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{serial_print, serial_println};

    #[test_case]
    fn print_smoke() {
        serial_print!("test print_smoke... ");
        println!("framebuffer smoke test");
        serial_println!("[ok]");
    }
}
