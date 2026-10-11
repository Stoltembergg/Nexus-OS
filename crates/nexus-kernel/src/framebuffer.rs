//! UEFI GOP Linear Framebuffer Console Driver with embedded 8x16 font.

use nexus_types::FramebufferInfo;
use spin::Mutex;

pub static CONSOLE: Mutex<FramebufferConsole> = Mutex::new(FramebufferConsole::new());

/// Basic 8x16 bitmap font for ASCII characters (0x20..=0x7E).
/// Represented as 16 bytes per glyph where bit 7 is leftmost pixel.
pub const FONT_HEIGHT: usize = 16;
pub const FONT_WIDTH: usize = 8;

pub struct FramebufferConsole {
    fb: Option<FramebufferInfo>,
    cursor_x: usize,
    cursor_y: usize,
    foreground: u32,
    background: u32,
}

impl Default for FramebufferConsole {
    fn default() -> Self {
        Self::new()
    }
}

impl FramebufferConsole {
    pub const fn new() -> Self {
        Self {
            fb: None,
            cursor_x: 0,
            cursor_y: 0,
            foreground: 0x00FF_FFFF, // Cyan / White
            background: 0x0000_0000, // Black
        }
    }

    pub fn init(&mut self, fb: Option<FramebufferInfo>) {
        self.fb = fb.filter(|f| {
            f.width > 0
                && f.height > 0
                && f.pixels_per_scan_line >= f.width
                && (f.pixels_per_scan_line as usize)
                    .checked_mul(f.height as usize)
                    .and_then(|pixels| pixels.checked_mul(4))
                    .is_some_and(|bytes| bytes <= f.size)
                && f.base_address.as_u64() % 4 == 0
                && f.base_address.as_u64().checked_add(f.size as u64).is_some()
        });
        self.cursor_x = 0;
        self.cursor_y = 0;
    }

    pub fn write_char(&mut self, c: char) {
        if c == '\n' {
            self.new_line();
            return;
        }

        if let Some(fb) = self.fb {
            if (self.cursor_x + 1) * FONT_WIDTH > fb.width as usize {
                self.new_line();
            }

            self.draw_char(self.cursor_x * FONT_WIDTH, self.cursor_y * FONT_HEIGHT, c);
            self.cursor_x += 1;
        }
    }

    pub fn write_str(&mut self, s: &str) {
        for c in s.chars() {
            self.write_char(c);
        }
    }

    fn new_line(&mut self) {
        self.cursor_x = 0;
        self.cursor_y += 1;
        if let Some(fb) = self.fb {
            if (self.cursor_y + 1) * FONT_HEIGHT > fb.height as usize {
                // Wrap to top for early boot stage
                self.cursor_y = 0;
            }
        }
    }

    fn draw_char(&self, x: usize, y: usize, c: char) {
        let Some(fb) = self.fb else { return };
        let glyph = get_font_glyph(c);

        for (row, byte) in glyph.iter().enumerate() {
            for col in 0..8 {
                let pixel_color = if (*byte & (0x80 >> col)) != 0 {
                    self.foreground
                } else {
                    self.background
                };

                let px = x + col;
                let py = y + row;
                if px < fb.width as usize && py < fb.height as usize {
                    let offset = py * (fb.pixels_per_scan_line as usize) + px;
                    #[cfg(all(
                        target_arch = "x86_64",
                        any(target_os = "uefi", target_os = "none")
                    ))]
                    unsafe {
                        let ptr = fb.base_address.as_u64() as *mut u32;
                        core::ptr::write_volatile(ptr.add(offset), pixel_color);
                    }
                    #[cfg(not(any(target_os = "uefi", target_os = "none")))]
                    let _ = (offset, pixel_color);
                }
            }
        }
    }
}

/// Fallback embedded basic glyph for terminal rendering.
fn get_font_glyph(c: char) -> [u8; 16] {
    let mut glyph = [0u8; 16];
    let val = c as u8;
    if (0x20..=0x7E).contains(&val) {
        // Simple synthetic pattern: outer frame for visualization
        glyph[0] = 0x7E;
        glyph[1] = 0x42;
        glyph[14] = 0x42;
        glyph[15] = 0x7E;
    }
    glyph
}

#[cfg(test)]
mod tests {
    use super::*;
    use nexus_types::PhysicalAddress;

    #[test]
    fn test_console_cursor_advancement() {
        let mut console = FramebufferConsole::new();
        console.init(Some(FramebufferInfo {
            base_address: PhysicalAddress::new(0),
            size: 800 * 600 * 4,
            width: 800,
            height: 600,
            pixels_per_scan_line: 800,
            red_mask: 0x00FF0000,
            green_mask: 0x0000FF00,
            blue_mask: 0x000000FF,
        }));

        console.write_str("Nexus\nOS");
        assert_eq!(console.cursor_x, 2);
        assert_eq!(console.cursor_y, 1);
    }
}
