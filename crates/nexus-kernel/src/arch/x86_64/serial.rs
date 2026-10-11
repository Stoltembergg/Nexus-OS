//! 16550 UART COM1 Serial Port Driver for Nexus OS.

use spin::Mutex;

pub const COM1_PORT: u16 = 0x3F8;

pub struct SerialPort {
    port: u16,
}

impl SerialPort {
    pub const fn new(port: u16) -> Self {
        Self { port }
    }

    /// Initializes COM1 serial port to 115200 baud, 8N1, FIFO enabled.
    pub fn init(&self) {
        unsafe {
            // Disable interrupts
            self.outb(1, 0x00);
            // Enable DLAB (set baud rate divisor)
            self.outb(3, 0x80);
            // Set divisor to 1 (lo byte 1, hi byte 0) -> 115200 baud
            self.outb(0, 0x01);
            self.outb(1, 0x00);
            // 8 bits, no parity, one stop bit (8N1)
            self.outb(3, 0x03);
            // Enable FIFO, clear them, with 14-byte threshold
            self.outb(2, 0xC7);
            // IRQs enabled, RTS/DSR set
            self.outb(4, 0x0B);
        }
    }

    /// Checks if the transmit buffer is empty (bit 5 of Line Status Register).
    pub fn is_transmit_empty(&self) -> bool {
        unsafe { (self.inb(5) & 0x20) != 0 }
    }

    /// Writes a single byte over the serial line.
    pub fn write_byte(&self, byte: u8) {
        #[cfg(not(any(target_os = "uefi", target_os = "none")))]
        {
            let _ = byte;
        }
        #[cfg(any(target_os = "uefi", target_os = "none"))]
        {
            while !self.is_transmit_empty() {
                core::hint::spin_loop();
            }
            unsafe {
                self.outb(0, byte);
            }
        }
    }

    /// Writes a string slice over the serial line.
    pub fn write_str(&self, s: &str) {
        for byte in s.bytes() {
            if byte == b'\n' {
                self.write_byte(b'\r');
            }
            self.write_byte(byte);
        }
    }

    #[inline]
    unsafe fn outb(&self, offset: u16, val: u8) {
        #[cfg(all(target_arch = "x86_64", any(target_os = "uefi", target_os = "none")))]
        {
            let port = self.port + offset;
            core::arch::asm!(
                "out dx, al",
                in("dx") port,
                in("al") val,
                options(nomem, nostack, preserves_flags)
            );
        }
        #[cfg(not(all(target_arch = "x86_64", any(target_os = "uefi", target_os = "none"))))]
        {
            let _ = (self.port, offset, val);
        }
    }

    #[inline]
    unsafe fn inb(&self, offset: u16) -> u8 {
        #[cfg(all(target_arch = "x86_64", any(target_os = "uefi", target_os = "none")))]
        {
            let port = self.port + offset;
            let val: u8;
            core::arch::asm!(
                "in al, dx",
                in("dx") port,
                out("al") val,
                options(nomem, nostack, preserves_flags)
            );
            val
        }
        #[cfg(not(all(target_arch = "x86_64", any(target_os = "uefi", target_os = "none"))))]
        {
            let _ = (self.port, offset);
            0 // Host has no UART; do not invent hardware state
        }
    }
}

pub static SERIAL1: Mutex<SerialPort> = Mutex::new(SerialPort::new(COM1_PORT));

#[macro_export]
macro_rules! serial_print {
    ($($arg:tt)*) => {
        $crate::arch::x86_64::serial::_print(format_args!($($arg)*))
    };
}

#[macro_export]
macro_rules! serial_println {
    () => ($crate::serial_print!("\n"));
    ($($arg:tt)*) => ($crate::serial_print!("{}\n", format_args!($($arg)*)));
}

pub fn _print(args: core::fmt::Arguments) {
    use core::fmt::Write;
    struct SerialWriter;
    impl Write for SerialWriter {
        fn write_str(&mut self, s: &str) -> core::fmt::Result {
            SERIAL1.lock().write_str(s);
            Ok(())
        }
    }
    let mut writer = SerialWriter;
    let _ = writer.write_fmt(args);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_serial_port_construction() {
        let port = SerialPort::new(COM1_PORT);
        assert_eq!(port.port, 0x3F8);
        assert!(!port.is_transmit_empty());
    }
}
