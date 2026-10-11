//! Windows NT Status Codes (NTSTATUS).

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(transparent)]
pub struct NtStatus(pub u32);

impl NtStatus {
    pub const STATUS_SUCCESS: Self = Self(0x00000000);
    pub const STATUS_UNSUCCESSFUL: Self = Self(0xC0000001);
    pub const STATUS_NOT_IMPLEMENTED: Self = Self(0xC0000002);
    pub const STATUS_INVALID_INFO_CLASS: Self = Self(0xC0000003);
    pub const STATUS_ACCESS_VIOLATION: Self = Self(0xC0000005);
    pub const STATUS_INVALID_HANDLE: Self = Self(0xC0000008);
    pub const STATUS_INVALID_PARAMETER: Self = Self(0xC000000D);
    pub const STATUS_NO_MEMORY: Self = Self(0xC0000017);
    pub const STATUS_ILLEGAL_INSTRUCTION: Self = Self(0xC000001D);
    pub const STATUS_BUFFER_TOO_SMALL: Self = Self(0xC0000023);
    pub const STATUS_IMAGE_ALREADY_LOADED: Self = Self(0xC000010E);
    pub const STATUS_INVALID_IMAGE_FORMAT: Self = Self(0xC000007B);
    pub const STATUS_NOT_FOUND: Self = Self(0xC0000225);

    /// Checks if the status represents success (severity code 0x0).
    #[inline]
    pub const fn is_success(&self) -> bool {
        (self.0 >> 30) == 0
    }

    /// Checks if the status represents an error (severity code 0x3).
    #[inline]
    pub const fn is_error(&self) -> bool {
        (self.0 >> 30) == 3
    }

    /// Returns human-readable description of known status codes.
    pub const fn description(&self) -> &'static str {
        match self.0 {
            0x00000000 => "STATUS_SUCCESS",
            0xC0000001 => "STATUS_UNSUCCESSFUL",
            0xC0000002 => "STATUS_NOT_IMPLEMENTED",
            0xC0000003 => "STATUS_INVALID_INFO_CLASS",
            0xC0000005 => "STATUS_ACCESS_VIOLATION",
            0xC0000008 => "STATUS_INVALID_HANDLE",
            0xC000000D => "STATUS_INVALID_PARAMETER",
            0xC0000017 => "STATUS_NO_MEMORY",
            0xC000001D => "STATUS_ILLEGAL_INSTRUCTION",
            0xC0000023 => "STATUS_BUFFER_TOO_SMALL",
            0xC000007B => "STATUS_INVALID_IMAGE_FORMAT",
            0xC000010E => "STATUS_IMAGE_ALREADY_LOADED",
            0xC0000225 => "STATUS_NOT_FOUND",
            _ => "STATUS_UNKNOWN",
        }
    }
}

impl core::fmt::Display for NtStatus {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{:#010X} ({})", self.0, self.description())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ntstatus_success() {
        assert!(NtStatus::STATUS_SUCCESS.is_success());
        assert!(!NtStatus::STATUS_SUCCESS.is_error());
    }

    #[test]
    fn test_ntstatus_error() {
        assert!(NtStatus::STATUS_ACCESS_VIOLATION.is_error());
        assert!(!NtStatus::STATUS_ACCESS_VIOLATION.is_success());
    }
}
