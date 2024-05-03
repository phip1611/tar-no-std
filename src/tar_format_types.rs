#![allow(unused_imports)]

use core::fmt::{Debug, Formatter};
use core::num::ParseIntError;
use core::ptr::copy_nonoverlapping;
use core::str::{from_utf8, Utf8Error};
use num_traits::Num;

/// Base type for strings embedded in a Tar header. The length depends on the
/// context. The returned string
///
/// An optionally null terminated string. The contents are either:
/// 1. A fully populated string with no null termination or
/// 2. A partially populated string where the unused bytes are zero.
///
/// The content is likely to be UTF-8/ASCII, but that is not verified by this
/// type. The
#[derive(Copy, Clone, PartialEq, Eq)]
#[repr(C)]
pub struct TarFormatString<const N: usize> {
    bytes: [u8; N],
}

/// A Tar format string is a fixed length byte array containing UTF-8 bytes.
/// This string will be null terminated if it doesn't fill the entire array.
impl<const N: usize> TarFormatString<N> {
    /// Constructor.
    pub const fn new(bytes: [u8; N]) -> Self {
        if N == 0 {
            panic!("Array cannot be zero length");
        }
        Self { bytes }
    }

    /// True if the is string empty (ignoring NULL bytes).
    pub const fn is_empty(&self) -> bool {
        self.bytes[0] == 0
    }

    /// Returns the length of the bytes. This is either the full capacity `N`
    /// or the data until the first NULL byte.
    pub fn size(&self) -> usize {
        memchr::memchr(0, &self.bytes).unwrap_or(N)
    }

    /// Returns a str ref without terminating or intermediate NULL bytes. The
    /// string is truncated at the first NULL byte, in case not the full length
    /// was used.
    pub fn as_str(&self) -> Result<&str, Utf8Error> {
        from_utf8(&self.bytes[0..self.size()])
    }

    /// Append to end of string. Panics if there is not enough capacity.
    pub fn append<const S: usize>(&mut self, other: &TarFormatString<S>) {
        let resulting_length = self.size() + other.size();
        if resulting_length > N {
            panic!("Result to long for capacity {}", N);
        }

        unsafe {
            let dst = self.bytes.as_mut_ptr().add(self.size());
            let src = other.bytes.as_ptr();
            copy_nonoverlapping(src, dst, other.size());
        }

        if resulting_length < N {
            self.bytes[resulting_length] = 0;
        }
    }
}

impl<const N: usize> Debug for TarFormatString<N> {
    fn fmt(&self, f: &mut Formatter) -> core::fmt::Result {
        let sub_array = &self.bytes[0..self.size()];
        write!(
            f,
            "str='{}',byte_usage={}/{}",
            from_utf8(sub_array).unwrap(),
            self.size(),
            N
        )
    }
}

/// A number with a specified base. Trailing spaces in the string are ignored.
#[derive(Copy, Clone, PartialEq, Eq)]
#[repr(C)]
pub struct TarFormatNumber<const N: usize, const R: u32>(TarFormatString<N>);

/// An octal number. Trailing spaces in the string are ignored.
#[derive(Copy, Clone, PartialEq, Eq)]
#[repr(C)]
pub struct TarFormatOctal<const N: usize>(TarFormatNumber<N, 8>);

/// A decimal number. Trailing spaces in the string are ignored.
#[derive(Copy, Clone, PartialEq, Eq)]
#[repr(C)]
pub struct TarFormatDecimal<const N: usize>(TarFormatNumber<N, 10>);

impl<const N: usize, const R: u32> TarFormatNumber<N, R> {
    pub fn as_number<T>(&self) -> core::result::Result<T, T::FromStrRadixErr>
    where
        T: num_traits::Num,
    {
        memchr::memchr2(b' ', b'\0', &self.0.bytes).map_or_else(
            || T::from_str_radix(self.0.as_str().unwrap_or("0"), R),
            |idx| {
                T::from_str_radix(
                    from_utf8(&self.0.bytes[..idx]).unwrap_or("0"),
                    8,
                )
            },
        )
    }

    /// Returns the raw string describing this type.
    pub fn as_raw_str(&self) -> core::result::Result<&str, Utf8Error> {
        self.0.as_str()
    }
}

impl<const N: usize, const R: u32> Debug for TarFormatNumber<N, R> {
    fn fmt(&self, f: &mut Formatter) -> core::fmt::Result {
        let sub_array = &self.0.bytes[0..self.0.size()];
        match self.as_number::<u64>() {
            Err(msg) => write!(f, "{} [{}]", msg, from_utf8(sub_array).unwrap()),
            Ok(val) => write!(f, "{} [{}]", val, from_utf8(sub_array).unwrap()),
        }
    }
}

impl<const N: usize> Debug for TarFormatOctal<N> {
    fn fmt(&self, f: &mut Formatter) -> core::fmt::Result {
        self.0.fmt(f)
    }
}

impl<const N: usize> Debug for TarFormatDecimal<N> {
    fn fmt(&self, f: &mut Formatter) -> core::fmt::Result {
        self.0.fmt(f)
    }
}

impl<const N: usize> TarFormatDecimal<N> {
    pub fn as_number<T>(&self) -> core::result::Result<T, T::FromStrRadixErr>
    where
        T: num_traits::Num,
    {
        self.0.as_number::<T>()
    }

    pub fn as_raw_str(&self) -> core::result::Result<&str, Utf8Error> {
        self.0.as_raw_str()
    }
}

impl<const N: usize> TarFormatOctal<N> {
    pub fn as_number<T>(&self) -> core::result::Result<T, T::FromStrRadixErr>
    where
        T: num_traits::Num,
    {
        self.0.as_number::<T>()
    }

    pub fn as_raw_str(&self) -> core::result::Result<&str, Utf8Error> {
        self.0.as_raw_str()
    }
}

mod tests {
    use super::TarFormatString;

    use core::mem::size_of_val;

    #[test]
    fn test_empty_string() {
        let empty = TarFormatString::new([0]);
        assert_eq!(size_of_val(&empty), 1);
        assert!(empty.is_empty());
        assert_eq!(empty.size(), 0);
        assert_eq!(empty.as_str(), Ok(""));
    }

    #[test]
    fn test_one_byte_string() {
        let s = TarFormatString::new([65]);
        assert_eq!(size_of_val(&s), 1);
        assert!(!s.is_empty());
        assert_eq!(s.size(), 1);
        assert_eq!(s.as_str(), Ok("A"));
    }

    #[test]
    fn test_two_byte_string_nul_terminated() {
        let s = TarFormatString::new([65, 0]);
        assert_eq!(size_of_val(&s), 2);
        assert!(!s.is_empty());
        assert_eq!(s.size(), 1);
        assert_eq!(s.as_str(), Ok("A"));
    }

    #[test]
    #[allow(clippy::cognitive_complexity)]
    fn test_append() {
        let mut s = TarFormatString::new([0; 20]);

        // When adding a zero terminated string with one byte of zero
        s.append(&TarFormatString::new([0]));
        // Then the result is no change
        assert_eq!(size_of_val(&s), 20);
        assert!(s.is_empty());
        assert_eq!(s.size(), 0);
        assert_eq!(s.as_str(), Ok(""));

        // When adding ABC
        s.append(&TarFormatString::new([65, 66, 67]));
        // Then the string contains the additional 3 chars
        assert_eq!(size_of_val(&s), 20);
        assert!(!s.is_empty());
        assert_eq!(s.size(), 3);
        assert_eq!(s.as_str(), Ok("ABC"));

        s.append(&TarFormatString::new([68, 69, 70]));
        // Then the string contains the additional 3 chars
        assert_eq!(size_of_val(&s), 20);
        assert!(!s.is_empty());
        assert_eq!(s.size(), 6);
        assert_eq!(s.as_str(), Ok("ABCDEF"));

        s.append(&TarFormatString::new([b'A'; 12]));
        // Then the string contains the additional 12 chars
        assert_eq!(size_of_val(&s), 20);
        assert!(!s.is_empty());
        assert_eq!(s.size(), 18);
        assert_eq!(s.as_str(), Ok("ABCDEFAAAAAAAAAAAA"));

        s.append(&TarFormatString::new([b'A'; 1]));
        // Then the string contains the additional 1 chars
        assert_eq!(size_of_val(&s), 20);
        assert!(!s.is_empty());
        assert_eq!(s.size(), 19);
        assert_eq!(s.as_str(), Ok("ABCDEFAAAAAAAAAAAAA"));

        s.append(&TarFormatString::new([b'Z'; 1]));
        // Then the string contains the additional 1 char, is full and not null terminated
        assert_eq!(size_of_val(&s), 20);
        assert!(!s.is_empty());
        assert_eq!(s.size(), 20);
        assert_eq!(s.as_str(), Ok("ABCDEFAAAAAAAAAAAAAZ"));
    }
}
