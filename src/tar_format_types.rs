#![allow(unused_imports)]

use core::fmt::{Debug, Formatter};
use core::num::ParseIntError;
use core::ptr::copy_nonoverlapping;
use core::str::{from_utf8, Utf8Error};
use num_traits::Num;

/// Base type for strings embedded in a Tar header. The length depends on the
/// context. The returned string is likely to be UTF-8/ASCII, which is verified
/// by getters, such as [`TarFormatString::as_str`].
///
/// An optionally null terminated string. The contents are either:
/// 1. A fully populated string with no null termination or
/// 2. A partially populated string where the unused bytes are zero.
#[derive(Copy, Clone, PartialEq, Eq)]
#[repr(C)]
pub struct TarFormatString<const N: usize> {
    bytes: [u8; N],
}

/// A Tar format string is a fixed length byte array containing UTF-8 bytes.
/// This string will be null terminated if it doesn't fill the entire array.
impl<const N: usize> TarFormatString<N> {
    /// Constructor.
    ///
    /// # Panics
    /// Panics of `N` is zero, i.e., the underlying array has no length.
    #[must_use]
    pub const fn new(bytes: [u8; N]) -> Self {
        assert!(N > 0, "array should have at least one element");
        Self { bytes }
    }

    /// True if the is string empty (ignoring NULL bytes).
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.bytes[0] == 0
    }

    /// Returns the length of the payload in bytes. This is either the full
    /// capacity `N` or the data until the first NULL byte.
    #[must_use]
    pub fn size(&self) -> usize {
        self.bytes.iter().position(|&byte| byte == 0).unwrap_or(N)
    }

    /// Returns a str ref without terminating or intermediate NULL bytes. The
    /// string is truncated at the first NULL byte, in case not the full length
    /// was used.
    ///
    /// # Errors
    /// Returns a [`Utf8Error`] error for invalid strings.
    pub fn as_str(&self) -> Result<&str, Utf8Error> {
        from_utf8(&self.bytes[0..self.size()])
    }

    /// Wrapper around [`Self::as_str`] that stops as soon as the first space
    /// is found. This is necessary to properly parse certain Tar-style encoded
    /// numbers. Some ustar implementations pad spaces which prevents the proper
    /// parsing as number.
    ///
    /// # Errors
    /// Returns a [`Utf8Error`] error for invalid strings.
    pub fn as_str_until_first_space(&self) -> Result<&str, Utf8Error> {
        from_utf8(&self.bytes[0..self.size()]).map(|str| {
            let end_index_exclusive = str.find(' ').unwrap_or(str.len());
            &str[0..end_index_exclusive]
        })
    }

    /// Append to end of string.
    ///
    /// # Panics
    /// Panics if there is not enough capacity.
    pub fn append<const S: usize>(&mut self, other: &TarFormatString<S>) {
        let resulting_length = self.size() + other.size();

        assert!(resulting_length <= N, "Result to long for capacity {N}");

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
            "str='{:?}',byte_usage={}/{}",
            from_utf8(sub_array),
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

#[cfg(test)]
impl<const N: usize> TarFormatOctal<N> {
    #[must_use]
    pub const fn new(bytes: [u8; N]) -> Self {
        Self(TarFormatNumber::<N, 8>::new(bytes))
    }
}

/// A decimal number. Trailing spaces in the string are ignored.
#[derive(Copy, Clone, PartialEq, Eq)]
#[repr(C)]
pub struct TarFormatDecimal<const N: usize>(TarFormatNumber<N, 10>);

impl<const N: usize, const R: u32> TarFormatNumber<N, R> {
    #[cfg(test)]
    const fn new(bytes: [u8; N]) -> Self {
        Self(TarFormatString::<N> { bytes })
    }

    /// Interprets the underlying value as a number of the specified type using
    /// its respective radix.
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying value cannot be parsed as a number
    /// of the specified type and respective radix.
    pub fn as_number<T>(&self) -> core::result::Result<T, T::FromStrRadixErr>
    where
        T: num_traits::Num,
    {
        let str = self.0.as_str_until_first_space().unwrap_or("0");
        T::from_str_radix(str, R)
    }

    /// Returns the underlying [`TarFormatString`].
    #[must_use]
    pub const fn as_inner(&self) -> &TarFormatString<N> {
        &self.0
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
    /// Interprets the underlying value as a number of the specified type using
    /// its respective radix.
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying value cannot be parsed as a number
    /// of the specified type and respective radix.
    pub fn as_number<T>(&self) -> core::result::Result<T, T::FromStrRadixErr>
    where
        T: num_traits::Num,
    {
        self.0.as_number::<T>()
    }

    /// Returns the underlying [`TarFormatString`].
    #[must_use]
    pub const fn as_inner(&self) -> &TarFormatString<N> {
        self.0.as_inner()
    }
}

impl<const N: usize> TarFormatOctal<N> {
    /// Interprets the underlying value as a number of the specified type using
    /// its respective radix.
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying value cannot be parsed as a number
    /// of the specified type and respective radix.
    pub fn as_number<T>(&self) -> core::result::Result<T, T::FromStrRadixErr>
    where
        T: num_traits::Num,
    {
        self.0.as_number::<T>()
    }

    /// Returns the underlying [`TarFormatString`].
    #[must_use]
    pub const fn as_inner(&self) -> &TarFormatString<N> {
        self.0.as_inner()
    }
}

#[cfg(test)]
mod tar_format_string_tests {
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
        let s = TarFormatString::new([b'A']);
        assert_eq!(size_of_val(&s), 1);
        assert!(!s.is_empty());
        assert_eq!(s.size(), 1);
        assert_eq!(s.as_str(), Ok("A"));
    }

    #[test]
    fn test_two_byte_string_nul_terminated() {
        let s = TarFormatString::new([b'A', 0, b'B']);
        assert_eq!(size_of_val(&s), 3);
        assert!(!s.is_empty());
        assert_eq!(s.size(), 1);
        assert_eq!(s.as_str(), Ok("A"));
    }

    #[test]
    fn test_str_until_first_space() {
        let s = TarFormatString::new([b'A', b'B', b' ', b'X', 0]);
        assert_eq!(size_of_val(&s), 5);
        assert!(!s.is_empty());
        assert_eq!(s.size(), 4);
        assert_eq!(s.as_str(), Ok("AB X"));
        assert_eq!(s.as_str_until_first_space(), Ok("AB"));
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
        s.append(&TarFormatString::new([b'A', b'B', b'C']));
        // Then the string contains the additional 3 chars
        assert_eq!(size_of_val(&s), 20);
        assert!(!s.is_empty());
        assert_eq!(s.size(), 3);
        assert_eq!(s.as_str(), Ok("ABC"));

        s.append(&TarFormatString::new([b'D', b'E', b'F']));
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

#[cfg(test)]
mod tar_format_number_tests {
    use crate::{TarFormatDecimal, TarFormatNumber, TarFormatString};

    #[test]
    fn test_as_number_with_space_in_string() {
        let str = [b'0', b'1', b'0', b' ', 0];
        let str = TarFormatNumber::<5, 10>::new(str);
        assert_eq!(str.as_number::<u64>(), Ok(10));
    }
}
