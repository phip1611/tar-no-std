/// An optionally null terminated string. The contents are either:
/// 1. A fully populated string with no null termination or
/// 2. A partially populated string where the unused bytes are zero.


/// A C-String that is stored in a static array. There is always a terminating
/// NULL-byte.
///
/// The content is likely to be UTF-8/ASCII, but that is not verified by this
/// type.
#[derive(Copy, Clone)]
#[repr(C)]
pub struct TarFormatString<const N: usize> {
    bytes: [u8; N]
}

use core::fmt::{Debug, Formatter, Result};
use core::str::from_utf8;
use core::ptr::copy_nonoverlapping;

impl<const N: usize> TarFormatString<N> {
    /// Constructor.
    pub fn new(bytes: [u8; N]) -> Self {
        if N == 0 {
            panic!("Array cannot be zero length");
        }
        Self {bytes }
    }

    /// Returns if the string empty (ignoring NULL bytes).
    pub const fn is_empty(&self) -> bool {
        self.bytes[0] == 0
    }

    // Returns if the string is NULL terminated
    pub const fn is_nul_terminated(&self) -> bool {
        return self.bytes[N-1] == 0;
    }

    /// Returns the length of the string (ignoring NULL bytes).
    pub fn len(&self) -> usize {
        if self.is_nul_terminated() {
            memchr::memchr(0, &self.bytes).unwrap()
        } else {
            N
        }
    }

    /// Returns a str ref without NULL bytes
    pub fn as_str(&self) -> &str
    {
        from_utf8(&self.bytes[0..self.len()]).expect("byte array is not UTF-8")
    }

    /// Append to end of string
    pub fn append<const S: usize>(&mut self, other: &TarFormatString<S>) {
        let resulting_length = self.len() + other.len();
        if resulting_length > N {
            panic!("Result to long for capacity {}", N);
        }

        unsafe {
            let dst = self.bytes.as_mut_ptr().add(self.len());
            let src = other.bytes.as_ptr();
            copy_nonoverlapping(src, dst, other.len());
            if resulting_length < N {
                self.bytes[resulting_length] = 0;
            }
        }
    }
}

impl<const N: usize> Debug for TarFormatString<N> {
    fn fmt(&self, f: &mut Formatter) -> Result {
        let sub_array: &[u8] = &self.bytes[0 .. self.len()];
        write!(f, "{:?}", sub_array.to_vec())
    }
}

mod tests
{
    use super::*;
    use core::mem::size_of_val;

    #[test]
    fn test_empty_string()
    {
        let empty = TarFormatString::new([0]);
        assert_eq!(size_of_val(&empty), 1);
        assert!(empty.is_empty());
        assert_eq!(empty.len(), 0);
        assert!(empty.is_nul_terminated());
        assert_eq!(empty.as_str(), "");
    }

    #[test]
    fn test_one_byte_string()
    {
        let s = TarFormatString::new([65]);
        assert_eq!(size_of_val(&s), 1);
        assert!(!s.is_empty());
        assert_eq!(s.len(), 1);
        assert!(!s.is_nul_terminated());
        assert_eq!(s.as_str(), "A");
    }

    #[test]
    fn test_two_byte_string_nul_terminated()
    {
        let s = TarFormatString::new([65, 0]);
        assert_eq!(size_of_val(&s), 2);
        assert!(!s.is_empty());
        assert_eq!(s.len(), 1);
        assert!(s.is_nul_terminated());
        assert_eq!(s.as_str(), "A");
    }

    #[test]
    fn test_append()
    {
        let mut s = TarFormatString::new([0;20]);

        // When adding a zero terminated string with one byte of zero
        s.append(&TarFormatString::new([0]));
        // Then the result is no change
        assert_eq!(size_of_val(&s), 20);
        assert!(s.is_empty());
        assert_eq!(s.len(), 0);
        assert!(s.is_nul_terminated());
        assert_eq!(s.as_str(), "");


        s.append(&TarFormatString::new([65, 66, 67]));
        assert_eq!(size_of_val(&s), 20);
        assert!(!s.is_empty());
        assert_eq!(s.len(), 3);
        assert!(s.is_nul_terminated());
        assert_eq!(s.as_str(), "ABC");

        s.append(&TarFormatString::new([68, 69, 70]));
        assert_eq!(size_of_val(&s), 20);
        assert!(!s.is_empty());
        assert_eq!(s.len(), 6);
        assert!(s.is_nul_terminated());
        assert_eq!(s.as_str(), "ABCDEF");

        assert_eq!(s.len() + 14, 20);

        s.append(&TarFormatString::new([b'A'; 12]));
        assert_eq!(size_of_val(&s), 20);
        assert!(!s.is_empty());
        assert_eq!(s.len(), 18);
        assert!(s.is_nul_terminated());
        assert_eq!(s.as_str(), "ABCDEFAAAAAAAAAAAA");

        s.append(&TarFormatString::new([b'A'; 1]));
        assert_eq!(size_of_val(&s), 20);
        assert!(!s.is_empty());
        assert_eq!(s.len(), 19);
        assert!(s.is_nul_terminated());
        assert_eq!(s.as_str(), "ABCDEFAAAAAAAAAAAAA");

        s.append(&TarFormatString::new([b'Z'; 1]));
        assert_eq!(size_of_val(&s), 20);
        assert!(!s.is_empty());
        assert_eq!(s.len(), 20);
        assert!(!s.is_nul_terminated());
        assert_eq!(s.as_str(), "ABCDEFAAAAAAAAAAAAAZ");
    }    

}