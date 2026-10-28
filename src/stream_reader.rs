// SPDX-License-Identifier: MIT

//! Module for `TarStreamReader`, which reads a Tar archive from a
//! [`BlockSource`] one block at a time.

use crate::BLOCKSIZE;
use crate::archive::CorruptDataError;
use core::error;
use core::fmt::{self, Display, Formatter};

/// Source of 512-byte blocks for `TarStreamReader`, such as a file, a flash
/// device, or a network stream.
///
/// It is implemented for closures with the same signature as
/// [`BlockSource::read_block`].
pub trait BlockSource {
    /// Error returned by the source.
    type Error;

    /// Fills `buf` with the next block of the archive.
    ///
    /// Returns `Ok(false)` if the source has no more blocks.
    ///
    /// # Errors
    /// Returns an error if the source cannot be read.
    fn read_block(&mut self, buf: &mut [u8; BLOCKSIZE]) -> Result<bool, Self::Error>;
}

impl<E, F> BlockSource for F
where
    F: FnMut(&mut [u8; BLOCKSIZE]) -> Result<bool, E>,
{
    type Error = E;

    fn read_block(&mut self, buf: &mut [u8; BLOCKSIZE]) -> Result<bool, E> {
        self(buf)
    }
}

/// Error returned by `TarStreamReader`.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum StreamError<E> {
    /// The [`BlockSource`] returned an error.
    Source(E),
    /// The archive is invalid.
    Corrupt(CorruptDataError),
}

impl<E> From<CorruptDataError> for StreamError<E> {
    fn from(error: CorruptDataError) -> Self {
        Self::Corrupt(error)
    }
}

impl<E: Display> Display for StreamError<E> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Source(error) => write!(f, "cannot read the next block: {error}"),
            Self::Corrupt(error) => Display::fmt(error, f),
        }
    }
}

impl<E: error::Error> error::Error for StreamError<E> {}
