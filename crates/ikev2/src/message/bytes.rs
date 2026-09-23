use crate::{Error, Result};

/// A cursor over received bytes.
pub struct Reader<'a> {
    data: &'a [u8],
}

impl<'a> Reader<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        Self { data }
    }

    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    pub fn rest(self) -> &'a [u8] {
        self.data
    }

    pub fn take(&mut self, len: usize) -> Result<&'a [u8]> {
        if self.data.len() < len {
            return Err(Error::Malformed(format!(
                "{len} bytes expected, {} left",
                self.data.len()
            )));
        }
        let (taken, rest) = self.data.split_at(len);
        self.data = rest;
        Ok(taken)
    }

    pub fn u8(&mut self) -> Result<u8> {
        Ok(self.take(1)?[0])
    }

    pub fn u16(&mut self) -> Result<u16> {
        let bytes = self.take(2)?;
        Ok(u16::from_be_bytes([bytes[0], bytes[1]]))
    }

    pub fn u32(&mut self) -> Result<u32> {
        let bytes = self.take(4)?;
        Ok(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }

    pub fn u64(&mut self) -> Result<u64> {
        let bytes = self.take(8)?;
        Ok(u64::from_be_bytes(bytes.try_into().expect("8 bytes")))
    }

    pub fn skip(&mut self, len: usize) -> Result<()> {
        self.take(len).map(drop)
    }
}

/// Big-endian appends to a buffer.
pub trait Writer {
    fn put_u8(&mut self, value: u8);
    fn put_u16(&mut self, value: u16);
    fn put_u32(&mut self, value: u32);
    fn put_u64(&mut self, value: u64);
}

impl Writer for Vec<u8> {
    fn put_u8(&mut self, value: u8) {
        self.push(value);
    }

    fn put_u16(&mut self, value: u16) {
        self.extend_from_slice(&value.to_be_bytes());
    }

    fn put_u32(&mut self, value: u32) {
        self.extend_from_slice(&value.to_be_bytes());
    }

    fn put_u64(&mut self, value: u64) {
        self.extend_from_slice(&value.to_be_bytes());
    }
}

/// A length that fits a 16-bit field.
pub fn len16(len: usize) -> Result<u16> {
    u16::try_from(len).map_err(|_| Error::Malformed(format!("{len} bytes do not fit a payload")))
}
