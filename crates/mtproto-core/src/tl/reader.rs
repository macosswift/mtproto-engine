use super::{TlError, TlResult, ids};

#[derive(Debug, Clone)]
pub struct Reader<'a> {
    data: &'a [u8],
    position: usize,
}

impl<'a> Reader<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        Self { data, position: 0 }
    }

    pub fn position(&self) -> usize {
        self.position
    }

    pub fn remaining(&self) -> usize {
        self.data.len() - self.position
    }

    pub fn is_empty(&self) -> bool {
        self.remaining() == 0
    }

    pub fn rest(&self) -> &'a [u8] {
        &self.data[self.position..]
    }

    pub fn finish(&self) -> TlResult<()> {
        match self.remaining() {
            0 => Ok(()),
            n => Err(TlError::TrailingData(n)),
        }
    }

    pub fn read_raw(&mut self, length: usize) -> TlResult<&'a [u8]> {
        if self.remaining() < length {
            return Err(TlError::UnexpectedEof { offset: self.position, needed: length });
        }
        let slice = &self.data[self.position..self.position + length];
        self.position += length;
        Ok(slice)
    }

    pub fn read_array<const N: usize>(&mut self) -> TlResult<[u8; N]> {
        Ok(self.read_raw(N)?.try_into().expect("length checked"))
    }

    pub fn skip(&mut self, length: usize) -> TlResult<()> {
        self.read_raw(length).map(|_| ())
    }

    pub fn peek_u32(&self) -> TlResult<u32> {
        let mut copy = self.clone();
        copy.read_u32()
    }

    pub fn read_i32(&mut self) -> TlResult<i32> {
        Ok(i32::from_le_bytes(self.read_array()?))
    }

    pub fn read_u32(&mut self) -> TlResult<u32> {
        Ok(u32::from_le_bytes(self.read_array()?))
    }

    pub fn read_i64(&mut self) -> TlResult<i64> {
        Ok(i64::from_le_bytes(self.read_array()?))
    }

    pub fn read_u64(&mut self) -> TlResult<u64> {
        Ok(u64::from_le_bytes(self.read_array()?))
    }

    pub fn read_f64(&mut self) -> TlResult<f64> {
        Ok(f64::from_le_bytes(self.read_array()?))
    }

    pub fn read_int128(&mut self) -> TlResult<[u8; 16]> {
        self.read_array()
    }

    pub fn read_int256(&mut self) -> TlResult<[u8; 32]> {
        self.read_array()
    }

    pub fn read_bool(&mut self) -> TlResult<bool> {
        match self.read_u32()? {
            ids::BOOL_TRUE => Ok(true),
            ids::BOOL_FALSE => Ok(false),
            other => Err(TlError::InvalidBool(other)),
        }
    }

    pub fn expect_constructor(&mut self, expected: u32) -> TlResult<()> {
        let offset = self.position;
        let found = self.read_u32()?;
        if found == expected { Ok(()) } else { Err(TlError::UnexpectedConstructor { offset, found }) }
    }

    pub fn read_bytes(&mut self) -> TlResult<&'a [u8]> {
        let start = self.position;
        let first = *self.data.get(self.position).ok_or(TlError::UnexpectedEof { offset: start, needed: 1 })?;
        let (header, length) = if first < 254 {
            self.position += 1;
            (1usize, first as usize)
        } else if first == 254 {
            let raw = self.read_array::<4>()?;
            (4usize, u32::from_le_bytes([raw[1], raw[2], raw[3], 0]) as usize)
        } else {
            return Err(TlError::InvalidLength { offset: start, length: first as i64 });
        };
        let total = (header + length).div_ceil(4) * 4;
        if self.data.len() - start < total {
            self.position = start;
            return Err(TlError::UnexpectedEof { offset: start, needed: total });
        }
        let value = &self.data[start + header..start + header + length];
        self.position = start + total;
        Ok(value)
    }

    pub fn read_vector_header(&mut self, max_count: usize) -> TlResult<usize> {
        self.expect_constructor(ids::VECTOR)?;
        self.read_count(max_count)
    }

    pub fn read_count(&mut self, max_count: usize) -> TlResult<usize> {
        let offset = self.position;
        let count = self.read_i32()?;
        if count < 0 || count as usize > max_count {
            return Err(TlError::InvalidLength { offset, length: count as i64 });
        }
        Ok(count as usize)
    }

    pub fn read_i64_vector(&mut self, max_count: usize) -> TlResult<Vec<i64>> {
        let count = self.read_vector_header(max_count)?;
        if self.remaining() < count * 8 {
            return Err(TlError::UnexpectedEof { offset: self.position, needed: count * 8 });
        }
        (0..count).map(|_| self.read_i64()).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::super::Writer;
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn short_bytes_layout() {
        let mut writer = Writer::new();
        writer.write_bytes(b"abc");
        assert_eq!(writer.as_slice(), &[3, b'a', b'b', b'c']);
        let mut writer = Writer::new();
        writer.write_bytes(b"abcd");
        assert_eq!(writer.as_slice(), &[4, b'a', b'b', b'c', b'd', 0, 0, 0]);
        let mut writer = Writer::new();
        writer.write_bytes(b"");
        assert_eq!(writer.as_slice(), &[0, 0, 0, 0]);
    }

    #[test]
    fn long_bytes_layout() {
        let data = vec![7u8; 254];
        let mut writer = Writer::new();
        writer.write_bytes(&data);
        let out = writer.into_inner();
        assert_eq!(&out[..4], &[254, 254, 0, 0]);
        assert_eq!(out.len(), 4 + 256);
        assert_eq!(&out[258..], &[0, 0]);
    }

    #[test]
    fn accepts_non_canonical_long_form_like_tdlib() {
        let data = [254u8, 3, 0, 0, 1, 2, 3, 0];
        let mut reader = Reader::new(&data);
        assert_eq!(reader.read_bytes().unwrap(), &[1, 2, 3]);
        assert!(reader.finish().is_ok());
    }

    #[test]
    fn rejects_truncated_bytes() {
        let data = [10u8, 1, 2, 3];
        let mut reader = Reader::new(&data);
        assert!(matches!(reader.read_bytes(), Err(TlError::UnexpectedEof { .. })));
        assert_eq!(reader.position(), 0);
        assert!(matches!(Reader::new(&[255u8, 0, 0, 0]).read_bytes(), Err(TlError::InvalidLength { .. })));
        assert!(matches!(Reader::new(&[]).read_bytes(), Err(TlError::UnexpectedEof { .. })));
    }

    #[test]
    fn vector_count_limits() {
        let mut writer = Writer::new();
        writer.write_vector_header(5);
        assert!(Reader::new(writer.as_slice()).read_vector_header(4).is_err());
        let mut writer = Writer::new();
        writer.write_u32(ids::VECTOR);
        writer.write_i32(-1);
        assert!(Reader::new(writer.as_slice()).read_vector_header(100).is_err());
        let mut writer = Writer::new();
        writer.write_vector_header(1000);
        assert!(Reader::new(writer.as_slice()).read_i64_vector(10_000).is_err());
    }

    #[test]
    fn bool_roundtrip_and_rejection() {
        let mut writer = Writer::new();
        writer.write_bool(true);
        writer.write_bool(false);
        writer.write_u32(0x1234_5678);
        let mut reader = Reader::new(writer.as_slice());
        assert!(reader.read_bool().unwrap());
        assert!(!reader.read_bool().unwrap());
        assert_eq!(reader.read_bool(), Err(TlError::InvalidBool(0x1234_5678)));
    }

    proptest! {
        #[test]
        fn bytes_roundtrip(data in proptest::collection::vec(any::<u8>(), 0..2000), tail in any::<i64>()) {
            let mut writer = Writer::new();
            writer.write_bytes(&data);
            writer.write_i64(tail);
            prop_assert_eq!(writer.len() % 4, 0);
            prop_assert_eq!(writer.len(), super::super::writer::serialized_bytes_len(data.len()) + 8);
            let mut reader = Reader::new(writer.as_slice());
            prop_assert_eq!(reader.read_bytes().unwrap(), &data[..]);
            prop_assert_eq!(reader.read_i64().unwrap(), tail);
            prop_assert!(reader.finish().is_ok());
        }

        #[test]
        fn scalars_roundtrip(a in any::<i32>(), b in any::<i64>(), c in any::<f64>(), d in any::<[u8; 16]>(), e in any::<[u8; 32]>(), v in proptest::collection::vec(any::<i64>(), 0..50)) {
            let mut writer = Writer::new();
            writer.write_i32(a);
            writer.write_i64(b);
            writer.write_f64(c);
            writer.write_int128(&d);
            writer.write_int256(&e);
            writer.write_i64_vector(&v);
            let mut reader = Reader::new(writer.as_slice());
            prop_assert_eq!(reader.read_i32().unwrap(), a);
            prop_assert_eq!(reader.read_i64().unwrap(), b);
            prop_assert_eq!(reader.read_f64().unwrap().to_bits(), c.to_bits());
            prop_assert_eq!(reader.read_int128().unwrap(), d);
            prop_assert_eq!(reader.read_int256().unwrap(), e);
            prop_assert_eq!(reader.read_i64_vector(100).unwrap(), v);
            prop_assert!(reader.finish().is_ok());
        }

        #[test]
        fn reader_never_panics_on_garbage(data in proptest::collection::vec(any::<u8>(), 0..64)) {
            let mut reader = Reader::new(&data);
            let _ = reader.read_bytes();
            let _ = reader.read_i64_vector(1 << 20);
            let _ = reader.read_bool();
            let _ = reader.read_int256();
        }
    }
}
