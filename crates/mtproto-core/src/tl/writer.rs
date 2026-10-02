use super::ids;

#[derive(Debug, Default, Clone)]
pub struct Writer {
    buffer: Vec<u8>,
}

impl Writer {
    pub fn new() -> Self {
        Self { buffer: Vec::new() }
    }

    pub fn with_capacity(capacity: usize) -> Self {
        Self { buffer: Vec::with_capacity(capacity) }
    }

    pub fn from_vec(buffer: Vec<u8>) -> Self {
        Self { buffer }
    }

    pub fn len(&self) -> usize {
        self.buffer.len()
    }

    pub fn is_empty(&self) -> bool {
        self.buffer.is_empty()
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.buffer
    }

    pub fn into_inner(self) -> Vec<u8> {
        self.buffer
    }

    pub fn write_i32(&mut self, value: i32) {
        self.buffer.extend_from_slice(&value.to_le_bytes());
    }

    pub fn write_u32(&mut self, value: u32) {
        self.buffer.extend_from_slice(&value.to_le_bytes());
    }

    pub fn write_i64(&mut self, value: i64) {
        self.buffer.extend_from_slice(&value.to_le_bytes());
    }

    pub fn write_u64(&mut self, value: u64) {
        self.buffer.extend_from_slice(&value.to_le_bytes());
    }

    pub fn write_f64(&mut self, value: f64) {
        self.buffer.extend_from_slice(&value.to_le_bytes());
    }

    pub fn write_int128(&mut self, value: &[u8; 16]) {
        self.buffer.extend_from_slice(value);
    }

    pub fn write_int256(&mut self, value: &[u8; 32]) {
        self.buffer.extend_from_slice(value);
    }

    pub fn write_raw(&mut self, data: &[u8]) {
        self.buffer.extend_from_slice(data);
    }

    pub fn write_bool(&mut self, value: bool) {
        self.write_u32(if value { ids::BOOL_TRUE } else { ids::BOOL_FALSE });
    }

    pub fn write_bytes(&mut self, data: &[u8]) {
        let length = data.len();
        let header = if length < 254 {
            self.buffer.push(length as u8);
            1
        } else {
            assert!(length < (1 << 24), "TL bytes value too long: {length}");
            self.buffer.push(254);
            self.buffer.extend_from_slice(&(length as u32).to_le_bytes()[..3]);
            4
        };
        self.buffer.extend_from_slice(data);
        let padding = (4 - (header + length) % 4) % 4;
        self.buffer.extend(core::iter::repeat_n(0u8, padding));
    }

    pub fn write_vector_header(&mut self, count: usize) {
        self.write_u32(ids::VECTOR);
        self.write_i32(i32::try_from(count).expect("vector too long"));
    }

    pub fn write_i64_vector(&mut self, values: &[i64]) {
        self.write_vector_header(values.len());
        for value in values {
            self.write_i64(*value);
        }
    }

    pub fn reserve_i32(&mut self) -> usize {
        let position = self.buffer.len();
        self.buffer.extend_from_slice(&[0; 4]);
        position
    }

    pub fn patch_i32(&mut self, position: usize, value: i32) {
        self.buffer[position..position + 4].copy_from_slice(&value.to_le_bytes());
    }
}

#[cfg_attr(not(test), allow(dead_code))]
pub(crate) fn serialized_bytes_len(length: usize) -> usize {
    let header = if length < 254 { 1 } else { 4 };
    (header + length).div_ceil(4) * 4
}
