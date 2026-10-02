#[derive(Debug, Default)]
pub struct InputBuffer {
    data: Vec<u8>,
    start: usize,
}

impl InputBuffer {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn len(&self) -> usize {
        self.data.len() - self.start
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.data[self.start..]
    }

    pub fn extend(&mut self, bytes: &[u8]) {
        if self.start > 0 && self.start >= self.data.len() / 2 {
            self.data.drain(..self.start);
            self.start = 0;
        }
        self.data.extend_from_slice(bytes);
    }

    pub fn consume(&mut self, count: usize) {
        assert!(count <= self.len(), "consume beyond buffer");
        self.start += count;
        if self.start == self.data.len() {
            self.data.clear();
            self.start = 0;
        }
    }

    pub fn take(&mut self, count: usize) -> Vec<u8> {
        let out = self.as_slice()[..count].to_vec();
        self.consume(count);
        out
    }

    pub fn shrink_if_idle(&mut self, keep: usize) {
        if self.is_empty() && self.data.capacity() > keep {
            self.data = Vec::with_capacity(keep);
            self.start = 0;
        }
    }

    pub fn capacity(&self) -> usize {
        self.data.capacity()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extend_consume_take() {
        let mut buffer = InputBuffer::new();
        buffer.extend(&[1, 2, 3, 4]);
        buffer.consume(1);
        assert_eq!(buffer.as_slice(), &[2, 3, 4]);
        buffer.extend(&[5]);
        assert_eq!(buffer.take(2), vec![2, 3]);
        assert_eq!(buffer.as_slice(), &[4, 5]);
        buffer.consume(2);
        assert!(buffer.is_empty());
    }

    #[test]
    fn compacts_and_shrinks() {
        let mut buffer = InputBuffer::new();
        buffer.extend(&vec![0u8; 1 << 20]);
        buffer.consume((1 << 20) - 1);
        buffer.extend(&[1]);
        assert_eq!(buffer.len(), 2);
        buffer.consume(2);
        buffer.shrink_if_idle(4096);
        assert!(buffer.capacity() <= 4096);
    }
}
