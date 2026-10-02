use zeroize::Zeroize;

pub trait SecureRandom {
    fn fill(&mut self, buffer: &mut [u8]);

    fn next_u64(&mut self) -> u64 {
        let mut bytes = [0u8; 8];
        self.fill(&mut bytes);
        u64::from_le_bytes(bytes)
    }

    fn next_u32(&mut self) -> u32 {
        let mut bytes = [0u8; 4];
        self.fill(&mut bytes);
        u32::from_le_bytes(bytes)
    }

    fn array<const N: usize>(&mut self) -> [u8; N]
    where
        Self: Sized,
    {
        let mut out = [0u8; N];
        self.fill(&mut out);
        out
    }
}

impl<T: SecureRandom + ?Sized> SecureRandom for &mut T {
    fn fill(&mut self, buffer: &mut [u8]) {
        (**self).fill(buffer)
    }
}

impl<T: SecureRandom + ?Sized> SecureRandom for Box<T> {
    fn fill(&mut self, buffer: &mut [u8]) {
        (**self).fill(buffer)
    }
}

const OS_RANDOM_POOL: usize = 256;

pub struct OsRandom {
    pool: [u8; OS_RANDOM_POOL],
    available: usize,
}

impl OsRandom {
    pub fn new() -> Self {
        Self { pool: [0; OS_RANDOM_POOL], available: 0 }
    }
}

impl Default for OsRandom {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Debug for OsRandom {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.debug_struct("OsRandom").finish_non_exhaustive()
    }
}

impl Drop for OsRandom {
    fn drop(&mut self) {
        self.pool.zeroize();
    }
}

impl SecureRandom for OsRandom {
    fn fill(&mut self, buffer: &mut [u8]) {
        if buffer.is_empty() {
            return;
        }
        if buffer.len() > OS_RANDOM_POOL / 2 {
            getrandom::fill(buffer).expect("operating system random source failed");
            return;
        }
        let mut offset = 0;
        while offset < buffer.len() {
            if self.available == 0 {
                getrandom::fill(&mut self.pool).expect("operating system random source failed");
                self.available = OS_RANDOM_POOL;
            }
            let start = OS_RANDOM_POOL - self.available;
            let take = (buffer.len() - offset).min(self.available);
            buffer[offset..offset + take].copy_from_slice(&self.pool[start..start + take]);
            self.pool[start..start + take].zeroize();
            self.available -= take;
            offset += take;
        }
    }
}

#[cfg(any(test, feature = "test-support"))]
#[derive(Debug, Clone)]
pub struct XorShiftRandom {
    state: u64,
}

#[cfg(any(test, feature = "test-support"))]
impl XorShiftRandom {
    pub fn new(seed: u64) -> Self {
        let mut z = seed.wrapping_add(0x9e37_79b9_7f4a_7c15);
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^= z >> 31;
        Self { state: if z == 0 { 0x2545_f491_4f6c_dd1d } else { z } }
    }

    fn step(&mut self) -> u64 {
        let mut x = self.state;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.state = x;
        x.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }
}

#[cfg(any(test, feature = "test-support"))]
impl SecureRandom for XorShiftRandom {
    fn fill(&mut self, buffer: &mut [u8]) {
        for chunk in buffer.chunks_mut(8) {
            let value = self.step().to_le_bytes();
            chunk.copy_from_slice(&value[..chunk.len()]);
        }
    }
}

#[cfg(any(test, feature = "test-support"))]
#[derive(Debug, Clone)]
pub struct SequenceRandom {
    data: Vec<u8>,
    position: usize,
    fallback: XorShiftRandom,
}

#[cfg(any(test, feature = "test-support"))]
impl SequenceRandom {
    pub fn new(data: Vec<u8>) -> Self {
        Self { data, position: 0, fallback: XorShiftRandom::new(0) }
    }

    pub fn remaining(&self) -> usize {
        self.data.len() - self.position
    }
}

#[cfg(any(test, feature = "test-support"))]
impl SecureRandom for SequenceRandom {
    fn fill(&mut self, buffer: &mut [u8]) {
        let available = self.remaining().min(buffer.len());
        buffer[..available].copy_from_slice(&self.data[self.position..self.position + available]);
        self.position += available;
        if available < buffer.len() {
            self.fallback.fill(&mut buffer[available..]);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn os_random_produces_distinct_values() {
        let mut rng = OsRandom::new();
        let a: [u8; 32] = rng.array();
        let b: [u8; 32] = rng.array();
        assert_ne!(a, b);
    }

    #[test]
    fn os_random_pool_never_repeats_or_keeps_handed_out_bytes() {
        let mut rng = OsRandom::new();
        let mut seen = std::collections::HashSet::new();
        for _ in 0..4096 {
            assert!(seen.insert(rng.next_u64()), "a 64-bit value repeated");
            let start = OS_RANDOM_POOL - rng.available;
            assert!(rng.pool[..start].iter().all(|byte| *byte == 0), "consumed pool bytes are wiped");
        }
        let mut odd = [0u8; 7];
        for _ in 0..100 {
            rng.fill(&mut odd);
            assert!(rng.available <= OS_RANDOM_POOL);
        }
        let mut large = [0u8; 4096];
        rng.fill(&mut large);
        assert!(large.iter().any(|byte| *byte != 0));
        let mut other = OsRandom::new();
        let first: [u8; 32] = rng.array();
        let second: [u8; 32] = other.array();
        assert_ne!(first, second, "independent pools");
    }

    #[test]
    fn sequence_random_replays_then_falls_back() {
        let mut rng = SequenceRandom::new(vec![1, 2, 3]);
        let mut first = [0u8; 2];
        rng.fill(&mut first);
        assert_eq!(first, [1, 2]);
        let mut second = [0u8; 4];
        rng.fill(&mut second);
        assert_eq!(second[0], 3);
        assert_eq!(rng.remaining(), 0);
    }

    #[test]
    fn xorshift_is_deterministic() {
        let mut a = XorShiftRandom::new(42);
        let mut b = XorShiftRandom::new(42);
        assert_eq!(a.next_u64(), b.next_u64());
        let mut c = XorShiftRandom::new(43);
        assert_ne!(a.next_u64(), c.next_u64());
        let firsts: std::collections::HashSet<u64> =
            (0..1000).map(|seed| XorShiftRandom::new(seed).next_u64()).collect();
        assert_eq!(firsts.len(), 1000);
    }
}
