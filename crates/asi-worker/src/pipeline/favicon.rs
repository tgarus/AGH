use base64::engine::general_purpose::STANDARD;
use base64::Engine;

/// Computes the canonical Shodan / FingerprintHub MurmurHash3 (32-bit signed)
/// over base64-encoded favicon bytes wrapped every 76 chars with LF newlines.
#[must_use]
pub fn mmh3_favicon_hash(raw_bytes: &[u8]) -> i64 {
    let encoded = STANDARD.encode(raw_bytes);
    let mut wrapped = String::with_capacity(encoded.len() + encoded.len() / 76 + 2);
    for (idx, ch) in encoded.chars().enumerate() {
        if idx > 0 && idx % 76 == 0 {
            wrapped.push('\n');
        }
        wrapped.push(ch);
    }
    wrapped.push('\n');

    let hash_u32 = murmur3_x86_32(wrapped.as_bytes(), 0);
    i64::from(hash_u32 as i32)
}

fn murmur3_x86_32(data: &[u8], seed: u32) -> u32 {
    const C1: u32 = 0xcc9e_2d51;
    const C2: u32 = 0x1b87_3593;

    let mut h1 = seed;
    let chunks = data.chunks_exact(4);
    let remainder = chunks.remainder();

    for chunk in chunks {
        let mut k1 = u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
        k1 = k1.wrapping_mul(C1);
        k1 = k1.rotate_left(15);
        k1 = k1.wrapping_mul(C2);

        h1 ^= k1;
        h1 = h1.rotate_left(13);
        h1 = h1.wrapping_mul(5).wrapping_add(0xe654_6b64);
    }

    let mut k1: u32 = 0;
    if remainder.len() >= 3 {
        k1 ^= u32::from(remainder[2]) << 16;
    }
    if remainder.len() >= 2 {
        k1 ^= u32::from(remainder[1]) << 8;
    }
    if !remainder.is_empty() {
        k1 ^= u32::from(remainder[0]);
        k1 = k1.wrapping_mul(C1);
        k1 = k1.rotate_left(15);
        k1 = k1.wrapping_mul(C2);
        h1 ^= k1;
    }

    h1 ^= u32::try_from(data.len()).unwrap_or(u32::MAX);
    h1 ^= h1 >> 16;
    h1 = h1.wrapping_mul(0x85eb_ca6b);
    h1 ^= h1 >> 13;
    h1 = h1.wrapping_mul(0xc2b2_ae35);
    h1 ^= h1 >> 16;
    h1
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn computes_deterministic_mmh3_hash() {
        let sample = [
            0x00_u8, 0x00, 0x01, 0x00, 0x01, 0x00, 0x01, 0x01, 0x00, 0x00, 0x01, 0x00, 0x18, 0x00,
        ];
        let h1 = mmh3_favicon_hash(&sample);
        let h2 = mmh3_favicon_hash(&sample);
        assert_eq!(h1, h2);
        assert_ne!(h1, 0);
    }
}
