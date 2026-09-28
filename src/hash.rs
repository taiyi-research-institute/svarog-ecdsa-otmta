//! 协议哈希编码 v2：每个参数为 u64 大端长度与原始字节，连续参数可唯一解析。
//! 每次 update 是一个完整参数；列表须先写元素个数，嵌套列表逐层写长度。

use blake2::{
    Blake2bVar,
    digest::{InvalidBufferSize, InvalidOutputSize, Update, VariableOutput},
};

pub(crate) struct FramedHash(Blake2bVar);

impl FramedHash {
    pub(crate) fn new(size: usize) -> Result<Self, InvalidOutputSize> {
        let mut h = Self(Blake2bVar::new(size)?);
        h.update(b"svarog-ecdsa-otmta/hash/v2");
        h.update(&(size as u64).to_be_bytes());
        Ok(h)
    }

    pub(crate) fn update(&mut self, bytes: &[u8]) {
        self.0.update(
            &u64::try_from(bytes.len())
                .expect("argument too large")
                .to_be_bytes(),
        );
        self.0.update(bytes);
    }

    pub(crate) fn finalize_variable(self, out: &mut [u8]) -> Result<(), InvalidBufferSize> {
        self.0.finalize_variable(out)
    }
}

/// 首个参数须为域分离标签；每个参数单独编码边界。
macro_rules! hash {
    ($nbytes:expr; $($arg:expr),+ $(,)?) => {{
        let mut out = vec![0u8; $nbytes];
        let mut h = $crate::hash::FramedHash::new(out.len()).unwrap();
        $(
            let bytes = $arg;
            h.update(bytes.as_ref());
        )+
        h.finalize_variable(&mut out).unwrap();
        out
    }};
}

/// 将随机预言机输出拒绝采样为均匀 secp256k1 标量，避免直接模约减的偏差。
pub(crate) fn scalar(domain: &[u8], args: &[&[u8]]) -> svarog_secp256k1::Scalar {
    use curve_abstract::{TrCurve, TrScalar};
    use svarog_secp256k1::{Scalar, Secp256k1};
    for counter in 0u64.. {
        let mut h = FramedHash::new(32).unwrap();
        h.update(domain);
        h.update(&(args.len() as u64).to_be_bytes());
        for arg in args {
            h.update(arg);
        }
        h.update(&counter.to_be_bytes());
        let mut out = [0u8; 32];
        h.finalize_variable(&mut out).unwrap();
        if out.as_slice() < Secp256k1::curve_order_bytes() {
            return Scalar::new_from_bytes(&out);
        }
    }
    unreachable!("scalar rejection counter exhausted")
}

#[cfg(test)]
mod tests {
    use curve_abstract::{TrCurve, TrPoint, TrScalar};
    use svarog_secp256k1::{Point, Scalar, Secp256k1};

    #[test]
    fn test_hash_macros_accept_mixed_inputs() {
        let sid = "test-hash-macro";
        let sid_owned = sid.to_string();
        let point = *Secp256k1::generator();

        let digest_a = hash!(
            32;
            b"endemic-ot-seed",
            7u16.to_be_bytes(),
            sid.as_bytes(),
            point.to_bytes(),
            b"tag",
            [1u8, 2, 3],
            vec![4u8, 5, 6]
        );
        let digest_b = hash!(
            32;
            b"endemic-ot-seed",
            7u16.to_be_bytes(),
            sid_owned.as_bytes(),
            point.clone().to_bytes(),
            b"tag",
            [1u8, 2, 3],
            vec![4u8, 5, 6]
        );
        assert_eq!(digest_a, digest_b);

        let point_a = Point::new_gx(&Scalar::new_from_bytes(&hash!(
            32;
            b"endemic-ot-h",
            0u16.to_be_bytes(),
            7u16.to_be_bytes(),
            sid.as_bytes(),
            point.to_bytes(),
            [9u8, 8, 7]
        )));
        let point_b = Point::new_gx(&Scalar::new_from_bytes(&hash!(
            32;
            b"endemic-ot-h",
            0u16.to_be_bytes(),
            7u16.to_be_bytes(),
            sid_owned.as_bytes(),
            point.to_bytes(),
            [9u8, 8, 7]
        )));
        assert_eq!(point_a, point_b);
    }
}

#[cfg(test)]
mod framing_tests {
    use super::*;

    #[test]
    fn argument_boundaries_are_unambiguous() {
        assert_ne!(
            hash!(32; b"test", b"ab", b"c"),
            hash!(32; b"test", b"a", b"bc")
        );
        assert_ne!(
            hash!(32; b"test", b"a|", b"b"),
            hash!(32; b"test", b"a", b"|b")
        );
        assert_ne!(hash!(32; b"test", b"a"), hash!(32; b"test", b"a", b""));
        assert_ne!(hash!(32; b"test", b"", b"a"), hash!(32; b"test", b"a", b""));
        assert_ne!(
            hash!(32; b"test", [0, 1], [2]),
            hash!(32; b"test", [0], [1, 2])
        );
    }

    #[test]
    fn encoding_matches_explicit_length_prefixes() {
        let mut raw = Blake2bVar::new(32).unwrap();
        for field in [
            b"svarog-ecdsa-otmta/hash/v2".as_slice(),
            &32u64.to_be_bytes(),
            b"tag",
            b"a",
            b"bc",
        ] {
            raw.update(&(field.len() as u64).to_be_bytes());
            raw.update(field);
        }
        let mut expected = [0; 32];
        raw.finalize_variable(&mut expected).unwrap();
        assert_eq!(hash!(32; b"tag", b"a", b"bc"), expected);
    }
}
