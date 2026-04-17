macro_rules! hash {
    ($nbytes:expr; $($arg:expr),+ $(,)?) => {{
        let mut out = vec![0u8; $nbytes];
        let mut h =
            <::blake2::Blake2bVar as ::blake2::digest::VariableOutput>::new(out.len()).unwrap();
        $(
            let bytes = $arg;
            ::blake2::digest::Update::update(&mut h, bytes.as_ref());
        )+
        ::blake2::digest::VariableOutput::finalize_variable(h, &mut out).unwrap();
        out
    }};
}

#[cfg(test)]
mod tests {
    use curve_abstract::{TrCurve, TrPoint, TrScalar};
    use svarog_secp256k1::{Point, Scalar, Secp256k1};

    #[test]
    fn test_hash_macros_accept_mixed_inputs() {
        let sid = "test-hash-macro";
        let sid_owned = sid.to_string();
        let point = Secp256k1::generator().clone();

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
