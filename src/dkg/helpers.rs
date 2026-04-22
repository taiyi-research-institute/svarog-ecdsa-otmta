use blake2::Blake2bVar;
use blake2::digest::{Update, VariableOutput};
use curve_abstract::{TrCurve, TrPoint, TrScalar};
use erreur::*;
use serde::{Deserialize, Serialize};
use svarog_secp256k1::{Secp256k1, Scalar, Point};

pub(crate) fn hash_commitment(
    sid: &str,
    i: usize,
    polycom_i: &[Point],
    blind_i: &[u8; 32],
) -> [u8; 32] {
    let mut h = Blake2bVar::new(32).unwrap();
    h.update(sid.as_bytes());
    h.update(&i.to_le_bytes());
    for pt in polycom_i {
        h.update(&pt.to_bytes());
    }
    h.update(blind_i);
    let mut out = [0u8; 32];
    h.finalize_variable(&mut out).unwrap();
    out
}

// ── Schnorr DLog proof (Fiat-Shamir with Blake2b) ──
//
// Prove: knows scalar `a` such that `A = a·G`.
//   1. Sample k, compute R = k·G
//   2. c = Hash(sid, party_id, "dlog", seq, G, A, R)   (Fiat-Shamir challenge)
//   3. s = k + c·a
//   Proof = (R, s)
//
// Verify: s·G == R + c·A

#[derive(Clone, Serialize, Deserialize)]
pub(crate) struct DLogProof {
    pub r: Point,
    pub s: Scalar,
}

fn dlog_challenge(
    sid: &str,
    party_id: usize,
    seq: usize,
    big_a: &Point,
    big_r: &Point,
) -> Scalar {
    let mut h = Blake2bVar::new(32).unwrap();
    h.update(b"dlog-proof");
    h.update(sid.as_bytes());
    h.update(&party_id.to_le_bytes());
    h.update(&seq.to_le_bytes());
    h.update(&Secp256k1::generator().to_bytes());
    h.update(&big_a.to_bytes());
    h.update(&big_r.to_bytes());
    let mut buf = [0u8; 32];
    h.finalize_variable(&mut buf).unwrap();
    Scalar::new_from_bytes(&buf)
}

/// Prove in batch that for each polynomial coefficient $a_k$, we know $a_k$ such that $A_k = a_k \cdot G$.
pub(crate) fn dlog_prove_batch(
    sid: &str,
    party_id: usize,
    coeffs: &[Scalar],
    polycom: &[Point],
) -> Vec<DLogProof> {
    coeffs
        .iter()
        .zip(polycom.iter())
        .enumerate()
        .map(|(seq, (a_k, big_a_k))| {
            let k = Scalar::new_rand();
            let big_r = Point::new_gx(&k);
            let c = dlog_challenge(sid, party_id, seq, big_a_k, &big_r);
            let s = k.add(&c.mul(a_k)); // s = k + c·a
            DLogProof { r: big_r, s }
        })
        .collect()
}

/// Verify in batch that `party_id`'s DLog proofs are valid.
/// For each index: `s·G == R + c·A_k`.
pub(crate) fn dlog_verify_batch(
    sid: &str,
    party_id: usize,
    proofs: &[DLogProof],
    polycom: &[Point],
) -> Resultat<()> {
    assert_throw!(
        proofs.len() == polycom.len(),
        "DLogProofCountMismatch",
        format!(
            "keygen: expected {} dlog proofs from player {}, got {}",
            polycom.len(),
            party_id,
            proofs.len()
        )
    );
    for (seq, (proof, big_a_k)) in proofs.iter().zip(polycom.iter()).enumerate() {
        let c = dlog_challenge(sid, party_id, seq, big_a_k, &proof.r);
        let lhs = Point::new_gx(&proof.s); // s·G
        let rhs = proof.r.add(&big_a_k.mul_x(&c)); // R + c·A
        assert_throw!(
            lhs == rhs,
            "InvalidDLogProof",
            format!(
                "keygen: invalid dlog proof from player {}, coeff {}",
                party_id, seq
            )
        );
    }
    Ok(())
}
