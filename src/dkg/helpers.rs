use blake2::Blake2bVar;
use blake2::digest::{Update, VariableOutput};
use curve_abstract::{TrCurve, TrPoint, TrScalar};
use erreur::*;
use serde::{Deserialize, Serialize};

pub(crate) fn hash_commitment<C: TrCurve>(
    sid: &str,
    i: usize,
    polycom_i: &[C::PointT],
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

// ── Schnorr DLog 证明 (基于 Blake2b 的 Fiat-Shamir 变换) ──
//
// 证明: 已知标量 `a` 使得 `A = a·G`.
//   1. 随机选取 k, 计算 R = k·G
//   2. c = Hash(sid, party_id, "dlog", seq, G, A, R)   (Fiat-Shamir 挑战)
//   3. s = k + c·a
//   证明 = (R, s)
//
// 验证: s·G == R + c·A

#[derive(Clone, Serialize, Deserialize)]
pub(crate) struct DLogProof<C: TrCurve> {
    pub r: C::PointT,
    pub s: C::ScalarT,
}

fn dlog_challenge<C: TrCurve + 'static>(
    sid: &str,
    party_id: usize,
    seq: usize,
    big_a: &C::PointT,
    big_r: &C::PointT,
) -> C::ScalarT {
    let mut h = Blake2bVar::new(32).unwrap();
    h.update(b"dlog-proof");
    h.update(sid.as_bytes());
    h.update(&party_id.to_le_bytes());
    h.update(&seq.to_le_bytes());
    h.update(&C::generator().to_bytes());
    h.update(&big_a.to_bytes());
    h.update(&big_r.to_bytes());
    let mut buf = [0u8; 32];
    h.finalize_variable(&mut buf).unwrap();
    C::ScalarT::new_from_bytes(&buf)
}

/// 批量证明: 对每个多项式系数 a_k, 证明知道其离散对数 (A_k = a_k·G).
/// 返回每个系数对应一个 DLogProof (长度 = 门限值).
pub(crate) fn dlog_prove_batch<C: TrCurve + 'static>(
    sid: &str,
    party_id: usize,
    coeffs: &[C::ScalarT],
    polycom: &[C::PointT],
) -> Vec<DLogProof<C>> {
    coeffs
        .iter()
        .zip(polycom.iter())
        .enumerate()
        .map(|(seq, (a_k, big_a_k))| {
            let k = C::ScalarT::new_rand();
            let big_r = C::PointT::new_gx(&k);
            let c = dlog_challenge::<C>(sid, party_id, seq, big_a_k, &big_r);
            let s = k.add(&c.mul(a_k)); // s = k + c·a
            DLogProof { r: big_r, s }
        })
        .collect()
}

/// 批量验证参与方 `party_id` 的 DLog 证明.
/// polycom[seq] = A_k, proof[seq] = (R, s). 验证: s·G == R + c·A_k.
pub(crate) fn dlog_verify_batch<C: TrCurve + 'static>(
    sid: &str,
    party_id: usize,
    proofs: &[DLogProof<C>],
    polycom: &[C::PointT],
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
        let c = dlog_challenge::<C>(sid, party_id, seq, big_a_k, &proof.r);
        let lhs = C::PointT::new_gx(&proof.s); // s·G
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
