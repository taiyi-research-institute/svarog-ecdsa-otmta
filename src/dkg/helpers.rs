//! DKG 阶段使用的小工具:
//! * `hash_commitment`: 对参与方 $i$ 的多项式承诺 + blind 做 Blake2b 摘要,
//!   用作 Round 0 的 hash-commitment (先承诺后揭示).
//! * Schnorr DLog 批量证明 (Fiat-Shamir): 对每个多项式承诺系数 $A_k = a_k G$,
//!   证明知道离散对数 $a_k$. 用于 keygen Round 1.
//!
//! 这两个工具是 DKG 的"防作弊砖块", 笔记中没单独成章, 是工程添加.

use blake2::Blake2bVar;
use blake2::digest::{Update, VariableOutput};
use curve_abstract::{TrCurve, TrPoint, TrScalar};
use erreur::*;
use serde::{Deserialize, Serialize};
use svarog_secp256k1::{Secp256k1, Scalar, Point};

/// 对参与方 $i$ 的多项式承诺向量 $(A_0, \ldots, A_t)$ + 盲化项 `blind_i`
/// 计算 Blake2b-256 哈希承诺. Round 0 广播 `hash_commitment(...)`,
/// Round 1 揭示原像, 接收方按相同方式重算并比对.
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

// ── Schnorr DLog 证明 (Fiat-Shamir 用 Blake2b) ──
//
// 证明: 知道标量 $a$, 满足 $A = a\cdot G$.
//   1. 摇 $k$, 算 $R = k\cdot G$.
//   2. $c = \mathrm{Hash}(\mathrm{sid}, \text{party\_id}, \texttt{"dlog"}, \text{seq}, G, A, R)$
//      (Fiat-Shamir 挑战, 把交互式 Sigma 协议非交互化).
//   3. $s = k + c\cdot a$.
//   证明 = $(R, s)$.
//
// 验证: $s\cdot G \stackrel{?}{=} R + c\cdot A$.

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

/// 批量证明: 对每个多项式系数 $a_k$, 证明 $A_k = a_k\cdot G$.
/// 输入 `coeffs = [a_0, \ldots, a_t]`, `polycom = [A_0, \ldots, A_t]`.
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

/// 批量验证 `party_id` 的所有 DLog 证明.
/// 对每个下标: $s\cdot G \stackrel{?}{=} R + c\cdot A_k$.
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
