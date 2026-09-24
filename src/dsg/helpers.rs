//! 签名时使用的小工具:
//! * `mta_session_id`: 为 (sender_i, receiver_j) 一对 RVOLE 调用派生
//!   独立 sid, 避免不同 pair 之间的哈希/挑战相互污染.
//! * $R_i = r_i\cdot G$ 的 hash-commitment, 见 `notes/07-orchestration.md`
//!   Round 1: 先承诺后揭示, 防 last-actor 操纵聚合 $R$.
//! * `compute_zeta_i`: 工程添加的 pairwise 再随机化, 满足 $\sum_i \zeta_i = 0$.
//!   把它加到 $\mathtt{sk}_i$ 上, 不改 $\mathtt{sk} = \sum_i \mathtt{sk}_i$,
//!   但把每方真实份额"重新均匀打散" (笔记未覆盖, 是 silence-laboratories
//!   实现的工程加固).

use crate::hash::FramedHash;

use curve_abstract::{TrCurve, TrPoint, TrScalar};
use svarog_secp256k1::{Point, Scalar, Secp256k1};

use super::super::dkg::PairwiseSeeds;

/// 计算 ECDSA recovery id $v \in \{0,1,2,3\}$.
/// bit0 = $y(R)$ 奇偶性; bit1 = $x(R) \ge n$ (溢出) — 后者在 secp256k1
/// 上概率约 $2^{-128}$, 但完整性起见仍计算.
pub(crate) fn recovery_id(big_r: &Point) -> u8 {
    let long = big_r.to_bytes_long();
    debug_assert_eq!(long.len(), 65);
    let y_parity = long[64] & 1;
    let x_bytes = &long[1..33];
    let n_bytes = Secp256k1::curve_order_bytes();
    // x_bytes, n_bytes 均为 32 字节大端整数, 字典序即数值序.
    let x_overflow: u8 = if x_bytes >= n_bytes { 1 } else { 0 };
    (x_overflow << 1) | y_parity
}

/// 为 $(\text{sender}=i,\ \text{receiver}=j)$ 这对 RVOLE/MtA 调用派生唯一 sid.
/// 同一对参与方在一次签名中跑两次 RVOLE (一次互换角色), 故下标顺序敏感.
pub(crate) fn mta_session_id(final_sid: &str, sender_i: usize, receiver_j: usize) -> String {
    format!("{}/dsg/mta/s={}/r={}", final_sid, sender_i, receiver_j)
}

/// 对参与方的 $R_i = r_i\cdot G$ 与一次性盲化值做哈希承诺.
/// 见 `notes/07-orchestration.md` Round 1.
pub(crate) fn hash_commitment_r_i(sid: &str, big_r_i: &Point, blind: &[u8; 32]) -> [u8; 32] {
    let mut h = FramedHash::new(32).unwrap();
    h.update(b"dsg/commit/r_i");
    h.update(sid.as_bytes());
    h.update(&big_r_i.to_bytes());
    h.update(blind);
    let mut out = [0u8; 32];
    h.finalize_variable(&mut out).unwrap();
    out
}

pub(crate) fn verify_commitment_r_i(
    sid: &str,
    big_r_i: &Point,
    blind: &[u8; 32],
    commitment: &[u8; 32],
) -> bool {
    let recomputed = hash_commitment_r_i(sid, big_r_i, blind);
    recomputed[..] == commitment[..]
}

/// 派生 pairwise 标量 $v_{ij} = \mathrm{Hash}(\text{seed}_{ij} \,\|\, \text{sig\_id}) \bmod n$.
/// `sig_id` 让 $v$ 跨签名会话不可重用; `seed_ij` 由 keygen 时较小编号方
/// 明文生成并发给较大编号方 (见 `dkg_orch::PairwiseSeeds`).
fn pairwise_v(seed: &[u8; 32], sig_id: &str) -> Scalar {
    let mut h = FramedHash::new(32).unwrap();
    h.update(b"dsg/zeta/pairwise");
    h.update(seed);
    h.update(sig_id.as_bytes());
    let mut out = [0u8; 32];
    h.finalize_variable(&mut out).unwrap();
    Scalar::new_from_bytes(&out)
}

/// $\zeta_i = \sum_{j<i} v_{ji} - \sum_{j>i} v_{ij}$ (对所有签方 $j \neq i$).
///
/// 反对称构造保证 $\sum_i \zeta_i = 0$:
/// 每对 $(j<i)$ 的 $v_{ji}$ 在编号 $i$ 处加, 在编号 $j$ 处减, 全局抵消.
///
/// `seeds.rec` 按 $j<i$ 索引 (从 $j$ 处收到的 seed);
/// `seeds.sent` 按 $j>i$ 索引 (我发给 $j$ 的 seed).
pub(crate) fn compute_zeta_i(
    seeds: &PairwiseSeeds,
    my_id: usize,
    sig_id: &str,
    others: &[usize],
) -> Scalar {
    let mut acc = Scalar::default();
    for &j in others {
        if j < my_id {
            let seed = seeds.rec.get(&j).expect("missing rec seed");
            acc = acc.add(&pairwise_v(seed, sig_id));
        } else if j > my_id {
            let seed = seeds.sent.get(&j).expect("missing sent seed");
            acc = acc.sub(&pairwise_v(seed, sig_id));
        }
    }
    acc
}

/// v2 绑定会话、初始化、基础公钥、签名方、消息、衍生偏移和批量顺序。
/// 消息路由仍使用调用方 sid，以便不同上下文在协议校验时报告失败。
pub(crate) fn signing_context(
    sid: &str,
    setup_sid: &str,
    public_key: &Point,
    signers: &std::collections::HashSet<usize>,
    messages: &[[u8; 32]],
    offsets: &[Scalar],
    batch: bool,
) -> String {
    let mut h = crate::hash::FramedHash::new(32).unwrap();
    h.update(b"signing/context/v2");
    h.update(if batch { b"batch" } else { b"single" });
    h.update(sid.as_bytes());
    h.update(setup_sid.as_bytes());
    h.update(&public_key.to_bytes());
    let mut ordered: Vec<_> = signers.iter().copied().collect();
    ordered.sort_unstable();
    h.update(&(ordered.len() as u64).to_be_bytes());
    for party in ordered {
        h.update(&(party as u64).to_be_bytes());
    }
    h.update(&(messages.len() as u64).to_be_bytes());
    for (message, offset) in messages.iter().zip(offsets) {
        h.update(message);
        h.update(&offset.to_bytes());
    }
    let mut out = [0; 32];
    h.finalize_variable(&mut out).unwrap();
    out.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// 🛡️ 2026-929 Step 4c：重构完整 R，保留符号，不只比较横坐标。
pub(crate) fn verify_signature_nonce(
    pk: &Point,
    m: &Scalar,
    r: &Scalar,
    s: &Scalar,
    nonce: &Point,
) -> erreur::Resultat<()> {
    use erreur::*;
    assert_throw!(
        *s != Scalar::default() && *r != Scalar::default() && *nonce != Point::default(),
        "InvalidSignature",
        "zero signature component or identity nonce"
    );
    let inverse = s.inv_ct();
    let reconstructed = pk.mul_x(&r.mul(&inverse)).add_gx(&m.mul(&inverse));
    assert_throw!(
        reconstructed == *nonce,
        "NonceSignMismatch",
        "signature must reconstruct the agreed signed nonce"
    );
    Ok(())
}

/// 🛡️ 2026-929 Step 4a：各方回传的聚合点必须与本地完整点相同。
pub(crate) fn verify_nonce_echo(local: &[Point], peer: &[Point]) -> erreur::Resultat<()> {
    use erreur::*;
    assert_throw!(
        local == peer,
        "NonceEchoMismatch",
        "peer aggregate nonce differs from local nonce"
    );
    Ok(())
}

#[cfg(test)]
mod patch_tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn nonce_echo_checks_sign_and_batch_order() {
        let a = Point::new_gx(&Scalar::new(5));
        let b = Point::new_gx(&Scalar::new(7));
        assert!(verify_nonce_echo(&[a, b], &[a, b]).is_ok());
        assert!(verify_nonce_echo(&[a, b], &[b, a]).is_err());
        assert!(verify_nonce_echo(&[a], &[Point::new_gx(&Scalar::new(5).neg())]).is_err());
    }

    #[test]
    fn signature_malleation_is_rejected() {
        let x = Scalar::new(3);
        let k = Scalar::new(7);
        let m = Scalar::new(11);
        let pk = Point::new_gx(&x);
        let nonce = Point::new_gx(&k);
        let r = Scalar::new_from_bytes(&nonce.to_bytes_long()[1..33]);
        let s = m.add(&r.mul(&x)).mul(&k.inv_ct());
        assert!(verify_signature_nonce(&pk, &m, &r, &s, &nonce).is_ok());
        assert!(verify_signature_nonce(&pk, &m, &r, &s.neg(), &nonce).is_err());
        assert!(verify_signature_nonce(&pk, &m, &r, &Scalar::default(), &nonce).is_err());
        assert!(verify_signature_nonce(&pk, &m, &Scalar::default(), &s, &nonce).is_err());
    }

    #[test]
    fn signing_context_binds_messages_offsets_roles_and_mode() {
        let signers: HashSet<_> = [1, 2].into_iter().collect();
        let reordered: HashSet<_> = [2, 1].into_iter().collect();
        let pk = Point::new_gx(&Scalar::new(3));
        let context = |parties: &HashSet<usize>, msg, offset, batch| {
            signing_context("session", "setup", &pk, parties, &[msg], &[offset], batch)
        };
        let first = context(&signers, [1; 32], Scalar::new(4), false);
        assert_eq!(first, context(&reordered, [1; 32], Scalar::new(4), false));
        assert_ne!(first, context(&signers, [2; 32], Scalar::new(4), false));
        assert_ne!(first, context(&signers, [1; 32], Scalar::new(5), false));
        assert_ne!(first, context(&signers, [1; 32], Scalar::new(4), true));
        assert_ne!(mta_session_id(&first, 1, 2), mta_session_id(&first, 2, 1));
    }
}
