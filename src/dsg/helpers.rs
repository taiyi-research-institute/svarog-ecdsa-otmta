//! 签名时使用的小工具:
//! * `mta_session_id`: 为 (sender_i, receiver_j) 一对 RVOLE 调用派生
//!   独立 sid, 避免不同 pair 之间的哈希链/挑战相互污染.
//! * $R_i = r_i\cdot G$ 的 hash-commitment, 见 `notes/07-orchestration.md`
//!   Round 1: 先承诺后揭示, 防 last-actor 操纵聚合 $R$.
//! * `compute_zeta_i`: 工程添加的 pairwise 再随机化, 满足 $\sum_i \zeta_i = 0$.
//!   把它加到 $\mathtt{sk}_i$ 上, 不改 $\mathtt{sk} = \sum_i \mathtt{sk}_i$,
//!   但把每方真实份额"重新均匀打散" (笔记未覆盖, 是 silence-laboratories
//!   实现的工程加固).

use blake2::Blake2bVar;
use blake2::digest::{Update, VariableOutput};
use curve_abstract::{TrPoint, TrScalar};
use svarog_secp256k1::{Point, Scalar};

use super::super::dkg::PairwiseSeeds;

/// 为 $(\text{sender}=i,\ \text{receiver}=j)$ 这对 RVOLE/MtA 调用派生唯一 sid.
/// 同一对参与方在一次签名中跑两次 RVOLE (一次互换角色), 故下标顺序敏感.
pub(crate) fn mta_session_id(final_sid: &str, sender_i: usize, receiver_j: usize) -> String {
    format!("{}/dsg/mta/s={}/r={}", final_sid, sender_i, receiver_j)
}

/// 对参与方的 $R_i = r_i\cdot G$ 与一次性盲化值做哈希承诺.
/// 见 `notes/07-orchestration.md` Round 1.
pub(crate) fn hash_commitment_r_i(
    sid: &str,
    big_r_i: &Point,
    blind: &[u8; 32],
) -> [u8; 32] {
    let mut h = Blake2bVar::new(32).unwrap();
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
    &recomputed[..] == &commitment[..]
}

/// 派生 pairwise 标量 $v_{ij} = \mathrm{Hash}(\text{seed}_{ij} \,\|\, \text{sig\_id}) \bmod n$.
/// `sig_id` 让 $v$ 跨签名会话不可重用; `seed_ij` 由 keygen 时较小编号方
/// 明文生成并发给较大编号方 (见 `dkg_orch::PairwiseSeeds`).
fn pairwise_v(seed: &[u8; 32], sig_id: &str) -> Scalar {
    let mut h = Blake2bVar::new(32).unwrap();
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
