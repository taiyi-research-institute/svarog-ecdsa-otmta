//! DKLS23 Reshare 编排层. *人数与门限不变*, 旧份额可丢失.
//!
//! 6 轮协议:
//! * Round 0a (广播) 存活宣告. 每方公开是否仍持有旧份额; 持有者还顺带广播
//!                   `expected_pk` 与 `chain_code` (都从自己 `vss_scheme` /
//!                   keystore 字段计算).
//! * Round 0b (P2P)  active producer 将 $\lambda_i x_i$ 随机加性 split 成
//!                   $N$ 份; 第 $k$ 份 P2P 发给 party $k$. 自己留第 $i$ 份.
//! * Round 1-4       标准 keygen, 各方多项式常数项 $=$ 收到的 splits 之和.
//!                   末尾在 `keygen_inner` 内比对聚合公钥与 Round 0a 共识 PK.
//!
//! 设计要点:
//!
//! * **不直接交付 $\lambda_i x_i$**. 任意单一接收方只看到一个均匀随机标量 (该
//!   producer 给它的那份); 集齐 $N$ 份才能重建 producer 的本地 $\lambda_i x_i$,
//!   而 $\lambda_i x_i$ 又是 secret 的加性份额 — 这一层 split 提供了与 fresh
//!   keygen 同等的"无单点可重构性".
//!
//! * **lost-share 无需调用方告知**. 谁在 Round 0a 没声称 `has_share` 谁就是
//!   lost; 即"提供不出 `old_keystore`"即定义为 lost.
//!
//! * **`expected_pk` / `chain_code` 不作参数**. active producer 各自从旧 keystore
//!   导出, 在 Round 0a 广播; active producers 之间必须给出相同值, 否则中止.
//!   lost-share / 新加入方采纳 active 的共识.
//!
//! 已确立约束:
//! * `new_players` 与旧 `vss_scheme.keys()` 完全相同 (人数和 id 都不变).
//! * `th` 与旧门限相同 (由调用方传入, 学习项目不做对账).
//! * 至少 $\mathrm{th}$ 个 active producer; 否则 Lagrange 无解, 中止.
//!
//! 注: 与 fresh keygen 的关系 — 整个 Round 1-4 复用 [`keygen_inner`], 仅常数项来源
//! 与公钥校验不同; 见 [`crate::dkg::KeygenMode`].

use std::collections::{HashMap, HashSet};

use curve_abstract::{TrCurve, TrMessenger, TrScalar};
use erreur::*;
use serde::{Deserialize, Serialize};
use svarog_lagrange::{Keystore, VerifiableSecretSharing};
use svarog_secp256k1::{Point, Scalar, Secp256k1};

use super::super::dkg::{KeygenMode, keygen_inner};

/// Round 0a 的存活宣告.
///
/// `has_share = true` 时 `pk_and_cc` 必为 `Some`; 否则必为 `None`.
#[derive(Clone, Default, Serialize, Deserialize)]
struct AliveAnnounce {
    has_share: bool,
    pk_and_cc: Option<(Point, [u8; 32])>,
}

/// 重共享, 保持人数和门限不变.
///
/// 参数:
/// * `new_players` - 新 (= 旧) 参与方 id 集合. 必须含 `i`.
/// * `i`, `th`     - 本方 id 与门限.
/// * `old_keystore`:
///     - `Some(ks)`: active producer, `ks.vss_scheme.keys() == new_players`;
///     - `None`:     lost-share 方 (旧曾参与 keygen 但已丢失份额).
pub async fn reshare(
    mut ch: impl TrMessenger,
    sid: String,
    new_players: HashSet<usize>,
    i: usize,
    th: usize,
    old_keystore: Option<&Keystore<Secp256k1>>,
) -> Resultat<Keystore<Secp256k1>> {
    assert_throw!(
        new_players.contains(&i),
        "InvalidArgument",
        format!("reshare: party {} not in new_players", i)
    );

    // 人数不变: 旧 keystore 的 vss_scheme key 集合 == new_players.
    if let Some(ks) = old_keystore {
        let old_set: HashSet<usize> = ks.vss_scheme.keys().copied().collect();
        assert_throw!(
            old_set == new_players,
            "InvalidArgument",
            "reshare: keystore's old player set must match new_players"
        );
    }

    let others: Vec<usize> = {
        let mut v: Vec<usize> = new_players.iter().copied().filter(|&p| p != i).collect();
        v.sort();
        v
    };
    let new_player_ordered: Vec<usize> = {
        let mut v: Vec<usize> = new_players.iter().copied().collect();
        v.sort();
        v
    };

    // ── Round 0a: 存活宣告 + (expected_pk, chain_code) 广播 ─────────────────

    let my_announce = match old_keystore {
        Some(ks) => AliveAnnounce {
            has_share: true,
            pk_and_cc: Some((ks.public_key(), ks.chain_code)),
        },
        None => AliveAnnounce::default(),
    };

    let mut announces: HashMap<usize, AliveAnnounce> = HashMap::new();
    announces.insert(i, my_announce.clone());
    for &j in &others {
        announces.insert(j, AliveAnnounce::default());
    }

    ch.register_send(&my_announce, &sid, "reshare/r0a/announce", i, 0, 0);
    for &j in &others {
        let slot = announces.get_mut(&j).unwrap();
        ch.register_recv(slot, &sid, "reshare/r0a/announce", j, 0, 0);
    }
    ch.exchange()
        .await
        .catch("FailedToExchange", "reshare Round 0a")?;

    let active_producers: HashSet<usize> = announces
        .iter()
        .filter_map(|(&id, a)| if a.has_share { Some(id) } else { None })
        .collect();

    assert_throw!(
        active_producers.len() >= th,
        "InsufficientActiveProducers",
        format!(
            "reshare: need >= {} active producers, got {}",
            th,
            active_producers.len()
        )
    );

    // active producers 必须广播一致的 (expected_pk, chain_code).
    let mut consensus: Option<(Point, [u8; 32])> = None;
    for &p in &active_producers {
        let pkc = announces[&p].pk_and_cc.as_ref().ifnone(
            "MalformedReshareAnnounce",
            format!("reshare: producer {} announced has_share=true but no pk/cc", p),
        )?;
        match &consensus {
            Some(c) => assert_throw!(
                c == pkc,
                "InconsistentReshareAnnounce",
                format!("reshare: producer {} disagrees with peers on pk/chain_code", p)
            ),
            None => consensus = Some(pkc.clone()),
        }
    }
    let (expected_pk, chain_code) = consensus.unwrap();

    // ── Round 0b: producer 随机 split + P2P 发送 ──────────────────────────

    let mut received_splits: HashMap<usize, Scalar> = HashMap::new();
    let mut my_pieces: HashMap<usize, Scalar> = HashMap::new();

    if let Some(ks) = old_keystore {
        // 本方是 active producer: 算 $\lambda_i x_i$, 随机 split.
        //
        // split 规则: 前 $N-1$ 份取均匀随机, 第 $N$ 份取 $\lambda_i x_i$ 减
        // 前面之和. 这样 $\sum_k$ 份额 $= \lambda_i x_i$ 严格成立.
        let lambda_i = Secp256k1::lagrange_lambda(i, &active_producers);
        let s_i = lambda_i.mul(&ks.xi);

        let mut running = s_i.clone();
        for (idx, &k) in new_player_ordered.iter().enumerate() {
            if idx + 1 < new_player_ordered.len() {
                let r = Scalar::new_rand();
                running = running.sub(&r);
                my_pieces.insert(k, r);
            } else {
                my_pieces.insert(k, running.clone());
            }
        }

        // 第 $i$ 份本地留存; 其余 P2P 发出.
        received_splits.insert(i, my_pieces[&i].clone());
        for &j in &others {
            ch.register_send(&my_pieces[&j], &sid, "reshare/r0b/split", i, j, 0);
        }
    }

    // 从其他 active producer 收 split.
    for &p in &active_producers {
        if p == i {
            continue;
        }
        received_splits.insert(p, Scalar::default());
    }
    for &p in &active_producers {
        if p == i {
            continue;
        }
        let slot = received_splits.get_mut(&p).unwrap();
        ch.register_recv(slot, &sid, "reshare/r0b/split", p, i, 0);
    }
    ch.exchange()
        .await
        .catch("FailedToExchange", "reshare Round 0b")?;

    // 多项式常数项 $:= \sum_p$ (收到的来自 $p$ 的 split).
    let mut ui_scalar = Secp256k1::zero().clone();
    for s in received_splits.values() {
        ui_scalar = ui_scalar.add(s);
    }

    // ── Round 1-4: 走 keygen_inner; 末尾比对 expected_pk ──────────────────

    keygen_inner(
        ch,
        sid,
        new_players,
        i,
        th,
        ui_scalar,
        chain_code,
        KeygenMode::Reshare {
            expected_public_key: expected_pk,
        },
    )
    .await
}

// ── tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dkg::keygen;
    use crate::dsg::sign;
    use crate::toy_messenger::ToyMessenger;
    use dashmap::DashMap;
    use std::sync::Arc;

    async fn run_keygen(
        players: HashSet<usize>,
        th: usize,
    ) -> Vec<Keystore<Secp256k1>> {
        let db = Arc::new(DashMap::new());
        let mut handles = Vec::new();
        for &i in &players {
            let dbi = db.clone();
            let pls = players.clone();
            let h = tokio::spawn(async move {
                let ch = ToyMessenger::new(dbi);
                keygen(ch, "dkg-sid".into(), pls, i, th, None, None)
                    .await
                    .unwrap()
            });
            handles.push(h);
        }
        let mut keystores = Vec::with_capacity(players.len());
        for h in handles {
            keystores.push(h.await.unwrap());
        }
        keystores.sort_by_key(|k| k.i);
        keystores
    }

    async fn run_reshare(
        sid: &str,
        inputs: Vec<(usize, Option<Keystore<Secp256k1>>)>,
        new_players: HashSet<usize>,
        new_th: usize,
    ) -> Vec<Keystore<Secp256k1>> {
        let db = Arc::new(DashMap::new());
        let mut handles = Vec::new();
        for (i, ks_opt) in inputs {
            let dbi = db.clone();
            let pls = new_players.clone();
            let sid_i = sid.to_string();
            let h = tokio::spawn(async move {
                let ch = ToyMessenger::new(dbi);
                reshare(ch, sid_i, pls, i, new_th, ks_opt.as_ref())
                    .await
                    .unwrap()
            });
            handles.push(h);
        }
        let mut keystores = Vec::with_capacity(handles.len());
        for h in handles {
            keystores.push(h.await.unwrap());
        }
        keystores.sort_by_key(|k| k.i);
        keystores
    }

    async fn run_sign(
        keystores: Vec<Keystore<Secp256k1>>,
        signers: HashSet<usize>,
    ) {
        let db = Arc::new(DashMap::new());
        let msg = [0xA5u8; 32];
        let sid = "sign-sid".to_string();
        let mut handles = Vec::new();
        for ks in keystores.into_iter().filter(|k| signers.contains(&k.i)) {
            let dbi = db.clone();
            let sg = signers.clone();
            let sid_i = sid.clone();
            let h = tokio::spawn(async move {
                let ch = ToyMessenger::new(dbi);
                sign(ch, sid_i, sg, &ks, Scalar::default(), msg)
                    .await
                    .unwrap()
            });
            handles.push(h);
        }
        let mut sigs = Vec::new();
        for h in handles {
            sigs.push(h.await.unwrap());
        }
        let first = sigs[0].clone();
        for s in &sigs[1..] {
            assert_eq!(s.r, first.r);
            assert_eq!(s.s, first.s);
        }
    }

    /// Rotation: 全员都有旧份额, 2-of-3 → 2-of-3. 公钥/链码不变, 任选 2 方可签.
    #[tokio::test(flavor = "multi_thread", worker_threads = 8)]
    async fn test_reshare_rotation_2_of_3() {
        let old_players: HashSet<usize> = [1usize, 2, 3].iter().copied().collect();
        let old_keystores = run_keygen(old_players.clone(), 2).await;
        let expected_pk = old_keystores[0].public_key();
        let chain_code = old_keystores[0].chain_code;
        let new_players = old_players.clone();
        let inputs: Vec<(usize, Option<Keystore<Secp256k1>>)> = old_keystores
            .iter()
            .map(|ks| (ks.i, Some(ks.clone())))
            .collect();

        let new_keystores = run_reshare("reshare-rot", inputs, new_players, 2).await;

        for ks in &new_keystores {
            assert_eq!(ks.public_key(), expected_pk);
            assert_eq!(ks.chain_code, chain_code);
        }

        let signers: HashSet<usize> = [2usize, 3].iter().copied().collect();
        run_sign(new_keystores, signers).await;
    }

    /// 3-of-2 keygen, 2 方提供分片 (party 3 丢份额), 全部 3 个 2-子集均可签.
    ///
    /// 与 `test_reshare_recover_lost_share` 的差异:
    /// * lost party 换到 3 号 (验证协议对任意 producer 子集对称);
    /// * 跑 $\binom{3}{2}=3$ 个签名子集 — 含/不含恢复方都覆盖;
    /// * 验证 active producer 的 `xi` 真被刷新 (保证 reshare 不是恒等映射).
    #[tokio::test(flavor = "multi_thread", worker_threads = 8)]
    async fn test_reshare_2_of_3_providers() {
        let old_players: HashSet<usize> = [1usize, 2, 3].iter().copied().collect();
        let old_keystores = run_keygen(old_players.clone(), 2).await;
        let expected_pk = old_keystores[0].public_key();
        let chain_code = old_keystores[0].chain_code;

        // Party 3 丢份额, 1 和 2 提供.
        let new_players = old_players.clone();
        let inputs: Vec<(usize, Option<Keystore<Secp256k1>>)> = old_keystores
            .iter()
            .map(|ks| {
                let opt = if ks.i == 3 { None } else { Some(ks.clone()) };
                (ks.i, opt)
            })
            .collect();

        let new_keystores = run_reshare("reshare-2of3-providers", inputs, new_players, 2).await;

        // 公钥与链码不变.
        for ks in &new_keystores {
            assert_eq!(ks.public_key(), expected_pk);
            assert_eq!(ks.chain_code, chain_code);
        }

        // active producer 的 xi 真被刷新, 不是恒等映射.
        for new_ks in &new_keystores {
            if new_ks.i == 3 {
                continue; // 旧 3 号无份额可比.
            }
            let old_ks = old_keystores.iter().find(|k| k.i == new_ks.i).unwrap();
            assert_ne!(
                new_ks.xi, old_ks.xi,
                "reshare did not rotate xi for party {}", new_ks.i
            );
        }

        // 全部 3 个 2-签名子集都能跑通.
        for subset in [[1usize, 2], [1, 3], [2, 3]] {
            let signers: HashSet<usize> = subset.iter().copied().collect();
            run_sign(new_keystores.clone(), signers).await;
        }
    }

    /// Lost-share 恢复: party 1 丢份额, party 2/3 协助, 协议自动识别.
    #[tokio::test(flavor = "multi_thread", worker_threads = 8)]
    async fn test_reshare_recover_lost_share() {
        let old_players: HashSet<usize> = [1usize, 2, 3].iter().copied().collect();
        let old_keystores = run_keygen(old_players.clone(), 2).await;
        let expected_pk = old_keystores[0].public_key();
        let chain_code = old_keystores[0].chain_code;

        let new_players = old_players.clone();
        let inputs: Vec<(usize, Option<Keystore<Secp256k1>>)> = old_keystores
            .iter()
            .map(|ks| {
                let opt = if ks.i == 1 { None } else { Some(ks.clone()) };
                (ks.i, opt)
            })
            .collect();

        let new_keystores = run_reshare("reshare-recover", inputs, new_players, 2).await;

        for ks in &new_keystores {
            assert_eq!(ks.public_key(), expected_pk);
            assert_eq!(ks.chain_code, chain_code);
        }

        let signers: HashSet<usize> = [1usize, 2].iter().copied().collect();
        run_sign(new_keystores, signers).await;
    }
}
