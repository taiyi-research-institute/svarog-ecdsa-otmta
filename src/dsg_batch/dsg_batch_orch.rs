//! DKLS23 批量 Sign 编排.
//!
//! 4 轮编排 (与 `crate::dsg::dsg_orch` 同形, 数据按 $N$ 加宽):
//! * R1  广播 $N$ 个 $R_i^{(s)}$ 的批量 hash commitment.
//! * R2  各方互发 RVOLE Round1 (SoftSpoken 每对一次, 跨 N 笔共享).
//! * R3  完成批量 RVOLE (bsize = $2N$).
//! * R4  广播 $N$ 组 $(s_0^{(s)}, s_1^{(s)})$ 部分签名, 各自聚合 $s = s_0 / s_1$.

use std::collections::{HashMap, HashSet};

use curve_abstract::{TrMessenger, TrPoint, TrScalar};
use erreur::*;
use serde::{Deserialize, Serialize};
use svarog_lagrange::{Keystore, VerifiableSecretSharing};
use svarog_secp256k1::{Point, Scalar, Secp256k1};

use crate::dkg::decode_keygen_aux;
use crate::dsg::EcdsaSignature;
use crate::dsg::helpers::{compute_zeta_i, mta_session_id, recovery_id};
use crate::dsg::softspoken_ot::{SSReceiverKeys, SoftSpokenMsg1, ss_receiver, ss_sender};

use super::helpers::{digest_after_round1, hash_commitment_r_batch, per_sig_sid, sorted_others};
use super::rvole::{
    RVOLEBatchMsg2, empty_msg2, rvole_round1_batch, rvole_round2_batch, rvole_round3_batch,
};

/// 门限 ECDSA 批量签名. 一次调用完成 N 笔签名.
pub async fn sign_batch(
    mut ch: impl TrMessenger,
    sid: String,
    signers: HashSet<usize>,
    keystore: &Keystore<Secp256k1>,
    offsets: Vec<Scalar>,
    msg_hashes: Vec<[u8; 32]>,
) -> Resultat<Vec<EcdsaSignature>> {
    let n_sigs = msg_hashes.len();
    assert_throw!(n_sigs >= 1, "EmptyBatch", "sign_batch: msg_hashes is empty");
    assert_throw!(
        offsets.len() == n_sigs,
        "OffsetLenMismatch",
        format!(
            "sign_batch: offsets.len()={} but msg_hashes.len()={}",
            offsets.len(),
            n_sigs
        )
    );
    let bsize = 2 * n_sigs;

    let aux = decode_keygen_aux(&keystore.aux).catch(
        "KeygenAuxDecodeFailed",
        "sign_batch: cannot decode aux blob",
    )?;
    let i = keystore.i;
    let n_signers = signers.len();
    assert_throw!(
        signers.contains(&i),
        "NotASigner",
        format!("party {} not in signers set", i)
    );
    let others = sorted_others(&signers, i);

    // ── Round 0. 本地准备 ────────────────────────────────────────────
    // 每笔签名一个派生公钥 $\mathrm{pk}'^{(s)} = Y + \nabla x^{(s)}\cdot G$,
    // 以及对应均摊到本方的偏移 $\nabla x^{(s)} / |S|$.
    let base_pk = keystore.public_key();
    let n_inv = Scalar::new(n_signers as i64).inv_ct();
    let pk_prime_per_sig: Vec<Point> = offsets.iter().map(|o| base_pk.add_gx(o)).collect();
    let delta_per_share_per_sig: Vec<Scalar> = offsets.iter().map(|o| o.mul(&n_inv)).collect();

    // 每笔签名各自的 $\phi_i^{(s)}$, $r_i^{(s)}$, $R_i^{(s)}$; 共用一个 blind.
    let phi_per_sig: Vec<Scalar> = (0..n_sigs).map(|_| Scalar::new_rand()).collect();
    let r_per_sig: Vec<Scalar> = (0..n_sigs).map(|_| Scalar::new_rand()).collect();
    let big_r_per_sig: Vec<Point> = r_per_sig.iter().map(Point::new_gx).collect();
    let blind_i: [u8; 32] = {
        let bytes = hash!(32; b"dsg_batch/blind", &Scalar::new_rand().to_bytes());
        let mut out = [0u8; 32];
        out.copy_from_slice(&bytes);
        out
    };
    let commit_i = hash_commitment_r_batch(&sid, &big_r_per_sig, &blind_i);

    // 每笔签名各自的 $\zeta_i^{(s)}$ (per-sig sid 派生) -> $\mathrm{sk}_i^{(s)}$.
    let lambda_i = Secp256k1::lagrange_lambda(i, &signers);
    let lambda_xi = lambda_i.mul(&keystore.xi);
    let sk_per_sig: Vec<Scalar> = (0..n_sigs)
        .map(|s| {
            let s_sid = per_sig_sid(&sid, s);
            let zeta_s = compute_zeta_i(&aux.seeds, i, &s_sid, &others);
            lambda_xi.add(&zeta_s).add(&delta_per_share_per_sig[s])
        })
        .collect();
    let pk_i_per_sig: Vec<Point> = sk_per_sig.iter().map(Point::new_gx).collect();

    // RVOLE Sender 输入向量: 按 sig 交错 [r^(1), sk^(1), r^(2), sk^(2), ...].
    let xa_vec: Vec<Scalar> = (0..n_sigs)
        .flat_map(|s| [r_per_sig[s].clone(), sk_per_sig[s].clone()])
        .collect();
    assert_throw!(
        xa_vec.len() == bsize,
        "InternalShape",
        "xa_vec length mismatch"
    );

    // ── Round 1: 交换批量承诺 ──────────────────────────────────────
    let mut commits: HashMap<usize, [u8; 32]> = HashMap::new();
    commits.insert(i, commit_i);
    for &j in &others {
        commits.insert(j, [0u8; 32]);
    }
    ch.register_send(&commit_i, &sid, "dsg_batch/r1/commit", i, 0, 0);
    for &j in &others {
        let slot = commits.get_mut(&j).unwrap();
        ch.register_recv(slot, &sid, "dsg_batch/r1/commit", j, 0, 0);
    }
    ch.exchange()
        .await
        .catch("ExchangeFailed", "dsg_batch round 1")?;

    let digest_i = digest_after_round1(&sid, &pk_prime_per_sig, &commits, &signers);

    // ── Round 2: 我作 RVOLE Receiver, pair (j -> i) ────────────────
    // 每对一次 SoftSpoken + 一个 $\beta_{j,i}$ (跨 $N$ 笔共享).
    let mut rvole_recv_state: HashMap<usize, (Vec<u8>, SSReceiverKeys)> = HashMap::new();
    let mut beta_table: HashMap<usize, Scalar> = HashMap::new();
    let mut my_round1_to_j: HashMap<usize, SoftSpokenMsg1> = HashMap::new();
    let mut their_round1_from_j: HashMap<usize, SoftSpokenMsg1> = HashMap::new();

    for &j in &others {
        let pair_sid = mta_session_id(&sid, j, i);
        let sender_seed = aux.pprf_seeds.as_sender.get(&j);
        assert_throw!(
            sender_seed.is_some(),
            "MissingPPRFSeed",
            format!("as_sender[{}]", j)
        );
        let sender_seed = sender_seed.unwrap();
        let (beta_bits_ji, beta_ji) = rvole_round1_batch(&pair_sid);
        let (round1, recv_out) = ss_receiver(&pair_sid, sender_seed, &beta_bits_ji);
        rvole_recv_state.insert(j, (beta_bits_ji, recv_out));
        beta_table.insert(j, beta_ji);
        my_round1_to_j.insert(j, round1);
        their_round1_from_j.insert(j, SoftSpokenMsg1::default());
    }

    for &j in &others {
        ch.register_send(&my_round1_to_j[&j], &sid, "dsg_batch/r2/mta1", i, j, 0);
        let slot = their_round1_from_j.get_mut(&j).unwrap();
        ch.register_recv(slot, &sid, "dsg_batch/r2/mta1", j, i, 0);
    }
    ch.exchange()
        .await
        .catch("ExchangeFailed", "dsg_batch round 2")?;

    // 本地: $\psi_{i,j}^{(s)} = \phi_i^{(s)} - \beta_{j,i}$ (每对 N 个).
    let mut psi_to_j: HashMap<usize, Vec<Scalar>> = HashMap::new();
    for &j in &others {
        let beta_ji = &beta_table[&j];
        let psis: Vec<Scalar> = (0..n_sigs).map(|s| phi_per_sig[s].sub(beta_ji)).collect();
        psi_to_j.insert(j, psis);
    }

    // ── Round 3: 我作 RVOLE Sender, pair (i -> j); 顺路发预签数据 ──
    let mut my_r3: HashMap<usize, Round3P2P> = HashMap::new();
    let mut their_r3: HashMap<usize, Round3P2P> = HashMap::new();
    let mut sender_c_uv: HashMap<usize, Vec<Scalar>> = HashMap::new();

    let empty_r3_template = Round3P2P {
        rvole_output: empty_msg2(bsize),
        digest: [0u8; 32],
        pk_i_per_sig: vec![Point::default(); n_sigs],
        big_r_per_sig: vec![Point::default(); n_sigs],
        blind: [0u8; 32],
        gamma_u_per_sig: vec![Point::default(); n_sigs],
        gamma_v_per_sig: vec![Point::default(); n_sigs],
        psi_per_sig: vec![Scalar::default(); n_sigs],
    };

    for &j in &others {
        let pair_sid = mta_session_id(&sid, i, j);
        let recv_seed = aux.pprf_seeds.as_receiver.get(&j);
        assert_throw!(
            recv_seed.is_some(),
            "MissingPPRFSeed",
            format!("as_receiver[{}]", j)
        );
        let recv_seed = recv_seed.unwrap();
        let send_out = ss_sender(&pair_sid, recv_seed, &their_round1_from_j[&j])
            .catch("SoftSpokenOTFailed", &format!("to j={}", j))?;
        let (rvole_out, c_vec) = rvole_round2_batch(&pair_sid, &send_out, &xa_vec);
        let mut gamma_u = Vec::with_capacity(n_sigs);
        let mut gamma_v = Vec::with_capacity(n_sigs);
        for s in 0..n_sigs {
            gamma_u.push(Point::new_gx(&c_vec[2 * s]));
            gamma_v.push(Point::new_gx(&c_vec[2 * s + 1]));
        }
        sender_c_uv.insert(j, c_vec);
        my_r3.insert(
            j,
            Round3P2P {
                rvole_output: rvole_out,
                digest: digest_i,
                pk_i_per_sig: pk_i_per_sig.clone(),
                big_r_per_sig: big_r_per_sig.clone(),
                blind: blind_i,
                gamma_u_per_sig: gamma_u,
                gamma_v_per_sig: gamma_v,
                psi_per_sig: psi_to_j[&j].clone(),
            },
        );
        their_r3.insert(j, empty_r3_template.clone());
    }

    for &j in &others {
        ch.register_send(&my_r3[&j], &sid, "dsg_batch/r3/p2p", i, j, 0);
        let slot = their_r3.get_mut(&j).unwrap();
        ch.register_recv(slot, &sid, "dsg_batch/r3/p2p", j, i, 0);
    }
    ch.exchange()
        .await
        .catch("ExchangeFailed", "dsg_batch round 3")?;

    // ── 本地聚合 ────────────────────────────────────────────────────
    let mut big_r_sum: Vec<Point> = big_r_per_sig.clone();
    let mut sum_pk_per_sig: Vec<Point> = pk_i_per_sig.clone();
    let mut sum_psi_to_me_per_sig = vec![Scalar::default(); n_sigs];
    let mut sum_u_per_sig = vec![Scalar::default(); n_sigs];
    let mut sum_v_per_sig = vec![Scalar::default(); n_sigs];

    for &j in &others {
        let r3 = &their_r3[&j];

        assert_throw!(
            r3.digest == digest_i,
            "DigestMismatch",
            format!("dsg_batch: peer {} digest mismatch", j)
        );
        assert_throw!(
            r3.big_r_per_sig.len() == n_sigs
                && r3.pk_i_per_sig.len() == n_sigs
                && r3.gamma_u_per_sig.len() == n_sigs
                && r3.gamma_v_per_sig.len() == n_sigs
                && r3.psi_per_sig.len() == n_sigs,
            "ShapeMismatch",
            format!("dsg_batch: peer {} wrong per-sig shape", j)
        );
        let recomputed = hash_commitment_r_batch(&sid, &r3.big_r_per_sig, &r3.blind);
        assert_throw!(
            recomputed == commits[&j],
            "InvalidCommitment",
            format!("dsg_batch: peer {} R-commitment open mismatch", j)
        );

        let (beta_bits_ji, recv_out) = rvole_recv_state.remove(&j).unwrap();
        let beta_ji = beta_table.remove(&j).unwrap();
        let pair_sid = mta_session_id(&sid, j, i);
        let d_vec =
            rvole_round3_batch(&pair_sid, bsize, &beta_bits_ji, &recv_out, &r3.rvole_output)
                .catch("RVOLEReceiverFailed", &format!("from j={}", j))?;

        for s in 0..n_sigs {
            let d_u = &d_vec[2 * s];
            let d_v = &d_vec[2 * s + 1];

            // $R_j^{(s)} \cdot \beta_{j,i} = G\cdot d_u + \Gamma_u^{(s)}$
            let lhs1 = r3.big_r_per_sig[s].mul_x(&beta_ji);
            let rhs1 = r3.gamma_u_per_sig[s].add_gx(d_u);
            assert_throw!(
                lhs1 == rhs1,
                "RVOLEConsistencyU",
                format!("dsg_batch: R-side check failed for j={} s={}", j, s)
            );
            // $\mathrm{pk}_j^{(s)} \cdot \beta_{j,i} = G\cdot d_v + \Gamma_v^{(s)}$
            let lhs2 = r3.pk_i_per_sig[s].mul_x(&beta_ji);
            let rhs2 = r3.gamma_v_per_sig[s].add_gx(d_v);
            assert_throw!(
                lhs2 == rhs2,
                "RVOLEConsistencyV",
                format!("dsg_batch: pk-side check failed for j={} s={}", j, s)
            );

            big_r_sum[s] = big_r_sum[s].add(&r3.big_r_per_sig[s]);
            sum_pk_per_sig[s] = sum_pk_per_sig[s].add(&r3.pk_i_per_sig[s]);
            sum_psi_to_me_per_sig[s] = sum_psi_to_me_per_sig[s].add(&r3.psi_per_sig[s]);

            let c = &sender_c_uv[&j];
            sum_u_per_sig[s] = sum_u_per_sig[s].add(&c[2 * s]).add(d_u);
            sum_v_per_sig[s] = sum_v_per_sig[s].add(&c[2 * s + 1]).add(d_v);
        }
    }

    for s in 0..n_sigs {
        assert_throw!(
            sum_pk_per_sig[s] == pk_prime_per_sig[s],
            "PublicKeyConsistency",
            format!("dsg_batch: sum of P_i mismatch at sig {}", s)
        );
    }

    // 每笔签名的 $\Phi_i^{(s)} = \phi_i^{(s)} + \sum_j \psi_{j,i}^{(s)}$,
    // 以及 $(s_0^{(s)}, s_1^{(s)})$ 和 $r_x^{(s)}$.
    let mut my_parts: Vec<(Scalar, Scalar)> = Vec::with_capacity(n_sigs);
    let mut r_x_per_sig: Vec<Scalar> = Vec::with_capacity(n_sigs);
    for s in 0..n_sigs {
        let r_long = big_r_sum[s].to_bytes_long();
        assert_throw!(
            r_long.len() == 65,
            "InvalidPoint",
            "to_bytes_long must return 65 bytes"
        );
        let r_x = Scalar::new_from_bytes(&r_long[1..33]);
        r_x_per_sig.push(r_x.clone());

        let phi_star_s = phi_per_sig[s].add(&sum_psi_to_me_per_sig[s]);
        let mut s_0 = r_x.mul(&sk_per_sig[s].mul(&phi_star_s).add(&sum_v_per_sig[s]));
        let s_1 = r_per_sig[s].mul(&phi_star_s).add(&sum_u_per_sig[s]);
        let m = Scalar::new_from_bytes(&msg_hashes[s]);
        s_0 = s_0.add(&m.mul(&phi_per_sig[s]));
        my_parts.push((s_0, s_1));
    }

    // ── Round 4: 广播每笔签名的部分签名 ──────────────────────────
    let my_bcast = Round4Bcast {
        parts: my_parts.clone(),
    };
    let mut partials: HashMap<usize, Round4Bcast> = HashMap::new();
    partials.insert(i, my_bcast.clone());
    let empty_bcast = Round4Bcast {
        parts: vec![(Scalar::default(), Scalar::default()); n_sigs],
    };
    for &j in &others {
        partials.insert(j, empty_bcast.clone());
    }
    ch.register_send(&my_bcast, &sid, "dsg_batch/r4/partial", i, 0, 0);
    for &j in &others {
        let slot = partials.get_mut(&j).unwrap();
        ch.register_recv(slot, &sid, "dsg_batch/r4/partial", j, 0, 0);
    }
    ch.exchange()
        .await
        .catch("ExchangeFailed", "dsg_batch round 4")?;

    // 聚合 + 本地 ECDSA 验签自检.
    let mut sigs = Vec::with_capacity(n_sigs);
    for s in 0..n_sigs {
        let mut sum_s_0 = Scalar::default();
        let mut sum_s_1 = Scalar::default();
        for &j in signers.iter() {
            let p = &partials[&j];
            assert_throw!(
                p.parts.len() == n_sigs,
                "ShapeMismatch",
                format!("dsg_batch: peer {} partial length mismatch", j)
            );
            sum_s_0 = sum_s_0.add(&p.parts[s].0);
            sum_s_1 = sum_s_1.add(&p.parts[s].1);
        }
        let s_val = sum_s_0.mul(&sum_s_1.inv_ct());
        let r_val = r_x_per_sig[s].clone();

        let m = Scalar::new_from_bytes(&msg_hashes[s]);
        let s_inv = s_val.inv_ct();
        let u1 = m.mul(&s_inv);
        let u2 = r_val.mul(&s_inv);
        let big_r_check = pk_prime_per_sig[s].mul_x(&u2).add_gx(&u1);
        let r_check_long = big_r_check.to_bytes_long();
        let r_check = Scalar::new_from_bytes(&r_check_long[1..33]);
        assert_throw!(
            r_check == r_val,
            "EcdsaVerifyFailed",
            format!("dsg_batch: local ECDSA verification mismatch at sig {}", s)
        );
        sigs.push(EcdsaSignature {
            r: r_val,
            s: s_val,
            v: recovery_id(&big_r_sum[s]),
        });
    }

    Ok(sigs)
}

// ── 轮间消息 ─────────────────────────────────────────────────────────────

/// Round 3 P2P 包: 批量 RVOLE Sender 回包 + R/pk 揭示 + $\Gamma$ 一致性 + $\psi$.
#[derive(Clone, Default, Serialize, Deserialize)]
struct Round3P2P {
    rvole_output: RVOLEBatchMsg2,
    digest: [u8; 32],
    /// $\mathrm{pk}_i^{(s)} = \mathrm{sk}_i^{(s)}\cdot G$, $N$ 个.
    pk_i_per_sig: Vec<Point>,
    /// $R_i^{(s)} = r_i^{(s)}\cdot G$, $N$ 个.
    big_r_per_sig: Vec<Point>,
    blind: [u8; 32],
    /// $\Gamma^{(u, s)}_{i,j}$, $\Gamma^{(v, s)}_{i,j}$, 各 $N$ 个.
    gamma_u_per_sig: Vec<Point>,
    gamma_v_per_sig: Vec<Point>,
    /// $\psi_{i,j}^{(s)} = \phi_i^{(s)} - \beta_{j,i}$, 每笔签名一个.
    psi_per_sig: Vec<Scalar>,
}

#[derive(Clone, Default, Serialize, Deserialize)]
struct Round4Bcast {
    /// 每笔签名一对 $(s_0^{(s)}, s_1^{(s)})$.
    parts: Vec<(Scalar, Scalar)>,
}

// ── tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dkg::keygen;
    use crate::toy_messenger::ToyMessenger;
    use dashmap::DashMap;
    use std::sync::Arc;

    async fn run_dkg(n: usize, th: usize) -> Vec<Keystore<Secp256k1>> {
        let players: HashSet<usize> = (1..=n).collect();
        let db = Arc::new(DashMap::new());
        let mut handles = Vec::new();
        for i in 1..=n {
            let dbi = db.clone();
            let players_i = players.clone();
            let h = tokio::spawn(async move {
                let ch = ToyMessenger::new(dbi);
                keygen(ch, "dkg-sid".into(), players_i, i, th, None, None)
                    .await
                    .unwrap()
            });
            handles.push(h);
        }
        let mut keystores = Vec::with_capacity(n);
        for h in handles {
            keystores.push(h.await.unwrap());
        }
        keystores.sort_by_key(|k| k.i);
        keystores
    }

    async fn run_batch_sign(
        keystores: Vec<Keystore<Secp256k1>>,
        signers: HashSet<usize>,
        msgs: Vec<[u8; 32]>,
        offsets: Vec<Scalar>,
    ) {
        assert_eq!(offsets.len(), msgs.len());
        let db = Arc::new(DashMap::new());
        let sid = "batch-sign-sid".to_string();
        let mut handles = Vec::new();
        for ks in keystores.into_iter().filter(|k| signers.contains(&k.i)) {
            let dbi = db.clone();
            let signers_i = signers.clone();
            let sid_i = sid.clone();
            let msgs_i = msgs.clone();
            let offsets_i = offsets.clone();
            let h = tokio::spawn(async move {
                let ch = ToyMessenger::new(dbi);
                sign_batch(ch, sid_i, signers_i, &ks, offsets_i, msgs_i)
                    .await
                    .unwrap()
            });
            handles.push(h);
        }
        let mut all = Vec::new();
        for h in handles {
            all.push(h.await.unwrap());
        }
        let first = all[0].clone();
        assert_eq!(first.len(), msgs.len());
        for batch in &all[1..] {
            assert_eq!(batch.len(), first.len());
            for s in 0..first.len() {
                assert_eq!(batch[s].r, first[s].r);
                assert_eq!(batch[s].s, first[s].s);
                assert_eq!(batch[s].v, first[s].v);
            }
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 8)]
    async fn test_batch_sign_2_of_2_n3() {
        let keystores = run_dkg(2, 2).await;
        let signers: HashSet<usize> = [1usize, 2].iter().copied().collect();
        let msgs: Vec<[u8; 32]> = (0..3u8).map(|x| [x; 32]).collect();
        let offsets = vec![Scalar::default(); msgs.len()];
        run_batch_sign(keystores, signers, msgs, offsets).await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 8)]
    async fn test_batch_sign_2_of_3_n2() {
        let keystores = run_dkg(3, 2).await;
        let signers: HashSet<usize> = [1usize, 3].iter().copied().collect();
        let msgs: Vec<[u8; 32]> = (10..12u8).map(|x| [x; 32]).collect();
        let offsets = vec![Scalar::default(); msgs.len()];
        run_batch_sign(keystores, signers, msgs, offsets).await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 8)]
    async fn test_batch_sign_3_of_3_n1() {
        // N=1 边界, 应当等价于单笔 sign.
        let keystores = run_dkg(3, 3).await;
        let signers: HashSet<usize> = [1usize, 2, 3].iter().copied().collect();
        let msgs: Vec<[u8; 32]> = vec![[0xA5u8; 32]];
        let offsets = vec![Scalar::default(); msgs.len()];
        run_batch_sign(keystores, signers, msgs, offsets).await;
    }

    /// 每笔签名独立 BIP-32 offset, 真正跑 per-sig $\nabla x^{(s)}$ 路径.
    #[tokio::test(flavor = "multi_thread", worker_threads = 8)]
    async fn test_batch_sign_distinct_offsets() {
        let keystores = run_dkg(3, 2).await;
        let signers: HashSet<usize> = [2usize, 3].iter().copied().collect();
        let msgs: Vec<[u8; 32]> = (0..4u8).map(|x| [x ^ 0x37; 32]).collect();
        let offsets: Vec<Scalar> = (0..msgs.len()).map(|_| Scalar::new_rand()).collect();
        run_batch_sign(keystores, signers, msgs, offsets).await;
    }
}
