//! DKLS23 Sign 编排层, 见 `notes/07-orchestration.md` 签名部分.
//!
//! 4 轮编排:
//! * R1  广播 $R_i$ 的 hash commitment.
//! * R2  各方互发 RVOLE Round1.
//! * R3  完成 RVOLE.
//! * R4  广播 $(s_0, s_1)$ 部分签名, 聚合得 $s = s_0 / s_1$.
//!
//! 工程添加:
//! * 末尾 *本地 ECDSA 验签*, 自检, `notes/07-orchestration` 未要求.

use std::collections::{HashMap, HashSet};

use blake2::Blake2bVar;
use blake2::digest::{Update, VariableOutput};
use curve_abstract::{TrMessenger, TrPoint, TrScalar};
use erreur::*;
use serde::{Deserialize, Serialize};
use svarog_lagrange::{Keystore, VerifiableSecretSharing};
use svarog_secp256k1::{Point, Scalar, Secp256k1};

use super::super::dkg::decode_keygen_aux;
use super::helpers::{compute_zeta_i, hash_commitment_r_i, mta_session_id, verify_commitment_r_i};
use super::rvole::{RVOLEMsg2, rvole_round1, rvole_round2, rvole_round3};
use super::softspoken_ot::{SSReceiverKeys, SoftSpokenMsg1, ss_receiver, ss_sender};

/// 门限 ECDSA 签名.
///
/// `offset` 是 BIP-32 密钥衍生算出来的私钥偏移量. 由调用者负责提供.
pub async fn sign(
    mut ch: impl TrMessenger,
    sid: String,
    signers: HashSet<usize>,
    keystore: &Keystore<Secp256k1>,
    offset: Scalar,
    msg_hash: [u8; 32],
) -> Resultat<EcdsaSignature> {
    let aux = decode_keygen_aux(&keystore.aux)
        .catch("KeygenAuxDecodeFailed", "sign: cannot decode aux blob")?;
    let i = keystore.i;
    let n_signers = signers.len();
    assert_throw!(
        signers.contains(&i),
        "NotASigner",
        format!("party {} not in signers set", i)
    );
    let others = sorted_others(&signers, i);

    // Round 0. 本地准备. 把派生私钥偏移量 `offset` 平摊到每个签名者.
    let pk_prime = keystore.public_key().add_gx(&offset);
    let n_inv = Scalar::new(n_signers as i64).inv_ct();
    let delta_per_share = offset.mul(&n_inv); // 平摊诀窍在此.

    // 生成 MtA 随机分片 $\phi_i$.
    let phi_i = Scalar::new_rand();

    // 生成签名 nonce 分片 $r_i$. 对 $r_i$ 做出承诺.
    let r_i = Scalar::new_rand();
    let blind_i: [u8; 32] = {
        let bytes = hash!(32; b"dsg/blind", &Scalar::new_rand().to_bytes());
        let mut out = [0u8; 32];
        out.copy_from_slice(&bytes);
        out
    };
    let R_i = Point::new_gx(&r_i);
    let commit_i = hash_commitment_r_i(&sid, &R_i, &blind_i);

    // Round 1: 交换 $\mathrm{Com}(R_i)$
    let mut commits: HashMap<usize, [u8; 32]> = HashMap::new();
    commits.insert(i, commit_i);
    for &j in &others {
        commits.insert(j, [0u8; 32]);
    }
    ch.register_send(&commit_i, &sid, "dsg/r1/commit", i, 0, 0);
    for &j in &others {
        let slot = commits.get_mut(&j).unwrap();
        ch.register_recv(slot, &sid, "dsg/r1/commit", j, 0, 0);
    }
    ch.exchange().await.catch("ExchangeFailed", "dsg round 1")?;

    let digest_i = digest_after_round1(&sid, &pk_prime, &commits, &signers);

    // Round 2: 我作 RVOLE Receiver, pair (j -> i)
    // (`notes/09` Step R1: 我抽 $\beta_{j \to i}$ -> $\chi_{j, i}$, 发 mta1.)
    //
    // pair_sid 的 sender=j, receiver=i. 把 round1 发给 j, j 在 R3 作 Sender 回 mta_msg2.
    // 同时收每个 j 发来 pair (i -> j) 的 round1.

    let mut rvole_recv_state: HashMap<usize, (Vec<u8>, SSReceiverKeys)> = HashMap::new();
    let mut chi_table: HashMap<usize, Scalar> = HashMap::new();
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
        let (beta_ij, chi_ij) = rvole_round1(&pair_sid);
        let (round1, recv_out) = ss_receiver(&pair_sid, sender_seed, &beta_ij);
        rvole_recv_state.insert(j, (beta_ij, recv_out));
        chi_table.insert(j, chi_ij);
        my_round1_to_j.insert(j, round1);
        their_round1_from_j.insert(j, SoftSpokenMsg1::default());
    }

    for &j in &others {
        ch.register_send(&my_round1_to_j[&j], &sid, "dsg/r2/mta1", i, j, 0);
        let slot = their_round1_from_j.get_mut(&j).unwrap();
        ch.register_recv(slot, &sid, "dsg/r2/mta1", j, i, 0);
    }
    ch.exchange().await.catch("ExchangeFailed", "dsg round 2")?;

    // ── 本地: sk_i, pk_i, ψ_{i->j} ─────────────────────────────────────
    // sk_i = λ_i · ξ_i + ζ_i + δ/n  (`notes/09` Step S1).

    let lambda_i = Secp256k1::lagrange_lambda(i, &signers);
    let zeta_i = compute_zeta_i(&aux.seeds, i, &sid, &others);
    let sk_i = lambda_i
        .mul(&keystore.xi)
        .add(&zeta_i)
        .add(&delta_per_share);
    let pk_i = Point::new_gx(&sk_i);

    let mut psi_to_j: HashMap<usize, Scalar> = HashMap::new();
    for &j in &others {
        // ψ_{i->j} = φ_i - χ_{i,j}, `notes/09` Step S2.
        psi_to_j.insert(j, phi_i.sub(&chi_table[&j]));
    }

    // ── Round 3: 我作 RVOLE Sender, pair (i -> j); 顺路发预签数据 ─────
    // (`notes/09` Step R2: 算 mta2, 一起发 R 揭示 + Γ + ψ.)

    let mut my_r3: HashMap<usize, Round3P2P> = HashMap::new();
    let mut their_r3: HashMap<usize, Round3P2P> = HashMap::new();
    let mut sender_uv: HashMap<usize, [Scalar; 2]> = HashMap::new();

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
        // 输入 a = (r_i, sk_i): 第 1 路用于 R 那条线, 第 2 路用于 sk · pk 那条.
        let (rvole_out, c_uv) = rvole_round2(&pair_sid, &send_out, &[r_i.clone(), sk_i.clone()]);
        // Γ 一致性点 (Step Γ).
        let gamma_u = Point::new_gx(&c_uv[0]);
        let gamma_v = Point::new_gx(&c_uv[1]);
        sender_uv.insert(j, c_uv);

        my_r3.insert(
            j,
            Round3P2P {
                rvole_output: rvole_out,
                digest: digest_i,
                pk_i: pk_i.clone(),
                big_r_i: R_i.clone(),
                blind: blind_i,
                gamma_u,
                gamma_v,
                psi: psi_to_j[&j].clone(),
            },
        );
        their_r3.insert(j, Round3P2P::default());
    }

    for &j in &others {
        ch.register_send(&my_r3[&j], &sid, "dsg/r3/p2p", i, j, 0);
        let slot = their_r3.get_mut(&j).unwrap();
        ch.register_recv(slot, &sid, "dsg/r3/p2p", j, i, 0);
    }
    ch.exchange().await.catch("ExchangeFailed", "dsg round 3")?;

    // ── 本地聚合 ─────────────────────────────────────────────────────
    // R = Σ R_j; Σ pk_j = pk' 校验; U_i = Σ (c+d), V_i 同理 (Step S2).

    let mut big_r = R_i.clone();
    let mut sum_pk_j = pk_i.clone();
    let mut sum_psi_to_me = Scalar::default();
    let mut sum_u = Scalar::default();
    let mut sum_v = Scalar::default();

    for &j in &others {
        let r3 = &their_r3[&j];

        // 用对方提交的 commit 复算 digest 一致性.
        assert_throw!(
            r3.digest == digest_i,
            "DigestMismatch",
            format!("dsg: peer {} digest mismatch", j)
        );
        assert_throw!(
            verify_commitment_r_i(&sid, &r3.big_r_i, &r3.blind, &commits[&j]),
            "InvalidCommitment",
            format!("dsg: peer {} R-commitment open mismatch", j)
        );

        // 处理 j 发来的 mta_msg2 (j 在 pair (j -> i) 是 RVOLE Sender).
        let (beta_ij, recv_out) = rvole_recv_state.remove(&j).unwrap();
        let chi_ji = chi_table.remove(&j).unwrap();
        let pair_sid = mta_session_id(&sid, j, i);
        let d_uv = rvole_round3(&pair_sid, &beta_ij, &recv_out, &r3.rvole_output)
            .catch("RVOLEReceiverFailed", &format!("from j={}", j))?;

        // Γ 一致性 (`notes/09` Step Γ): R_j · χ = G·d_u + Γ_u; pk_j · χ = G·d_v + Γ_v.
        let lhs1 = r3.big_r_i.mul_x(&chi_ji);
        let rhs1 = r3.gamma_u.add_gx(&d_uv[0]);
        assert_throw!(
            lhs1 == rhs1,
            "RVOLEConsistencyU",
            format!("dsg: R-side check failed for j={}", j)
        );
        let lhs2 = r3.pk_i.mul_x(&chi_ji);
        let rhs2 = r3.gamma_v.add_gx(&d_uv[1]);
        assert_throw!(
            lhs2 == rhs2,
            "RVOLEConsistencyV",
            format!("dsg: pk-side check failed for j={}", j)
        );

        big_r = big_r.add(&r3.big_r_i);
        sum_pk_j = sum_pk_j.add(&r3.pk_i);
        sum_psi_to_me = sum_psi_to_me.add(&r3.psi);

        let c = &sender_uv[&j];
        // U_i (Step S2): Σ_{j≠i} (c^{(u)}_{i->j} + d^{(u)}_{j->i}); V_i 同理.
        sum_u = sum_u.add(&c[0]).add(&d_uv[0]);
        sum_v = sum_v.add(&c[1]).add(&d_uv[1]);
    }

    assert_throw!(
        sum_pk_j == pk_prime,
        "PublicKeyConsistency",
        "dsg: sum of P_i does not equal derived public key"
    );

    // r_x = x(R) mod n.
    let r_long = big_r.to_bytes_long();
    assert_throw!(
        r_long.len() == 65,
        "InvalidPoint",
        "to_bytes_long must return 65 bytes"
    );
    let r_x = Scalar::new_from_bytes(&r_long[1..33]);

    // Φ_i = φ_i + Σ_{j≠i} ψ_{j->i} (`notes/09` Step S2).
    let phi_star = phi_i.add(&sum_psi_to_me);
    // s_0 = r_x · (sk_i · Φ_i + V_i) + m · φ_i  (Step S2/S3).
    let mut s_0 = r_x.mul(&sk_i.mul(&phi_star).add(&sum_v));
    // s_1 = r_i · Φ_i + U_i.
    let s_1 = r_i.mul(&phi_star).add(&sum_u);

    // 消息绑定.
    let m = Scalar::new_from_bytes(&msg_hash);
    s_0 = s_0.add(&m.mul(&phi_i));

    // ── Round 4: 广播部分签名 (s_0, s_1), 聚合 s = Σs_0 / Σs_1 ───────

    let my_partial = Round4Bcast {
        s_0: s_0.clone(),
        s_1: s_1.clone(),
    };
    let mut partials: HashMap<usize, Round4Bcast> = HashMap::new();
    partials.insert(i, my_partial.clone());
    for &j in &others {
        partials.insert(j, Round4Bcast::default());
    }
    ch.register_send(&my_partial, &sid, "dsg/r4/partial", i, 0, 0);
    for &j in &others {
        let slot = partials.get_mut(&j).unwrap();
        ch.register_recv(slot, &sid, "dsg/r4/partial", j, 0, 0);
    }
    ch.exchange().await.catch("ExchangeFailed", "dsg round 4")?;

    let mut sum_s_0 = Scalar::default();
    let mut sum_s_1 = Scalar::default();
    for &j in signers.iter() {
        let p = &partials[&j];
        sum_s_0 = sum_s_0.add(&p.s_0);
        sum_s_1 = sum_s_1.add(&p.s_1);
    }
    let s = sum_s_0.mul(&sum_s_1.inv_ct());
    let r = r_x.clone();

    // 工程自检: 本地 ECDSA 验签.
    {
        let s_inv = s.inv_ct();
        let u1 = m.mul(&s_inv);
        let u2 = r.mul(&s_inv);
        let big_r_check = pk_prime.mul_x(&u2).add_gx(&u1);
        let r_check_long = big_r_check.to_bytes_long();
        let r_check = Scalar::new_from_bytes(&r_check_long[1..33]);
        assert_throw!(
            r_check == r,
            "EcdsaVerifyFailed",
            "dsg: local ECDSA verification did not match"
        );
    }

    Ok(EcdsaSignature { r, s })
}

// ── 签名输出 + 轮间消息 + 内部辅助 ──────────────────────────────────────

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EcdsaSignature {
    pub r: Scalar,
    pub s: Scalar,
}

/// Round 3 P2P 包: RVOLE 第二轮 + R/pk 揭示 + Γ 一致性点 + ψ 偏移.
#[derive(Clone, Default, Serialize, Deserialize)]
struct Round3P2P {
    rvole_output: RVOLEMsg2,
    digest: [u8; 32],
    pk_i: Point,
    big_r_i: Point,
    blind: [u8; 32],
    /// $\Gamma^{(u)}_{i,j} = c^{(u)}_{i \to j} \cdot G$, 见 `notes/09` Step Γ.
    gamma_u: Point,
    /// $\Gamma^{(v)}_{i,j} = c^{(v)}_{i \to j} \cdot G$.
    gamma_v: Point,
    /// $\psi_{i \to j} = \phi_i - \chi_{i, j}$, `notes/09` Step S2.
    psi: Scalar,
}

#[derive(Clone, Default, Serialize, Deserialize)]
struct Round4Bcast {
    s_0: Scalar,
    s_1: Scalar,
}

fn sorted_others(signers: &HashSet<usize>, me: usize) -> Vec<usize> {
    let mut v: Vec<usize> = signers.iter().copied().filter(|&p| p != me).collect();
    v.sort();
    v
}

/// 把 $\mathrm{pk}'$ 与全员 R 承诺哈希成全局 digest, 用于跨方一致性检查.
fn digest_after_round1(
    sid: &str,
    pk_prime: &Point,
    commits: &HashMap<usize, [u8; 32]>,
    signers: &HashSet<usize>,
) -> [u8; 32] {
    let mut sorted: Vec<usize> = signers.iter().copied().collect();
    sorted.sort();
    let mut h = Blake2bVar::new(32).unwrap();
    h.update(b"dsg/digest");
    h.update(sid.as_bytes());
    h.update(&pk_prime.to_bytes());
    for j in sorted {
        h.update(&(j as u64).to_le_bytes());
        h.update(&commits[&j]);
    }
    let mut out = [0u8; 32];
    h.finalize_variable(&mut out).unwrap();
    out
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

    async fn run_sign(keystores: Vec<Keystore<Secp256k1>>, signers: HashSet<usize>) {
        let db = Arc::new(DashMap::new());
        let msg = [0xA5u8; 32];
        let sid = "sign-sid".to_string();
        let mut handles = Vec::new();
        for ks in keystores.into_iter().filter(|k| signers.contains(&k.i)) {
            let dbi = db.clone();
            let signers_i = signers.clone();
            let sid_i = sid.clone();
            let h = tokio::spawn(async move {
                let ch = ToyMessenger::new(dbi);
                sign(ch, sid_i, signers_i, &ks, Scalar::default(), msg)
                    .await
                    .unwrap()
            });
            handles.push(h);
        }
        let mut sigs = Vec::new();
        for h in handles {
            sigs.push(h.await.unwrap());
        }
        // All parties must agree on the signature.
        let first = sigs[0].clone();
        for s in &sigs[1..] {
            assert_eq!(s.r, first.r);
            assert_eq!(s.s, first.s);
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 8)]
    async fn test_sign_2_of_2() {
        let keystores = run_dkg(2, 2).await;
        let signers: HashSet<usize> = [1usize, 2].iter().copied().collect();
        run_sign(keystores, signers).await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 8)]
    async fn test_sign_2_of_3() {
        let keystores = run_dkg(3, 2).await;
        let signers: HashSet<usize> = [1usize, 3].iter().copied().collect();
        run_sign(keystores, signers).await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 8)]
    async fn test_sign_3_of_3() {
        let keystores = run_dkg(3, 3).await;
        let signers: HashSet<usize> = [1usize, 2, 3].iter().copied().collect();
        run_sign(keystores, signers).await;
    }
}
