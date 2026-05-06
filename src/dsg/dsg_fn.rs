//! DKLS23 signing as a single async function. Mirrors `simple-dkls23/src/dsg.rs`
//! flattened from a 4-round state machine into one linear flow over a
//! `TrMessenger`-style transport.

use std::collections::{HashMap, HashSet};

use blake2::Blake2bVar;
use blake2::digest::{Update, VariableOutput};
use curve_abstract::{TrMessenger, TrPoint, TrScalar};
use erreur::*;
use serde::{Deserialize, Serialize};
use svarog_lagrange::{Keystore, VerifiableSecretSharing};
use svarog_secp256k1::{Point, Scalar, Secp256k1};

use super::super::dkg::decode_keygen_aux;
use super::helpers::{
    compute_zeta_i, hash_commitment_r_i, mta_session_id, verify_commitment_r_i,
};
use super::rvole::{RVOLEOutput, RVOLEReceiver, RVOLESender};
use super::soft_spoken_ot::Round1Output;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EcdsaSignature {
    pub r: Scalar,
    pub s: Scalar,
}

#[derive(Clone, Default, Serialize, Deserialize)]
struct Round3P2P {
    rvole_output: RVOLEOutput,
    digest: [u8; 32],
    pk_i: Point,
    big_r_i: Point,
    blind: [u8; 32],
    gamma_u: Point,
    gamma_v: Point,
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

/// Threshold ECDSA signing.
///
/// `additive_offset = Some(δ)` makes the participants jointly sign for the
/// derived public key `PK + δG` (BIP-32 hardening lives upstream). `None`
/// signs the original keystore key.
pub async fn sign(
    mut ch: impl TrMessenger,
    sid: String,
    signers: HashSet<usize>,
    keystore: &Keystore<Secp256k1>,
    additive_offset: Option<Scalar>,
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

    // ── (Round 0) local setup ────────────────────────────────────────────

    let offset = additive_offset.unwrap_or(Scalar::new(0));
    let pk_prime = keystore.public_key().add_gx(&offset);
    let n_inv = Scalar::new(n_signers as i64).inv_ct();
    let delta_per_share = offset.mul(&n_inv);

    let phi_i = Scalar::new_rand();
    let r_i = Scalar::new_rand();
    let blind_i: [u8; 32] = {
        let bytes = hash!(32; b"dsg/blind", &Scalar::new_rand().to_bytes());
        let mut out = [0u8; 32];
        out.copy_from_slice(&bytes);
        out
    };
    let big_r_i = Point::new_gx(&r_i);
    let commit_i = hash_commitment_r_i(&sid, &big_r_i, &blind_i);

    // ── Round 1: broadcast commit_i ──────────────────────────────────────

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

    // ── Round 2: each i acts as RVOLE Receiver in pair (j → i) ──────────
    //
    // The sid for that pair uses j as sender, i as receiver. We send the
    // resulting `round1` to j (so that j as RVOLE Sender can produce mta_msg2
    // back at Round 3). Symmetrically receive from each j the `round1` for
    // pair (i → j).

    let mut rvole_states: HashMap<usize, RVOLEReceiver> = HashMap::new();
    let mut chi_table: HashMap<usize, Scalar> = HashMap::new();
    let mut my_round1_to_j: HashMap<usize, Round1Output> = HashMap::new();
    let mut their_round1_from_j: HashMap<usize, Round1Output> = HashMap::new();

    for &j in &others {
        let pair_sid = mta_session_id(&sid, j, i);
        let sender_seed = aux.pprf_seeds.as_sender.get(&j);
        assert_throw!(
            sender_seed.is_some(),
            "MissingPPRFSeed",
            format!("as_sender[{}]", j)
        );
        let sender_seed = sender_seed.unwrap();
        let (state, round1, chi_ij) = RVOLEReceiver::new(&pair_sid, sender_seed);
        rvole_states.insert(j, state);
        chi_table.insert(j, chi_ij);
        my_round1_to_j.insert(j, round1);
        their_round1_from_j.insert(j, Round1Output::default());
    }

    for &j in &others {
        ch.register_send(&my_round1_to_j[&j], &sid, "dsg/r2/mta1", i, j, 0);
        let slot = their_round1_from_j.get_mut(&j).unwrap();
        ch.register_recv(slot, &sid, "dsg/r2/mta1", j, i, 0);
    }
    ch.exchange().await.catch("ExchangeFailed", "dsg round 2")?;

    // ── Local: sk_i, pk_i, psi_ij ────────────────────────────────────────

    let lambda_i = Secp256k1::lagrange_lambda(i, &signers);
    let zeta_i = compute_zeta_i(&aux.seeds, i, &sid, &others);
    let sk_i = lambda_i
        .mul(&keystore.xi)
        .add(&zeta_i)
        .add(&delta_per_share);
    let pk_i = Point::new_gx(&sk_i);

    let mut psi_to_j: HashMap<usize, Scalar> = HashMap::new();
    for &j in &others {
        psi_to_j.insert(j, phi_i.sub(&chi_table[&j]));
    }

    // ── Round 3: I act as RVOLE Sender in pair (i → j); ship presign data ──

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
        let (rvole_out, c_uv) = RVOLESender::process(
            &pair_sid,
            recv_seed,
            &[r_i.clone(), sk_i.clone()],
            &their_round1_from_j[&j],
        )
        .catch("RVOLESenderFailed", &format!("to j={}", j))?;
        let gamma_u = Point::new_gx(&c_uv[0]);
        let gamma_v = Point::new_gx(&c_uv[1]);
        sender_uv.insert(j, c_uv);

        my_r3.insert(
            j,
            Round3P2P {
                rvole_output: rvole_out,
                digest: digest_i,
                pk_i: pk_i.clone(),
                big_r_i: big_r_i.clone(),
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

    // ── Local: combine ──────────────────────────────────────────────────

    let mut big_r = big_r_i.clone();
    let mut sum_pk_j = pk_i.clone();
    let mut sum_psi_to_me = Scalar::new(0);
    let mut sum_u = Scalar::new(0);
    let mut sum_v = Scalar::new(0);

    for &j in &others {
        let r3 = &their_r3[&j];

        // Re-derive the same digest using their commit and check.
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

        // Process the mta_msg2 from j (j was Sender in pair (j → i)).
        let state = rvole_states.remove(&j).unwrap();
        let chi_ji = chi_table.remove(&j).unwrap();
        let d_uv = state
            .process(&r3.rvole_output)
            .catch("RVOLEReceiverFailed", &format!("from j={}", j))?;

        // Consistency: R_j * chi == G * d_u + gamma_u; pk_j * chi == G * d_v + gamma_v.
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
        sum_u = sum_u.add(&c[0]).add(&d_uv[0]);
        sum_v = sum_v.add(&c[1]).add(&d_uv[1]);
    }

    assert_throw!(
        sum_pk_j == pk_prime,
        "PublicKeyConsistency",
        "dsg: sum of P_i does not equal derived public key"
    );

    // r_x = x(R) mod n
    let r_long = big_r.to_bytes_long();
    assert_throw!(
        r_long.len() == 65,
        "InvalidPoint",
        "to_bytes_long must return 65 bytes"
    );
    let r_x = Scalar::new_from_bytes(&r_long[1..33]);

    let phi_star = phi_i.add(&sum_psi_to_me);
    let mut s_0 = r_x.mul(&sk_i.mul(&phi_star).add(&sum_v));
    let s_1 = r_i.mul(&phi_star).add(&sum_u);

    // Message binding: s_0 += m * phi_i.
    let m = Scalar::new_from_bytes(&msg_hash);
    s_0 = s_0.add(&m.mul(&phi_i));

    // ── Round 4: broadcast partial (s_0, s_1) ───────────────────────────

    let my_partial = Round4Bcast { s_0: s_0.clone(), s_1: s_1.clone() };
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

    let mut sum_s_0 = Scalar::new(0);
    let mut sum_s_1 = Scalar::new(0);
    for &j in signers.iter() {
        let p = &partials[&j];
        sum_s_0 = sum_s_0.add(&p.s_0);
        sum_s_1 = sum_s_1.add(&p.s_1);
    }
    let s = sum_s_0.mul(&sum_s_1.inv_ct());
    let r = r_x.clone();

    // ── Local ECDSA verify ──────────────────────────────────────────────
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
                sign(ch, sid_i, signers_i, &ks, None, msg).await.unwrap()
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
