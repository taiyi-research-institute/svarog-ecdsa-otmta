use std::collections::{HashMap, HashSet};

use blake2::Blake2bVar;
use blake2::digest::{Update, VariableOutput};
use curve_abstract::{TrCurve, TrMessenger, TrPoint, TrScalar};
use erreur::*;
use rug::Integer;
use svarog_lagrange::{Keystore, VerifiableSecretSharing};
use svarog_secp256k1::{Secp256k1, Scalar, Point};

use super::endemic_ot::{
    EndemicOTMsg1, EndemicOTMsg2, EndemicOTReceiver, EndemicOTSender,
};
use super::helpers::{DLogProof, dlog_prove_batch, dlog_verify_batch, hash_commitment};
use super::soft_spoken::{
    build_pprf, eval_pprf, PPRFOutput, ReceiverOTSeed, SenderOTSeed,
};

/// All-but-one PPRF seeds for one party, covering pairwise PPRF instances with counterparties.
///
/// Base OT outputs are consumed locally by `build_pprf` / `eval_pprf` during keygen
/// and discarded; only these stretched seeds are kept for signing-time MtA.
///
/// For each counterparty $j \neq i$:
/// * `as_receiver[j]`: punctured leaf indices + reconstructed leaves (i was PPRF Receiver, j was PPRF Sender).
/// * `as_sender[j]`: full leaf table (i was PPRF Sender, j was PPRF Receiver).
pub struct PairPPRFSeeds {
    pub as_receiver: HashMap<usize, ReceiverOTSeed>,
    pub as_sender: HashMap<usize, SenderOTSeed>,
}

/// Pairwise plaintext seeds used at signing to derive the per-party randomization $\zeta_i$.
///
/// For each pair $(i, j)$ with $i < j$, the smaller-id party generates 32 random bytes
/// and sends them in plaintext to the larger-id party.
/// The seed itself is not a secret; uniqueness across keygen sessions suffices.
///
/// At signing time both parties derive
/// $v_{ij} = \mathrm{Hash}(\mathrm{seed}_{ij} \| \mathrm{sig\_id})$
/// and the per-party offset
/// $\zeta_i = \sum_{j < i} v_{ji} - \sum_{j > i} v_{ij}$ globally cancels:
/// $\sum_i \zeta_i = 0$.
pub struct PairwiseSeeds {
    /// Seeds I (smaller id) generated and sent to j (larger id). Keyed by j.
    pub sent: HashMap<usize, [u8; 32]>,
    /// Seeds I (larger id) received from j (smaller id). Keyed by j.
    pub rec: HashMap<usize, [u8; 32]>,
}

/// Combined output of the keygen protocol: VSS keystore + PPRF seeds + pairwise seeds.
pub struct KeygenOutput {
    pub keystore: Keystore<Secp256k1>,
    pub pprf_seeds: PairPPRFSeeds,
    pub seeds: PairwiseSeeds,
}

pub async fn keygen(
    mut ch: impl TrMessenger,
    sid: String,
    players: HashSet<usize>,
    i: usize,
    th: usize,
    ui: Option<Integer>,
    cc: Option<[u8; 32]>,
) -> Resultat<KeygenOutput> {
    let others: Vec<usize> = {
        let mut val: Vec<usize> = players.iter().copied().filter(|&p| p != i).collect();
        val.sort();
        val
    };

    // (Round 0) generate Shamir shares, exchange commitments.

    let ui_scalar = match ui {
        Some(ref v) => Scalar::new_from_int(v.clone()),
        None => Scalar::new_rand(),
    };

    let (polycoeff_i, my_polycom, my_polyeval_at_j) =
        Secp256k1::generate_shares(&ui_scalar, &players, th);

    // Blinding term for Round 0 commitment, revealed in Round 1.
    let my_com0_blind: [u8; 32] = {
        let mut buf = [0u8; 32];
        let mut h = Blake2bVar::new(32).unwrap();
        h.update(b"r_i_nonce");
        h.update(&Scalar::new_rand().to_bytes());
        h.finalize_variable(&mut buf).unwrap();
        buf
    };
    let my_com0 = hash_commitment(&sid, i, &my_polycom, &my_com0_blind);

    let mut our_com0: HashMap<usize, [u8; 32]> = HashMap::new();
    our_com0.insert(i, my_com0);
    for &j in &others {
        our_com0.insert(j, [0u8; 32]);
    }

    ch.register_send(&my_com0, &sid, "keygen/r0/com", i, 0, 0);
    for &j in &others {
        let obj = our_com0.get_mut(&j).unwrap();
        ch.register_recv(obj, &sid, "keygen/r0/com", j, 0, 0);
    }
    ch.exchange()
        .await
        .catch("FailedToExchangeMpcMessages", "At keygen round 0")?;

    // (Round 1) DLog proofs for polynomial coefficients; reveal Round 0 commitment.

    let my_dlog_proofs = dlog_prove_batch(&sid, i, &polycoeff_i, &my_polycom);

    let mut others_com0_blind: HashMap<usize, [u8; 32]> = HashMap::new();
    let mut others_polycom: HashMap<usize, Vec<Point>> = HashMap::new();
    let mut others_polyeval: HashMap<usize, Scalar> = HashMap::new();
    let mut others_dlog: HashMap<usize, Vec<DLogProof>> = HashMap::new();
    for &j in &others {
        others_com0_blind.insert(j, [0u8; 32]);
        others_polycom.insert(j, vec![]);
        others_polyeval.insert(j, Scalar::default());
        others_dlog.insert(j, vec![]);
    }

    for &j in &others {
        ch.register_send(&my_com0_blind, &sid, "keygen/r1/com0_blind", i, j, 0);
        ch.register_send(&my_polycom, &sid, "keygen/r1/polycom", i, j, 0);
        ch.register_send(&my_polyeval_at_j[&j], &sid, "keygen/r1/polyeval", i, j, 0);
        ch.register_send(&my_dlog_proofs, &sid, "keygen/r1/dlog", i, j, 0);
    }
    for &j in &others {
        let slot = others_com0_blind.get_mut(&j).unwrap();
        ch.register_recv(slot, &sid, "keygen/r1/com0_blind", j, i, 0);
        let slot = others_polycom.get_mut(&j).unwrap();
        ch.register_recv(slot, &sid, "keygen/r1/polycom", j, i, 0);
        let slot = others_polyeval.get_mut(&j).unwrap();
        ch.register_recv(slot, &sid, "keygen/r1/polyeval", j, i, 0);
        let slot = others_dlog.get_mut(&j).unwrap();
        ch.register_recv(slot, &sid, "keygen/r1/dlog", j, i, 0);
    }
    ch.exchange()
        .await
        .catch("FailedToExchangeMpcMessages", "At keygen round 1")?;

    // vss_scheme: elliptic curve commitments to each player's polynomial coefficients.
    let mut vss_scheme: HashMap<usize, Vec<Point>> = HashMap::new();
    vss_scheme.insert(i, my_polycom.clone());

    let mut my_lagrange_shares_j: HashMap<usize, Scalar> = HashMap::new();

    for &j in &others {
        let expected = hash_commitment(&sid, j, &others_polycom[&j], &others_com0_blind[&j]);
        assert_throw!(
            expected == our_com0[&j],
            "InvalidCommitment",
            format!("keygen: commitment mismatch for player {}", j)
        );

        for pt in &others_polycom[&j] {
            assert_throw!(
                pt != Secp256k1::identity(),
                "InvalidPolynomialPoint",
                format!("keygen: identity point in F_j for player {}", j)
            );
        }

        // DLog verification: peer knows the discrete log of each polycom coefficient
        dlog_verify_batch(&sid, j, &others_dlog[&j], &others_polycom[&j])?;

        vss_scheme.insert(j, others_polycom[&j].clone());
        my_lagrange_shares_j.insert(j, others_polyeval[&j].clone());
    }

    // Feldman VSS verification: $f_j(i)G = F_j(i)$.
    Secp256k1::verify_fj_at_i(i, &my_lagrange_shares_j, &vss_scheme)?;

    // Compute own secret share: $x_i = f_i(i) + \sum_{j\neq i} f_j(i)$.
    let mut xi_scalar = my_polyeval_at_j[&i].clone();
    for (_, fji) in &my_lagrange_shares_j {
        xi_scalar = xi_scalar.add(fji);
    }

    let chain_code = cc.unwrap_or([0u8; 32]);

    let keystore = Keystore {
        i,
        ui: ui.unwrap_or_else(|| ui_scalar.to_int()),
        xi: xi_scalar,
        vss_scheme,
        chain_code,
        aux: sid.as_bytes().to_vec(),
    };

    // Self-consistency sanity check (defends against implementation bugs, not malicious peers).
    //
    // The public key has two locally-derivable expressions, both functions of the same
    // `vss_scheme`:
    //   PK_A = sum_j polycom[j][0]                          // sum of constant terms
    //   PK_B = sum_j lambda_j * (sum_k F_k(j))              // Lagrange interpolation of x_j G
    // They must be equal by construction. A mismatch means a bug in the Lagrange /
    // polynomial library or a malformed `vss_scheme` (e.g. degree disagreeing with `th`).
    // Honesty against malicious peers is enforced upstream by `verify_fj_at_i`.
    {
        let mut recovered = Secp256k1::identity().clone();
        for &j in players.iter() {
            let xj_com = Secp256k1::eval_xi_com(j, &keystore.vss_scheme);
            let lambda_j = Secp256k1::lagrange_lambda(j, &players);
            recovered = recovered.add(&xj_com.mul_x(&lambda_j));
        }
        assert_throw!(
            recovered == keystore.public_key(),
            "PublicKeyRecoveryMismatch",
            "keygen: two local derivations of the public key disagree (likely a Lagrange / VSS implementation bug)"
        );
    }

    // (Round 2, OT) each party generates one EndemicOTReceiver per counterparty,
    // sends Msg1 to each j, and receives Msg1 from each j.

    let mut my_ot_receivers: HashMap<usize, EndemicOTReceiver> = HashMap::new();
    let mut my_ot_msg1s: HashMap<usize, EndemicOTMsg1> = HashMap::new();
    let mut others_ot_msg1: HashMap<usize, EndemicOTMsg1> = HashMap::new();

    for &j in &others {
        let mut msg1 = EndemicOTMsg1::default();
        let receiver = EndemicOTReceiver::new(&sid, &mut msg1);
        my_ot_receivers.insert(j, receiver);
        my_ot_msg1s.insert(j, msg1);
        others_ot_msg1.insert(j, EndemicOTMsg1::default());
    }

    for &j in &others {
        ch.register_send(&my_ot_msg1s[&j], &sid, "keygen/r2/ot_msg1", i, j, 0);
        let slot = others_ot_msg1.get_mut(&j).unwrap();
        ch.register_recv(slot, &sid, "keygen/r2/ot_msg1", j, i, 0);
    }
    ch.exchange()
        .await
        .catch("FailedToExchangeMpcMessages", "At keygen round 2")?;

    // (Round 3, OT) base OT msg2 + PPRF correction values + pairwise seeds.
    //
    // For each j: process j's base OT msg1 as Sender to obtain SenderOutput,
    // immediately stretch it via build_pprf to a SenderOTSeed (kept) plus a
    // PPRFOutput (sent to j). Pairwise seeds piggyback in the same exchange.

    let mut others_ot_msg2: HashMap<usize, EndemicOTMsg2> = HashMap::new();
    let mut others_pprf_output: HashMap<usize, PPRFOutput> = HashMap::new();
    let mut as_pprf_sender: HashMap<usize, SenderOTSeed> = HashMap::new();

    let mut sent_seeds: HashMap<usize, [u8; 32]> = HashMap::new();
    let mut rec_seeds: HashMap<usize, [u8; 32]> = HashMap::new();
    for &j in &others {
        if j > i {
            let mut buf = [0u8; 32];
            let mut h = Blake2bVar::new(32).unwrap();
            h.update(b"keygen/seed_i_j");
            h.update(&Scalar::new_rand().to_bytes());
            h.finalize_variable(&mut buf).unwrap();
            sent_seeds.insert(j, buf);
        } else {
            rec_seeds.insert(j, [0u8; 32]);
        }
    }

    for &j in &others {
        let mut msg2_i_to_j = EndemicOTMsg2::default();
        let sender_out =
            EndemicOTSender::process(&sid, &others_ot_msg1[&j], &mut msg2_i_to_j)
                .catch("OTSenderFailed", format!("At keygen round 3, i={} as sender to j={}", i, j))?;

        // Stretch base OT into all-but-one PPRF seeds.
        let pair_sid = format!("{}/pprf/{}-{}", &sid, i.min(j), i.max(j));
        let mut pprf_out = PPRFOutput::default();
        let mut sender_seed = SenderOTSeed::default();
        build_pprf(&pair_sid, &sender_out, &mut sender_seed, &mut pprf_out);
        as_pprf_sender.insert(j, sender_seed);

        ch.register_send(&msg2_i_to_j, &sid, "keygen/r3/ot_msg2", i, j, 0);
        ch.register_send(&pprf_out, &sid, "keygen/r3/pprf", i, j, 0);
        if j > i {
            ch.register_send(&sent_seeds[&j], &sid, "keygen/r3/seed", i, j, 0);
        }
        others_ot_msg2.insert(j, EndemicOTMsg2::default());
        others_pprf_output.insert(j, PPRFOutput::default());
    }
    for &j in &others {
        let slot = others_ot_msg2.get_mut(&j).unwrap();
        ch.register_recv(slot, &sid, "keygen/r3/ot_msg2", j, i, 0);
        let slot = others_pprf_output.get_mut(&j).unwrap();
        ch.register_recv(slot, &sid, "keygen/r3/pprf", j, i, 0);
        if j < i {
            let slot = rec_seeds.get_mut(&j).unwrap();
            ch.register_recv(slot, &sid, "keygen/r3/seed", j, i, 0);
        }
    }
    ch.exchange()
        .await
        .catch("FailedToExchangeMpcMessages", "At keygen round 3")?;

    // Local: process received Msg2 to obtain ReceiverOutput, then eval PPRF.

    let mut as_pprf_receiver: HashMap<usize, ReceiverOTSeed> = HashMap::new();
    for (j, receiver) in my_ot_receivers {
        let recv_out = receiver
            .process(&others_ot_msg2[&j])
            .catch("OTReceiverFailed", format!("At keygen local OT, i={} as receiver from j={}", i, j))?;

        let pair_sid = format!("{}/pprf/{}-{}", &sid, i.min(j), i.max(j));
        let mut receiver_seed = ReceiverOTSeed::default();
        eval_pprf(&pair_sid, &recv_out, &others_pprf_output[&j], &mut receiver_seed)
            .catch("PPRFEvalFailed", format!("At keygen local PPRF, i={} from j={}", i, j))?;
        as_pprf_receiver.insert(j, receiver_seed);
    }

    Ok(KeygenOutput {
        keystore,
        pprf_seeds: PairPPRFSeeds {
            as_receiver: as_pprf_receiver,
            as_sender: as_pprf_sender,
        },
        seeds: PairwiseSeeds { sent: sent_seeds, rec: rec_seeds },
    })
}
