use std::collections::{HashMap, HashSet};

use blake2::Blake2bVar;
use blake2::digest::{Update, VariableOutput};
use curve_abstract::{TrCurve, TrMessenger, TrScalar};
use erreur::*;
use rug::Integer;
use svarog_lagrange::{Keystore, VerifiableSecretSharing};
use svarog_secp256k1::{Secp256k1, Scalar, Point};

use super::endemic_ot::{
    EndemicOTMsg1, EndemicOTMsg2, EndemicOTReceiver, EndemicOTSender,
    ReceiverOutput, SenderOutput,
};
use super::helpers::{DLogProof, dlog_prove_batch, dlog_verify_batch, hash_commitment};

/// OT seeds for one party, covering all pairwise OT instances with counterparties.
///
/// For each counterparty $j \neq i$:
/// * `as_receiver[j]`: choice bits + KAPPA decryption keys (i was Receiver, j was Sender).
/// * `as_sender[j]`: KAPPA encryption key pairs (i was Sender, j was Receiver).
pub struct PairOTSeeds {
    pub as_receiver: HashMap<usize, ReceiverOutput>,
    pub as_sender: HashMap<usize, SenderOutput>,
}

/// Combined output of the keygen protocol: VSS keystore + pairwise OT seeds.
pub struct KeygenOutput {
    pub keystore: Keystore<Secp256k1>,
    pub ot_seeds: PairOTSeeds,
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

    // (Round 3, OT) each party acts as Sender for each j's Msg1,
    // generates and sends Msg2 to j, and receives Msg2 from j.

    let mut others_ot_msg2: HashMap<usize, EndemicOTMsg2> = HashMap::new();
    let mut as_sender: HashMap<usize, SenderOutput> = HashMap::new();

    for &j in &others {
        let mut msg2_i_to_j = EndemicOTMsg2::default();
        let sender_out =
            EndemicOTSender::process(&sid, &others_ot_msg1[&j], &mut msg2_i_to_j)
                .catch("OTSenderFailed", format!("At keygen round 3, i={} as sender to j={}", i, j))?;
        as_sender.insert(j, sender_out);
        ch.register_send(&msg2_i_to_j, &sid, "keygen/r3/ot_msg2", i, j, 0);
        others_ot_msg2.insert(j, EndemicOTMsg2::default());
    }
    for &j in &others {
        let slot = others_ot_msg2.get_mut(&j).unwrap();
        ch.register_recv(slot, &sid, "keygen/r3/ot_msg2", j, i, 0);
    }
    ch.exchange()
        .await
        .catch("FailedToExchangeMpcMessages", "At keygen round 3")?;

    // Local: each party processes received Msg2 to obtain its ReceiverOutput.

    let mut as_receiver: HashMap<usize, ReceiverOutput> = HashMap::new();
    for (j, receiver) in my_ot_receivers {
        let recv_out = receiver
            .process(&others_ot_msg2[&j])
            .catch("OTReceiverFailed", format!("At keygen local OT, i={} as receiver from j={}", i, j))?;
        as_receiver.insert(j, recv_out);
    }

    Ok(KeygenOutput {
        keystore,
        ot_seeds: PairOTSeeds { as_receiver, as_sender },
    })
}
