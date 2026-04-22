use std::collections::{HashMap, HashSet};

use blake2::Blake2bVar;
use blake2::digest::{Update, VariableOutput};
use curve_abstract::{TrCurve, TrMessenger, TrScalar};
use erreur::*;
use rug::Integer;
use svarog_lagrange::{Keystore, VerifiableSecretSharing};
use svarog_secp256k1::{Secp256k1, Scalar, Point};

use super::helpers::{DLogProof, dlog_prove_batch, dlog_verify_batch, hash_commitment};

pub async fn keygen(
    mut ch: impl TrMessenger,
    sid: String,
    players: HashSet<usize>,
    i: usize,
    th: usize,
    ui: Option<Integer>,
    cc: Option<[u8; 32]>,
) -> Resultat<Keystore<Secp256k1>> {
    let others: Vec<usize> = {
        let mut val: Vec<usize> = players.iter().copied().filter(|&p| p != i).collect();
        val.sort();
        val
    };

    // ※ Round 0: generate Shamir shares, exchange commitments.

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

    // ※ Round 1: DLog proofs for polynomial coefficients; reveal Round 0 commitment.

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

        // ── DLog verification: peer knows the discrete log of each polycom coefficient ──
        dlog_verify_batch(&sid, j, &others_dlog[&j], &others_polycom[&j])?;

        vss_scheme.insert(j, others_polycom[&j].clone());
        my_lagrange_shares_j.insert(j, others_polyeval[&j].clone());
    }

    // ── Feldman VSS verification: f_j(i)·G == F_j(i) ──

    Secp256k1::verify_fj_at_i(i, &my_lagrange_shares_j, &vss_scheme)?;

    // ── Compute own secret share: x_i = f_i(i) + Σ_j f_j(i) ──

    let mut xi_scalar = my_polyeval_at_j[&i].clone();
    for (_, fji) in &my_lagrange_shares_j {
        xi_scalar = xi_scalar.add(fji);
    }

    // ── Assemble Keystore ──

    let chain_code = cc.unwrap_or([0u8; 32]);

    Ok(Keystore {
        i,
        ui: ui.unwrap_or_else(|| ui_scalar.to_int()),
        xi: xi_scalar,
        vss_scheme,
        chain_code,
        aux: sid.as_bytes().to_vec(),
    })
}
