use std::collections::{HashMap, HashSet};

use blake2::Blake2bVar;
use blake2::digest::{Update, VariableOutput};
use curve_abstract::{TrCurve, TrMessenger, TrScalar};
use erreur::*;
use rug::Integer;
use svarog_lagrange::{Keystore, VerifiableSecretSharing};

use super::helpers::{DLogProof, dlog_prove_batch, dlog_verify_batch, hash_commitment};

pub async fn keygen<C>(
    mut ch: impl TrMessenger,
    sid: String,
    players: HashSet<usize>,
    i: usize,
    th: usize,
    ui: Option<Integer>,
    cc: Option<[u8; 32]>,
) -> Resultat<Keystore<C>>
where
    C: TrCurve + Default + Clone + 'static,
{
    let others: Vec<usize> = {
        let mut val: Vec<usize> = players.iter().copied().filter(|&p| p != i).collect();
        val.sort();
        val
    };

    // ══════════════════════════════════════════════
    // Round 0 (broadcast): 生成VSS份额, 广播commitment
    // ══════════════════════════════════════════════

    let ui_scalar = match ui {
        Some(ref v) => C::ScalarT::new_from_int(v.clone()),
        None => C::ScalarT::new_rand(),
    };

    let (polycoeff_i, polycom_i, polyeval_ij) = C::generate_shares(&ui_scalar, &players, th);

    let com0_blind: [u8; 32] = {
        // 承诺盲因子 (非 ECDSA 签名随机数 k, Round 1 会公开)
        let mut buf = [0u8; 32];
        let mut h = Blake2bVar::new(32).unwrap();
        h.update(b"r_i_nonce");
        h.update(&C::ScalarT::new_rand().to_bytes());
        h.finalize_variable(&mut buf).unwrap();
        buf
    };
    let mon_com0 = hash_commitment::<C>(&sid, i, &polycom_i, &com0_blind);

    let mut notre_com0: HashMap<usize, [u8; 32]> = HashMap::new();
    notre_com0.insert(i, mon_com0);
    for &j in &others {
        notre_com0.insert(j, [0u8; 32]);
    }

    ch.register_send(&mon_com0, &sid, "keygen/r0/com", i, 0, 0);
    for &j in &others {
        let obj = notre_com0.get_mut(&j).unwrap();
        ch.register_recv(obj, &sid, "keygen/r0/com", j, 0, 0);
    }
    ch.exchange()
        .await
        .catch("FailedToExchangeMpcMessages", "At keygen round 0")?;

    // ── DLog 证明: 证明知道 polycom_i 各系数的离散对数 ──
    let mes_dlog_proofs = dlog_prove_batch::<C>(&sid, i, &polycoeff_i, &polycom_i);

    // ══════════════════════════════════════════════
    // Round 1 (P2P): 发送com0_blind, polycom_i, polyeval_ij; 验证承诺和VSS
    // ══════════════════════════════════════════════

    let mut ses_blind: HashMap<usize, [u8; 32]> = HashMap::new();
    let mut ses_polycom: HashMap<usize, Vec<C::PointT>> = HashMap::new();
    let mut ses_polyeval: HashMap<usize, C::ScalarT> = HashMap::new();
    let mut ses_dlog: HashMap<usize, Vec<DLogProof<C>>> = HashMap::new();
    for &j in &others {
        ses_blind.insert(j, [0u8; 32]);
        ses_polycom.insert(j, vec![]);
        ses_polyeval.insert(j, C::ScalarT::default());
        ses_dlog.insert(j, vec![]);
    }

    for &j in &others {
        ch.register_send(&com0_blind, &sid, "keygen/r1/blind", i, j, 0);
        ch.register_send(&polycom_i, &sid, "keygen/r1/polycom", i, j, 0);
        ch.register_send(&polyeval_ij[&j], &sid, "keygen/r1/polyeval", i, j, 0);
        ch.register_send(&mes_dlog_proofs, &sid, "keygen/r1/dlog", i, j, 0);
    }
    for &j in &others {
        let slot = ses_blind.get_mut(&j).unwrap();
        ch.register_recv(slot, &sid, "keygen/r1/blind", j, i, 0);
        let slot = ses_polycom.get_mut(&j).unwrap();
        ch.register_recv(slot, &sid, "keygen/r1/polycom", j, i, 0);
        let slot = ses_polyeval.get_mut(&j).unwrap();
        ch.register_recv(slot, &sid, "keygen/r1/polyeval", j, i, 0);
        let slot = ses_dlog.get_mut(&j).unwrap();
        ch.register_recv(slot, &sid, "keygen/r1/dlog", j, i, 0);
    }
    ch.exchange()
        .await
        .catch("FailedToExchangeMpcMessages", "At keygen round 1")?;

    // ── 验证承诺 ──

    let mut vss_scheme: HashMap<usize, Vec<C::PointT>> = HashMap::new();
    vss_scheme.insert(i, polycom_i.clone());

    let mut xji_map: HashMap<usize, C::ScalarT> = HashMap::new();

    for &j in &others {
        let expected = hash_commitment::<C>(&sid, j, &ses_polycom[&j], &ses_blind[&j]);
        assert_throw!(
            expected == notre_com0[&j],
            "InvalidCommitment",
            format!("keygen: commitment mismatch for player {}", j)
        );

        for pt in &ses_polycom[&j] {
            assert_throw!(
                pt != C::identity(),
                "InvalidPolynomialPoint",
                format!("keygen: identity point in F_j for player {}", j)
            );
        }

        // ── DLog 验证: 证明对方确实知道 polycom 各系数的离散对数 ──
        dlog_verify_batch::<C>(&sid, j, &ses_dlog[&j], &ses_polycom[&j])?;

        vss_scheme.insert(j, ses_polycom[&j].clone());
        xji_map.insert(j, ses_polyeval[&j].clone());
    }

    // ── Feldman VSS 验证: f_j(i)·G == F_j(i) ──

    C::verify_fj_at_i(i, &xji_map, &vss_scheme)?;

    // ── 计算本方秘密份额 x_i = f_i(i) + Σ_j f_j(i) ──

    let mut xi_scalar = polyeval_ij[&i].clone();
    for (_, fji) in &xji_map {
        xi_scalar = xi_scalar.add(fji);
    }

    // ── 组装 Keystore ──

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
