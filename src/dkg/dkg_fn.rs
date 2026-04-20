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

    // ※ Round 0: 生成 Shamir 份额, 交换相关的承诺.

    let ui_scalar = match ui {
        Some(ref v) => C::ScalarT::new_from_int(v.clone()),
        None => C::ScalarT::new_rand(),
    };

    let (polycoeff_i, my_polycom, my_polyeval_at_j) = C::generate_shares(&ui_scalar, &players, th);

    // 用于承诺的盲项. 会在 Round 1 公开.
    // 这不是 ECDSA 签名中的临时密钥.
    let my_com0_blind: [u8; 32] = {
        let mut buf = [0u8; 32];
        let mut h = Blake2bVar::new(32).unwrap();
        h.update(b"r_i_nonce");
        h.update(&C::ScalarT::new_rand().to_bytes());
        h.finalize_variable(&mut buf).unwrap();
        buf
    };
    let my_com0 = hash_commitment::<C>(&sid, i, &my_polycom, &my_com0_blind);

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

    // ※ Round 1: 对 Shamir 多项式系数进行 DLog 证明. 顺便开示 Round 0 的承诺.

    // 此处基于 DLog 证明知道多项式的所有系数.
    let my_dlog_proofs = dlog_prove_batch::<C>(&sid, i, &polycoeff_i, &my_polycom);

    let mut others_com0_blind: HashMap<usize, [u8; 32]> = HashMap::new();
    let mut others_polycom: HashMap<usize, Vec<C::PointT>> = HashMap::new();
    let mut others_polyeval: HashMap<usize, C::ScalarT> = HashMap::new();
    let mut others_dlog: HashMap<usize, Vec<DLogProof<C>>> = HashMap::new();
    for &j in &others {
        others_com0_blind.insert(j, [0u8; 32]);
        others_polycom.insert(j, vec![]);
        others_polyeval.insert(j, C::ScalarT::default());
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

    // vss scheme 是 Keygen 所有参与方的多项式系数的椭圆曲线承诺.
    let mut vss_scheme: HashMap<usize, Vec<C::PointT>> = HashMap::new();
    vss_scheme.insert(i, my_polycom.clone());

    for &j in &others {
        let expected = hash_commitment::<C>(&sid, j, &others_polycom[&j], &others_com0_blind[&j]);
        assert_throw!(
            expected == our_com0[&j],
            "InvalidCommitment",
            format!("keygen: commitment mismatch for player {}", j)
        );

        for pt in &others_polycom[&j] {
            assert_throw!(
                pt != C::identity(),
                "InvalidPolynomialPoint",
                format!("keygen: identity point in F_j for player {}", j)
            );
        }

        dlog_verify_batch::<C>(&sid, j, &others_dlog[&j], &others_polycom[&j])?;

        vss_scheme.insert(j, others_polycom[&j].clone());
    }

    // 验证 $ f_j(i)·G == F_j(i) $
    C::verify_fj_at_i(i, &others_polyeval, &vss_scheme)?;

    // 计算本方用于插值的秘密份额 $x_i = f_i(i) + Σ_j f_j(i)$
    let mut xi_scalar = my_polyeval_at_j[&i].clone();
    for (_, fji) in &others_polyeval {
        xi_scalar = xi_scalar.add(fji);
    }

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
