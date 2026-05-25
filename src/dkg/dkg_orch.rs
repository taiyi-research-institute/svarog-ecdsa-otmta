//! DKLS23 DKG 编排层.
//!
//! 4 轮编排:
//! * Round 1  广播多项式承诺 $\mathrm{Com}(\vec F_i)$ (hash commitment).
//! * Round 2  揭示 $\vec F_i$ 与盲化值, DLog 证明, 点对点发 $f_i(j)$ 份额.
//! * Round 3  发 EndemicOT Msg1 (作为 Receiver).
//! * Round 4  发 EndemicOT Msg2 + PPRF 校正 (作为 Sender) + pairwise seed.

use std::collections::{HashMap, HashSet};

use blake2::Blake2bVar;
use blake2::digest::{Update, VariableOutput};
use curve_abstract::{TrCurve, TrMessenger, TrPoint, TrScalar};
use erreur::*;
use rand::Rng;
use rug::Integer;
use serde::{Deserialize, Serialize};
use serde_pickle::{DeOptions, SerOptions};
use svarog_lagrange::{Keystore, VerifiableSecretSharing};
use svarog_secp256k1::{Point, Scalar, Secp256k1};

use super::endemic_ot::{self, EndemicOTMsg1, EndemicOTMsg2, EndemicOTRound1};
use super::helpers::{DLogProof, dlog_prove_batch, dlog_verify_batch, hash_commitment};
use super::softspoken_pprf::{
    PPRFOutput, PPRFReceiverOTSeed, PPRFSenderOTSeed, pprf_build_and_prove, pprf_eval_and_verify,
};

/// DKLS23 keygen 主流程.
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

    let ui_scalar = match ui {
        Some(ref v) => Scalar::new_from_int(v.clone()),
        None => Scalar::new_rand(),
    };

    // [Round 1] Shamir 多项式份额.
    let (polycoeff_i, my_polycom, my_polyeval_at_j) =
        Secp256k1::generate_shares(&ui_scalar, &players, th);

    // [Round 1] commitment 的盲化项. 在 Round 2 一并揭示.
    let my_com0_blind: [u8; 32] = {
        let mut buf = [0u8; 32];
        rand::rng().fill_bytes(&mut buf);
        buf
    };
    let my_com0 = hash_commitment(&sid, i, &my_polycom, &my_com0_blind);

    let mut our_com0: HashMap<usize, [u8; 32]> = HashMap::new();
    our_com0.insert(i, my_com0);
    for &j in &others {
        our_com0.insert(j, [0u8; 32]);
    }

    ch.register_send(&my_com0, &sid, "keygen/r1/com", i, 0, 0);
    for &j in &others {
        let obj = our_com0.get_mut(&j).unwrap();
        ch.register_recv(obj, &sid, "keygen/r1/com", j, 0, 0);
    }
    ch.exchange()
        .await
        .catch("FailedToExchangeMpcMessages", "At keygen Round 1")?;

    // [Round 2] DLog 证明: 自己知晓多项式的每个系数.
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
        ch.register_send(&my_com0_blind, &sid, "keygen/r2/com0_blind", i, j, 0);
        ch.register_send(&my_polycom, &sid, "keygen/r2/polycom", i, j, 0);
        ch.register_send(&my_polyeval_at_j[&j], &sid, "keygen/r2/polyeval", i, j, 0);
        ch.register_send(&my_dlog_proofs, &sid, "keygen/r2/dlog", i, j, 0);
    }
    for &j in &others {
        let slot = others_com0_blind.get_mut(&j).unwrap();
        ch.register_recv(slot, &sid, "keygen/r2/com0_blind", j, i, 0);
        let slot = others_polycom.get_mut(&j).unwrap();
        ch.register_recv(slot, &sid, "keygen/r2/polycom", j, i, 0);
        let slot = others_polyeval.get_mut(&j).unwrap();
        ch.register_recv(slot, &sid, "keygen/r2/polyeval", j, i, 0);
        let slot = others_dlog.get_mut(&j).unwrap();
        ch.register_recv(slot, &sid, "keygen/r2/dlog", j, i, 0);
    }
    ch.exchange()
        .await
        .catch("FailedToExchangeMpcMessages", "At keygen Round 2")?;

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

        // [Round 2] DLog 验证: 对手确实知晓他的多项式的每个系数.
        dlog_verify_batch(&sid, j, &others_dlog[&j], &others_polycom[&j])?;

        vss_scheme.insert(j, others_polycom[&j].clone());
        my_lagrange_shares_j.insert(j, others_polyeval[&j].clone());
    }

    // [Round 2] Feldman VSS 验证: $f_j(i) \cdot G \stackrel{?}{=} F_j(i)$.
    Secp256k1::verify_fj_at_i(i, &my_lagrange_shares_j, &vss_scheme)?;

    // [Round 2] 计算自身秘密份额 $x_i = f_i(i) + \sum_{j \neq i} f_j(i)$.
    let mut xi_scalar = my_polyeval_at_j[&i].clone();
    for (_, fji) in &my_lagrange_shares_j {
        xi_scalar = xi_scalar.add(fji);
    }

    let chain_code = cc.unwrap_or([0u8; 32]);

    let mut keystore = Keystore {
        i,
        ui: ui.unwrap_or_else(|| ui_scalar.to_int()),
        xi: xi_scalar,
        vss_scheme,
        chain_code,
        aux: vec![],
    };

    // 工程自检, 防实现 bug, 不防恶意对手.
    //
    // 公钥有两条本地可推导的等价表达式 (均仅用 `vss_scheme`):
    // 常数项之和   `PK_A = sum(j, polycom[j][0])`
    // Lagrange 插值 `PK_B = sum(j, λ_j * (sum(k, F_k(j))))`
    // 二者必然相等 — 不等则说明 Lagrange/多项式库有 bug, 或 `vss_scheme` 阶不匹配 `th`.
    // 对手恶意行为由 `verify_fj_at_i` 兜底.
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

    // [Round 3] Endemic OT. 它是安全假设更弱的 Base OT, 对 SoftSpoken 够用了.
    // 详见结构体的注释, 以及笔记 00 ~ 03.

    let mut my_ot_receivers: HashMap<usize, EndemicOTRound1> = HashMap::new();
    let mut my_ot_msg1s: HashMap<usize, EndemicOTMsg1> = HashMap::new();
    let mut others_ot_msg1: HashMap<usize, EndemicOTMsg1> = HashMap::new();

    for &j in &others {
        let mut msg1 = EndemicOTMsg1::default();
        let receiver = endemic_ot::round1(&sid, &mut msg1);
        my_ot_receivers.insert(j, receiver);
        my_ot_msg1s.insert(j, msg1);
        others_ot_msg1.insert(j, EndemicOTMsg1::default());
    }

    for &j in &others {
        ch.register_send(&my_ot_msg1s[&j], &sid, "keygen/r3/ot_msg1", i, j, 0);
        let slot = others_ot_msg1.get_mut(&j).unwrap();
        ch.register_recv(slot, &sid, "keygen/r3/ot_msg1", j, i, 0);
    }
    ch.exchange()
        .await
        .catch("FailedToExchangeMpcMessages", "At keygen Round 3")?;

    // [Round 4] PPRF.

    let mut others_ot_msg2: HashMap<usize, EndemicOTMsg2> = HashMap::new();
    let mut others_pprf_output: HashMap<usize, PPRFOutput> = HashMap::new();
    let mut as_pprf_sender: HashMap<usize, PPRFSenderOTSeed> = HashMap::new();

    let mut sent_seeds: HashMap<usize, [u8; 32]> = HashMap::new();
    let mut recv_seeds: HashMap<usize, [u8; 32]> = HashMap::new();
    for &j in &others {
        if j > i {
            let mut buf = [0u8; 32];
            let mut h = Blake2bVar::new(32).unwrap();
            h.update(b"keygen/seed_i_j");
            h.update(&Scalar::new_rand().to_bytes());
            h.finalize_variable(&mut buf).unwrap();
            sent_seeds.insert(j, buf);
        } else {
            recv_seeds.insert(j, [0u8; 32]);
        }
    }

    for &j in &others {
        let mut msg2_i_to_j = EndemicOTMsg2::default();
        let sender_out = endemic_ot::round2(&sid, &others_ot_msg1[&j], &mut msg2_i_to_j).catch(
            "OTSenderFailed",
            format!("At keygen Round 4, i={} as sender to j={}", i, j),
        )?;

        // 把 base OT 拉伸为 all-but-one PPRF 种子.
        let pair_sid = format!("{}/pprf/{}-{}", &sid, i.min(j), i.max(j));
        let mut pprf_out = PPRFOutput::default();
        let mut sender_seed = PPRFSenderOTSeed::default();
        pprf_build_and_prove(&pair_sid, &sender_out, &mut sender_seed, &mut pprf_out);
        as_pprf_sender.insert(j, sender_seed);

        ch.register_send(&msg2_i_to_j, &sid, "keygen/r4/ot_msg2", i, j, 0);
        ch.register_send(&pprf_out, &sid, "keygen/r4/pprf", i, j, 0);
        if j > i {
            ch.register_send(&sent_seeds[&j], &sid, "keygen/r4/seed", i, j, 0);
        }
        others_ot_msg2.insert(j, EndemicOTMsg2::default());
        others_pprf_output.insert(j, PPRFOutput::default());
    }
    for &j in &others {
        let slot = others_ot_msg2.get_mut(&j).unwrap();
        ch.register_recv(slot, &sid, "keygen/r4/ot_msg2", j, i, 0);
        let slot = others_pprf_output.get_mut(&j).unwrap();
        ch.register_recv(slot, &sid, "keygen/r4/pprf", j, i, 0);
        if j < i {
            let slot = recv_seeds.get_mut(&j).unwrap();
            ch.register_recv(slot, &sid, "keygen/r4/seed", j, i, 0);
        }
    }
    ch.exchange()
        .await
        .catch("FailedToExchangeMpcMessages", "At keygen Round 4")?;

    // 本地: 处理收到的 Msg2 得 ReceiverOutput, 再 eval PPRF.

    let mut as_pprf_receiver: HashMap<usize, PPRFReceiverOTSeed> = HashMap::new();
    for (j, receiver) in my_ot_receivers {
        let recv_out = endemic_ot::round3(receiver, &others_ot_msg2[&j]).catch(
            "OTReceiverFailed",
            format!("At keygen local OT, i={} as receiver from j={}", i, j),
        )?;

        let pair_sid = format!("{}/pprf/{}-{}", &sid, i.min(j), i.max(j));
        let mut receiver_seed = PPRFReceiverOTSeed::default();
        pprf_eval_and_verify(
            &pair_sid,
            &recv_out,
            &others_pprf_output[&j],
            &mut receiver_seed,
        )
        .catch(
            "PPRFEvalFailed",
            format!("At keygen local PPRF, i={} from j={}", i, j),
        )?;
        as_pprf_receiver.insert(j, receiver_seed);
    }

    let keygen_aux = KeygenAux {
        sid,
        pprf_seeds: PPRFSeeds {
            as_receiver: as_pprf_receiver,
            as_sender: as_pprf_sender,
        },
        seeds: PairwiseSeeds {
            sent: sent_seeds,
            rec: recv_seeds,
        },
    };
    keystore.aux = serde_pickle::to_vec(&keygen_aux, SerOptions::new()).catch(
        "KeygenAuxEncodeFailed",
        "failed to encode keygen aux payload",
    )?;

    Ok(keystore)
}

// ── keygen 输出类型 + 解码辅助 ─────────────────────────────────────────

/// 单方持有的全部 PPRF 种子 (覆盖与所有对手的 pairwise PPRF 实例).
///
/// keygen 的 base OT 输出在本地被 `build_pprf` / `eval_pprf` 拉伸后丢弃,
/// 仅保留这些拉伸后的种子供签名期 MtA 使用.
///
/// 对每个对手 $j \neq i$:
/// * `as_receiver[j]`: 穿孔下标 + 重建叶子 (我作 PPRF Receiver, j 作 Sender).
/// * `as_sender[j]`: 完整叶子表 (我作 PPRF Sender, j 作 Receiver).
#[derive(Clone, Serialize, Deserialize)]
pub struct PPRFSeeds {
    pub as_receiver: HashMap<usize, PPRFReceiverOTSeed>,
    pub as_sender: HashMap<usize, PPRFSenderOTSeed>,
}

/// 签名期用于派生 $\zeta_i$ 的明文 pairwise seed (工程添加, `notes/09` 未覆盖).
///
/// 对每对 $(i, j), i < j$, 较小 id 方生成 32 字节随机数, 明文发给较大 id 方.
/// seed 本身不是秘密, 跨 keygen session 唯一即可.
///
/// 签名期双方派生
/// $v_{ij} = \mathrm{Hash}(\mathrm{seed}_{ij} \| \mathrm{sig\_id})$,
/// 进而 $\zeta_i = \sum_{j < i} v_{ji} - \sum_{j > i} v_{ij}$, 全局抵消
/// $\sum_i \zeta_i = 0$, 见 `dsg/helpers.rs::compute_zeta_i`.
#[derive(Clone, Serialize, Deserialize)]
pub struct PairwiseSeeds {
    /// 我 (较小 id) 生成发给 j (较大 id) 的 seed, key 为 j.
    pub sent: HashMap<usize, [u8; 32]>,
    /// 我 (较大 id) 从 j (较小 id) 收到的 seed, key 为 j.
    pub rec: HashMap<usize, [u8; 32]>,
}

/// `keygen` 打包到 `Keystore::aux` 的补充资料.
///
/// 公钥份额本身放在 `Keystore`; 这里只装签名期 OT/PPRF 物料 + pairwise seed.
#[derive(Clone, Serialize, Deserialize)]
pub struct KeygenAux {
    pub sid: String,
    pub pprf_seeds: PPRFSeeds,
    pub seeds: PairwiseSeeds,
}

pub fn decode_keygen_aux(aux: &[u8]) -> Resultat<KeygenAux> {
    serde_pickle::from_slice(aux, DeOptions::new()).catch(
        "KeygenAuxDecodeFailed",
        "failed to decode keygen aux payload",
    )
}
