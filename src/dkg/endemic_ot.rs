//! Endemic OT. 见 `notes/03-endemic-ot.md`.
//!
//! 一次调用并行执行 `KAPPA = 256` 个 1-2 OT, 对每个实例:
//! * Receiver 持选择位 $w\in\{0,1\}$, 拿到密钥 $\rho_w$;
//! * Sender 同时拿到 $(\rho_0, \rho_1)$, 但学不到 $w$.
//!
//! 论文出处: Masny–Rindal, "Endemic OT", Fig.8,
//! <https://eprint.iacr.org/2019/706.pdf>.

use curve_abstract::{TrPoint, TrScalar};
use erreur::*;
use rand::Rng;
use serde::{Deserialize, Serialize};
use svarog_secp256k1::{Scalar, Point};

/// 安全参数: 并行执行 KAPPA 个 OT 实例 (= secp256k1 标量比特数).
const KAPPA: usize = 256;

/// KAPPA 对应的字节数.
const KAPPA_BYTES: usize = 32;

fn endemic_ot_idx(idx: usize) -> u16 {
    debug_assert!(idx <= u16::MAX as usize);
    idx as u16
}

/// 从字节数组里取出第 `idx` 比特.
fn extract_bit(packed: &[u8], idx: usize) -> u8 {
    (packed[idx / 8] >> (idx % 8)) & 1
}

/// Hash-to-curve: 把 `seed` 映射到一个离散对数未知的 secp256k1 点.
/// 
/// try-and-increment 法: 每轮哈希得候选横坐标, 检查其是否存在对应纵坐标.  
/// 单轮成功率 ~50%, 期望迭代 2 次.
fn hash_to_curve(seed: &[u8]) -> Point {
    let mut ctr: u32 = 0;
    loop {
        let x = hash!(32; b"endemic-ot-htg", seed, ctr.to_be_bytes());
        let mut buf = [0u8; 33];
        buf[0] = 0x02;
        buf[1..].copy_from_slice(&x);
        if let Ok(p) = Point::new_from_bytes(&buf) {
            return p;
        }
        ctr += 1;
    }
}

/// Endemic OT 第一条消息 (Receiver -> Sender). 对每个 idx 携带 $(R_0, R_1)$.
#[derive(Clone, Serialize, Deserialize, Default)]
pub struct EndemicOTMsg1 {
    R0_list: Vec<Point>,
    R1_list: Vec<Point>,
}

/// Endemic OT 第二条消息 (Sender -> Receiver). 对每个 idx 携带 $M_{a,0}, M_{a,1}$.
#[derive(Clone, Serialize, Deserialize, Default)]
pub struct EndemicOTMsg2 {
    ma0_list: Vec<Point>,
    ma1_list: Vec<Point>,
}

/// Sender 输出: KAPPA 对加密密钥 $(\rho_0, \rho_1)$, 按 idx 平铺成两个并列向量.
#[derive(Clone, Serialize, Deserialize, Default)]
pub struct EndemicOTSenderKeys {
    pub rho_0_list: Vec<Vec<u8>>,
    pub rho_1_list: Vec<Vec<u8>>,
}

/// Receiver 输出: KAPPA 个选择位 + KAPPA 个解密密钥 $\rho_w$.
#[derive(Clone, Serialize, Deserialize, Default)]
pub struct EndemicOTReceiverOutput {
    pub choice_bits: Vec<u8>,
    pub otp_dec_keys: Vec<Vec<u8>>,
}

/// Receiver 中间状态. `round1` 创建并产出 Msg1; 收到 Msg2 后传给 `round3` 完成.
#[derive(Clone, Serialize, Deserialize, Default)]
pub struct EndemicOTRound1 {
    choices: Vec<u8>,
    blind_terms: Vec<Scalar>,
}

/// Receiver 对每个 Endemic OT 实例, 
/// * 生成并保存选择位 $w$ 和 盲化标量 $t_b$;
/// * 发送 Msg1 = $(R_0, R_1)$, 恰有一个是 $R_w$, 另一个是 $R_{1-w}$.
pub fn round1(sid: &str, ret_msg1: &mut EndemicOTMsg1) -> EndemicOTRound1 {
    ret_msg1.R0_list = Vec::with_capacity(KAPPA);
    ret_msg1.R1_list = Vec::with_capacity(KAPPA);

    let mut choices = vec![0u8; KAPPA_BYTES];
    rand::rng().fill_bytes(&mut choices);
    let blind_terms: Vec<Scalar> = (0..KAPPA).map(|_| Scalar::new_rand()).collect();

    for idx in 0..KAPPA {
        let choice_bit = u16::from(extract_bit(&choices, idx));
        let blind = &blind_terms[idx];

        // $R_{1-w}$ 由 hash-to-curve 生成, 确保离散对数未知.
        let mut nonce = [0u8; 32];
        rand::rng().fill_bytes(&mut nonce);
        let Rblind = hash_to_curve(&nonce);

        // $R_w$, 详见 `03-endemic-ot.md` 公式 (Rw).
        let hw = Point::new_gx(&Scalar::new_from_bytes(&hash!(
            KAPPA_BYTES;
            b"endemic-ot-h",
            choice_bit.to_be_bytes(),
            endemic_ot_idx(idx).to_be_bytes(),
            sid.as_bytes(),
            Rblind.to_bytes()
        )));
        let Rchoose = Point::new_gx(blind).sub(&hw);

        if choice_bit == 0 {
            ret_msg1.R0_list.push(Rchoose);
            ret_msg1.R1_list.push(Rblind);
        } else {
            ret_msg1.R0_list.push(Rblind);
            ret_msg1.R1_list.push(Rchoose);
        }
    }

    EndemicOTRound1 {
        choices,
        blind_terms,
    }
}

// ════════════════════════════════════════════════
// Sender (无状态)
// ════════════════════════════════════════════════

/// Sender 对每个 Endemic OT 实例,
///
/// * 接收 $R_0, R_1$,
/// * 生成并发送消息 $M_{a,0}, M_{a,1}$,
/// * 生成并保存密钥 $\rho_0, \rho_1$.
pub fn round2(
    sid: &str,
    msg1: &EndemicOTMsg1,
    msg2: &mut EndemicOTMsg2,
) -> Resultat<EndemicOTSenderKeys> {
    assert_throw!(
        msg1.R0_list.len() == KAPPA && msg1.R1_list.len() == KAPPA,
        "EndemicOTMsg1LengthMismatch",
        format!(
            "expected {} entries in Msg1, got R0_list: {}, R1_list: {}",
            KAPPA,
            msg1.R0_list.len(),
            msg1.R1_list.len()
        )
    );

    msg2.ma0_list = Vec::with_capacity(KAPPA);
    msg2.ma1_list = Vec::with_capacity(KAPPA);
    let mut rho_0_list = Vec::with_capacity(KAPPA);
    let mut rho_1_list = Vec::with_capacity(KAPPA);

    for idx in 0..KAPPA {
        let r_0 = &msg1.R0_list[idx];
        let r_1 = &msg1.R1_list[idx];

        let Mb0 = r_0.add(&Point::new_gx(&Scalar::new_from_bytes(&hash!(
            KAPPA_BYTES;
            b"endemic-ot-h",
            0u16.to_be_bytes(),
            endemic_ot_idx(idx).to_be_bytes(),
            sid.as_bytes(),
            r_1.to_bytes()
        ))));
        let Mb1 = r_1.add(&Point::new_gx(&Scalar::new_from_bytes(&hash!(
            KAPPA_BYTES;
            b"endemic-ot-h",
            1u16.to_be_bytes(),
            endemic_ot_idx(idx).to_be_bytes(),
            sid.as_bytes(),
            r_0.to_bytes()
        ))));

        let ta0 = Scalar::new_rand();
        let ta1 = Scalar::new_rand();

        let m_a_0 = Point::new_gx(&ta0);
        let m_a_1 = Point::new_gx(&ta1);
        msg2.ma0_list.push(m_a_0);
        msg2.ma1_list.push(m_a_1);

        let rho_0 = hash!(
            KAPPA_BYTES;
            b"endemic-ot-seed",
            endemic_ot_idx(idx).to_be_bytes(),
            Mb0.mul_x(&ta0).to_bytes()
        );
        let rho_1 = hash!(
            KAPPA_BYTES;
            b"endemic-ot-seed",
            endemic_ot_idx(idx).to_be_bytes(),
            Mb1.mul_x(&ta1).to_bytes()
        );

        rho_0_list.push(rho_0);
        rho_1_list.push(rho_1);
    }

    Ok(EndemicOTSenderKeys { rho_0_list, rho_1_list })
}

/// Receiver 对每个 Endemic OT 实例,
/// * 计算并保存密钥 $\rho_w$;
/// * 保存选择位 $w$ 以供后续 PPRF 使用.
pub fn round3(state: EndemicOTRound1, msg2: &EndemicOTMsg2) -> Resultat<EndemicOTReceiverOutput> {
    assert_throw!(
        msg2.ma0_list.len() == KAPPA && msg2.ma1_list.len() == KAPPA,
        "EndemicOTMsg2LengthMismatch",
        format!(
            "expected {} entries in each Msg2 list, got ma0: {}, ma1: {}",
            KAPPA,
            msg2.ma0_list.len(),
            msg2.ma1_list.len()
        )
    );

    let mut otp_dec_keys = Vec::with_capacity(KAPPA);
    for idx in 0..KAPPA {
        let w = extract_bit(&state.choices, idx);
        let m_a_w = if w == 0 {
            &msg2.ma0_list[idx]
        } else {
            &msg2.ma1_list[idx]
        };

        let shared = m_a_w.mul_x(&state.blind_terms[idx]);
        otp_dec_keys.push(hash!(
            KAPPA_BYTES;
            b"endemic-ot-seed",
            endemic_ot_idx(idx).to_be_bytes(),
            shared.to_bytes()
        )); // rho_w = H'(idx, t_b · M_{a,w})
    }

    Ok(EndemicOTReceiverOutput {
        choice_bits: state.choices,
        otp_dec_keys,
    })
}

// ════════════════════════════════════════════════
// Tests
// ════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use curve_abstract::{TrPoint, TrScalar};
    use rand::Rng;
    use svarog_secp256k1::{Scalar, Point};

    /// 正确性测试: Receiver 的 $\rho_w$ 必须等于 Sender 的 $\rho_w$.
    #[test]
    fn test_endemic_ot_correctness() {
        let sid = "test-endemic-ot-session";

        let mut msg1 = EndemicOTMsg1::default();
        let receiver = round1(sid, &mut msg1);

        let mut msg2 = EndemicOTMsg2::default();
        let sender_output = round2(sid, &msg1, &mut msg2).unwrap();

        let receiver_output = round3(receiver, &msg2).unwrap();

        for idx in 0..KAPPA {
            let w = extract_bit(&receiver_output.choice_bits, idx);
            let sender_rho = if w == 0 {
                &sender_output.rho_0_list[idx]
            } else {
                &sender_output.rho_1_list[idx]
            };
            assert_eq!(
                sender_rho, &receiver_output.otp_dec_keys[idx],
                "OT key mismatch: idx={}, w={}",
                idx, w
            );
        }
    }

    /// 安全漏洞复现: 恶意 Receiver 若知道 $R_{1-w}$ 的离散对数, 即可恢复 $\rho_{1-w}$,
    /// 验证了 `notes/03-endemic-ot.md` §5 的攻击 (打破对 Sender 的隐私).
    ///
    /// 攻击思路: 若 $R_{1-w} = s\cdot G$ 且 $s$ 已知, 那么
    /// $M_{b,1-w} = (s + \alpha_{1-w})\cdot G$, 进而
    /// $t_{a,1-w}\cdot M_{b,1-w} = (s + \alpha_{1-w})\cdot M_{a,1-w}$.
    /// 攻击者用 $(s, \alpha_{1-w}, M_{a,1-w})$ 即可重算 $\rho_{1-w}$.
    #[test]
    fn test_evil_receiver_breaks_sender_privacy() {
        let sid = "test-evil-receiver";

        // --- Evil Receiver: same as EndemicOTReceiver::new but retains s. ---
        let mut choices = vec![0u8; KAPPA_BYTES];
        rand::rng().fill_bytes(&mut choices);
        let blind_terms: Vec<Scalar> = (0..KAPPA).map(|_| Scalar::new_rand()).collect();
        let mut evil_s_terms: Vec<Scalar> = Vec::with_capacity(KAPPA);

        let mut msg1 = EndemicOTMsg1::default();
        msg1.R0_list = Vec::with_capacity(KAPPA);
        msg1.R1_list = Vec::with_capacity(KAPPA);

        for idx in 0..KAPPA {
            let choice_bit = u16::from(extract_bit(&choices, idx));
            let blind = &blind_terms[idx];

            let s = Scalar::new_rand();
            let Rblind = Point::new_gx(&s);
            evil_s_terms.push(s);

            let hw = Point::new_gx(&Scalar::new_from_bytes(&hash!(
                KAPPA_BYTES;
                b"endemic-ot-h",
                choice_bit.to_be_bytes(),
                endemic_ot_idx(idx).to_be_bytes(),
                sid.as_bytes(),
                Rblind.to_bytes()
            )));
            let Rchoose = Point::new_gx(blind).sub(&hw);

            if choice_bit == 0 {
                msg1.R0_list.push(Rchoose);
                msg1.R1_list.push(Rblind);
            } else {
                msg1.R0_list.push(Rblind);
                msg1.R1_list.push(Rchoose);
            }
        }

        let mut msg2 = EndemicOTMsg2::default();
        let sender_output = round2(sid, &msg1, &mut msg2).unwrap();

        // --- Evil Receiver computes rho_{1-w} for every idx. ---
        for idx in 0..KAPPA {
            let w = extract_bit(&choices, idx);
            // r_w is the R point for the chosen side; alpha is hashed with (1-w, idx, sid, r_w).
            let (one_minus_w, r_w, m_a_other) = if w == 0 {
                (1u16, &msg1.R0_list[idx], &msg2.ma1_list[idx])
            } else {
                (0u16, &msg1.R1_list[idx], &msg2.ma0_list[idx])
            };

            // alpha_{1-w} = H(1-w, idx, sid, R_w)  — public info
            let alpha = Scalar::new_from_bytes(&hash!(
                KAPPA_BYTES;
                b"endemic-ot-h",
                one_minus_w.to_be_bytes(),
                endemic_ot_idx(idx).to_be_bytes(),
                sid.as_bytes(),
                r_w.to_bytes()
            ));

            // t_{a,1-w} * M_{b,1-w} = (s + alpha) * M_{a,1-w}
            let shared = m_a_other.mul_x(&evil_s_terms[idx].add(&alpha));

            let evil_rho = hash!(
                KAPPA_BYTES;
                b"endemic-ot-seed",
                endemic_ot_idx(idx).to_be_bytes(),
                shared.to_bytes()
            );

            let sender_rho_other = if w == 0 {
                &sender_output.rho_1_list[idx]
            } else {
                &sender_output.rho_0_list[idx]
            };

            assert_eq!(
                evil_rho, *sender_rho_other,
                "evil receiver failed to recover rho_{{1-w}}: idx={}, w={}",
                idx, w
            );
        }
    }
}
