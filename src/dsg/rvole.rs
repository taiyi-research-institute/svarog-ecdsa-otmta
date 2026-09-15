//! 🛡️ 2026-976 §4.4、§4.5、附录 B.3：Variant III RVOLE 与指定输入转换。
//!
//! Sender 为每个指定输入 a_i 采样随机 w_i，随机 VOLE 产生 c_i + d_i = w_i b。
//! Sender 同轮发送 δ_i = a_i − w_i，Receiver 在校验通过后把 d_i 加上 δ_i b。
//! gadget 在会话开始时生成，长度 L = 2688；一列额外随机负载用于一致性检查。
//! theta 绑定初始化与本次 SoftSpoken 的公开记录、修正矩阵及其维度。
//! sigma 是按固定顺序吸收校验值的单个 64 字节摘要。

use erreur::*;
use serde::{Deserialize, Serialize};

use curve_abstract::TrScalar;
use svarog_secp256k1::Scalar;

use super::softspoken_ot::{
    BSIZE, KAPPA_BYTES, L, L_BYTES, SSReceiverKeys, SSSenderKeys, expand_seed,
};
use crate::rng::fill_random;

/// Receiver 摇随机 $\beta$ (将来作为 MtA 的盲化因子) 并计算 $b = \langle g, \beta\rangle$.
/// SoftSpoken Receiver 由调用方用同一 $\beta$ 单独驱动.
pub fn rvole_round1(sid: &str) -> (Vec<u8>, Scalar) {
    let mut beta = vec![0u8; L_BYTES];
    fill_random(&mut beta);

    // b = <g, β> (`notes/misc-gadget.md`).
    let gadget = generate_gadget_vec(sid);
    let mut b = Scalar::default();
    for (i, gv) in gadget.iter().enumerate() {
        if extract_bit(&beta, i) == 1 {
            b = b.add(gv);
        }
    }

    (beta, b)
}

/// Sender 计算自己的加法份额 $z_a$,
/// 并构造相应的 RVOLE 网线消息 (Sender -> Receiver).
/// `send_out` 由调用方通过 `ss_sender` 单独得到.
pub fn rvole_round2(
    sid: &str,
    send_out: SSSenderKeys,
    xa_vec: &[Scalar; BSIZE],
) -> (RVOLEMsg2, [Scalar; BSIZE]) {
    let alpha_0: Vec<Vec<Vec<u8>>> = (0..NUM_CHOICES)
        .map(|j| expand_seed(sid, j, &send_out.keys0[j], OT_WIDTH))
        .collect();
    let alpha_0 = |j: usize, i: usize| Scalar::new_from_bytes(&alpha_0[j][i]);
    let alpha_1: Vec<Vec<Vec<u8>>> = (0..NUM_CHOICES)
        .map(|j| expand_seed(sid, j, &send_out.keys1[j], OT_WIDTH))
        .collect();
    let alpha_1 = |j: usize, i: usize| Scalar::new_from_bytes(&alpha_1[j][i]);

    // "完全版" Round 2, Sender 聚合 $z_a = -\sum_j g_j\cdot\alpha^0_j$
    let gadget = generate_gadget_vec(sid);
    let mut za: [Scalar; BSIZE] = [Scalar::default(), Scalar::default()];
    for i in 0..BSIZE {
        let mut acc = Scalar::default();
        for j in 0..NUM_CHOICES {
            // $z_a$ 求和的每一项 (上一行)
            acc = acc.add(&gadget[j].mul(&alpha_0(j, i)));
        }
        za[i] = acc.neg();
    }

    // `06-rvole.md` 公式 (resp-eta) 第一项, 也就是 $x_a^{(k)}$.
    // 2026-976 §4.4：修正矩阵只使用新采样的随机负载。
    let random_inputs: Vec<Scalar> = (0..BSIZE).map(|_| Scalar::new_rand()).collect();
    let eta_vals: Vec<Scalar> = (0..NUM_CHECKS).map(|_| Scalar::new_rand()).collect();

    let mut output = RVOLEMsg2::default();
    output.delta = xa_vec
        .iter()
        .zip(&random_inputs)
        .map(|(a, w)| a.sub(w).to_bytes())
        .collect();
    for j in 0..NUM_CHOICES {
        // "完全版" 修正矩阵功能列定义
        for i in 0..BSIZE {
            let v = alpha_0(j, i).sub(&alpha_1(j, i)).add(&random_inputs[i]);
            output.a_tilde[j][i] = v.to_bytes();
        }
        // "完全版" 修正矩阵检查列定义
        for k in 0..NUM_CHECKS {
            let v = alpha_0(j, BSIZE + k)
                .sub(&alpha_1(j, BSIZE + k))
                .add(&eta_vals[k]);
            output.a_tilde[j][BSIZE + k] = v.to_bytes();
        }
    }

    // `06-rvole.md` 公式 (challenge)
    let theta = theta_table(sid, &send_out.transcript, &output.a_tilde);

    // 完成 `06-rvole.md` 公式 (resp-eta) 的计算.
    for k in 0..NUM_CHECKS {
        let mut s = eta_vals[k].clone();
        for i in 0..BSIZE {
            s = s.add(&theta[k][i].mul(&random_inputs[i]));
        }
        output.eta[k] = s.to_bytes();
    }

    // 按 OT 实例、校验列的顺序吸收校验值。
    let mut sigma = crate::hash::FramedHash::new(64).unwrap();

    sigma.update(b"dsg/rvole/sigma");
    sigma.update(sid.as_bytes());
    sigma.update(&(NUM_CHOICES as u64).to_be_bytes());
    sigma.update(&(NUM_CHECKS as u64).to_be_bytes());
    for j in 0..NUM_CHOICES {
        for k in 0..NUM_CHECKS {
            let mut v = alpha_0(j, BSIZE + k);
            for i in 0..BSIZE {
                v = v.add(&theta[k][i].mul(&alpha_0(j, i)));
            }
            sigma.update(&v.to_bytes());
        }
    }
    let mut mu = vec![0u8; 64];
    sigma.finalize_variable(&mut mu).unwrap();
    output.sigma = mu;

    (output, za)
}

/// Receiver 验证 Sender 的响应, 计算自己的加法份额 $z_b$.
/// `beta` / `recv_out` 来自 round 1 + `ss_receiver`.
pub fn rvole_round3(
    sid: &str,
    beta: &[u8],
    recv_out: SSReceiverKeys,
    output: &RVOLEMsg2,
) -> Resultat<[Scalar; BSIZE]> {
    assert_throw!(
        beta.len() == L_BYTES
            && recv_out.keys_chosen.len() == NUM_CHOICES
            && recv_out
                .keys_chosen
                .iter()
                .all(|key| key.len() == KAPPA_BYTES)
            && output.a_tilde.len() == NUM_CHOICES
            && output
                .a_tilde
                .iter()
                .all(|row| row.len() == BSIZE + NUM_CHECKS
                    && row.iter().all(|v| canonical_scalar(v)))
            && output.eta.len() == NUM_CHECKS
            && output.eta.iter().all(|v| canonical_scalar(v))
            && output.delta.len() == BSIZE
            && output.delta.iter().all(|v| canonical_scalar(v))
            && output.sigma.len() == 64,
        "RVOLEShape",
        "invalid RVOLE dimensions or scalar encoding"
    );
    let theta = theta_table(sid, &recv_out.transcript, &output.a_tilde);

    let keys: Vec<Vec<Vec<u8>>> = (0..NUM_CHOICES)
        .map(|j| expand_seed(sid, j, &recv_out.keys_chosen[j], OT_WIDTH))
        .collect();

    let mut d_biz: Vec<Vec<Scalar>> = (0..NUM_CHOICES)
        .map(|_| (0..BSIZE).map(|_| Scalar::default()).collect())
        .collect();
    let mut d_hat: Vec<Vec<Scalar>> = (0..NUM_CHOICES)
        .map(|_| (0..NUM_CHECKS).map(|_| Scalar::default()).collect())
        .collect();

    // 演算一下可知, 对第 j OT 槽位第 i 负载,
    // $$ D_{j,i} = \alpha^0_{j,i} + \beta_j \cdot x_{a,i} $$.
    for j in 0..NUM_CHOICES {
        let bit = extract_bit(beta, j);
        for i in 0..BSIZE {
            let opt0 = Scalar::new_from_bytes(&keys[j][i]);
            let opt1 = opt0.add(&Scalar::new_from_bytes(&output.a_tilde[j][i]));
            d_biz[j][i] = if bit == 1 { opt1 } else { opt0 };
        }
        for k in 0..NUM_CHECKS {
            let opt0 = Scalar::new_from_bytes(&keys[j][BSIZE + k]);
            let opt1 = opt0.add(&Scalar::new_from_bytes(&output.a_tilde[j][BSIZE + k]));
            d_hat[j][k] = if bit == 1 { opt1 } else { opt0 };
        }
    }

    // Receiver 重算校验值的摘要，并与 Sender 的 sigma 比较。

    let mut sigma = crate::hash::FramedHash::new(64).unwrap();

    sigma.update(b"dsg/rvole/sigma");
    sigma.update(sid.as_bytes());
    sigma.update(&(NUM_CHOICES as u64).to_be_bytes());
    sigma.update(&(NUM_CHECKS as u64).to_be_bytes());

    for j in 0..NUM_CHOICES {
        let bit = extract_bit(beta, j);
        for k in 0..NUM_CHECKS {
            let mut v = d_hat[j][k].clone();
            for i in 0..BSIZE {
                v = v.add(&theta[k][i].mul(&d_biz[j][i]));
            }
            // bit=1 时减去 Sender 揭示的 η_k, 抹去随机化.
            if bit == 1 {
                v = v.sub(&Scalar::new_from_bytes(&output.eta[k]));
            }
            sigma.update(&v.to_bytes());
        }
    }

    let mut mu_prime = [0u8; 64];
    sigma.finalize_variable(&mut mu_prime).unwrap();

    assert_throw!(
        &mu_prime[..] == &output.sigma[..],
        "RVOLEMuCheckFailed",
        "rvole receiver: mu hash mismatch"
    );

    // d[i] = <g, d_dot[..][i]>: 收尾内积.
    let gadget = generate_gadget_vec(sid);
    let mut d = [Scalar::default(), Scalar::default()];
    for i in 0..BSIZE {
        let mut acc = Scalar::default();
        for j in 0..NUM_CHOICES {
            acc = acc.add(&gadget[j].mul(&d_biz[j][i]));
        }
        d[i] = acc;
    }
    // 校验已通过，才把随机 VOLE 转成指定输入；状态被消费，不能重复转换。
    let mut b = Scalar::default();
    for (j, g) in gadget.iter().enumerate() {
        if extract_bit(beta, j) == 1 {
            b = b.add(g);
        }
    }
    for i in 0..BSIZE {
        d[i] = d[i].add(&b.mul(&Scalar::new_from_bytes(&output.delta[i])));
    }
    Ok(d)
}

// ── 网线消息 + 内部辅助 ──────────────────────────────────────────────────

/// RVOLE 网线消息 (Sender -> Receiver).
#[derive(Clone, Serialize, Deserialize)]
pub struct RVOLEMsg2 {
    /// 修正矩阵 $\tilde a$, 详见 `06-rvole.md` "完全版" Round 1 中 Sender 的修正
    /// 矩阵 (功能列和检查列).
    pub a_tilde: Vec<Vec<Vec<u8>>>,
    /// Sender 响应的第一项 $\eta$, 详见 `06-rvole.md` 公式 (resp-eta).
    pub eta: Vec<Vec<u8>>,
    /// Sender 响应的第二项 $\sigma$, 详见 `06-rvole.md` "完全版" Round 2 中
    /// Sender 响应 $\sigma$.
    pub sigma: Vec<u8>,
    /// 一次性指定输入偏移 δ = a − w，须在随机 VOLE 校验通过后应用。
    pub delta: Vec<Vec<u8>>,
}

impl Default for RVOLEMsg2 {
    fn default() -> Self {
        Self {
            a_tilde: (0..NUM_CHOICES)
                .map(|_| (0..OT_WIDTH).map(|_| vec![0u8; KAPPA_BYTES]).collect())
                .collect(),
            eta: (0..NUM_CHECKS).map(|_| vec![0u8; KAPPA_BYTES]).collect(),
            sigma: vec![0u8; 64],
            delta: vec![vec![0u8; KAPPA_BYTES]; BSIZE],
        }
    }
}

/// 实现 `misc-gadget.md` 公式 (gvec)
pub fn generate_gadget_vec(sid: &str) -> Vec<Scalar> {
    (0..NUM_CHOICES)
        .map(|i| {
            crate::hash::scalar(
                b"dsg/rvole/gadget",
                &[sid.as_bytes(), &(i as u64).to_le_bytes()],
            )
        })
        .collect()
}

#[inline]
fn extract_bit(packed: &[u8], idx: usize) -> u8 {
    (packed[idx / 8] >> (idx % 8)) & 1
}

/// 双下标挑战表 $\theta^{(k, \ell')}$ (`notes/06-rvole.md` "完全版" 中 Receiver
/// 用以聚合修正矩阵列的挑战).
///
/// 先用 Blake2b 流式哈希把 `a_tilde` 全表 bind 进种子, 再派生 $\rho \times \ell$ 个
/// 标量, 实现 Fiat-Shamir 防作弊.
fn theta_table(sid: &str, transcript: &[u8; 32], a_tilde: &[Vec<Vec<u8>>]) -> Vec<Vec<Scalar>> {
    let mut acc = crate::hash::FramedHash::new(32).unwrap();

    acc.update(b"dsg/rvole/theta-bind");
    acc.update(sid.as_bytes());
    acc.update(transcript);
    acc.update(&(BSIZE as u64).to_be_bytes());
    acc.update(&(a_tilde.len() as u64).to_be_bytes());
    for row in a_tilde {
        acc.update(&(row.len() as u64).to_be_bytes());
        for cell in row {
            acc.update(cell);
        }
    }
    let mut bind = [0u8; 32];
    acc.finalize_variable(&mut bind).unwrap();

    let mut theta = vec![vec![Scalar::default(); BSIZE]; NUM_CHECKS];
    for k in 0..NUM_CHECKS {
        for i in 0..BSIZE {
            theta[k][i] = crate::hash::scalar(
                b"dsg/rvole/theta",
                &[&bind, &(k as u64).to_le_bytes(), &(i as u64).to_le_bytes()],
            );
        }
    }
    theta
}

/// 一次 SoftSpoken OT 槽要派生的并行密钥条数:
/// 前 `BSIZE` 条给 RVOLE 主载荷, 后 `RHO` 条给一致性检查.
pub const OT_WIDTH: usize = BSIZE + NUM_CHECKS;
pub const NUM_CHECKS: usize = 1;
/// gadget 长度 $\xi = L$ (`notes/misc-gadget.md`).
const NUM_CHOICES: usize = L;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dkg::{PPRFReceiverOTSeed, PPRFSenderOTSeed};
    use crate::dsg::softspoken_ot::{
        LAMBDA_C_BYTES, LAMBDA_C_DIV_SOFT_SPOKEN_K, SOFT_SPOKEN_Q, ss_receiver, ss_sender,
    };
    use rand::Rng;

    fn fresh_seed_pair() -> (PPRFSenderOTSeed, PPRFReceiverOTSeed) {
        let mut sender = PPRFSenderOTSeed::default();
        let mut receiver = PPRFReceiverOTSeed::default();
        let mut rng = rand::rng();
        for i in 0..LAMBDA_C_DIV_SOFT_SPOKEN_K {
            for j in 0..SOFT_SPOKEN_Q {
                let mut buf = vec![0u8; LAMBDA_C_BYTES];
                rng.fill_bytes(&mut buf);
                sender.otp_enc_keys[i][j] = buf.clone();
                receiver.otp_dec_keys[i][j] = buf;
            }
            let mut byte = [0u8; 1];
            rng.fill_bytes(&mut byte);
            let chosen = (byte[0] as usize) % SOFT_SPOKEN_Q;
            receiver.random_choices[i] = chosen as u8;
            receiver.otp_dec_keys[i][chosen] = vec![0u8; LAMBDA_C_BYTES];
        }
        (sender, receiver)
    }

    #[test]
    fn reject_modified_transcript_and_malformed_response() {
        let (sender_seed, receiver_seed) = fresh_seed_pair();
        let sid = "rvole-adversarial";
        let (beta, _) = rvole_round1(sid);
        let (round1, recv) = ss_receiver(sid, &sender_seed, &beta);
        let send = ss_sender(sid, &receiver_seed, &round1).unwrap();
        assert_eq!(send.transcript, recv.transcript);
        let (out, _) = rvole_round2(sid, send, &[Scalar::new(3), Scalar::new(5)]);
        let fresh_recv = || SSReceiverKeys {
            transcript: recv.transcript,
            keys_chosen: recv.keys_chosen.clone(),
        };
        let mut wrong_transcript = fresh_recv();
        wrong_transcript.transcript[0] ^= 1;
        assert!(rvole_round3(sid, &beta, wrong_transcript, &out).is_err());
        let mut modified = out.clone();
        modified.sigma[0] ^= 1;
        assert!(rvole_round3(sid, &beta, fresh_recv(), &modified).is_err());
        modified = out.clone();
        modified.a_tilde.pop();
        assert!(rvole_round3(sid, &beta, fresh_recv(), &modified).is_err());
        modified = out.clone();
        modified.delta[0] = vec![255; 32];
        assert!(rvole_round3(sid, &beta, fresh_recv(), &modified).is_err());
        modified = out.clone();
        modified.eta[0] = Scalar::new_from_bytes(&out.eta[0])
            .add(&Scalar::new(1))
            .to_bytes();
        assert!(rvole_round3(sid, &beta, fresh_recv(), &modified).is_err());
        assert!(rvole_round3(sid, &beta, fresh_recv(), &out).is_ok());
    }

    #[test]
    fn test_gadget_length() {
        let g = generate_gadget_vec("xx");
        assert_eq!(g.len(), L);
    }

    #[test]
    fn rvole_correctness() {
        let (sender_seed, receiver_seed) = fresh_seed_pair();
        let sid = "rvole-test";

        let (beta, b) = rvole_round1(sid);
        let (round1, recv_out) = ss_receiver(sid, &sender_seed, &beta);
        let a = [Scalar::new_rand(), Scalar::new_rand()];
        let send_out = ss_sender(sid, &receiver_seed, &round1).unwrap();
        let (out, c) = rvole_round2(sid, send_out, &a);
        let d = rvole_round3(sid, &beta, recv_out, &out).unwrap();

        for i in 0..BSIZE {
            let lhs = c[i].add(&d[i]);
            let rhs = a[i].mul(&b);
            assert_eq!(lhs, rhs, "RVOLE additivity failed at i={}", i);
        }
    }
}

fn canonical_scalar(bytes: &[u8]) -> bool {
    use curve_abstract::TrCurve;
    bytes.len() == KAPPA_BYTES && bytes < svarog_secp256k1::Secp256k1::curve_order_bytes()
}
