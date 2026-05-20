//! Random Vector OLE (DKLS23 §5.2). 见 `notes/06-rvole.md`, `notes/misc-gadget.md`.
//!
//! 对每个 Sender 输入 $a_k$ ($k \in [\ell] = $ `L_BATCH`) 和单个 Receiver 输入 $b$,
//! 产出 加法份额 $c_k, d_k$ 满足 $c_k + d_k = a_k \cdot b \pmod n$.
//! 额外 `RHO = 1` 列用于 Receiver 检查 Sender 诚实性 (mu-check).
//!
//! gadget 替代 $2^j$ (见 `notes/misc-gadget.md`):
//!   $b = \langle g, \beta \rangle$, $\xi = L = \kappa + 2\lambda_s = 512$.
//!
//! 实现是 `notes/06-rvole.md` "完全版" 协议的 *哈希链* 变体:
//!   `mu_hash` 用 Blake2b 链式累加 $\xi \cdot \rho$ 个 $v$ 值, 不发送原始 verify
//!   向量, 显著节省带宽.
//!
//! `theta_table` 即 `notes/06-rvole.md` "完全版" 中 Receiver 用以聚合修正矩阵列
//! 的双下标挑战 $\theta^{(k,\ell')}$, 这里命名为 chi-绑定后的 `theta`.

use erreur::*;
use serde::{Deserialize, Serialize};

use curve_abstract::TrScalar;
use svarog_secp256k1::Scalar;

use super::super::dkg::{PPRFReceiverOTSeed, PPRFSenderOTSeed};
use super::softspoken_ot::{
    KAPPA_BYTES, L, BSIZE, L_BYTES, SSReceiverKeys, SoftSpokenMsg1, SoftSpokenOTReceiver,
    SoftSpokenOTSender, expand_seed,
};

/// 一次 SoftSpoken OT 槽要派生的并行密钥条数:
/// 前 `L_BATCH` 条给 RVOLE 主载荷, 后 `RHO` 条给一致性检查.
pub const OT_WIDTH: usize = BSIZE + NUM_CHECKS;

pub const NUM_CHECKS: usize = 1;

/// gadget 长度 $\xi = L$ (`notes/misc-gadget.md`).
const NUM_CHOICES: usize = L;

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
}

impl Default for RVOLEMsg2 {
    fn default() -> Self {
        Self {
            a_tilde: (0..NUM_CHOICES)
                .map(|_| (0..OT_WIDTH).map(|_| vec![0u8; KAPPA_BYTES]).collect())
                .collect(),
            eta: (0..NUM_CHECKS).map(|_| vec![0u8; KAPPA_BYTES]).collect(),
            sigma: vec![0u8; 64],
        }
    }
}

/// 实现 `misc-gadget.md` 公式 (gvec)
pub fn generate_gadget_vec(sid: &str) -> Vec<Scalar> {
    (0..NUM_CHOICES)
        .map(|i| {
            let bytes =
                hash!(KAPPA_BYTES; b"dsg/rvole/gadget", sid.as_bytes(), &(i as u64).to_le_bytes());
            Scalar::new_from_bytes(&bytes)
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
/// 先用 Blake2b 链式哈希把 `a_tilde` 全表 bind 进种子, 再派生 $\rho \times \ell$ 个
/// 标量, 实现 Fiat-Shamir 防作弊.
fn theta_table(sid: &str, a_tilde: &[Vec<Vec<u8>>]) -> Vec<Vec<Scalar>> {
    let mut acc = <::blake2::Blake2bVar as ::blake2::digest::VariableOutput>::new(32).unwrap();
    use ::blake2::digest::Update;
    acc.update(b"dsg/rvole/theta-bind");
    acc.update(sid.as_bytes());
    for row in a_tilde {
        for cell in row {
            acc.update(cell);
        }
    }
    let mut bind = [0u8; 32];
    ::blake2::digest::VariableOutput::finalize_variable(acc, &mut bind).unwrap();

    let mut theta = vec![vec![Scalar::default(); BSIZE]; NUM_CHECKS];
    for k in 0..NUM_CHECKS {
        for i in 0..BSIZE {
            let bytes = hash!(
                KAPPA_BYTES;
                b"dsg/rvole/theta",
                &bind,
                &(k as u64).to_le_bytes(),
                &(i as u64).to_le_bytes()
            );
            theta[k][i] = Scalar::new_from_bytes(&bytes);
        }
    }
    theta
}

// ── Receiver ─────────────────────────────────────────────────────────────

pub struct RVOLEReceiverPrivacy {
    pub sid: String,
    pub beta: Vec<u8>,
    pub recv_out: SSReceiverKeys,
}

/// 承接 SoftSpokenOT Round 1 Receiver, 摇随机 $\beta$, 将来作为 MtA 的盲化因子.
pub fn rvole_round1(
    sid: &str,
    sender_seed: &PPRFSenderOTSeed,
) -> (RVOLEReceiverPrivacy, SoftSpokenMsg1, Scalar) {
    use rand::Rng;
    let mut beta = vec![0u8; L_BYTES];
    rand::rng().fill_bytes(&mut beta);

    // b = <g, β> (`notes/misc-gadget.md`).
    let gadget = generate_gadget_vec(sid);
    let mut b = Scalar::default();
    for (i, gv) in gadget.iter().enumerate() {
        if extract_bit(&beta, i) == 1 {
            b = b.add(gv);
        }
    }

    // TODO: 把这个调用挪到外面去.
    let (ss_msg1, ss_receiver_keys) = SoftSpokenOTReceiver::ss_round1(sid, sender_seed, &beta);
    let state = RVOLEReceiverPrivacy {
        sid: sid.to_string(),
        beta,
        recv_out: ss_receiver_keys,
    };
    // TODO: 重构为 (beta, b), 避免重复构造 state.
    (state, ss_msg1, b)
}

pub struct RVOLESender;

impl RVOLESender {
    /// Sender 计算自己的加法份额 $z_a$,
    /// 并构造相应的 RVOLE 网线消息 (Sender -> Receiver).
    pub fn rvole_round2(
        sid: &str,
        receiver_seed: &PPRFReceiverOTSeed,
        xa_vec: &[Scalar; BSIZE],
        round1: &SoftSpokenMsg1,
    ) -> Resultat<(RVOLEMsg2, [Scalar; BSIZE])> {
        // TODO: 把这个调用挪到外面去.
        let send_out = SoftSpokenOTSender::ss_round2(sid, receiver_seed, round1)
            .catch("SoftSpokenOTFailed", "rvole sender")?;

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
        let eta_vals: Vec<Scalar> = (0..NUM_CHECKS).map(|_| Scalar::new_rand()).collect();

        let mut output = RVOLEMsg2::default();
        for j in 0..NUM_CHOICES {
            // "完全版" 修正矩阵功能列定义
            for i in 0..BSIZE {
                let v = alpha_0(j, i).sub(&alpha_1(j, i)).add(&xa_vec[i]);
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
        let theta = theta_table(sid, &output.a_tilde);

        // 完成 `06-rvole.md` 公式 (resp-eta) 的计算.
        for k in 0..NUM_CHECKS {
            let mut s = eta_vals[k].clone();
            for i in 0..BSIZE {
                s = s.add(&theta[k][i].mul(&xa_vec[i]));
            }
            output.eta[k] = s.to_bytes();
        }

        // 走哈希链变体, 不是 "完全版" 里裸标量形式的 $\sigma$.
        let mut sigma =
            <::blake2::Blake2bVar as ::blake2::digest::VariableOutput>::new(64).unwrap();
        use ::blake2::digest::Update;
        sigma.update(b"dsg/rvole/sigma");
        sigma.update(sid.as_bytes());
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
        ::blake2::digest::VariableOutput::finalize_variable(sigma, &mut mu).unwrap();
        output.sigma = mu;

        Ok((output, za))
    }
}


impl RVOLEReceiverPrivacy {
    /// Receiver 验证 Sender 的响应, 计算自己的加法份额 $z_b$.
    pub fn round3_rvole(&self, output: &RVOLEMsg2) -> Resultat<[Scalar; BSIZE]> {
        let theta = theta_table(&self.sid, &output.a_tilde);

        let keys: Vec<Vec<Vec<u8>>> = (0..NUM_CHOICES)
            .map(|j| expand_seed(&self.sid, j, &self.recv_out.keys_chosen[j], OT_WIDTH))
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
            let bit = extract_bit(&self.beta, j);
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

        // "完全版" 中 $\sigma$ 在 Sender 一侧被改造成了哈希形式, verify 等式因此用不上.

        let mut sigma =
            <::blake2::Blake2bVar as ::blake2::digest::VariableOutput>::new(64).unwrap();
        use ::blake2::digest::Update;
        sigma.update(b"dsg/rvole/sigma");
        sigma.update(self.sid.as_bytes());

        for j in 0..NUM_CHOICES {
            let bit = extract_bit(&self.beta, j);
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
        ::blake2::digest::VariableOutput::finalize_variable(sigma, &mut mu_prime).unwrap();

        assert_throw!(
            &mu_prime[..] == &output.sigma[..],
            "RVOLEMuCheckFailed",
            "rvole receiver: mu hash mismatch"
        );

        // d[i] = <g, d_dot[..][i]>: 收尾内积.
        let gadget = generate_gadget_vec(&self.sid);
        let mut d = [Scalar::default(), Scalar::default()];
        for i in 0..BSIZE {
            let mut acc = Scalar::default();
            for j in 0..NUM_CHOICES {
                acc = acc.add(&gadget[j].mul(&d_biz[j][i]));
            }
            d[i] = acc;
        }
        Ok(d)
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    use crate::dsg::softspoken_ot::{LAMBDA_C_BYTES, LAMBDA_C_DIV_SOFT_SPOKEN_K, SOFT_SPOKEN_Q};
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
    fn test_gadget_length() {
        let g = generate_gadget_vec("xx");
        assert_eq!(g.len(), L);
    }

    #[test]
    fn rvole_correctness() {
        let (sender_seed, receiver_seed) = fresh_seed_pair();
        let sid = "rvole-test";

        let (state, round1, b) = rvole_round1(sid, &sender_seed);
        let a = [Scalar::new_rand(), Scalar::new_rand()];
        let (out, c) = RVOLESender::rvole_round2(sid, &receiver_seed, &a, &round1).unwrap();
        let d = state.round3_rvole(&out).unwrap();

        for i in 0..BSIZE {
            let lhs = c[i].add(&d[i]);
            let rhs = a[i].mul(&b);
            assert_eq!(lhs, rhs, "RVOLE additivity failed at i={}", i);
        }
    }
}
