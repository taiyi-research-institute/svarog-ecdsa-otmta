//! Random Vector OLE (DKLS23 §5.2). 见 `notes/06-rvole-derand.md`,
//! `notes/07-gadget.md`, `notes/08-rvole.md`.
//!
//! 对每个 Sender 输入 $a_k$ ($k \in [\ell] = $ `L_BATCH`) 和单个 Receiver 输入 $b$,
//! 产出 加法份额 $c_k, d_k$ 满足 $c_k + d_k = a_k \cdot b \pmod n$.
//! 额外 `RHO = 1` 列用于 Receiver 检查 Sender 诚实性 (mu-check).
//!
//! gadget 替代 $2^j$ (见 `notes/07-gadget.md`):
//!   $b = \langle g, \beta \rangle$, $\xi = L = \kappa + 2\lambda_s = 512$.
//!
//! 走的是 `notes/08-rvole.md` §"改进路线" 的 *哈希链* 变体:
//!   `mu_hash` 用 Blake2b 链式累加 $\xi \cdot \rho$ 个 $v$ 值, 不发送 (verify-vec)
//!   公式中那些大向量, 显著节省带宽.
//!
//! `theta_table` 即 `notes/06-rvole-derand.md` 公式 (zb.tj) 的 $\theta^{(k,\ell')}$
//! 双下标挑战, 这里命名为 chi-绑定后的 `theta`.
//!
//! 镜像 sl-oblivious 的 RVOLE 实现, 仅复用本仓库的 SoftSpoken 层.

use erreur::*;
use serde::{Deserialize, Serialize};

use curve_abstract::TrScalar;
use svarog_secp256k1::Scalar;

use super::super::dkg::{ReceiverOTSeed, SenderOTSeed};
use super::soft_spoken_ot::{
    KAPPA_BYTES, L, L_BATCH, L_BYTES, OT_WIDTH, RHO, ReceiverExtendedOutput, Round1Output,
    SoftSpokenOTReceiver, SoftSpokenOTSender,
};

/// gadget 长度 $\xi = L$ (`notes/07-gadget.md`).
const XI: usize = L;

/// RVOLE 网线消息 (Sender → Receiver).
#[derive(Clone, Serialize, Deserialize)]
pub struct RVOLEOutput {
    /// `notes/06` 公式 (za) 的 $\tilde a_{j,i}$ 表, 形状 [XI][OT_WIDTH][KAPPA_BYTES].
    pub a_tilde: Vec<Vec<Vec<u8>>>,
    /// `notes/06` 公式 (eta) 的最终 $\eta_k$ 揭示值, 长度 RHO.
    pub eta: Vec<Vec<u8>>,
    /// `notes/08` §"改进路线": 链式哈希得到的 $\mu$ 摘要, 64 字节.
    pub mu_hash: Vec<u8>,
}

impl Default for RVOLEOutput {
    fn default() -> Self {
        Self {
            a_tilde: (0..XI)
                .map(|_| (0..OT_WIDTH).map(|_| vec![0u8; KAPPA_BYTES]).collect())
                .collect(),
            eta: (0..RHO).map(|_| vec![0u8; KAPPA_BYTES]).collect(),
            mu_hash: vec![0u8; 64],
        }
    }
}

/// 生成 gadget 向量 $g \in F_n^{\xi}$.
/// 见 `notes/07-gadget.md`: 替代 $\{2^j\}$ 以提供 leftover hash lemma 所需均匀性.
pub fn generate_gadget_vec(sid: &str) -> Vec<Scalar> {
    (0..XI)
        .map(|i| {
            let bytes = hash!(KAPPA_BYTES; b"dsg/rvole/gadget", sid.as_bytes(), &(i as u64).to_le_bytes());
            Scalar::new_from_bytes(&bytes)
        })
        .collect()
}

#[inline]
fn extract_bit(packed: &[u8], idx: usize) -> u8 {
    (packed[idx / 8] >> (idx % 8)) & 1
}

/// 双下标挑战表 $\theta^{(k, \ell')}$ (`notes/06` 公式 (zb.tj),
/// `notes/08` 公式 (sigma)).
///
/// 先用 Blake2b 链式哈希把 `a_tilde` 全表 bind 进种子, 再派生 $\rho \times \ell$ 个
/// 标量, 实现 Fiat-Shamir 防作弊.
fn theta_table(sid: &str, a_tilde: &[Vec<Vec<u8>>]) -> Vec<Vec<Scalar>> {
    let mut acc =
        <::blake2::Blake2bVar as ::blake2::digest::VariableOutput>::new(32).unwrap();
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

    let mut theta = vec![vec![Scalar::new(0); L_BATCH]; RHO];
    for k in 0..RHO {
        for i in 0..L_BATCH {
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

pub struct RVOLEReceiver {
    pub sid: String,
    /// 选择位向量 $\beta \in \{0,1\}^L$, 满足 $b = \langle g, \beta \rangle$.
    pub beta: Vec<u8>,
    pub recv_out: ReceiverExtendedOutput,
}

impl RVOLEReceiver {
    /// Receiver 第 1 步: 抽 $\beta$, 算 $b = \langle g, \beta \rangle$,
    /// 走 SoftSpoken OT 的 Receiver 角色得到 `Round1Output` 发给 Sender.
    pub fn new(
        sid: &str,
        sender_seed: &SenderOTSeed,
    ) -> (RVOLEReceiver, Round1Output, Scalar) {
        use rand::Rng;
        let mut beta = vec![0u8; L_BYTES];
        rand::rng().fill_bytes(&mut beta);

        // b = <g, β> (`notes/07-gadget.md`).
        let gadget = generate_gadget_vec(sid);
        let mut b = Scalar::new(0);
        for (i, gv) in gadget.iter().enumerate() {
            if extract_bit(&beta, i) == 1 {
                b = b.add(gv);
            }
        }

        let (round1, recv_out) = SoftSpokenOTReceiver::process(sid, sender_seed, &beta);
        let state = RVOLEReceiver { sid: sid.to_string(), beta, recv_out };
        (state, round1, b)
    }

    /// Receiver 第 2 步: 收到 `RVOLEOutput`, 复算 $\mu'$ 与 Sender 提供的 mu_hash 比对,
    /// 通过则输出 $d_i = \langle g, \dot d_{*,i} \rangle$, 满足 $c_i + d_i = a_i b$.
    ///
    /// 公式: `notes/06` (zb.tj) 内积一致性 + (verify) 检查;
    /// 哈希链版本见 `notes/08` §改进路线.
    pub fn process(&self, output: &RVOLEOutput) -> Resultat<[Scalar; L_BATCH]> {
        let theta = theta_table(&self.sid, &output.a_tilde);

        // d_dot[j][i]: i ∈ [L_BATCH] 主载荷; d_hat[j][k]: k ∈ [RHO] 一致性列.
        let mut d_dot: Vec<Vec<Scalar>> =
            (0..XI).map(|_| (0..L_BATCH).map(|_| Scalar::new(0)).collect()).collect();
        let mut d_hat: Vec<Vec<Scalar>> =
            (0..XI).map(|_| (0..RHO).map(|_| Scalar::new(0)).collect()).collect();

        for j in 0..XI {
            let bit = extract_bit(&self.beta, j);
            for i in 0..L_BATCH {
                let opt0 = Scalar::new_from_bytes(&self.recv_out.v_x[j][i]);
                let opt1 = opt0.add(&Scalar::new_from_bytes(&output.a_tilde[j][i]));
                d_dot[j][i] = if bit == 1 { opt1 } else { opt0 };
            }
            for k in 0..RHO {
                let opt0 = Scalar::new_from_bytes(&self.recv_out.v_x[j][L_BATCH + k]);
                let opt1 = opt0.add(&Scalar::new_from_bytes(&output.a_tilde[j][L_BATCH + k]));
                d_hat[j][k] = if bit == 1 { opt1 } else { opt0 };
            }
        }

        // mu_prime: 哈希链式累加, 对应 `notes/08` §改进路线.
        let mut mu_acc =
            <::blake2::Blake2bVar as ::blake2::digest::VariableOutput>::new(64).unwrap();
        use ::blake2::digest::Update;
        mu_acc.update(b"dsg/rvole/mu");
        mu_acc.update(self.sid.as_bytes());

        for j in 0..XI {
            let bit = extract_bit(&self.beta, j);
            for k in 0..RHO {
                let mut v = d_hat[j][k].clone();
                for i in 0..L_BATCH {
                    v = v.add(&theta[k][i].mul(&d_dot[j][i]));
                }
                // bit=1 时减去 Sender 揭示的 η_k, 抹去随机化.
                let chosen = if bit == 1 {
                    v.sub(&Scalar::new_from_bytes(&output.eta[k]))
                } else {
                    v
                };
                mu_acc.update(&chosen.to_bytes());
            }
        }

        let mut mu_prime = [0u8; 64];
        ::blake2::digest::VariableOutput::finalize_variable(mu_acc, &mut mu_prime).unwrap();

        assert_throw!(
            &mu_prime[..] == &output.mu_hash[..],
            "RVOLEMuCheckFailed",
            "rvole receiver: mu hash mismatch"
        );

        // d[i] = <g, d_dot[..][i]>: 收尾内积.
        let gadget = generate_gadget_vec(&self.sid);
        let mut d = [Scalar::new(0), Scalar::new(0)];
        for i in 0..L_BATCH {
            let mut acc = Scalar::new(0);
            for j in 0..XI {
                acc = acc.add(&gadget[j].mul(&d_dot[j][i]));
            }
            d[i] = acc;
        }
        Ok(d)
    }
}

// ── Sender ───────────────────────────────────────────────────────────────

pub struct RVOLESender;

impl RVOLESender {
    /// Sender 一次性: 调 SoftSpoken OT (Sender 角色) 拿到 $(\alpha_0, \alpha_1)$,
    /// 算出 $\tilde a$、随机化 $\eta$、`mu_hash`, 输出本地 $c_i$.
    ///
    /// 公式映射:
    /// * $c_i = -\sum_j g_j \cdot \alpha_0(j, i)$ — `notes/06` 公式 (za).
    /// * $\tilde a_{j,i} = \alpha_0 - \alpha_1 + a_i$ — (za) 派生.
    /// * `eta_k` 上线值 $= \eta_k + \sum_i \theta^{(k,i)} a_i$ — (eta).
    /// * `mu_hash` 链式 $\sum_j \alpha_0(j, L+k) + \sum_i \theta^{(k,i)} \alpha_0(j,i)$
    ///   — `notes/08` §改进路线 (verify-vec → 哈希链).
    pub fn process(
        sid: &str,
        receiver_seed: &ReceiverOTSeed,
        a: &[Scalar; L_BATCH],
        round1: &Round1Output,
    ) -> Resultat<(RVOLEOutput, [Scalar; L_BATCH])> {
        let send_out = SoftSpokenOTSender::process(sid, receiver_seed, round1)
            .catch("SoftSpokenOTFailed", "rvole sender")?;

        let alpha_0 = |j: usize, i: usize| Scalar::new_from_bytes(&send_out.v_0[j][i]);
        let alpha_1 = |j: usize, i: usize| Scalar::new_from_bytes(&send_out.v_1[j][i]);

        let gadget = generate_gadget_vec(sid);

        // c[i] = -Σ_j g_j · α_0(j, i)  (公式 (za)).
        let mut c: [Scalar; L_BATCH] = [Scalar::new(0), Scalar::new(0)];
        for i in 0..L_BATCH {
            let mut acc = Scalar::new(0);
            for j in 0..XI {
                acc = acc.add(&gadget[j].mul(&alpha_0(j, i)));
            }
            c[i] = acc.neg();
        }

        // 抽样 η_k, 用于 derand 的 mu-check 一致性列.
        let eta_vals: Vec<Scalar> = (0..RHO).map(|_| Scalar::new_rand()).collect();

        // ã[j][i]:
        //   i < L_BATCH:        α_0(j, i)            - α_1(j, i) + a[i]
        //   i = L_BATCH + k:    α_0(j, L_BATCH + k)  - α_1(j, L_BATCH + k) + η_k
        let mut output = RVOLEOutput::default();
        for j in 0..XI {
            for i in 0..L_BATCH {
                let v = alpha_0(j, i).sub(&alpha_1(j, i)).add(&a[i]);
                output.a_tilde[j][i] = v.to_bytes();
            }
            for k in 0..RHO {
                let v = alpha_0(j, L_BATCH + k)
                    .sub(&alpha_1(j, L_BATCH + k))
                    .add(&eta_vals[k]);
                output.a_tilde[j][L_BATCH + k] = v.to_bytes();
            }
        }

        // a_tilde 固定后再生成 θ (Fiat-Shamir).
        let theta = theta_table(sid, &output.a_tilde);

        // 网线 η: η_k + Σ_i θ_{k,i} · a_i  (公式 (eta)).
        for k in 0..RHO {
            let mut s = eta_vals[k].clone();
            for i in 0..L_BATCH {
                s = s.add(&theta[k][i].mul(&a[i]));
            }
            output.eta[k] = s.to_bytes();
        }

        // mu_hash: 与 Receiver 走完全一致的链式哈希.
        let mut mu_acc =
            <::blake2::Blake2bVar as ::blake2::digest::VariableOutput>::new(64).unwrap();
        use ::blake2::digest::Update;
        mu_acc.update(b"dsg/rvole/mu");
        mu_acc.update(sid.as_bytes());
        for j in 0..XI {
            for k in 0..RHO {
                let mut v = alpha_0(j, L_BATCH + k);
                for i in 0..L_BATCH {
                    v = v.add(&theta[k][i].mul(&alpha_0(j, i)));
                }
                mu_acc.update(&v.to_bytes());
            }
        }
        let mut mu = vec![0u8; 64];
        ::blake2::digest::VariableOutput::finalize_variable(mu_acc, &mut mu).unwrap();
        output.mu_hash = mu;

        Ok((output, c))
    }
}

// ── tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dsg::soft_spoken_ot::{LAMBDA_C_BYTES, LAMBDA_C_DIV_SOFT_SPOKEN_K, SOFT_SPOKEN_Q};
    use rand::Rng;

    fn fresh_seed_pair() -> (SenderOTSeed, ReceiverOTSeed) {
        let mut sender = SenderOTSeed::default();
        let mut receiver = ReceiverOTSeed::default();
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

        let (state, round1, b) = RVOLEReceiver::new(sid, &sender_seed);
        let a = [Scalar::new_rand(), Scalar::new_rand()];
        let (out, c) = RVOLESender::process(sid, &receiver_seed, &a, &round1).unwrap();
        let d = state.process(&out).unwrap();

        for i in 0..L_BATCH {
            let lhs = c[i].add(&d[i]);
            let rhs = a[i].mul(&b);
            assert_eq!(lhs, rhs, "RVOLE additivity failed at i={}", i);
        }
    }
}
