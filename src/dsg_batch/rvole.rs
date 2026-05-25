//! 批量 RVOLE: 与 `crate::dsg::rvole` 同一协议, 但 bsize 在运行期可变
//! ($2N$, $N$ 为本次批量签名笔数), 不再写死为 `BSIZE = 2`.
//!
//! Sender 输入 $a_k$ ($k \in [\mathrm{bsize}]$), Receiver 输入单个 $b$,
//! 输出加法份额 $c_k + d_k = a_k \cdot b \pmod n$.
//! 一致性检查列数仍为 `NUM_CHECKS = 1` (mu-check, 哈希链变体).
//!
//! gadget 长度 $\xi = L = 512$, 与单笔版一致 (`notes/misc-gadget.md`).

use erreur::*;
use serde::{Deserialize, Serialize};

use curve_abstract::TrScalar;
use svarog_secp256k1::Scalar;

use crate::dsg::softspoken_ot::{KAPPA_BYTES, L, L_BYTES, SSReceiverKeys, SSSenderKeys, expand_seed};

/// Receiver 端 round1: 摇随机 $\beta$ 并算 $b = \langle g, \beta \rangle$.
/// 与 bsize 无关 (gadget 内积只吃 $\beta$).
pub(crate) fn rvole_round1_batch(sid: &str) -> (Vec<u8>, Scalar) {
    use rand::Rng;
    let mut beta = vec![0u8; L_BYTES];
    rand::rng().fill_bytes(&mut beta);

    let gadget = generate_gadget_vec(sid);
    let mut b = Scalar::default();
    for (i, gv) in gadget.iter().enumerate() {
        if extract_bit(&beta, i) == 1 {
            b = b.add(gv);
        }
    }
    (beta, b)
}

/// Sender 端 round2: 输入 bsize 个 $a_k$, 输出加法份额 $z_a$ + 网线消息.
pub(crate) fn rvole_round2_batch(
    sid: &str,
    send_out: &SSSenderKeys,
    xa_vec: &[Scalar],
) -> (RVOLEBatchMsg2, Vec<Scalar>) {
    use ::blake2::Blake2bVar;
    use ::blake2::digest::{Update, VariableOutput};

    let bsize = xa_vec.len();
    let ot_width = bsize + NUM_CHECKS;

    let alpha_0: Vec<Vec<Vec<u8>>> = (0..NUM_CHOICES)
        .map(|j| expand_seed(sid, j, &send_out.keys0[j], ot_width))
        .collect();
    let alpha_0 = |j: usize, i: usize| Scalar::new_from_bytes(&alpha_0[j][i]);
    let alpha_1: Vec<Vec<Vec<u8>>> = (0..NUM_CHOICES)
        .map(|j| expand_seed(sid, j, &send_out.keys1[j], ot_width))
        .collect();
    let alpha_1 = |j: usize, i: usize| Scalar::new_from_bytes(&alpha_1[j][i]);

    let gadget = generate_gadget_vec(sid);
    let mut za = vec![Scalar::default(); bsize];
    for i in 0..bsize {
        let mut acc = Scalar::default();
        for j in 0..NUM_CHOICES {
            acc = acc.add(&gadget[j].mul(&alpha_0(j, i)));
        }
        za[i] = acc.neg();
    }

    let eta_vals: Vec<Scalar> = (0..NUM_CHECKS).map(|_| Scalar::new_rand()).collect();

    let mut output = empty_msg2(bsize);
    for j in 0..NUM_CHOICES {
        for i in 0..bsize {
            let v = alpha_0(j, i).sub(&alpha_1(j, i)).add(&xa_vec[i]);
            output.a_tilde[j][i] = v.to_bytes();
        }
        for k in 0..NUM_CHECKS {
            let v = alpha_0(j, bsize + k)
                .sub(&alpha_1(j, bsize + k))
                .add(&eta_vals[k]);
            output.a_tilde[j][bsize + k] = v.to_bytes();
        }
    }

    let theta = theta_table(sid, bsize, &output.a_tilde);

    for k in 0..NUM_CHECKS {
        let mut s = eta_vals[k].clone();
        for i in 0..bsize {
            s = s.add(&theta[k][i].mul(&xa_vec[i]));
        }
        output.eta[k] = s.to_bytes();
    }

    let mut sigma = Blake2bVar::new(64).unwrap();
    sigma.update(b"dsg/rvole/sigma");
    sigma.update(sid.as_bytes());
    for j in 0..NUM_CHOICES {
        for k in 0..NUM_CHECKS {
            let mut v = alpha_0(j, bsize + k);
            for i in 0..bsize {
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

/// Receiver 端 round3: 验证 mu, 收尾内积出 $z_b$.
pub(crate) fn rvole_round3_batch(
    sid: &str,
    bsize: usize,
    beta: &[u8],
    recv_out: &SSReceiverKeys,
    msg2: &RVOLEBatchMsg2,
) -> Resultat<Vec<Scalar>> {
    use ::blake2::Blake2bVar;
    use ::blake2::digest::{Update, VariableOutput};

    let ot_width = bsize + NUM_CHECKS;
    let theta = theta_table(sid, bsize, &msg2.a_tilde);

    let keys: Vec<Vec<Vec<u8>>> = (0..NUM_CHOICES)
        .map(|j| expand_seed(sid, j, &recv_out.keys_chosen[j], ot_width))
        .collect();

    let mut d_biz: Vec<Vec<Scalar>> = (0..NUM_CHOICES)
        .map(|_| (0..bsize).map(|_| Scalar::default()).collect())
        .collect();
    let mut d_hat: Vec<Vec<Scalar>> = (0..NUM_CHOICES)
        .map(|_| (0..NUM_CHECKS).map(|_| Scalar::default()).collect())
        .collect();

    for j in 0..NUM_CHOICES {
        let bit = extract_bit(beta, j);
        for i in 0..bsize {
            let opt0 = Scalar::new_from_bytes(&keys[j][i]);
            let opt1 = opt0.add(&Scalar::new_from_bytes(&msg2.a_tilde[j][i]));
            d_biz[j][i] = if bit == 1 { opt1 } else { opt0 };
        }
        for k in 0..NUM_CHECKS {
            let opt0 = Scalar::new_from_bytes(&keys[j][bsize + k]);
            let opt1 = opt0.add(&Scalar::new_from_bytes(&msg2.a_tilde[j][bsize + k]));
            d_hat[j][k] = if bit == 1 { opt1 } else { opt0 };
        }
    }

    let mut sigma = Blake2bVar::new(64).unwrap();
    sigma.update(b"dsg/rvole/sigma");
    sigma.update(sid.as_bytes());
    for j in 0..NUM_CHOICES {
        let bit = extract_bit(beta, j);
        for k in 0..NUM_CHECKS {
            let mut v = d_hat[j][k].clone();
            for i in 0..bsize {
                v = v.add(&theta[k][i].mul(&d_biz[j][i]));
            }
            if bit == 1 {
                v = v.sub(&Scalar::new_from_bytes(&msg2.eta[k]));
            }
            sigma.update(&v.to_bytes());
        }
    }
    let mut mu_prime = [0u8; 64];
    sigma.finalize_variable(&mut mu_prime).unwrap();
    assert_throw!(
        &mu_prime[..] == &msg2.sigma[..],
        "RVOLEMuCheckFailed",
        "rvole receiver: mu hash mismatch"
    );

    let gadget = generate_gadget_vec(sid);
    let mut d = vec![Scalar::default(); bsize];
    for i in 0..bsize {
        let mut acc = Scalar::default();
        for j in 0..NUM_CHOICES {
            acc = acc.add(&gadget[j].mul(&d_biz[j][i]));
        }
        d[i] = acc;
    }
    Ok(d)
}

// ── 网线消息 + 内部辅助 ──────────────────────────────────────────────────

/// 批量 RVOLE 网线消息 (Sender -> Receiver).
/// 形状: $\tilde a \in \mathbb{B}^{\xi \times (\mathrm{bsize}+\rho) \times \kappa/8}$.
#[derive(Clone, Default, Serialize, Deserialize)]
pub(crate) struct RVOLEBatchMsg2 {
    pub a_tilde: Vec<Vec<Vec<u8>>>,
    pub eta: Vec<Vec<u8>>,
    pub sigma: Vec<u8>,
}

pub(crate) fn empty_msg2(bsize: usize) -> RVOLEBatchMsg2 {
    RVOLEBatchMsg2 {
        a_tilde: (0..NUM_CHOICES)
            .map(|_| (0..bsize + NUM_CHECKS).map(|_| vec![0u8; KAPPA_BYTES]).collect())
            .collect(),
        eta: (0..NUM_CHECKS).map(|_| vec![0u8; KAPPA_BYTES]).collect(),
        sigma: vec![0u8; 64],
    }
}

/// gadget 向量, 与 `dsg::rvole::generate_gadget_vec` 同一域分离串
/// (两版 RVOLE 必须看到相同 gadget).
fn generate_gadget_vec(sid: &str) -> Vec<Scalar> {
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

/// Fiat-Shamir 派生 $\theta^{(k, \ell')}$, 行 = NUM_CHECKS, 列 = bsize.
fn theta_table(sid: &str, bsize: usize, a_tilde: &[Vec<Vec<u8>>]) -> Vec<Vec<Scalar>> {
    use ::blake2::Blake2bVar;
    use ::blake2::digest::{Update, VariableOutput};

    let mut acc = Blake2bVar::new(32).unwrap();
    acc.update(b"dsg/rvole/theta-bind");
    acc.update(sid.as_bytes());
    for row in a_tilde {
        for cell in row {
            acc.update(cell);
        }
    }
    let mut bind = [0u8; 32];
    acc.finalize_variable(&mut bind).unwrap();

    let mut theta = vec![vec![Scalar::default(); bsize]; NUM_CHECKS];
    for k in 0..NUM_CHECKS {
        for i in 0..bsize {
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

const NUM_CHOICES: usize = L;
const NUM_CHECKS: usize = 1;
