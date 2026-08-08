//! SoftSpoken OT 密钥协商, 有两轮:
//! (1) Recevier 发送 $u$ 向量和 Fiat-Shamir 证明;
//!

use erreur::*;
use serde::{Deserialize, Serialize};

use super::super::dkg::{PPRFReceiverOTSeed, PPRFSenderOTSeed};
use super::gf2pow128::mult_gf2pow128;
use crate::rng::fill_random;

/// SoftSpoken Receiver
/// 计算和发送 u 向量以及相应的 Fiat-Shamir 证明,
/// 保存 OT 密钥供外层协议使用.
pub fn ss_receiver(
    sid: &str,
    sender_seed: &PPRFSenderOTSeed,
    choices: &[u8],
) -> (SoftSpokenMsg1, SSReceiverKeys) {
    debug_assert_eq!(choices.len(), L_BYTES);

    // 把真实选项 $\beta$ 和随机选项 $\beta^\mathrm{ext}$ 拼接成 $\hat{\beta}$.
    // 这就是 公式 (umat) 的第一项.
    let betahat: Vec<u8> = {
        let mut buf = vec![0u8; L_PRIME_BYTES];
        buf[..L_BYTES].copy_from_slice(choices);

        fill_random(&mut buf[L_BYTES..]);
        buf
    };

    let mut output = SoftSpokenMsg1::default();
    let mut extended_output = SSReceiverKeys::new(choices.to_vec());

    let mut r_x: Vec<Vec<Vec<u8>>> = (0..SOFT_SPOKEN_Q)
        .map(|_| {
            (0..LAMBDA_C_DIV_SOFT_SPOKEN_K)
                .map(|_| vec![0u8; L_PRIME_BYTES])
                .collect()
        })
        .collect();

    for i in 0..LAMBDA_C_DIV_SOFT_SPOKEN_K {
        for j in 0..SOFT_SPOKEN_Q {
            // 公式 (umat) 上方文字.
            r_x[j][i] = prg_expand(sid, &sender_seed.otp_enc_keys[i][j]);
        }
        let u_i = &mut output.u[i];
        for byte in 0..L_PRIME_BYTES {
            // 公式 (umat) 第一项.
            let mut acc = betahat[byte];
            for j in 0..SOFT_SPOKEN_Q {
                // 公式 (umat) 第二项.
                acc ^= r_x[j][i][byte];
            }
            u_i[byte] = acc;
        }
    }

    // 公式 (vmat).
    let mut v: Vec<Vec<u8>> = (0..LAMBDA_C).map(|_| vec![0u8; L_PRIME_BYTES]).collect();
    for i in 0..LAMBDA_C_DIV_SOFT_SPOKEN_K {
        for bit_index in 0..SOFT_SPOKEN_K {
            for j in 0..SOFT_SPOKEN_Q {
                let bit = ((j >> bit_index) & 0x01) as u8;
                let mask = bit_to_mask(bit);
                let row = &mut v[i * SOFT_SPOKEN_K + bit_index];
                for k in 0..L_PRIME_BYTES {
                    row[k] ^= mask & r_x[j][i][k];
                }
            }
        }
    }

    let digest = matrix_digest(sid, &output.u);
    let chi: Vec<[u8; 16]> = (0..SOFT_SPOKEN_M).map(|j| derive_chi(&digest, j)).collect();

    for j in 0..SOFT_SPOKEN_M {
        // 公式 (beta-tilde) 第一项.
        let mut betahat_jchunk = [0u8; S_BYTES];
        betahat_jchunk.copy_from_slice(&betahat[j * S_BYTES..(j + 1) * S_BYTES]);
        let prod = mult_gf2pow128(&betahat_jchunk, &chi[j]);
        for k in 0..S_BYTES {
            output.beta_tilde[k] ^= prod[k];
        }

        for i in 0..LAMBDA_C {
            // 公式 (tmat) 第一项.
            let mut t_hat_j = [0u8; S_BYTES];
            t_hat_j.copy_from_slice(&v[i][j * S_BYTES..(j + 1) * S_BYTES]);
            let prod = mult_gf2pow128(&t_hat_j, &chi[j]);
            for k in 0..S_BYTES {
                output.t[i][k] ^= prod[k];
            }
        }
    }

    const FROM: usize = SOFT_SPOKEN_M * S_BYTES;

    // 公式 (beta-tilde) 第二项.
    for k in 0..S_BYTES {
        output.beta_tilde[k] ^= betahat[FROM + k];
    }
    // 公式 (tmat) 第二项.
    for i in 0..LAMBDA_C {
        for k in 0..S_BYTES {
            output.t[i][k] ^= v[i][FROM + k];
        }
    }

    let psi = transpose_bool_matrix(&v);
    for j in 0..L {
        extended_output.keys_chosen[j] = hash_row(sid, j, &psi[j]);
    }

    (output, extended_output)
}

/// Sender 对 $u$ 向量进行 Fiat-Shamir 验证,
/// 保存 Sender OT 密钥供外层协议使用.
pub fn ss_sender(
    sid: &str,
    receiver_seed: &PPRFReceiverOTSeed,
    msg1: &SoftSpokenMsg1,
) -> Resultat<SSSenderKeys> {
    // 公式 (wmat) 中的 $r_{i,x}$, 即 PPRF/GGM 树的叶子节点的哈希.
    let mut leaves: Vec<Vec<Vec<u8>>> = (0..SOFT_SPOKEN_Q)
        .map(|_| {
            (0..LAMBDA_C_DIV_SOFT_SPOKEN_K)
                .map(|_| vec![0u8; L_PRIME_BYTES])
                .collect()
        })
        .collect();
    for i in 0..LAMBDA_C_DIV_SOFT_SPOKEN_K {
        let chosen = receiver_seed.random_choices[i] as usize;
        for j in 0..SOFT_SPOKEN_Q {
            if j == chosen {
                // 打孔叶子的哈希设为 0.
            } else {
                leaves[j][i] = prg_expand(sid, &receiver_seed.otp_dec_keys[i][j]);
            }
        }
    }

    let mut w_matrix: Vec<Vec<u8>> = (0..LAMBDA_C).map(|_| vec![0u8; L_PRIME_BYTES]).collect();
    for i in 0..LAMBDA_C_DIV_SOFT_SPOKEN_K {
        let delta = receiver_seed.random_choices[i];
        for bit_index in 0..SOFT_SPOKEN_K {
            for j in 0..SOFT_SPOKEN_Q {
                let delta_minus_x = delta ^ (j as u8);
                let bit = (delta_minus_x >> bit_index) & 0x01;
                let mask = bit_to_mask(bit);
                let row_idx = i * SOFT_SPOKEN_K + bit_index;
                for k in 0..L_PRIME_BYTES {
                    // 公式 (wmat) 花括号部分.
                    w_matrix[row_idx][k] ^= mask & leaves[j][i][k];
                }
            }

            let delta_i = (delta >> bit_index) & 0x01;
            let delta_mask = bit_to_mask(delta_i);
            let row_idx = i * SOFT_SPOKEN_K + bit_index;
            for k in 0..L_PRIME_BYTES {
                // 公式 (wmat) 花括号以外的部分.
                w_matrix[row_idx][k] ^= delta_mask & msg1.u[i][k];
            }
        }
    }

    // 把所有打孔点的下标拼接成比特串 $\Delta$.
    let mut Delta = vec![0u8; LAMBDA_C_BYTES];
    for i in 0..LAMBDA_C_DIV_SOFT_SPOKEN_K {
        let delta = receiver_seed.random_choices[i];
        for bit_index in 0..SOFT_SPOKEN_K {
            let delta_i = (delta >> bit_index) & 0x01;
            let global_bit = i * SOFT_SPOKEN_K + bit_index;
            Delta[global_bit / 8] ^= delta_i << (global_bit % 8);
        }
    }

    let digest = matrix_digest(sid, &msg1.u);
    let chi: Vec<[u8; 16]> = (0..SOFT_SPOKEN_M).map(|j| derive_chi(&digest, j)).collect();

    const FROM: usize = SOFT_SPOKEN_M * S_BYTES;
    const TO: usize = (SOFT_SPOKEN_M + 1) * S_BYTES;

    for i in 0..LAMBDA_C {
        let mut q_row = [0u8; S_BYTES];

        for j in 0..SOFT_SPOKEN_M {
            let mut q_hat_j = [0u8; S_BYTES];
            q_hat_j.copy_from_slice(&w_matrix[i][j * S_BYTES..(j + 1) * S_BYTES]);
            // 公式 (verify) 等号左边花括号部分.
            let prod = mult_gf2pow128(&q_hat_j, &chi[j]);
            for k in 0..S_BYTES {
                q_row[k] ^= prod[k];
            }
        }

        for (k, idx) in (FROM..TO).enumerate() {
            // 公式 (verify) 等号左边花括号以外的部分.
            q_row[k] ^= w_matrix[i][idx];
        }

        let bit = extract_bit(&Delta, i);
        let mask = bit_to_mask(bit);
        let mut expected = [0u8; S_BYTES];
        for k in 0..S_BYTES {
            // 公式 (verify) 等号右边.
            expected[k] = msg1.t[i][k] ^ (mask & msg1.beta_tilde[k]);
        }
        assert_throw!(
            q_row == expected,
            "AbortProtocolAndBanReceiver",
            format!("dsg/softspoken: KOS check failed at row {}", i)
        );
    }

    let mut zeta = transpose_bool_matrix(&w_matrix);
    let mut output = SSSenderKeys::default();
    for j in 0..L {
        // Sender 计算 0 侧密钥
        output.keys0[j] = hash_row(sid, j, &zeta[j]);
        for k in 0..LAMBDA_C_BYTES {
            zeta[j][k] ^= Delta[k];
        }
        // Sender 计算 1 侧密钥
        output.keys1[j] = hash_row(sid, j, &zeta[j]);
    }

    Ok(output)
}

/// 把 SoftSpoken 输出的 random OT 种子 $\rho_j$ 进一步派生成 `width` 条
/// 并行的 `KAPPA_BYTES` 字节伪随机串. 调用方 (例如 `rvole`) 决定 `width`.
///
/// 域分隔标签 `b"dsg/softspoken/expand"` 与 `randomize_row` 的标签不同,
/// 防止两层意外撞用同一种子.
pub fn expand_seed(sid: &str, j: usize, seed: &[u8], width: usize) -> Vec<Vec<u8>> {
    let need = width * KAPPA_BYTES;
    let mut bytes = Vec::with_capacity(need);
    let mut ctr: u32 = 0;
    while bytes.len() < need {
        let take = std::cmp::min(64, need - bytes.len());
        let block = hash!(
            take;
            b"dsg/softspoken/expand",
            sid.as_bytes(),
            &(j as u64).to_le_bytes(),
            seed,
            &ctr.to_le_bytes()
        );
        bytes.extend_from_slice(&block);
        ctr += 1;
    }
    (0..width)
        .map(|k| bytes[k * KAPPA_BYTES..(k + 1) * KAPPA_BYTES].to_vec())
        .collect()
}

// ── 协议消息和密钥类型 ──────────────────────────────────────────────────

#[derive(Clone, Serialize, Deserialize)]
pub struct SoftSpokenMsg1 {
    /// 公式 (umat)
    pub u: Vec<Vec<u8>>,
    /// 公式 (beta-tilde)
    pub beta_tilde: Vec<u8>,
    /// 公式 (tmat)
    pub t: Vec<Vec<u8>>,
}

impl Default for SoftSpokenMsg1 {
    fn default() -> Self {
        Self {
            u: (0..LAMBDA_C_DIV_SOFT_SPOKEN_K)
                .map(|_| vec![0u8; L_PRIME_BYTES])
                .collect(),
            beta_tilde: vec![0u8; S_BYTES],
            t: (0..LAMBDA_C).map(|_| vec![0u8; S_BYTES]).collect(),
        }
    }
}

/// $\rho^\beta$.
#[derive(Clone)]
pub struct SSReceiverKeys {
    pub keys_chosen: Vec<Vec<u8>>, // [L][KAPPA_BYTES]
}

impl SSReceiverKeys {
    pub fn new(choices: Vec<u8>) -> Self {
        debug_assert_eq!(choices.len(), L_BYTES);
        Self {
            keys_chosen: (0..L).map(|_| vec![0u8; KAPPA_BYTES]).collect(),
        }
    }
}

/// $\rho^0, \rho^1$.
#[derive(Clone)]
pub struct SSSenderKeys {
    pub keys0: Vec<Vec<u8>>,
    pub keys1: Vec<Vec<u8>>,
}

impl Default for SSSenderKeys {
    fn default() -> Self {
        let blank = || (0..L).map(|_| vec![0u8; KAPPA_BYTES]).collect();
        Self {
            keys0: blank(),
            keys1: blank(),
        }
    }
}

// ── 协议常量 ────────────────────────────────────────────────────────────

pub const KAPPA: usize = 256;
pub const KAPPA_BYTES: usize = 32;
pub const LAMBDA_C: usize = 256;
pub const LAMBDA_C_BYTES: usize = 32;
pub const LAMBDA_S: usize = 128;
pub const S: usize = 128;
pub const S_BYTES: usize = 16;
pub const BSIZE: usize = 2;
pub const SOFT_SPOKEN_K: usize = 4;
pub const L: usize = KAPPA + 2 * LAMBDA_S; // 512
pub const L_BYTES: usize = L >> 3; // 64
pub const L_PRIME: usize = L + S; // 640
pub const L_PRIME_BYTES: usize = L_PRIME >> 3; // 80
pub const SOFT_SPOKEN_M: usize = L / S; // 4
pub const SOFT_SPOKEN_Q: usize = 1 << SOFT_SPOKEN_K; // 16
pub const LAMBDA_C_DIV_SOFT_SPOKEN_K: usize = LAMBDA_C / SOFT_SPOKEN_K; // 64

// ── 内部辅助 ────────────────────────────────────────────────────────────

#[inline]
fn extract_bit(packed: &[u8], idx: usize) -> u8 {
    (packed[idx / 8] >> (idx % 8)) & 1
}

#[inline]
fn bit_to_mask(bit: u8) -> u8 {
    -((bit & 1) as i8) as u8
}

/// PRG: 32-byte seed -> `n` bytes (chained Blake2b ≤64-byte blocks with counter).
fn prg_bytes(domain: &[u8], sid: &str, seed: &[u8], n: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(n);
    let mut ctr: u32 = 0;
    while out.len() < n {
        let take = std::cmp::min(64, n - out.len());
        let block = hash!(take; domain, sid.as_bytes(), seed, &ctr.to_le_bytes());
        out.extend_from_slice(&block);
        ctr += 1;
    }
    out
}

/// PRG: 32-byte seed -> `L_PRIME_BYTES` bytes.
fn prg_expand(sid: &str, seed: &[u8]) -> Vec<u8> {
    prg_bytes(b"dsg/softspoken/prg", sid, seed, L_PRIME_BYTES)
}

/// Domain-separated KOS challenge seed.
fn matrix_digest(sid: &str, u: &[Vec<u8>]) -> [u8; 32] {
    let mut h = <::blake2::Blake2bVar as ::blake2::digest::VariableOutput>::new(32).unwrap();
    use ::blake2::digest::Update;
    h.update(b"dsg/softspoken/matrix_hash");
    h.update(sid.as_bytes());
    for row in u {
        h.update(row);
    }
    let mut out = [0u8; 32];
    ::blake2::digest::VariableOutput::finalize_variable(h, &mut out).unwrap();
    out
}

/// `chi_j` = 16-byte field element derived from `(j, digest)`.
fn derive_chi(digest: &[u8; 32], j: usize) -> [u8; 16] {
    let bytes = hash!(S_BYTES; b"dsg/softspoken/chi", &(j as u64).to_le_bytes(), digest);
    let mut out = [0u8; 16];
    out.copy_from_slice(&bytes);
    out
}

fn hash_row(sid: &str, j: usize, row: &[u8]) -> Vec<u8> {
    hash!(KAPPA_BYTES;
        b"dsg/softspoken/randomize",
        sid.as_bytes(),
        &(j as u64).to_le_bytes(),
        row
    )
}

pub fn transpose_bool_matrix(input: &[Vec<u8>]) -> Vec<Vec<u8>> {
    debug_assert_eq!(input.len(), LAMBDA_C);
    let mut output: Vec<Vec<u8>> = (0..L_PRIME).map(|_| vec![0u8; LAMBDA_C_BYTES]).collect();
    for row_byte in 0..LAMBDA_C_BYTES {
        for row_bit_in_byte in 0..8 {
            for column_byte in 0..L_PRIME_BYTES {
                for column_bit_in_byte in 0..8 {
                    let row_bit_index = (row_byte << 3) + row_bit_in_byte;
                    let column_bit_index = (column_byte << 3) + column_bit_in_byte;
                    let bit = (input[row_bit_index][column_byte] >> column_bit_in_byte) & 0x01;
                    output[column_bit_index][row_byte] |= bit << row_bit_in_byte;
                }
            }
        }
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::Rng;

    /// mock 一个合法的 Sender/Receiver OT 种子对. 仅用于测试正确性, 不保证安全性.
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
            // Erase the chosen leaf from the receiver side.
            receiver.otp_dec_keys[i][chosen] = vec![0u8; LAMBDA_C_BYTES];
        }
        (sender, receiver)
    }

    #[test]
    fn soft_spoken_correctness() {
        let (sender_seed, receiver_seed) = fresh_seed_pair();
        let sid = "test-softspoken";
        let mut choices = vec![0u8; L_BYTES];
        rand::rng().fill_bytes(&mut choices);

        let (round1, recv_out) = ss_receiver(sid, &sender_seed, &choices);
        let send_out = ss_sender(sid, &receiver_seed, &round1).unwrap();

        for i in 0..L {
            let bit = extract_bit(&choices, i);
            let recv = &recv_out.keys_chosen[i];
            let send = if bit == 1 {
                &send_out.keys1[i]
            } else {
                &send_out.keys0[i]
            };
            assert_eq!(recv, send, "row {} bit={}", i, bit);
        }
    }
}
