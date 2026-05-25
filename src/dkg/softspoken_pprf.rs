//! "多缺一" PPRF (SoftSpoken 扩展的种子层), 见 `04-pprf.md`.
//!
//! 输入: `KAPPA = 256` 对 base OT 密钥 ($\rho_0, \rho_1$).
//! 输出: `NUM_TREES = 64` 棵小 GGM 树, 每棵 $Q = 16$ 个叶子.
//! Sender 拿到全部 $64 \times 16$ 个叶子;
//! Receiver 拿到每棵树除一个被打孔叶子 (punctured) 之外的全部叶子.
//!
//! 论文出处: Roy 2022 "SoftSpokenOT", <https://eprint.iacr.org/2022/192.pdf>.

use blake2::Blake2bVar;
use blake2::digest::{Update, VariableOutput};
use erreur::*;
use serde::{Deserialize, Serialize};

use super::endemic_ot::{EndemicOTReceiverOutput, EndemicOTSenderKeys};

/// Sender 构造和证明 PPRF
pub fn pprf_build_and_prove(
    sid: &str,
    sender_base: &EndemicOTSenderKeys,
    sender_seed: &mut PPRFSenderOTSeed,
    pprf_output: &mut PPRFOutput,
) {
    for j in 0..NUM_TREES {
        // 公式 (first-layer)
        let mut Ti: Vec<Vec<u8>> = vec![vec![0u8; LAMBDA_C_BYTES]; SOFT_SPOKEN_Q];
        Ti[0] = sender_base.rho_0_list[j * SOFT_SPOKEN_K].clone();
        Ti[1] = sender_base.rho_1_list[j * SOFT_SPOKEN_K].clone();

        let pprf_j = &mut pprf_output.trees[j];

        for i in 1..SOFT_SPOKEN_K {
            let mut Tnext: Vec<Vec<u8>> = vec![vec![0u8; LAMBDA_C_BYTES]; SOFT_SPOKEN_Q];

            // 公式 (next-layer)
            for y in 0..(1usize << i) {
                let (left, right) = prg_expand(sid, &Ti[y]);
                Tnext[2 * y] = left;
                Tnext[2 * y + 1] = right;
            }

            // 公式 (correction)
            let big_idx = j * SOFT_SPOKEN_K + i;
            let mut t_left = sender_base.rho_0_list[big_idx].clone();
            let mut t_right = sender_base.rho_1_list[big_idx].clone();
            for y in 0..(1usize << i) {
                for b in 0..LAMBDA_C_BYTES {
                    t_left[b] ^= Tnext[2 * y][b];
                    t_right[b] ^= Tnext[2 * y + 1][b];
                }
            }
            pprf_j.t_left[i - 1] = t_left;
            pprf_j.t_right[i - 1] = t_right;

            Ti = Tnext;
        }

        sender_seed.otp_enc_keys[j] = Ti.clone();

        // Sender 进行 ProvePPRF, 为所有叶子生成异或承诺 和 哈希承诺.
        let mut t_tilda = vec![0u8; LAMBDA_C_BYTES * 2];
        let mut vec_s_tilda: Vec<Vec<u8>> = Vec::with_capacity(SOFT_SPOKEN_Q);
        for z in 0..SOFT_SPOKEN_Q {
            let sz_tilda = leaf_proof(sid, &Ti[z]);
            for b in 0..(LAMBDA_C_BYTES * 2) {
                t_tilda[b] ^= sz_tilda[b];
            }
            vec_s_tilda.push(sz_tilda);
        }
        pprf_j.tilde_t = t_tilda;
        pprf_j.tilde_s = aggregate_proof(sid, &vec_s_tilda);
    }
}

/// Receiver 重构和验证 PPRF
pub fn pprf_eval_and_verify(
    sid: &str,
    receiver_base: &EndemicOTReceiverOutput,
    pprf_output: &PPRFOutput,
    receiver_seed: &mut PPRFReceiverOTSeed,
) -> Resultat<()> {
    for j in 0..NUM_TREES {
        let pprf_j = &pprf_output.trees[j];

        let beta_0 = extract_bit(&receiver_base.choice_bits, j * SOFT_SPOKEN_K) as usize;
        let mut Trecv: Vec<Vec<u8>> = vec![vec![0u8; LAMBDA_C_BYTES]; SOFT_SPOKEN_Q];
        Trecv[beta_0] = receiver_base.otp_dec_keys[j * SOFT_SPOKEN_K].clone();

        let mut yi: usize = beta_0 ^ 1;

        for i in 1..SOFT_SPOKEN_K {
            let mut Tnext: Vec<Vec<u8>> = vec![vec![0u8; LAMBDA_C_BYTES]; SOFT_SPOKEN_Q];

            // 公式 (copy)
            for y in 0..(1usize << i) {
                if y == yi {
                    continue;
                }
                let (left, right) = prg_expand(sid, &Trecv[y]);
                Tnext[2 * y] = left;
                Tnext[2 * y + 1] = right;
            }

            // 公式 (infer) 里的 rho 项
            let beta_i = extract_bit(&receiver_base.choice_bits, j * SOFT_SPOKEN_K + i) as usize;
            let rho_beta_i = &receiver_base.otp_dec_keys[j * SOFT_SPOKEN_K + i];

            // 公式 (infer) 里的 t 项
            let t_side = match beta_i {
                0 => &pprf_j.t_left[i - 1],
                _ => &pprf_j.t_right[i - 1],
            };

            // 完成公式 (infer)
            let mut x = vec![0u8; LAMBDA_C_BYTES];
            for b in 0..LAMBDA_C_BYTES {
                x[b] = t_side[b] ^ rho_beta_i[b];
            }
            for y in 0..(1usize << i) {
                if y == yi {
                    continue;
                }
                for b in 0..LAMBDA_C_BYTES {
                    x[b] ^= /* 公式 (infer) 里的大异或项 */ Tnext[2 * y + beta_i][b];
                }
            }

            // 公式 (cursor). 以下表达式的顺序不能变!
            Tnext[2 * yi + beta_i] = x;
            Trecv = Tnext;
            yi = 2 * yi + (1 - beta_i);
        }

        // Receiver 进行 VerifyPPRF
        {
            let mut s_tilda_star: Vec<Vec<u8>> = (0..SOFT_SPOKEN_Q)
                .map(|_| vec![0u8; LAMBDA_C_BYTES * 2])
                .collect();

            // 公式 (infer-sy) 第一项
            let mut missing = pprf_j.tilde_t.clone();

            for z in 0..SOFT_SPOKEN_Q {
                if z == yi {
                    continue;
                }
                
                // 公式 (infer-sz) 第二项, 即大异或项
                s_tilda_star[z] = leaf_proof(sid, &Trecv[z]);
                for b in 0..(LAMBDA_C_BYTES * 2) {
                    missing[b] ^= s_tilda_star[z][b];
                }
            }
            s_tilda_star[yi] = missing;

            // 公式 (infer-s)
            let digest = aggregate_proof(sid, &s_tilda_star);

            assert_throw!(
                digest == pprf_j.tilde_s,
                "InvalidPPRFProof",
                format!("PPRF proof mismatch at tree j={}", j)
            );
        }

        receiver_seed.random_choices[j] = yi as u8;
        receiver_seed.otp_dec_keys[j] = Trecv;
    }
    Ok(())
}

// ── 协议消息和密钥类型 ──────────────────────────────────────────────────

/// 单棵 PPRF
#[derive(Clone, Serialize, Deserialize)]
pub struct PPRF {
    /// 所有层在选 0 时的校正串, 详见公式 (correction).
    pub t_left: Vec<Vec<u8>>,
    /// 所有层在选 1 时的校正串, 详见公式 (correction).
    pub t_right: Vec<Vec<u8>>,
    /// Sender 对所有叶子节点的哈希承诺.
    pub tilde_s: Vec<u8>,
    /// Sender 对所有叶子节点的异或承诺.
    pub tilde_t: Vec<u8>,
}

impl Default for PPRF {
    fn default() -> Self {
        Self {
            t_left: (0..SOFT_SPOKEN_K - 1)
                .map(|_| vec![0u8; LAMBDA_C_BYTES])
                .collect(),
            t_right: (0..SOFT_SPOKEN_K - 1)
                .map(|_| vec![0u8; LAMBDA_C_BYTES])
                .collect(),
            tilde_s: vec![0u8; LAMBDA_C_BYTES * 2],
            tilde_t: vec![0u8; LAMBDA_C_BYTES * 2],
        }
    }
}

/// PPRF 网线消息: NUM_TREES 棵并行的小树, Sender -> Receiver.
#[derive(Clone, Serialize, Deserialize)]
pub struct PPRFOutput {
    pub trees: Vec<PPRF>,
}

impl Default for PPRFOutput {
    fn default() -> Self {
        Self {
            trees: (0..NUM_TREES).map(|_| PPRF::default()).collect(),
        }
    }
}

/// Sender 侧状态: 每棵小树的完整叶子表.
#[derive(Clone, Serialize, Deserialize)]
pub struct PPRFSenderOTSeed {
    /// `otp_enc_keys[j][y]` = 第 $j$ 棵树的第 $y$ 个叶子, LAMBDA_C_BYTES 字节.
    pub otp_enc_keys: Vec<Vec<Vec<u8>>>,
}

impl Default for PPRFSenderOTSeed {
    fn default() -> Self {
        Self {
            otp_enc_keys: (0..NUM_TREES)
                .map(|_| {
                    (0..SOFT_SPOKEN_Q)
                        .map(|_| vec![0u8; LAMBDA_C_BYTES])
                        .collect()
                })
                .collect(),
        }
    }
}

/// Receiver 侧状态: 打孔叶子下标 + 可重建的叶子表.
#[derive(Clone, Serialize, Deserialize)]
pub struct PPRFReceiverOTSeed {
    /// 每棵树的打孔叶子下标 $y^*_j \in [Q]$.
    pub random_choices: Vec<u8>,
    /// `otp_dec_keys[j][y]` = 第 $j$ 棵树的第 $y$ 个叶子.
    /// $y = y^*_j$ 处保留为 0 (Receiver 不知道这个叶子).
    pub otp_dec_keys: Vec<Vec<Vec<u8>>>,
}

impl Default for PPRFReceiverOTSeed {
    fn default() -> Self {
        Self {
            random_choices: vec![0u8; NUM_TREES],
            otp_dec_keys: (0..NUM_TREES)
                .map(|_| {
                    (0..SOFT_SPOKEN_Q)
                        .map(|_| vec![0u8; LAMBDA_C_BYTES])
                        .collect()
                })
                .collect(),
        }
    }
}

// ── 协议常量 + 内部辅助 ─────────────────────────────────────────────────

/// 计算安全参数 $\kappa$ (= secp256k1 标量比特数).
const LAMBDA_C: usize = 256;
const LAMBDA_C_BYTES: usize = 32;

/// 单棵小树深度 $K$.
const SOFT_SPOKEN_K: usize = 4;
/// 单棵小树叶子数 $Q = 2^K$.
const SOFT_SPOKEN_Q: usize = 1 << SOFT_SPOKEN_K;
/// 并行小树数量, $\kappa / K$.
const NUM_TREES: usize = LAMBDA_C / SOFT_SPOKEN_K;

/// 辅助函数. 从 bitvec 提取第 idx 比特.
fn extract_bit(packed: &[u8], idx: usize) -> u8 {
    (packed[idx / 8] >> (idx % 8)) & 1
}

/// PRG: 32 字节种子 -> (左孩子, 右孩子), 每个 LAMBDA_C_BYTES 字节.
/// 对应 `notes/04` 中 GGM 树的内部展开.
fn prg_expand(sid: &str, seed: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let out = hash!(LAMBDA_C_BYTES * 2; b"abo-pprf-prg", sid.as_bytes(), seed);
    let left = out[..LAMBDA_C_BYTES].to_vec();
    let right = out[LAMBDA_C_BYTES..].to_vec();
    (left, right)
}

/// 公式 (sz-tag)
fn leaf_proof(sid: &str, leaf: &[u8]) -> Vec<u8> {
    hash!(LAMBDA_C_BYTES * 2; b"abo-pprf-proof", sid.as_bytes(), leaf)
}

/// 单棵树所有 $\tilde{s}_y$ 的聚合哈希 (即 `notes/04` 中的 $\tilde s$).
fn aggregate_proof(sid: &str, stildas: &[Vec<u8>]) -> Vec<u8> {
    let mut h = Blake2bVar::new(LAMBDA_C_BYTES * 2).unwrap();
    h.update(b"abo-pprf-hash");
    h.update(sid.as_bytes());
    for s in stildas {
        h.update(s);
    }
    let mut out = vec![0u8; LAMBDA_C_BYTES * 2];
    h.finalize_variable(&mut out).unwrap();
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dkg::endemic_ot::{self, EndemicOTMsg1, EndemicOTMsg2};

    /// 端到端正确性: Sender 构造的 PPRF 树能被 Receiver 正确打开 (除打孔叶子之外),
    /// 且 Receiver 的已知叶子等于 Sender 的对应叶子.
    #[test]
    fn test_pprf_correctness() {
        let sid = "test-pprf-session";

        // First run base OT to get matched (SenderOutput, ReceiverOutput).
        let mut msg1 = EndemicOTMsg1::default();
        let receiver = endemic_ot::round1(sid, &mut msg1);
        let mut msg2 = EndemicOTMsg2::default();
        let sender_base = endemic_ot::round2(sid, &msg1, &mut msg2).unwrap();
        let receiver_base = endemic_ot::round3(receiver, &msg2).unwrap();

        // Build PPRF as Sender.
        let mut sender_seed = PPRFSenderOTSeed::default();
        let mut pprf_out = PPRFOutput::default();
        pprf_build_and_prove(sid, &sender_base, &mut sender_seed, &mut pprf_out);

        // Evaluate as Receiver.
        let mut receiver_seed = PPRFReceiverOTSeed::default();
        pprf_eval_and_verify(sid, &receiver_base, &pprf_out, &mut receiver_seed).unwrap();

        // For each tree, every non-punctured leaf must match Sender's leaf.
        for j in 0..NUM_TREES {
            let y_star = receiver_seed.random_choices[j] as usize;
            for y in 0..SOFT_SPOKEN_Q {
                if y == y_star {
                    continue;
                }
                assert_eq!(
                    sender_seed.otp_enc_keys[j][y], receiver_seed.otp_dec_keys[j][y],
                    "leaf mismatch: j={}, y={}, y_star={}",
                    j, y, y_star
                );
            }
        }
    }
}
