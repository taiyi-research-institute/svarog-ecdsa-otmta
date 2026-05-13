//! All-but-one PPRF (SoftSpoken 扩展的种子层), 见 `notes/04-pprf.md`.
//!
//! 输入: `KAPPA = 256` 对 base OT 密钥 ($\rho_0, \rho_1$).
//! 输出: 拆成 `NUM_TREES = 64` 棵小 GGM 树, 每棵深度 $K = 4$, 共 $Q = 16$ 个叶子.
//! Sender 拿到全部 $64 \times 16$ 个叶子; Receiver 拿到每棵树除一个被穿孔
//! (punctured) 叶子之外的全部叶子.
//!
//! 核心算法 (`notes/04`):
//! * `build_pprf` ↔ 笔记 §"Sender 进行 BuildPPRF" + §"Sender 进行 ProvePPRF".
//!   逐层 PRG 展开, 把每层下一对 base OT 密钥 XOR 上 "本层左/右孩子的 XOR 累加",
//!   形成层校正对 $t_i[0], t_i[1]$. 末尾对所有叶子算
//!   $\tilde s_y, \tilde t = \bigoplus_y \tilde s_y$.
//! * `eval_pprf` ↔ 笔记 §"Receiver 进行 EvalPPRF" + §"Receiver 进行 VerifyPPRF".
//!   按选择位逐层定位穿孔点 $y^*_j$, 用层校正对反推未知子树.
//!   最终用 $\tilde t$ 反算丢失的 $\tilde s_{y^*}$, 重哈希对照 $\tilde s$.
//!
//! 论文出处: Roy 2022 "SoftSpokenOT", <https://eprint.iacr.org/2022/192.pdf>.

use blake2::Blake2bVar;
use blake2::digest::{Update, VariableOutput};
use erreur::*;
use serde::{Deserialize, Serialize};

use super::endemic_ot::{EndemicOTReceiverOutput, EndemicOTSenderKeys};

/// 计算安全参数 $\kappa$ (= secp256k1 标量比特数).
const LAMBDA_C: usize = 256;
const LAMBDA_C_BYTES: usize = 32;

/// 单棵小树深度 $K$.
const SOFT_SPOKEN_K: usize = 4;
/// 单棵小树叶子数 $Q = 2^K$.
const SOFT_SPOKEN_Q: usize = 1 << SOFT_SPOKEN_K;
/// 并行小树数量, $\kappa / K$.
const NUM_TREES: usize = LAMBDA_C / SOFT_SPOKEN_K;

/// 单棵小树的 PPRF 数据: $K-1$ 对层校正 + all-but-one 证明.
#[derive(Clone, Serialize, Deserialize)]
pub struct PPRF {
    /// 逐层经 OTP 掩码后的层校正对 $(t_i[0], t_i[1])$, $i = 1..K-1$.
    pub t: Vec<(Vec<u8>, Vec<u8>)>,
    /// 把所有叶子的证明值 $\tilde{s}_y$ 哈希聚合, 即 `notes/04` 中的 $\tilde s$.
    pub s_tilda: Vec<u8>,
    /// 所有 $\tilde{s}_y$ 的 XOR 累加, 即 `notes/04` 中的 $\tilde t$;
    /// 让 Receiver 能反推那一片缺失的 $\tilde{s}_{y^*}$.
    pub t_tilda: Vec<u8>,
}

impl Default for PPRF {
    fn default() -> Self {
        Self {
            t: (0..SOFT_SPOKEN_K - 1)
                .map(|_| (vec![0u8; LAMBDA_C_BYTES], vec![0u8; LAMBDA_C_BYTES]))
                .collect(),
            s_tilda: vec![0u8; LAMBDA_C_BYTES * 2],
            t_tilda: vec![0u8; LAMBDA_C_BYTES * 2],
        }
    }
}

/// PPRF 网线消息: NUM_TREES 棵并行的小树, Sender → Receiver.
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
pub struct SenderOTSeed {
    /// `otp_enc_keys[j][y]` = 第 $j$ 棵树的第 $y$ 个叶子, LAMBDA_C_BYTES 字节.
    pub otp_enc_keys: Vec<Vec<Vec<u8>>>,
}

impl Default for SenderOTSeed {
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

/// Receiver 侧状态: 穿孔叶子下标 + 可重建的叶子表.
#[derive(Clone, Serialize, Deserialize)]
pub struct ReceiverOTSeed {
    /// 每棵树的穿孔叶子下标 $y^*_j \in [Q]$.
    pub random_choices: Vec<u8>,
    /// `otp_dec_keys[j][y]` = 第 $j$ 棵树的第 $y$ 个叶子.
    /// $y = y^*_j$ 处保留为 0 (Receiver 不知道这个叶子).
    pub otp_dec_keys: Vec<Vec<Vec<u8>>>,
}

impl Default for ReceiverOTSeed {
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

// ── 辅助函数 ──────────────────────────────────────────────────

fn extract_bit(packed: &[u8], idx: usize) -> u8 {
    (packed[idx / 8] >> (idx % 8)) & 1
}

/// PRG: 32 字节种子 → (左孩子, 右孩子), 每个 LAMBDA_C_BYTES 字节.
/// 对应 `notes/04` 中 GGM 树的内部展开.
fn prg_expand(sid: &str, seed: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let out = hash!(LAMBDA_C_BYTES * 2; b"abo-pprf-prg", sid.as_bytes(), seed);
    let left = out[..LAMBDA_C_BYTES].to_vec();
    let right = out[LAMBDA_C_BYTES..].to_vec();
    (left, right)
}

/// 单叶证明派生: $\tilde{s}_y$, 长度 $2 \cdot$ LAMBDA_C_BYTES.
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

// ── build_pprf (Sender 侧) ──────────────────────────────────

/// Sender 侧 PPRF 构造, 见 `notes/04` §"Sender 进行 BuildPPRF" + §"ProvePPRF".
///
/// 对每棵树 $j$:
/// * 把第 $jK$ 对 base OT 密钥作为根的左右孩子, 经 PRG 逐层展开 $K-1$ 次,
///   得到 $2^K$ 个叶子.
/// * 在第 $i$ 层 ($1 \le i \le K-1$), 把下一对 base OT 密钥
///   $(\rho_0, \rho_1)$ 与 "本层全部左孩子的 XOR" / "本层全部右孩子的 XOR"
///   异或, 形成层校正对 $\Rightarrow$ `pprf_output.trees[j].t[i-1]`.
/// * 末尾对每个叶子算 $\tilde s_y = \mathrm{leaf\_proof}(s_y)$, 写入
///   $\tilde t = \bigoplus_y \tilde s_y$ 与 $\tilde s = \mathrm{Hash}(\tilde s_*)$.
pub fn build_pprf(
    sid: &str,
    sender_base: &EndemicOTSenderKeys,
    sender_seed: &mut SenderOTSeed,
    pprf_output: &mut PPRFOutput,
) {
    for j in 0..NUM_TREES {
        let mut s_i: Vec<Vec<u8>> = vec![vec![0u8; LAMBDA_C_BYTES]; SOFT_SPOKEN_Q];
        s_i[0] = sender_base.rho_0_list[j * SOFT_SPOKEN_K].clone();
        s_i[1] = sender_base.rho_1_list[j * SOFT_SPOKEN_K].clone();

        let pprf_j = &mut pprf_output.trees[j];

        for i in 1..SOFT_SPOKEN_K {
            let mut s_next: Vec<Vec<u8>> =
                vec![vec![0u8; LAMBDA_C_BYTES]; SOFT_SPOKEN_Q];

            for y in 0..(1usize << i) {
                let (left, right) = prg_expand(sid, &s_i[y]);
                s_next[2 * y] = left;
                s_next[2 * y + 1] = right;
            }

            let big_idx = j * SOFT_SPOKEN_K + i;
            let mut t_left = sender_base.rho_0_list[big_idx].clone();
            let mut t_right = sender_base.rho_1_list[big_idx].clone();
            for y in 0..(1usize << i) {
                for b in 0..LAMBDA_C_BYTES {
                    t_left[b] ^= s_next[2 * y][b];
                    t_right[b] ^= s_next[2 * y + 1][b];
                }
            }
            pprf_j.t[i - 1] = (t_left, t_right);

            s_i = s_next;
        }

        // 保存完整叶子表.
        sender_seed.otp_enc_keys[j] = s_i.clone();

        // 聚合证明: t_tilda = ⊕_y leaf_proof(s_y); s_tilda = Hash(全部 leaf_proof).
        let mut t_tilda = vec![0u8; LAMBDA_C_BYTES * 2];
        let mut stildas: Vec<Vec<u8>> = Vec::with_capacity(SOFT_SPOKEN_Q);
        for y in 0..SOFT_SPOKEN_Q {
            let stilda_y = leaf_proof(sid, &s_i[y]);
            for b in 0..(LAMBDA_C_BYTES * 2) {
                t_tilda[b] ^= stilda_y[b];
            }
            stildas.push(stilda_y);
        }
        pprf_j.t_tilda = t_tilda;
        pprf_j.s_tilda = aggregate_proof(sid, &stildas);
    }
}

// ── eval_pprf (Receiver 侧) ─────────────────────────────────

/// Receiver 侧 PPRF 求值 + 校验,
/// 见 `notes/04` §"Receiver 进行 EvalPPRF" + §"Receiver 进行 VerifyPPRF".
///
/// 对每棵树 $j$, Receiver 的 $K$ 个选择位
/// $(\beta_{jK}, \ldots, \beta_{jK+K-1})$ 决定穿孔叶子下标 $y^*_j$.
/// 逐层用层校正对 $t_{i-1}$ 反推那一片未知子树, 最终重建除 $y^*_j$ 外的全部叶子.
/// 最后用 $\tilde t$ 反算 $\tilde s_{y^*}$, 重哈希对比 Sender 提供的 $\tilde s$.
pub fn eval_pprf(
    sid: &str,
    receiver_base: &EndemicOTReceiverOutput,
    pprf_output: &PPRFOutput,
    receiver_seed: &mut ReceiverOTSeed,
) -> Resultat<()> {
    for j in 0..NUM_TREES {
        let pprf_j = &pprf_output.trees[j];

        let beta_0 = extract_bit(&receiver_base.choice_bits, j * SOFT_SPOKEN_K) as usize;
        let mut s_star: Vec<Vec<u8>> =
            vec![vec![0u8; LAMBDA_C_BYTES]; SOFT_SPOKEN_Q];
        s_star[beta_0] = receiver_base.otp_dec_keys[j * SOFT_SPOKEN_K].clone();

        // y_star 跟踪当前层的穿孔 (未知) 下标.
        let mut y_star: usize = beta_0 ^ 1;

        for i in 1..SOFT_SPOKEN_K {
            let mut s_next: Vec<Vec<u8>> =
                vec![vec![0u8; LAMBDA_C_BYTES]; SOFT_SPOKEN_Q];

            // 对所有已知 seed 做 PRG 展开, 跳过 y_star.
            for y in 0..(1usize << i) {
                if y == y_star {
                    continue;
                }
                let (left, right) = prg_expand(sid, &s_star[y]);
                s_next[2 * y] = left;
                s_next[2 * y + 1] = right;
            }

            // 用本层 base OT 密钥 (选择位侧) 反推 y_star 的 β-侧孩子.
            let beta_i = extract_bit(
                &receiver_base.choice_bits,
                j * SOFT_SPOKEN_K + i,
            ) as usize;
            let big_f_star = &receiver_base.otp_dec_keys[j * SOFT_SPOKEN_K + i];

            let t_side = match beta_i {
                0 => &pprf_j.t[i - 1].0,
                _ => &pprf_j.t[i - 1].1,
            };

            // x = t_side ⊕ ρ_β = ⊕_{所有 y} s_next[2y+β]; 减去已知, 余下未知.
            let mut x = vec![0u8; LAMBDA_C_BYTES];
            for b in 0..LAMBDA_C_BYTES {
                x[b] = t_side[b] ^ big_f_star[b];
            }
            for y in 0..(1usize << i) {
                if y == y_star {
                    continue;
                }
                for b in 0..LAMBDA_C_BYTES {
                    x[b] ^= s_next[2 * y + beta_i][b];
                }
            }
            s_next[2 * y_star + beta_i] = x;

            s_star = s_next;
            // 旧 y_star 的 (1-β) 侧孩子, 即新的未知点.
            y_star = 2 * y_star + (1 - beta_i);
        }

        // VerifyPPRF: 用 t_tilda 反算缺失的 s_tilda_{y_star}, 重哈希比对 s_tilda.
        let mut s_tilda_star: Vec<Vec<u8>> = (0..SOFT_SPOKEN_Q)
            .map(|_| vec![0u8; LAMBDA_C_BYTES * 2])
            .collect();
        for y in 0..SOFT_SPOKEN_Q {
            if y == y_star {
                continue;
            }
            s_tilda_star[y] = leaf_proof(sid, &s_star[y]);
        }
        let mut missing = pprf_j.t_tilda.clone();
        for y in 0..SOFT_SPOKEN_Q {
            if y == y_star {
                continue;
            }
            for b in 0..(LAMBDA_C_BYTES * 2) {
                missing[b] ^= s_tilda_star[y][b];
            }
        }
        s_tilda_star[y_star] = missing;

        let digest = aggregate_proof(sid, &s_tilda_star);
        assert_throw!(
            digest == pprf_j.s_tilda,
            "InvalidPPRFProof",
            format!("PPRF proof mismatch at tree j={}", j)
        );

        receiver_seed.random_choices[j] = y_star as u8;
        receiver_seed.otp_dec_keys[j] = s_star;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dkg::endemic_ot::{
        self, EndemicOTMsg1, EndemicOTMsg2,
    };

    /// 端到端正确性: Sender 构造的 PPRF 树能被 Receiver 正确打开 (除穿孔叶子之外),
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
        let mut sender_seed = SenderOTSeed::default();
        let mut pprf_out = PPRFOutput::default();
        build_pprf(sid, &sender_base, &mut sender_seed, &mut pprf_out);

        // Evaluate as Receiver.
        let mut receiver_seed = ReceiverOTSeed::default();
        eval_pprf(sid, &receiver_base, &pprf_out, &mut receiver_seed).unwrap();

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
