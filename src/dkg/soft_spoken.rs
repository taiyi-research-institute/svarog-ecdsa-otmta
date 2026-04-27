//! SoftSpoken PPRF extension (all-but-one).
//!
//! Stretches κ pairs of base OT keys into the "all-but-one" leaf seeds
//! that signing-time MtA needs.
//!
//! See `dkg_fn.md` Section A and Roy 2022, https://eprint.iacr.org/2022/192.pdf.

use blake2::Blake2bVar;
use blake2::digest::{Update, VariableOutput};
use erreur::*;
use serde::{Deserialize, Serialize};

use super::endemic_ot::{ReceiverOutput, SenderOutput};

/// Computational security parameter ($\kappa$ = secp256k1 scalar bit length).
const LAMBDA_C: usize = 256;
const LAMBDA_C_BYTES: usize = 32;

/// Per-tree depth $K$.
const SOFT_SPOKEN_K: usize = 4;
/// Leaves per small tree, $Q = 2^K$.
const SOFT_SPOKEN_Q: usize = 1 << SOFT_SPOKEN_K;
/// Number of parallel small trees, $\kappa / K$.
const NUM_TREES: usize = LAMBDA_C / SOFT_SPOKEN_K;

/// Per-tree PPRF data: $K - 1$ layer correction pairs + all-but-one proof.
#[derive(Clone, Serialize, Deserialize)]
pub struct PPRF {
    /// Layer-by-layer OTP-masked correction pairs $(t_i[0], t_i[1])$ for $i = 1..K-1$.
    pub t: Vec<(Vec<u8>, Vec<u8>)>,
    /// Hash digest binding all leaf-derived proof values $\tilde{s}_y$.
    pub s_tilda: Vec<u8>,
    /// XOR accumulator over all $\tilde{s}_y$, lets Receiver reconstruct the missing one.
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

/// PPRF output: NUM_TREES parallel PPRF trees, sent Sender → Receiver.
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

/// Sender-side state: full leaf table for each small tree.
pub struct SenderOTSeed {
    /// `otp_enc_keys[j][y]` = leaf $y$ of tree $j$, LAMBDA_C_BYTES bytes.
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

/// Receiver-side state: punctured leaf indices + reconstructable leaves.
pub struct ReceiverOTSeed {
    /// Per-tree punctured leaf index $y^*_j \in [Q]$.
    pub random_choices: Vec<u8>,
    /// `otp_dec_keys[j][y]` = leaf $y$ of tree $j$.
    /// Position $y = y^*_j$ holds zeros (Receiver does not know that leaf).
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

// ── helpers ──────────────────────────────────────────────────

fn extract_bit(packed: &[u8], idx: usize) -> u8 {
    (packed[idx / 8] >> (idx % 8)) & 1
}

/// PRG: 32-byte seed → (left child, right child), each LAMBDA_C_BYTES bytes.
fn prg_expand(sid: &str, seed: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let out = hash!(LAMBDA_C_BYTES * 2; b"abo-pprf-prg", sid.as_bytes(), seed);
    let left = out[..LAMBDA_C_BYTES].to_vec();
    let right = out[LAMBDA_C_BYTES..].to_vec();
    (left, right)
}

/// Per-leaf prove derivation: $\tilde{s}_y$ = 2 · LAMBDA_C_BYTES bytes.
fn leaf_proof(sid: &str, leaf: &[u8]) -> Vec<u8> {
    hash!(LAMBDA_C_BYTES * 2; b"abo-pprf-proof", sid.as_bytes(), leaf)
}

/// Aggregate hash over all $\tilde{s}_y$ values for one tree.
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

// ── build_pprf (Sender side) ─────────────────────────────────

/// Sender-side PPRF construction.
///
/// For each tree $j$, expand the base OT pair at index $jK$ via PRG into
/// $2^K$ leaves through $K - 1$ levels.
/// At each level, the next base OT pair $(\rho_0, \rho_1)$ is XOR-masked with
/// "XOR of all left children" / "XOR of all right children" to produce the
/// correction pair stored in `pprf_output.trees[j].t[i - 1]`.
/// Final aggregate proof is written to `t_tilda` / `s_tilda`.
pub fn build_pprf(
    sid: &str,
    sender_base: &SenderOutput,
    sender_seed: &mut SenderOTSeed,
    pprf_output: &mut PPRFOutput,
) {
    for j in 0..NUM_TREES {
        let mut s_i: Vec<Vec<u8>> = vec![vec![0u8; LAMBDA_C_BYTES]; SOFT_SPOKEN_Q];
        s_i[0] = sender_base.otp_enc_keys[j * SOFT_SPOKEN_K].rho_0.clone();
        s_i[1] = sender_base.otp_enc_keys[j * SOFT_SPOKEN_K].rho_1.clone();

        let pprf_j = &mut pprf_output.trees[j];

        for i in 1..SOFT_SPOKEN_K {
            let mut s_next: Vec<Vec<u8>> =
                vec![vec![0u8; LAMBDA_C_BYTES]; SOFT_SPOKEN_Q];

            for y in 0..(1usize << i) {
                let (left, right) = prg_expand(sid, &s_i[y]);
                s_next[2 * y] = left;
                s_next[2 * y + 1] = right;
            }

            let big_f = &sender_base.otp_enc_keys[j * SOFT_SPOKEN_K + i];
            let mut t_left = big_f.rho_0.clone();
            let mut t_right = big_f.rho_1.clone();
            for y in 0..(1usize << i) {
                for b in 0..LAMBDA_C_BYTES {
                    t_left[b] ^= s_next[2 * y][b];
                    t_right[b] ^= s_next[2 * y + 1][b];
                }
            }
            pprf_j.t[i - 1] = (t_left, t_right);

            s_i = s_next;
        }

        // Save the full leaf table.
        sender_seed.otp_enc_keys[j] = s_i.clone();

        // Aggregate proof: t_tilda = ⊕_y leaf_proof(s_y); s_tilda = Hash(all leaf_proof's).
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

// ── eval_pprf (Receiver side) ────────────────────────────────

/// Receiver-side PPRF evaluation.
///
/// For each tree $j$, the Receiver's $K$ choice bits
/// $(\beta_{jK}, \ldots, \beta_{jK + K - 1})$
/// determine the punctured leaf index $y^*_j$.
/// They reconstruct all leaves except $y^*_j$ and finally check
/// `t_tilda` / `s_tilda` for Sender honesty.
pub fn eval_pprf(
    sid: &str,
    receiver_base: &ReceiverOutput,
    pprf_output: &PPRFOutput,
    receiver_seed: &mut ReceiverOTSeed,
) -> Resultat<()> {
    for j in 0..NUM_TREES {
        let pprf_j = &pprf_output.trees[j];

        let beta_0 = extract_bit(&receiver_base.choice_bits, j * SOFT_SPOKEN_K) as usize;
        let mut s_star: Vec<Vec<u8>> =
            vec![vec![0u8; LAMBDA_C_BYTES]; SOFT_SPOKEN_Q];
        s_star[beta_0] = receiver_base.otp_dec_keys[j * SOFT_SPOKEN_K].clone();

        // y_star tracks the punctured (unknown) index at the current level.
        let mut y_star: usize = beta_0 ^ 1;

        for i in 1..SOFT_SPOKEN_K {
            let mut s_next: Vec<Vec<u8>> =
                vec![vec![0u8; LAMBDA_C_BYTES]; SOFT_SPOKEN_Q];

            // PRG-expand all known seeds (skip y_star).
            for y in 0..(1usize << i) {
                if y == y_star {
                    continue;
                }
                let (left, right) = prg_expand(sid, &s_star[y]);
                s_next[2 * y] = left;
                s_next[2 * y + 1] = right;
            }

            // Use base OT key on choice side to recover the missing β-side child of y_star.
            let beta_i = extract_bit(
                &receiver_base.choice_bits,
                j * SOFT_SPOKEN_K + i,
            ) as usize;
            let big_f_star = &receiver_base.otp_dec_keys[j * SOFT_SPOKEN_K + i];

            let t_side = match beta_i {
                0 => &pprf_j.t[i - 1].0,
                _ => &pprf_j.t[i - 1].1,
            };

            // x = t_side ⊕ ρ_β = ⊕_{all y} s_next[2y + β]; subtract known to leave the unknown.
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
            // The (1 - β)-side child of the old y_star is now the new unknown.
            y_star = 2 * y_star + (1 - beta_i);
        }

        // Verify: reconstruct missing s_tilda_{y_star} via t_tilda, then re-hash and compare.
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
        EndemicOTMsg1, EndemicOTMsg2, EndemicOTReceiver, EndemicOTSender,
    };

    /// End-to-end correctness: a Sender-built PPRF tree is correctly opened by a Receiver
    /// up to the punctured leaf, and Receiver's known leaves equal Sender's leaves.
    #[test]
    fn test_pprf_correctness() {
        let sid = "test-pprf-session";

        // First run base OT to get matched (SenderOutput, ReceiverOutput).
        let mut msg1 = EndemicOTMsg1::default();
        let receiver = EndemicOTReceiver::new(sid, &mut msg1);
        let mut msg2 = EndemicOTMsg2::default();
        let sender_base = EndemicOTSender::process(sid, &msg1, &mut msg2).unwrap();
        let receiver_base = receiver.process(&msg2).unwrap();

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
