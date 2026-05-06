//! SoftSpoken OT extension (signing-time random OT).
//!
//! Stretches `LAMBDA_C` punctured-PRF leaves (already produced at keygen by
//! `dkg/soft_spoken.rs`) into `L` 1-out-of-2 random OTs, each producing
//! `OT_WIDTH` parallel `KAPPA_BYTES` strings.
//!
//! Reference: SoftSpokenOT (Roy 2022, eprint 2022/192) and DKLS23 5.1.
//! Mirrors `sl-oblivious/src/soft_spoken/soft_spoken_ot.rs`.
//!
//! Role flipping (vs. PPRF):
//!   PPRF Sender (full leaf table) ↔ SoftSpoken OT Receiver.
//!   PPRF Receiver (punctured) ↔ SoftSpoken OT Sender.

use erreur::*;
use rand::Rng;
use serde::{Deserialize, Serialize};

use super::super::dkg::{ReceiverOTSeed, SenderOTSeed};

// ── parameters (identical to sl-oblivious) ────────────────────────────────

pub const KAPPA: usize = 256;
pub const KAPPA_BYTES: usize = 32;
pub const LAMBDA_C: usize = 256;
pub const LAMBDA_C_BYTES: usize = 32;
pub const LAMBDA_S: usize = 128;
pub const S: usize = 128;
pub const S_BYTES: usize = 16;
pub const L_BATCH: usize = 2;
pub const RHO: usize = 1;
pub const SOFT_SPOKEN_K: usize = 4;
pub const L: usize = KAPPA + 2 * LAMBDA_S; // 512
pub const L_BYTES: usize = L >> 3; // 64
pub const L_PRIME: usize = L + S; // 640
pub const L_PRIME_BYTES: usize = L_PRIME >> 3; // 80
pub const SOFT_SPOKEN_M: usize = L / S; // 4
pub const OT_WIDTH: usize = L_BATCH + RHO; // 3
pub const SOFT_SPOKEN_Q: usize = 1 << SOFT_SPOKEN_K; // 16
pub const LAMBDA_C_DIV_SOFT_SPOKEN_K: usize = LAMBDA_C / SOFT_SPOKEN_K; // 64

// ── messages / outputs ────────────────────────────────────────────────────

#[derive(Clone, Serialize, Deserialize)]
pub struct Round1Output {
    /// `u[i]`, length `L_PRIME_BYTES`, for `i ∈ [LAMBDA_C_DIV_SOFT_SPOKEN_K]`.
    pub u: Vec<Vec<u8>>,
    /// `S_BYTES`-byte consistency check value.
    pub x: Vec<u8>,
    /// `t[i]`, length `S_BYTES`, for `i ∈ [LAMBDA_C]`.
    pub t: Vec<Vec<u8>>,
}

impl Default for Round1Output {
    fn default() -> Self {
        Self {
            u: (0..LAMBDA_C_DIV_SOFT_SPOKEN_K)
                .map(|_| vec![0u8; L_PRIME_BYTES])
                .collect(),
            x: vec![0u8; S_BYTES],
            t: (0..LAMBDA_C).map(|_| vec![0u8; S_BYTES]).collect(),
        }
    }
}

#[derive(Clone)]
pub struct SenderExtendedOutput {
    pub v_0: Vec<Vec<Vec<u8>>>, // [L][OT_WIDTH][KAPPA_BYTES]
    pub v_1: Vec<Vec<Vec<u8>>>,
}

impl Default for SenderExtendedOutput {
    fn default() -> Self {
        let blank = || (0..L)
            .map(|_| (0..OT_WIDTH).map(|_| vec![0u8; KAPPA_BYTES]).collect())
            .collect();
        Self { v_0: blank(), v_1: blank() }
    }
}

#[derive(Clone)]
pub struct ReceiverExtendedOutput {
    pub choices: Vec<u8>, // L bits packed in L_BYTES
    pub v_x: Vec<Vec<Vec<u8>>>, // [L][OT_WIDTH][KAPPA_BYTES]
}

impl ReceiverExtendedOutput {
    pub fn new(choices: Vec<u8>) -> Self {
        debug_assert_eq!(choices.len(), L_BYTES);
        Self {
            choices,
            v_x: (0..L)
                .map(|_| (0..OT_WIDTH).map(|_| vec![0u8; KAPPA_BYTES]).collect())
                .collect(),
        }
    }
}

// ── GF(2^128) multiplication, ported verbatim from sl-oblivious/mul_poly.rs ──

pub fn binary_field_multiply_gf_2_128(a: &[u8; 16], b_data: &[u8; 16]) -> [u8; 16] {
    const W: usize = 8;
    const T: usize = 16;

    let mut c = [0u8; T * 2];
    let mut b = [0u8; T + 1];
    b[..16].copy_from_slice(b_data);

    for k in 0..W {
        for j in 0..T {
            let mask = -(((a[j] >> k) & 0x01) as i8) as u8;
            for i in 0..T + 1 {
                c[j + i] ^= b[i] & mask;
            }
        }
        for i in (1..=T).rev() {
            b[i] = (b[i] << 1) | (b[i - 1] >> 7);
        }
        b[0] <<= 1;
    }
    for i in (T..=2 * T - 1).rev() {
        c[i - 16] ^= c[i];
        c[i - 16] ^= c[i] << 1;
        c[i - 15] ^= c[i] >> 7;
        c[i - 16] ^= c[i] << 2;
        c[i - 15] ^= c[i] >> 6;
        c[i - 16] ^= c[i] << 7;
        c[i - 15] ^= c[i] >> 1;
    }

    c[..16].try_into().unwrap()
}

// ── helpers ────────────────────────────────────────────────────────────────

#[inline]
fn extract_bit(packed: &[u8], idx: usize) -> u8 {
    (packed[idx / 8] >> (idx % 8)) & 1
}

#[inline]
fn bit_to_mask(bit: u8) -> u8 {
    -((bit & 1) as i8) as u8
}

/// PRG: 32-byte seed → `n` bytes (chained Blake2b ≤64-byte blocks with counter).
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

/// PRG: 32-byte seed → `L_PRIME_BYTES` bytes.
fn prg_expand(sid: &str, seed: &[u8]) -> Vec<u8> {
    prg_bytes(b"dsg/softspoken/prg", sid, seed, L_PRIME_BYTES)
}

/// Domain-separated KOS challenge seed.
fn matrix_digest(sid: &str, u: &[Vec<u8>]) -> [u8; 32] {
    let mut h =
        <::blake2::Blake2bVar as ::blake2::digest::VariableOutput>::new(32).unwrap();
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

/// Per-row randomization: derive `OT_WIDTH * KAPPA_BYTES` bytes from
/// `(sid, j, zeta_or_psi_row)`, then split into OT_WIDTH chunks.
fn randomize_row(sid: &str, j: usize, row: &[u8]) -> Vec<Vec<u8>> {
    let need = OT_WIDTH * KAPPA_BYTES;
    let mut bytes = Vec::with_capacity(need);
    let mut ctr: u32 = 0;
    while bytes.len() < need {
        let take = std::cmp::min(64, need - bytes.len());
        let block = hash!(
            take;
            b"dsg/softspoken/randomize",
            sid.as_bytes(),
            &(j as u64).to_le_bytes(),
            row,
            &ctr.to_le_bytes()
        );
        bytes.extend_from_slice(&block);
        ctr += 1;
    }
    (0..OT_WIDTH)
        .map(|k| bytes[k * KAPPA_BYTES..(k + 1) * KAPPA_BYTES].to_vec())
        .collect()
}

/// Transpose a `LAMBDA_C × L_PRIME` bit matrix to `L_PRIME × LAMBDA_C`.
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

// ── Receiver ──────────────────────────────────────────────────────────────

pub struct SoftSpokenOTReceiver;

impl SoftSpokenOTReceiver {
    /// `choices` packs `L` selection bits into `L_BYTES`.
    pub fn process(
        sid: &str,
        sender_seed: &SenderOTSeed,
        choices: &[u8],
    ) -> (Round1Output, ReceiverExtendedOutput) {
        debug_assert_eq!(choices.len(), L_BYTES);

        // Pad choices with 128 bits of "challenge" randomness to L_PRIME.
        let extended_packed_choices: Vec<u8> = {
            let mut buf = vec![0u8; L_PRIME_BYTES];
            buf[..L_BYTES].copy_from_slice(choices);
            // Fresh randomness for the extra block.
            use rand::Rng;
            rand::rng().fill_bytes(&mut buf[L_BYTES..]);
            buf
        };

        let mut output = Round1Output::default();
        let mut extended_output = ReceiverExtendedOutput::new(choices.to_vec());

        // r_x[j][i] is the PRG expansion of leaf j of small tree i.
        let mut r_x: Vec<Vec<Vec<u8>>> =
            (0..SOFT_SPOKEN_Q)
                .map(|_| (0..LAMBDA_C_DIV_SOFT_SPOKEN_K).map(|_| vec![0u8; L_PRIME_BYTES]).collect())
                .collect();

        for i in 0..LAMBDA_C_DIV_SOFT_SPOKEN_K {
            for j in 0..SOFT_SPOKEN_Q {
                r_x[j][i] = prg_expand(sid, &sender_seed.otp_enc_keys[i][j]);
            }
            // u[i] = (XOR over j of r_x[j][i]) XOR extended_packed_choices.
            let u_i = &mut output.u[i];
            for byte in 0..L_PRIME_BYTES {
                let mut acc = extended_packed_choices[byte];
                for j in 0..SOFT_SPOKEN_Q {
                    acc ^= r_x[j][i][byte];
                }
                u_i[byte] = acc;
            }
        }

        // V matrix: v[i*K + bit_index][k] = Σ_{j} (j>>bit_index)&1 * r_x[j][i][k]
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

        // Fiat-Shamir consistency challenges.
        let digest = matrix_digest(sid, &output.u);
        let chi: Vec<[u8; 16]> = (0..SOFT_SPOKEN_M).map(|j| derive_chi(&digest, j)).collect();

        // x = Σ_j chi_j · x_hat_j  where x_hat_j is jth S-byte chunk of choices.
        for j in 0..SOFT_SPOKEN_M {
            let mut x_hat_j = [0u8; S_BYTES];
            x_hat_j.copy_from_slice(&extended_packed_choices[j * S_BYTES..(j + 1) * S_BYTES]);
            let prod = binary_field_multiply_gf_2_128(&x_hat_j, &chi[j]);
            for k in 0..S_BYTES {
                output.x[k] ^= prod[k];
            }

            for i in 0..LAMBDA_C {
                let mut t_hat_j = [0u8; S_BYTES];
                t_hat_j.copy_from_slice(&v[i][j * S_BYTES..(j + 1) * S_BYTES]);
                let prod = binary_field_multiply_gf_2_128(&t_hat_j, &chi[j]);
                for k in 0..S_BYTES {
                    output.t[i][k] ^= prod[k];
                }
            }
        }

        const FROM: usize = SOFT_SPOKEN_M * S_BYTES;

        // Tail block: x ^= last S_BYTES of choices, t[i] ^= last S_BYTES of v[i].
        for k in 0..S_BYTES {
            output.x[k] ^= extended_packed_choices[FROM + k];
        }
        for i in 0..LAMBDA_C {
            for k in 0..S_BYTES {
                output.t[i][k] ^= v[i][FROM + k];
            }
        }

        // Truncate v to first L rows (drop the S consistency rows) — actually
        // we transpose the full LAMBDA_C × L_PRIME matrix and keep first L rows.
        let psi = transpose_bool_matrix(&v);
        for j in 0..L {
            extended_output.v_x[j] = randomize_row(sid, j, &psi[j]);
        }

        (output, extended_output)
    }
}

// ── Sender ────────────────────────────────────────────────────────────────

pub struct SoftSpokenOTSender;

impl SoftSpokenOTSender {
    pub fn process(
        sid: &str,
        receiver_seed: &ReceiverOTSeed,
        round1: &Round1Output,
    ) -> Resultat<SenderExtendedOutput> {
        // r_x[j][i]: PRG of leaf j of tree i, but the chosen leaf y*_i is unknown
        // (kept as zeros).
        let mut r_x: Vec<Vec<Vec<u8>>> =
            (0..SOFT_SPOKEN_Q)
                .map(|_| (0..LAMBDA_C_DIV_SOFT_SPOKEN_K).map(|_| vec![0u8; L_PRIME_BYTES]).collect())
                .collect();
        for i in 0..LAMBDA_C_DIV_SOFT_SPOKEN_K {
            let chosen = receiver_seed.random_choices[i] as usize;
            for j in 0..SOFT_SPOKEN_Q {
                if j == chosen {
                    // r_x[j][i] stays zero.
                } else {
                    r_x[j][i] = prg_expand(sid, &receiver_seed.otp_dec_keys[i][j]);
                }
            }
        }

        // Build w_matrix: per bit, XOR contributions and message.u.
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
                        w_matrix[row_idx][k] ^= mask & r_x[j][i][k];
                    }
                }

                let delta_i = (delta >> bit_index) & 0x01;
                let delta_mask = bit_to_mask(delta_i);
                let row_idx = i * SOFT_SPOKEN_K + bit_index;
                for k in 0..L_PRIME_BYTES {
                    w_matrix[row_idx][k] ^= delta_mask & round1.u[i][k];
                }
            }
        }

        // packed_nabla: packed deltas of all small trees, length LAMBDA_C bits.
        let mut packed_nabla = vec![0u8; LAMBDA_C_BYTES];
        for i in 0..LAMBDA_C_DIV_SOFT_SPOKEN_K {
            let delta = receiver_seed.random_choices[i];
            for bit_index in 0..SOFT_SPOKEN_K {
                let delta_i = (delta >> bit_index) & 0x01;
                let global_bit = i * SOFT_SPOKEN_K + bit_index;
                packed_nabla[global_bit / 8] ^= delta_i << (global_bit % 8);
            }
        }

        // Same Fiat-Shamir transform as receiver.
        let digest = matrix_digest(sid, &round1.u);
        let chi: Vec<[u8; 16]> = (0..SOFT_SPOKEN_M).map(|j| derive_chi(&digest, j)).collect();

        const FROM: usize = SOFT_SPOKEN_M * S_BYTES;
        const TO: usize = (SOFT_SPOKEN_M + 1) * S_BYTES;

        for i in 0..LAMBDA_C {
            let mut q_row = [0u8; S_BYTES];

            for j in 0..SOFT_SPOKEN_M {
                let mut q_hat_j = [0u8; S_BYTES];
                q_hat_j.copy_from_slice(&w_matrix[i][j * S_BYTES..(j + 1) * S_BYTES]);
                let prod = binary_field_multiply_gf_2_128(&q_hat_j, &chi[j]);
                for k in 0..S_BYTES {
                    q_row[k] ^= prod[k];
                }
            }

            for (k, idx) in (FROM..TO).enumerate() {
                q_row[k] ^= w_matrix[i][idx];
            }

            // Compare against t[i] + delta_i * x.
            let bit = extract_bit(&packed_nabla, i);
            let mask = bit_to_mask(bit);
            let mut expected = [0u8; S_BYTES];
            for k in 0..S_BYTES {
                expected[k] = round1.t[i][k] ^ (mask & round1.x[k]);
            }
            assert_throw!(
                q_row == expected,
                "AbortProtocolAndBanReceiver",
                format!("dsg/softspoken: KOS check failed at row {}", i)
            );
        }

        // Transpose w_matrix to zeta of shape L_PRIME × LAMBDA_C, take first L rows.
        let mut zeta = transpose_bool_matrix(&w_matrix);

        let mut output = SenderExtendedOutput::default();
        for j in 0..L {
            // v_0[j] = randomize(zeta[j])
            output.v_0[j] = randomize_row(sid, j, &zeta[j]);
            // v_1[j] = randomize(zeta[j] XOR packed_nabla)
            for k in 0..LAMBDA_C_BYTES {
                zeta[j][k] ^= packed_nabla[k];
            }
            output.v_1[j] = randomize_row(sid, j, &zeta[j]);
        }

        Ok(output)
    }
}

// ── tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use rand::Rng;

    /// Produce a matched (SenderOTSeed, ReceiverOTSeed) pair without going
    /// through the keygen PPRF construction. Equivalent to "all but one"
    /// random seed OT setup but generated locally for testing.
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
            // Erase the chosen leaf from the receiver side.
            receiver.otp_dec_keys[i][chosen] = vec![0u8; LAMBDA_C_BYTES];
        }
        (sender, receiver)
    }

    #[test]
    fn gf2_128_fermat_squaring() {
        for _ in 0..3 {
            let r: [u8; 16] = rand::random();
            let mut t = r;
            for _ in 0..128 {
                t = binary_field_multiply_gf_2_128(&t, &t);
            }
            assert_eq!(t, r);
        }
    }

    #[test]
    fn soft_spoken_correctness() {
        let (sender_seed, receiver_seed) = fresh_seed_pair();
        let sid = "test-softspoken";
        let mut choices = vec![0u8; L_BYTES];
        rand::rng().fill_bytes(&mut choices);

        let (round1, recv_out) = SoftSpokenOTReceiver::process(sid, &sender_seed, &choices);
        let send_out = SoftSpokenOTSender::process(sid, &receiver_seed, &round1).unwrap();

        for i in 0..L {
            let bit = extract_bit(&choices, i);
            for k in 0..OT_WIDTH {
                let recv = &recv_out.v_x[i][k];
                let send = if bit == 1 { &send_out.v_1[i][k] } else { &send_out.v_0[i][k] };
                assert_eq!(recv, send, "row {} width {} bit={}", i, k, bit);
            }
        }
    }
}
