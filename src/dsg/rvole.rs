//! Random Vector OLE (DKLS23 §5.2). For each of `L_BATCH` Sender inputs `a_k`
//! and one Receiver input `b`, produce additive shares `c_k`, `d_k` such that
//! `c_k + d_k = a_k * b` mod n. RHO=1 extra column is used for the consistency
//! mu-check that lets the Receiver reject a cheating Sender.
//!
//! Mirrors `sl-oblivious/src/rvole.rs`. Uses our own SoftSpoken layer.

use erreur::*;
use serde::{Deserialize, Serialize};

use curve_abstract::TrScalar;
use svarog_secp256k1::Scalar;

use super::super::dkg::{ReceiverOTSeed, SenderOTSeed};
use super::soft_spoken_ot::{
    KAPPA_BYTES, L, L_BATCH, L_BYTES, OT_WIDTH, RHO, ReceiverExtendedOutput, Round1Output,
    SoftSpokenOTReceiver, SoftSpokenOTSender,
};

const XI: usize = L; // gadget length

#[derive(Clone, Serialize, Deserialize)]
pub struct RVOLEOutput {
    pub a_tilde: Vec<Vec<Vec<u8>>>, // [XI][OT_WIDTH][KAPPA_BYTES]
    pub eta: Vec<Vec<u8>>,          // [RHO][KAPPA_BYTES]
    pub mu_hash: Vec<u8>,           // 64 bytes
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

fn theta_table(sid: &str, a_tilde: &[Vec<Vec<u8>>]) -> Vec<Vec<Scalar>> {
    // Bind a_tilde via a chain hash to make theta dependent on its content.
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
    pub beta: Vec<u8>, // L_BYTES
    pub recv_out: ReceiverExtendedOutput,
}

impl RVOLEReceiver {
    pub fn new(
        sid: &str,
        sender_seed: &SenderOTSeed,
    ) -> (RVOLEReceiver, Round1Output, Scalar) {
        use rand::Rng;
        let mut beta = vec![0u8; L_BYTES];
        rand::rng().fill_bytes(&mut beta);

        // b = <g, beta>
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

    pub fn process(&self, output: &RVOLEOutput) -> Resultat<[Scalar; L_BATCH]> {
        let theta = theta_table(&self.sid, &output.a_tilde);

        // d_dot[j][i] for i in [L_BATCH], d_hat[j][k] for k in [RHO].
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

        // mu_prime_hash
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

        // d[i] = <g, d_dot[..][i]>
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

        // c[i] = -Σ_j g_j * alpha_0(j, i)
        let mut c: [Scalar; L_BATCH] = [Scalar::new(0), Scalar::new(0)];
        for i in 0..L_BATCH {
            let mut acc = Scalar::new(0);
            for j in 0..XI {
                acc = acc.add(&gadget[j].mul(&alpha_0(j, i)));
            }
            c[i] = acc.neg();
        }

        // Sample eta values.
        let eta_vals: Vec<Scalar> = (0..RHO).map(|_| Scalar::new_rand()).collect();

        // a_tilde[j][i]:
        //   for i < L_BATCH:        alpha_0(j, i)            - alpha_1(j, i) + a[i]
        //   for i = L_BATCH + k:    alpha_0(j, L_BATCH + k)  - alpha_1(j, L_BATCH + k) + eta[k]
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

        // theta after a_tilde fixed.
        let theta = theta_table(sid, &output.a_tilde);

        // Final eta sent over the wire: eta_k + Σ_i theta[k][i] * a[i].
        for k in 0..RHO {
            let mut s = eta_vals[k].clone();
            for i in 0..L_BATCH {
                s = s.add(&theta[k][i].mul(&a[i]));
            }
            output.eta[k] = s.to_bytes();
        }

        // mu_hash: bind output via the same chain as Receiver expects.
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
