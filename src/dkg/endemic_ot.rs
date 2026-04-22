/// Endemic OT (secp256k1)
///
/// Ideal functionality:
/// Execute KAPPA OT instances in parallel. For each instance,
/// * Receiver holds choice bit w, obtains decryption key rho_w.
/// * Sender obtains (rho_0, rho_1), but does not learn w.
///
/// Protocol flow:
/// 1. Receiver -> Sender: for each idx send R_0, R_1
/// 2. Sender -> Receiver: for each idx send M_b_0, M_b_1
/// 3. Both parties compute OT keys rho locally.
///
/// Reference: Fig.8, https://eprint.iacr.org/2019/706.pdf
use curve_abstract::{TrPoint, TrScalar};
use erreur::*;
use rand::Rng;
use serde::{Deserialize, Serialize};
use svarog_secp256k1::{Scalar, Point};

/// Security parameter: 256 parallel OT instances (secp256k1 scalar bit length).
const KAPPA: usize = 256;

/// Byte length corresponding to KAPPA.
const KAPPA_BYTES: usize = 32;

fn endemic_ot_idx(idx: usize) -> u16 {
    debug_assert!(idx <= u16::MAX as usize);
    idx as u16
}

// Helper: extract bit `idx` from a packed byte array.
fn extract_bit(packed: &[u8], idx: usize) -> u8 {
    (packed[idx / 8] >> (idx % 8)) & 1
}

// Hash-to-curve (try-and-increment): 
// maps `seed` to a secp256k1 point whose DL is unknown.
// On each attempt, we hash (tag, seed, counter) to a candidate x-coordinate 
// and checks whether 0x02||x is a valid compressed point.
// ~50% success per try; expected 2 iterations.
fn hash_to_curve(seed: &[u8]) -> Point {
    let mut ctr: u32 = 0;
    loop {
        let x = hash!(32; b"endemic-ot-htg", seed, ctr.to_be_bytes());
        let mut buf = [0u8; 33];
        buf[0] = 0x02;
        buf[1..].copy_from_slice(&x);
        if let Ok(p) = Point::new_from_bytes(&buf) {
            return p;
        }
        ctr += 1;
    }
}

/// Endemic OT first message (Receiver -> Sender).
/// Contains (R_0, R_1) curve points for each idx.
#[derive(Clone, Serialize, Deserialize)]
pub struct EndemicOTMsg1 {
    R0_list: Vec<Point>,
    R1_list: Vec<Point>,
}

impl Default for EndemicOTMsg1 {
    fn default() -> Self {
        Self {
            R0_list: vec![],
            R1_list: vec![],
        }
    }
}

/// Endemic OT second message (Sender -> Receiver).
/// Contains $M_{b,0}$ and $M_{b,1}$ curve points for each idx.
#[derive(Clone, Serialize, Deserialize)]
pub struct EndemicOTMsg2 {
    mb0_list: Vec<Point>,
    mb1_list: Vec<Point>,
}

impl Default for EndemicOTMsg2 {
    fn default() -> Self {
        Self { mb0_list: vec![], mb1_list: vec![] }
    }
}

/// Sender encryption key pair for a single idx.
pub struct OTPEncKeys {
    pub rho_0: Vec<u8>,
    pub rho_1: Vec<u8>,
}

/// Sender output: KAPPA encryption key pairs.
pub struct SenderOutput {
    pub otp_enc_keys: Vec<OTPEncKeys>,
}

/// Receiver output: choice bits + KAPPA decryption keys.
pub struct ReceiverOutput {
    pub choice_bits: Vec<u8>,
    pub otp_dec_keys: Vec<Vec<u8>>,
}

/// Receiver intermediate state. Created in new(), completed after calling process() on Msg2.
#[derive(Clone, Serialize, Deserialize)]
pub struct EndemicOTReceiver {
    choices: Vec<u8>,
    blind_terms: Vec<Scalar>,
}

impl EndemicOTReceiver {
    /// Step 1: generate Msg1. Persist choice bits and blinding scalars.
    ///
    /// For each OT instance, generates:
    /// * Choice bit $w$, blinding scalar $t_a$, and $R_{1-w} = \mathrm{HG}(\text{nonce})$.
    /// * $R_w = t_a \cdot G - \mathrm{H}(\text{tag}_h, w, \text{idx}, \text{sid}, R_{1-w}) \cdot G$.
    pub fn new(sid: &str, out_msg1: &mut EndemicOTMsg1) -> Self {
        out_msg1.R0_list = Vec::with_capacity(KAPPA);
        out_msg1.R1_list = Vec::with_capacity(KAPPA);

        let mut choices = vec![0u8; KAPPA_BYTES];
        rand::rng().fill_bytes(&mut choices);
        let blind_terms: Vec<Scalar> = (0..KAPPA).map(|_| Scalar::new_rand()).collect();

        for idx in 0..KAPPA {
            let choice_bit = u16::from(extract_bit(&choices, idx));
            let blind = &blind_terms[idx];

            // R_{1-w}: hash-to-curve with fresh nonce so DL is unknown (ROM assumption).
            let mut nonce = [0u8; 32];
            rand::rng().fill_bytes(&mut nonce);
            let Rblind = hash_to_curve(&nonce);

            // $R_w = t_a*G − H(w, idx, sid, R_{1-w})·G$
            let hw = Point::new_gx(&Scalar::new_from_bytes(&hash!(
                KAPPA_BYTES;
                b"endemic-ot-h",
                choice_bit.to_be_bytes(),
                endemic_ot_idx(idx).to_be_bytes(),
                sid.as_bytes(),
                Rblind.to_bytes()
            )));
            let Rchoose = Point::new_gx(blind).sub(&hw);

            if choice_bit == 0 {
                out_msg1.R0_list.push(Rchoose);
                out_msg1.R1_list.push(Rblind);
            } else {
                out_msg1.R0_list.push(Rblind);
                out_msg1.R1_list.push(Rchoose);
            }
        }

        Self {
            choices,
            blind_terms,
        }
    }

    /// Process Msg2 and compute the Receiver's OT output.
    ///
    /// For each idx: $\rho_w = \mathrm{H}(\text{idx},\ M_{b,w} \cdot t_a)$.
    pub fn process(self, msg2: &EndemicOTMsg2) -> Resultat<ReceiverOutput> {
        assert_throw!(
            msg2.mb0_list.len() == KAPPA && msg2.mb1_list.len() == KAPPA,
            "EndemicOTMsg2LengthMismatch",
            format!(
                "expected {} entries in each Msg2 list, got mb0: {}, mb1: {}",
                KAPPA,
                msg2.mb0_list.len(),
                msg2.mb1_list.len()
            )
        );

        let mut otp_dec_keys = Vec::with_capacity(KAPPA);
        for idx in 0..KAPPA {
            let w = extract_bit(&self.choices, idx);
            let m_b_w = if w == 0 {
                &msg2.mb0_list[idx]
            } else {
                &msg2.mb1_list[idx]
            };
            // rho_w = H'(idx, M_{b,w} · t_a)
            let shared = m_b_w.mul_x(&self.blind_terms[idx]);
            otp_dec_keys.push(hash!(
                KAPPA_BYTES;
                b"endemic-ot-seed",
                endemic_ot_idx(idx).to_be_bytes(),
                shared.to_bytes()
            ));
        }

        Ok(ReceiverOutput {
            choice_bits: self.choices,
            otp_dec_keys,
        })
    }
}

// ════════════════════════════════════════════════
// Sender (stateless)
// ════════════════════════════════════════════════

pub struct EndemicOTSender;

impl EndemicOTSender {
    /// Step 2: process Msg1, produce Msg2, output Sender OT keys.
    ///
    /// For each OT instance idx:
    ///   $M_{a,0} = R_0 + \mathrm{H}(0, \text{idx}, \text{sid}, R_1) \cdot G$
    ///   $M_{a,1} = R_1 + \mathrm{H}(1, \text{idx}, \text{sid}, R_0) \cdot G$
    ///   $t_{b,0}, t_{b,1} \leftarrow \mathbb{Z}_q$
    ///   $M_{b,0} = t_{b,0} \cdot G,\quad M_{b,1} = t_{b,1} \cdot G$  -> written to Msg2
    ///   $\rho_0 = \mathrm{H}(\text{idx}, t_{b,0} \cdot M_{a,0})$
    ///   $\rho_1 = \mathrm{H}(\text{idx}, t_{b,1} \cdot M_{a,1})$
    pub fn process(
        sid: &str,
        msg1: &EndemicOTMsg1,
        msg2: &mut EndemicOTMsg2,
    ) -> Resultat<SenderOutput> {
        assert_throw!(
            msg1.R0_list.len() == KAPPA && msg1.R1_list.len() == KAPPA,
            "EndemicOTMsg1LengthMismatch",
            format!(
                "expected {} entries in Msg1, got R0_list: {}, R1_list: {}",
                KAPPA,
                msg1.R0_list.len(),
                msg1.R1_list.len()
            )
        );

        msg2.mb0_list = Vec::with_capacity(KAPPA);
        msg2.mb1_list = Vec::with_capacity(KAPPA);
        let mut otp_enc_keys = Vec::with_capacity(KAPPA);

        for idx in 0..KAPPA {
            let r_0 = &msg1.R0_list[idx];
            let r_1 = &msg1.R1_list[idx];

            let Ma0 = r_0.add(&Point::new_gx(&Scalar::new_from_bytes(&hash!(
                KAPPA_BYTES;
                b"endemic-ot-h",
                0u16.to_be_bytes(),
                endemic_ot_idx(idx).to_be_bytes(),
                sid.as_bytes(),
                r_1.to_bytes()
            ))));
            let Ma1 = r_1.add(&Point::new_gx(&Scalar::new_from_bytes(&hash!(
                KAPPA_BYTES;
                b"endemic-ot-h",
                1u16.to_be_bytes(),
                endemic_ot_idx(idx).to_be_bytes(),
                sid.as_bytes(),
                r_0.to_bytes()
            ))));

            let tb0 = Scalar::new_rand();
            let tb1 = Scalar::new_rand();

            let m_b_0 = Point::new_gx(&tb0);
            let m_b_1 = Point::new_gx(&tb1);
            msg2.mb0_list.push(m_b_0);
            msg2.mb1_list.push(m_b_1);

            let rho_0 = hash!(
                KAPPA_BYTES;
                b"endemic-ot-seed",
                endemic_ot_idx(idx).to_be_bytes(),
                Ma0.mul_x(&tb0).to_bytes()
            );
            let rho_1 = hash!(
                KAPPA_BYTES;
                b"endemic-ot-seed",
                endemic_ot_idx(idx).to_be_bytes(),
                Ma1.mul_x(&tb1).to_bytes()
            );

            otp_enc_keys.push(OTPEncKeys { rho_0, rho_1 });
        }

        Ok(SenderOutput { otp_enc_keys })
    }
}

// ════════════════════════════════════════════════
// Tests
// ════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use curve_abstract::{TrPoint, TrScalar};
    use rand::Rng;
    use svarog_secp256k1::{Scalar, Point};

    /// Correctness: Receiver's rho_w must equal Sender's rho_w.
    #[test]
    fn test_endemic_ot_correctness() {
        let sid = "test-endemic-ot-session";

        let mut msg1 = EndemicOTMsg1::default();
        let receiver = EndemicOTReceiver::new(sid, &mut msg1);

        let mut msg2 = EndemicOTMsg2::default();
        let sender_output = EndemicOTSender::process(sid, &msg1, &mut msg2).unwrap();

        let receiver_output = receiver.process(&msg2).unwrap();

        for idx in 0..KAPPA {
            let w = extract_bit(&receiver_output.choice_bits, idx);
            let sender_rho = if w == 0 {
                &sender_output.otp_enc_keys[idx].rho_0
            } else {
                &sender_output.otp_enc_keys[idx].rho_1
            };
            assert_eq!(
                sender_rho, &receiver_output.otp_dec_keys[idx],
                "OT key mismatch: idx={}, w={}",
                idx, w
            );
        }
    }

    /// Security vulnerability demo: a malicious Receiver who retains the DL of $R_{1-w}$
    /// can recover $\rho_{1-w}$, confirming the attack in endemic_ot.md §5.2.
    ///
    /// The attack: $R_{1-w} = s \cdot G$ with $s$ known.
    /// Then $M_{a,1-w} = (s + \alpha_{1-w}) \cdot G$, so
    /// $t_{b,1-w} \cdot M_{a,1-w} = (s + \alpha_{1-w}) \cdot M_{b,1-w}$.
    #[test]
    fn test_evil_receiver_breaks_sender_privacy() {
        let sid = "test-evil-receiver";

        // --- Evil Receiver: same as EndemicOTReceiver::new but retains s. ---
        let mut choices = vec![0u8; KAPPA_BYTES];
        rand::rng().fill_bytes(&mut choices);
        let blind_terms: Vec<Scalar> = (0..KAPPA).map(|_| Scalar::new_rand()).collect();
        let mut evil_s_terms: Vec<Scalar> = Vec::with_capacity(KAPPA);

        let mut msg1 = EndemicOTMsg1::default();
        msg1.R0_list = Vec::with_capacity(KAPPA);
        msg1.R1_list = Vec::with_capacity(KAPPA);

        for idx in 0..KAPPA {
            let choice_bit = u16::from(extract_bit(&choices, idx));
            let blind = &blind_terms[idx];

            let s = Scalar::new_rand();
            let Rblind = Point::new_gx(&s);
            evil_s_terms.push(s);

            let hw = Point::new_gx(&Scalar::new_from_bytes(&hash!(
                KAPPA_BYTES;
                b"endemic-ot-h",
                choice_bit.to_be_bytes(),
                endemic_ot_idx(idx).to_be_bytes(),
                sid.as_bytes(),
                Rblind.to_bytes()
            )));
            let Rchoose = Point::new_gx(blind).sub(&hw);

            if choice_bit == 0 {
                msg1.R0_list.push(Rchoose);
                msg1.R1_list.push(Rblind);
            } else {
                msg1.R0_list.push(Rblind);
                msg1.R1_list.push(Rchoose);
            }
        }

        let mut msg2 = EndemicOTMsg2::default();
        let sender_output = EndemicOTSender::process(sid, &msg1, &mut msg2).unwrap();

        // --- Evil Receiver computes rho_{1-w} for every idx. ---
        for idx in 0..KAPPA {
            let w = extract_bit(&choices, idx);
            // r_w is the R point for the chosen side; alpha is hashed with (1-w, idx, sid, r_w).
            let (one_minus_w, r_w, m_b_other) = if w == 0 {
                (1u16, &msg1.R0_list[idx], &msg2.mb1_list[idx])
            } else {
                (0u16, &msg1.R1_list[idx], &msg2.mb0_list[idx])
            };

            // alpha_{1-w} = H(1-w, idx, sid, R_w)  — public info
            let alpha = Scalar::new_from_bytes(&hash!(
                KAPPA_BYTES;
                b"endemic-ot-h",
                one_minus_w.to_be_bytes(),
                endemic_ot_idx(idx).to_be_bytes(),
                sid.as_bytes(),
                r_w.to_bytes()
            ));

            // t_{b,1-w} * M_{a,1-w} = (s + alpha) * M_{b,1-w}
            let shared = m_b_other.mul_x(&evil_s_terms[idx].add(&alpha));

            let evil_rho = hash!(
                KAPPA_BYTES;
                b"endemic-ot-seed",
                endemic_ot_idx(idx).to_be_bytes(),
                shared.to_bytes()
            );

            let sender_rho_other = if w == 0 {
                &sender_output.otp_enc_keys[idx].rho_1
            } else {
                &sender_output.otp_enc_keys[idx].rho_0
            };

            assert_eq!(
                evil_rho, *sender_rho_other,
                "evil receiver failed to recover rho_{{1-w}}: idx={}, w={}",
                idx, w
            );
        }
    }
}
