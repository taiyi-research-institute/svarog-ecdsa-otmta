//! Signing-time small helpers: session-id derivation, R commitments,
//! and the per-party pairwise randomization `zeta_i`.

use blake2::Blake2bVar;
use blake2::digest::{Update, VariableOutput};
use curve_abstract::{TrPoint, TrScalar};
use svarog_secp256k1::{Point, Scalar};

use super::super::dkg::PairwiseSeeds;

/// Derive a unique session-id for the (sender_i, receiver_j) RVOLE/MtA instance.
pub(crate) fn mta_session_id(final_sid: &str, sender_i: usize, receiver_j: usize) -> String {
    format!("{}/dsg/mta/s={}/r={}", final_sid, sender_i, receiver_j)
}

/// Hash commitment to a party's R_i = r_i*G with a fresh blind.
pub(crate) fn hash_commitment_r_i(
    sid: &str,
    big_r_i: &Point,
    blind: &[u8; 32],
) -> [u8; 32] {
    let mut h = Blake2bVar::new(32).unwrap();
    h.update(b"dsg/commit/r_i");
    h.update(sid.as_bytes());
    h.update(&big_r_i.to_bytes());
    h.update(blind);
    let mut out = [0u8; 32];
    h.finalize_variable(&mut out).unwrap();
    out
}

pub(crate) fn verify_commitment_r_i(
    sid: &str,
    big_r_i: &Point,
    blind: &[u8; 32],
    commitment: &[u8; 32],
) -> bool {
    let recomputed = hash_commitment_r_i(sid, big_r_i, blind);
    &recomputed[..] == &commitment[..]
}

/// Derive `v_{ij} = Hash(seed_ij || sig_id)` reduced mod n.
fn pairwise_v(seed: &[u8; 32], sig_id: &str) -> Scalar {
    let mut h = Blake2bVar::new(32).unwrap();
    h.update(b"dsg/zeta/pairwise");
    h.update(seed);
    h.update(sig_id.as_bytes());
    let mut out = [0u8; 32];
    h.finalize_variable(&mut out).unwrap();
    Scalar::new_from_bytes(&out)
}

/// `zeta_i = Σ_{j<i} v_{ji} − Σ_{j>i} v_{ij}` over signers j ≠ i.
///
/// `seeds.rec` keyed by j<i (seed received from j); `seeds.sent` keyed by j>i (seed I sent to j).
pub(crate) fn compute_zeta_i(
    seeds: &PairwiseSeeds,
    my_id: usize,
    sig_id: &str,
    others: &[usize],
) -> Scalar {
    let mut acc = Scalar::new(0);
    for &j in others {
        if j < my_id {
            let seed = seeds.rec.get(&j).expect("missing rec seed");
            acc = acc.add(&pairwise_v(seed, sig_id));
        } else if j > my_id {
            let seed = seeds.sent.get(&j).expect("missing sent seed");
            acc = acc.sub(&pairwise_v(seed, sig_id));
        }
    }
    acc
}
