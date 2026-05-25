use std::collections::{HashMap, HashSet};

use blake2::Blake2bVar;
use blake2::digest::{Update, VariableOutput};
use curve_abstract::TrPoint;
use svarog_secp256k1::Point;

pub(crate) fn hash_commitment_r_batch(
    sid: &str,
    big_r_list: &[Point],
    blind: &[u8; 32],
) -> [u8; 32] {
    let mut h = Blake2bVar::new(32).unwrap();
    h.update(b"dsg_batch/commit/r");
    h.update(sid.as_bytes());
    h.update(&(big_r_list.len() as u64).to_le_bytes());
    for r in big_r_list {
        h.update(&r.to_bytes());
    }
    h.update(blind);
    let mut out = [0u8; 32];
    h.finalize_variable(&mut out).unwrap();
    out
}

pub(crate) fn per_sig_sid(sid: &str, s: usize) -> String {
    format!("{}/batch/sig/{}", sid, s)
}

pub(crate) fn sorted_others(signers: &HashSet<usize>, me: usize) -> Vec<usize> {
    let mut v: Vec<usize> = signers.iter().copied().filter(|&p| p != me).collect();
    v.sort();
    v
}

pub(crate) fn digest_after_round1(
    sid: &str,
    pk_prime_per_sig: &[Point],
    commits: &HashMap<usize, [u8; 32]>,
    signers: &HashSet<usize>,
) -> [u8; 32] {
    let mut sorted: Vec<usize> = signers.iter().copied().collect();
    sorted.sort();
    let mut h = Blake2bVar::new(32).unwrap();
    h.update(b"dsg_batch/digest");
    h.update(sid.as_bytes());
    h.update(&(pk_prime_per_sig.len() as u64).to_le_bytes());
    for pk in pk_prime_per_sig {
        h.update(&pk.to_bytes());
    }
    for j in sorted {
        h.update(&(j as u64).to_le_bytes());
        h.update(&commits[&j]);
    }
    let mut out = [0u8; 32];
    h.finalize_variable(&mut out).unwrap();
    out
}
