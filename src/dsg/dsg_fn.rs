use std::collections::HashSet;

use curve_abstract::TrMessenger;
use erreur::*;
use svarog_lagrange::Keystore;
use svarog_secp256k1::Secp256k1;

pub async fn sign(
    _ch: impl TrMessenger,
    _sid: String,
    _players: HashSet<usize>,
    _keystore: &mut Keystore<Secp256k1>,
) -> Resultat<()> {
    todo!("sign is not implemented yet; decode keygen aux from keystore.aux first")
}
