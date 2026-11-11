//! Session-local encryption for point-to-point messages.
//!
//! Noise NN protects against passive observation only: peers are not
//! authenticated and an active intermediary can impersonate either side.
//! Broadcast messages are encrypted separately for each recipient, but this
//! does not guarantee broadcast agreement against an active adversary.
//! The existing `TrMessenger` API does not tie receive destinations to the
//! exchange lifetime; this private adapter inherits that limitation. Its only
//! callers must keep every registered destination alive until exchange returns.

use curve_abstract::TrMessenger;
use serde::{Deserialize, Serialize};
use std::{
    any::Any,
    collections::{HashMap, HashSet},
};

// NN uses no static identity keys, so neither peer is authenticated.
// 25519 provides ephemeral X25519 key exchange; AESGCM encrypts messages;
// SHA256 provides the hash and key derivation used by Noise.
const PATTERN: &str = "Noise_NN_25519_AESGCM_SHA256";
const HANDSHAKE_1: &str = "__svarog_secure_nn_1";
const HANDSHAKE_2: &str = "__svarog_secure_nn_2";
const CHUNK: usize = 48 * 1024;
// Leave room below the relay's request limit for framing and metadata.
const MAX_MESSAGE: usize = 120 * 1024 * 1024;
const MAX_WIRE: usize = 124 * 1024 * 1024;

#[derive(Debug)]
pub(crate) struct SecureError(String);
impl std::fmt::Display for SecureError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}
impl std::error::Error for SecureError {}
fn err(e: impl std::fmt::Display) -> SecureError {
    SecureError(e.to_string())
}

#[derive(Clone, Serialize, Deserialize)]
struct Fragment {
    nonce: u64,
    #[serde(with = "serde_bytes")]
    ciphertext: Vec<u8>,
}
#[derive(Clone, Serialize, Deserialize)]
struct WireMessage {
    fragments: Vec<Fragment>,
}
#[derive(Serialize, Deserialize)]
struct Payload {
    sid: String,
    topic: String,
    src: usize,
    dst: usize,
    seq: usize,
    index: usize,
    total: usize,
    #[serde(with = "serde_bytes")]
    data: Vec<u8>,
}
#[derive(Clone, Hash, Eq, PartialEq)]
struct Address {
    sid: String,
    topic: String,
    src: usize,
    dst: usize,
    seq: usize,
}
struct Peer {
    state: snow::StatelessTransportState,
    next_nonce: u64,
    received: HashSet<u64>,
}
type Decode = Box<dyn Fn(&[u8], &mut dyn Any) -> Result<(), SecureError> + Send>;
struct Pending {
    addr: Address,
    buf: Box<WireMessage>,
    out: *mut dyn Any,
    decode: Decode,
}

pub(crate) struct SecureMessenger<M: TrMessenger> {
    // Drop the underlying messenger before the boxed receive buffers it holds.
    inner: M,
    _handshake_buffers: (HashMap<usize, Vec<u8>>, HashMap<usize, Vec<u8>>),
    sid: String,
    me: usize,
    peers: HashMap<usize, Peer>,
    pending: Vec<Pending>,
    pending_keys: HashSet<Address>,
    sent_keys: HashSet<Address>,
    error: Option<SecureError>,
}
// The existing trait permits storing borrowed receive destinations without
// enforcing their lifetime. All values accepted by register_recv are Send;
// the private call sites must retain them throughout exchange.
unsafe impl<M: TrMessenger> Send for SecureMessenger<M> {}

impl<M: TrMessenger> SecureMessenger<M> {
    pub(crate) async fn establish(
        inner: M,
        sid: &str,
        players: &HashSet<usize>,
        me: usize,
    ) -> Result<Self, SecureError> {
        if !players.contains(&me) || players.contains(&0) || sid.is_empty() {
            return Err(err("invalid secure-session participants or sid"));
        }
        let params: snow::params::NoiseParams = PATTERN.parse().map_err(err)?;
        let mut states = HashMap::new();
        let mut first = HashMap::<usize, Vec<u8>>::new();
        let mut second = HashMap::<usize, Vec<u8>>::new();
        for &peer in players {
            if peer == me {
                continue;
            }
            // Length-prefix sid and the ordered participant pair in the transcript.
            let mut prologue = b"svarog-noise-nn-v1".to_vec();
            prologue.extend_from_slice(&(sid.len() as u64).to_be_bytes());
            prologue.extend_from_slice(sid.as_bytes());
            prologue.extend_from_slice(&(me.min(peer) as u64).to_be_bytes());
            prologue.extend_from_slice(&(me.max(peer) as u64).to_be_bytes());
            let builder = snow::Builder::new(params.clone())
                .prologue(&prologue)
                .map_err(err)?;
            let state = if me < peer {
                builder.build_initiator()
            } else {
                builder.build_responder()
            }
            .map_err(err)?;
            states.insert(peer, state);
            first.insert(peer, Vec::new());
            second.insert(peer, Vec::new());
        }
        // Drop the messenger before handshake receive buffers if setup is
        // cancelled or fails with registered receives still pending.
        let mut inner = inner;
        for (&peer, state) in &mut states {
            if me < peer {
                let mut buf = vec![0; 256];
                let n = state.write_message(&[], &mut buf).map_err(err)?;
                buf.truncate(n);
                inner.register_send(&buf, sid, HANDSHAKE_1, me, peer, 0);
            } else {
                inner.register_recv(
                    first
                        .get_mut(&peer)
                        .ok_or_else(|| err("missing handshake buffer"))?,
                    sid,
                    HANDSHAKE_1,
                    peer,
                    me,
                    0,
                );
            }
        }
        inner.exchange().await.map_err(err)?;
        for (&peer, state) in &mut states {
            if me > peer {
                let mut buf = vec![0; 256];
                state
                    .read_message(
                        first.get(&peer).ok_or_else(|| err("missing handshake"))?,
                        &mut buf,
                    )
                    .map_err(err)?;
                let n = state.write_message(&[], &mut buf).map_err(err)?;
                buf.truncate(n);
                inner.register_send(&buf, sid, HANDSHAKE_2, me, peer, 0);
            } else {
                inner.register_recv(
                    second
                        .get_mut(&peer)
                        .ok_or_else(|| err("missing handshake buffer"))?,
                    sid,
                    HANDSHAKE_2,
                    peer,
                    me,
                    0,
                );
            }
        }
        inner.exchange().await.map_err(err)?;
        let mut peers = HashMap::new();
        for (peer, mut state) in states {
            if me < peer {
                let mut buf = vec![0; 256];
                state
                    .read_message(
                        second.get(&peer).ok_or_else(|| err("missing handshake"))?,
                        &mut buf,
                    )
                    .map_err(err)?;
            }
            let state = state.into_stateless_transport_mode().map_err(err)?;
            peers.insert(
                peer,
                Peer {
                    state,
                    next_nonce: 0,
                    received: HashSet::new(),
                },
            );
        }
        Ok(Self {
            inner,
            _handshake_buffers: (first, second),
            sid: sid.into(),
            me,
            peers,
            pending: Vec::new(),
            pending_keys: HashSet::new(),
            sent_keys: HashSet::new(),
            error: None,
        })
    }
    fn valid_sid(&self, sid: &str) -> bool {
        sid == self.sid
            || sid
                .strip_prefix(&self.sid)
                .is_some_and(|s| s.starts_with('/'))
    }
    fn seal(
        &mut self,
        address: &Address,
        receiver: usize,
        bytes: &[u8],
    ) -> Result<WireMessage, SecureError> {
        if !self.valid_sid(&address.sid)
            || address.src != self.me
            || (address.dst != 0 && address.dst != receiver)
        {
            return Err(err("invalid outgoing address"));
        }
        if bytes.len() > MAX_MESSAGE {
            return Err(err("message exceeds limit"));
        }
        let peer = self
            .peers
            .get_mut(&receiver)
            .ok_or_else(|| err("unknown receiver"))?;
        let total = bytes.len().max(1).div_ceil(CHUNK);
        let mut fragments = Vec::with_capacity(total);
        for index in 0..total {
            let start = index * CHUNK;
            let end = (start + CHUNK).min(bytes.len());
            let data = if bytes.is_empty() {
                vec![]
            } else {
                bytes[start..end].to_vec()
            };
            let payload = Payload {
                sid: address.sid.clone(),
                topic: address.topic.clone(),
                src: address.src,
                dst: address.dst,
                seq: address.seq,
                index,
                total,
                data,
            };
            let plain = serde_pickle::to_vec(&payload, Default::default()).map_err(err)?;
            if plain.len() > 65535 - 16 {
                return Err(err("secure fragment header too large"));
            }
            let nonce = peer.next_nonce;
            peer.next_nonce = nonce.checked_add(1).ok_or_else(|| err("nonce exhausted"))?;
            if nonce == u64::MAX {
                return Err(err("nonce exhausted"));
            }
            let mut ciphertext = vec![0; plain.len() + 16];
            let n = peer
                .state
                .write_message(nonce, &plain, &mut ciphertext)
                .map_err(err)?;
            ciphertext.truncate(n);
            fragments.push(Fragment { nonce, ciphertext });
        }
        let wire = WireMessage { fragments };
        if serde_pickle::to_vec(&wire, Default::default())
            .map_err(err)?
            .len()
            > MAX_WIRE
        {
            return Err(err("encrypted message exceeds wire limit"));
        }
        Ok(wire)
    }
    fn open(&mut self, address: &Address, message: &WireMessage) -> Result<Vec<u8>, SecureError> {
        if !self.valid_sid(&address.sid)
            || (address.dst != 0 && address.dst != self.me)
            || address.src == 0
        {
            return Err(err("invalid incoming address"));
        }
        let peer = self
            .peers
            .get_mut(&address.src)
            .ok_or_else(|| err("unknown sender"))?;
        let total = message.fragments.len();
        if total == 0 || total > MAX_MESSAGE.div_ceil(CHUNK) {
            return Err(err("invalid fragment count"));
        }
        let mut parts = Vec::with_capacity(total);
        for (index, fragment) in message.fragments.iter().enumerate() {
            if fragment.ciphertext.len() > 65535 || peer.received.contains(&fragment.nonce) {
                return Err(err("invalid or replayed fragment"));
            }
            let mut plain = vec![0; fragment.ciphertext.len()];
            let n = peer
                .state
                .read_message(fragment.nonce, &fragment.ciphertext, &mut plain)
                .map_err(err)?;
            plain.truncate(n);
            let p: Payload = serde_pickle::from_slice(&plain, Default::default()).map_err(err)?;
            if p.sid != address.sid
                || p.topic != address.topic
                || p.src != address.src
                || p.dst != address.dst
                || p.seq != address.seq
                || p.index != index
                || p.total != total
                || p.data.len() > CHUNK
            {
                return Err(err("fragment context mismatch"));
            }
            peer.received.insert(fragment.nonce);
            parts.extend_from_slice(&p.data);
            if parts.len() > MAX_MESSAGE {
                return Err(err("message exceeds limit"));
            }
        }
        Ok(parts)
    }
}

impl<M: TrMessenger> TrMessenger for SecureMessenger<M> {
    type Err = SecureError;
    fn register_send<T>(
        &mut self,
        val: &T,
        sid: &str,
        topic: &str,
        src: usize,
        dst: usize,
        seq: usize,
    ) -> &mut Self
    where
        T: Serialize + for<'de> Deserialize<'de> + Clone + Send + Sync + 'static,
    {
        if self.error.is_some() {
            return self;
        }
        let address = Address {
            sid: sid.into(),
            topic: topic.into(),
            src,
            dst,
            seq,
        };
        if !self.sent_keys.insert(address.clone()) {
            self.error = Some(err("duplicate send address"));
            return self;
        }
        let bytes = match serde_pickle::to_vec(val, Default::default()) {
            Ok(bytes) => bytes,
            Err(e) => {
                self.error = Some(err(e));
                return self;
            }
        };
        let receivers: Vec<usize> = if dst == 0 {
            self.peers.keys().copied().collect()
        } else {
            vec![dst]
        };
        let route = format!(
            "{}{}",
            if dst == 0 {
                "__svarog_secure_b/"
            } else {
                "__svarog_secure_p/"
            },
            topic
        );
        for receiver in receivers {
            match self.seal(&address, receiver, &bytes) {
                Ok(wire) => {
                    self.inner
                        .register_send(&wire, sid, &route, src, receiver, seq);
                }
                Err(e) => {
                    self.error = Some(e);
                    break;
                }
            }
        }
        self
    }
    fn register_recv<T>(
        &mut self,
        out: &mut T,
        sid: &str,
        topic: &str,
        src: usize,
        dst: usize,
        seq: usize,
    ) -> &mut Self
    where
        T: Serialize + for<'de> Deserialize<'de> + Clone + Send + Sync + 'static,
    {
        if self.error.is_some() {
            return self;
        }
        let addr = Address {
            sid: sid.into(),
            topic: topic.into(),
            src,
            dst,
            seq,
        };
        if !self.pending_keys.insert(addr.clone()) {
            self.error = Some(err("duplicate receive address"));
            return self;
        }
        let mut buf = Box::new(WireMessage { fragments: vec![] });
        let route = format!(
            "{}{}",
            if dst == 0 {
                "__svarog_secure_b/"
            } else {
                "__svarog_secure_p/"
            },
            topic
        );
        self.inner
            .register_recv(buf.as_mut(), sid, &route, src, self.me, seq);
        let decode: Decode = Box::new(|bytes, output| {
            let obj = output
                .downcast_mut::<T>()
                .ok_or_else(|| err("invalid receive type"))?;
            *obj = serde_pickle::from_slice(bytes, Default::default()).map_err(err)?;
            Ok(())
        });
        self.pending.push(Pending {
            addr,
            buf,
            out: out as *mut T as *mut dyn Any,
            decode,
        });
        self
    }
    async fn exchange(&mut self) -> Result<(), SecureError> {
        if let Some(e) = &self.error {
            return Err(err(e));
        }
        // If the future is cancelled at the await point, do not reuse a
        // messenger whose sends, receives, and nonce state may be partial.
        self.error = Some(err("secure exchange was interrupted"));
        if let Err(e) = self.inner.exchange().await {
            self.error = Some(err(e));
            return Err(err(self.error.as_ref().unwrap()));
        }
        let pending = std::mem::take(&mut self.pending);
        for item in pending {
            let result = self.open(&item.addr, &item.buf).and_then(|bytes| {
                // The private protocol callers retain each destination until this exchange completes.
                unsafe { (item.decode)(&bytes, &mut *item.out) }
            });
            if let Err(e) = result {
                self.error = Some(e);
                return Err(err(self.error.as_ref().unwrap()));
            }
        }
        self.pending_keys.clear();
        self.error = None;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::toy_messenger::ToyMessenger;
    use dashmap::DashMap;
    use std::sync::Arc;

    async fn pair() -> (
        SecureMessenger<ToyMessenger>,
        SecureMessenger<ToyMessenger>,
        Arc<DashMap<u128, Vec<u8>>>,
    ) {
        let db = Arc::new(DashMap::new());
        let players = HashSet::from([1, 2]);
        let (a, b) = tokio::join!(
            SecureMessenger::establish(ToyMessenger::new(db.clone()), "session", &players, 1),
            SecureMessenger::establish(ToyMessenger::new(db.clone()), "session", &players, 2)
        );
        (a.unwrap(), b.unwrap(), db)
    }

    #[tokio::test]
    async fn encrypted_messages_support_broadcast_and_out_of_order_receives() {
        let (mut a, mut b, db) = pair().await;
        let secret = "private payload sentinel".to_string();
        let large = serde_bytes::ByteBuf::from(vec![0x5b; CHUNK * 3]);
        let broadcast = "broadcast payload sentinel".to_string();
        let mut got_secret = String::new();
        let mut got_large = serde_bytes::ByteBuf::new();
        let mut got_broadcast = String::new();
        a.register_send(&secret, "session/ot-setup", "first", 1, 2, 0);
        a.register_send(&large, "session", "second", 1, 2, 0);
        a.register_send(&broadcast, "session", "broadcast", 1, 0, 0);
        b.register_recv(&mut got_broadcast, "session", "broadcast", 1, 0, 0);
        b.register_recv(&mut got_large, "session", "second", 1, 2, 0);
        b.register_recv(&mut got_secret, "session/ot-setup", "first", 1, 2, 0);
        let (ra, rb) = tokio::join!(a.exchange(), b.exchange());
        ra.unwrap();
        rb.unwrap();
        assert_eq!(got_secret, secret);
        assert_eq!(got_large, large);
        assert_eq!(got_broadcast, broadcast);
        for value in db.iter() {
            assert!(!value.windows(secret.len()).any(|v| v == secret.as_bytes()));
            assert!(
                !value
                    .windows(broadcast.len())
                    .any(|v| v == broadcast.as_bytes())
            );
            assert!(!value.windows(256).any(|v| v.iter().all(|&x| x == 0x5b)));
        }
    }

    #[tokio::test]
    async fn cancelled_exchange_cannot_be_reused() {
        let (mut a, _b, _) = pair().await;
        let mut output = String::new();
        a.register_recv(&mut output, "session", "never-sent", 2, 1, 0);
        let result = tokio::time::timeout(std::time::Duration::from_millis(20), a.exchange()).await;
        assert!(result.is_err());
        assert!(a.exchange().await.is_err());
    }

    #[tokio::test]
    async fn replay_tamper_and_wrong_context_are_rejected() {
        let (mut a, mut b, _) = pair().await;
        let addr = Address {
            sid: "session".into(),
            topic: "private".into(),
            src: 1,
            dst: 2,
            seq: 0,
        };
        let wire = a.seal(&addr, 2, b"hello").unwrap();
        let mut tampered = wire.clone();
        tampered.fragments[0].ciphertext[0] ^= 1;
        assert!(b.open(&addr, &tampered).is_err());
        let mut other = addr.clone();
        other.topic = "other".into();
        assert!(b.open(&other, &wire).is_err());
        assert_eq!(b.open(&addr, &wire).unwrap(), b"hello");
        assert!(b.open(&addr, &wire).is_err());
    }
}
