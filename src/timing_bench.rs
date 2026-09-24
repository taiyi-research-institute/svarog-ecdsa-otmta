//! 可复现的 sign 基准；事件通知通信，不含人工轮询延迟或真实网络 RTT。
//! 用 release 构建，只在显式运行 ignored 测试时执行。
use std::{any::Any, collections::HashMap, sync::Arc};

use crate::hash::FramedHash;

use curve_abstract::TrMessenger;
use dashmap::DashMap;
use erreur::*;
use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Instant;
use tokio::sync::{Barrier, Notify};

type DePtr = *mut dyn Any;
type DeFn = Box<dyn Fn(&[u8], &mut dyn Any) -> Resultat<()>>;

pub struct BenchmarkMessenger {
    db: Arc<DashMap<u128, Vec<u8>>>,
    notify: Arc<Notify>,
    rounds: Arc<AtomicUsize>,
    tx: Vec<(u128, Vec<u8>)>,
    rx: HashMap<u128, (DePtr, DeFn)>,
}

unsafe impl Send for BenchmarkMessenger {}

impl BenchmarkMessenger {
    pub fn new(
        db: Arc<DashMap<u128, Vec<u8>>>,
        notify: Arc<Notify>,
        rounds: Arc<AtomicUsize>,
    ) -> Self {
        Self {
            db,
            notify,
            rounds,
            tx: Vec::new(),
            rx: HashMap::new(),
        }
    }
}

impl TrMessenger for BenchmarkMessenger {
    type Err = Box<Erreur>;

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
        let key = index(sid, topic, src, dst, seq);
        let buf = serde_pickle::to_vec(val, Default::default()).unwrap();
        self.tx.push((key, buf));
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
        let key = index(sid, topic, src, dst, seq);
        let de_ptr: DePtr = out as *mut T as *mut dyn Any;
        let de_fn: DeFn = Box::new(|bytes: &[u8], obj: &mut dyn Any| -> Resultat<()> {
            let obj_typed: &mut T = obj.downcast_mut().unwrap();
            *obj_typed = serde_pickle::from_slice(bytes, Default::default())
                .catch("DeserializationFailed", "BenchmarkMessenger")?;
            Ok(())
        });
        let _ = self.rx.insert(key, (de_ptr, de_fn));
        self
    }

    async fn exchange(&mut self) -> Resultat<()> {
        self.rounds.fetch_add(1, Ordering::Relaxed);
        // 发送: 将所有缓存的消息写入共享 DashMap.
        for (key, val) in self.tx.drain(..) {
            self.db.insert(key, val);
        }

        self.notify.notify_waiters();
        // 先注册通知，再检查消息，避免丢失唤醒。
        let keys: Vec<u128> = self.rx.keys().cloned().collect();
        for key in &keys {
            loop {
                let ready = self.notify.notified();
                tokio::pin!(ready);
                ready.as_mut().enable();
                if self.db.contains_key(key) {
                    break;
                }
                ready.await;
            }
            let buf = self.db.get(key).unwrap().clone();
            let (de_ptr, de_fn) = self.rx.get(key).unwrap();
            unsafe {
                de_fn(&buf, &mut **de_ptr)?;
            }
        }
        self.rx.clear();

        Ok(())
    }
}

fn index(sid: &str, topic: &str, src: usize, dst: usize, seq: usize) -> u128 {
    let mut hasher = FramedHash::new(16).unwrap();
    hasher.update(b"toy-messenger/address");
    hasher.update(sid.as_bytes());
    hasher.update(topic.as_bytes());
    hasher.update(&(src as u64).to_le_bytes());
    hasher.update(&(dst as u64).to_le_bytes());
    hasher.update(&(seq as u64).to_le_bytes());
    let mut buf = [0u8; 16];
    hasher.finalize_variable(&mut buf).unwrap();
    u128::from_le_bytes(buf)
}

use std::collections::HashSet;
use svarog_lagrange::Keystore;
use svarog_secp256k1::{Scalar, Secp256k1};

async fn generate_keys(
    n: usize,
    threshold: usize,
    sid: &str,
) -> (Vec<Keystore<Secp256k1>>, f64, usize) {
    let db = Arc::new(DashMap::new());
    let notify = Arc::new(Notify::new());
    let barrier = Arc::new(Barrier::new(n));
    let mut tasks = Vec::new();
    for party in 1..=n {
        let counter = Arc::new(AtomicUsize::new(0));
        let messenger = BenchmarkMessenger::new(db.clone(), notify.clone(), counter.clone());
        let barrier = barrier.clone();
        let sid = sid.to_owned();
        tasks.push(tokio::spawn(async move {
            barrier.wait().await;
            let start = Instant::now();
            let key = crate::keygen(
                messenger,
                sid,
                (1..=n).collect(),
                party,
                threshold,
                None,
                None,
            )
            .await
            .unwrap();
            (
                key,
                start.elapsed().as_secs_f64() * 1000.0,
                counter.load(Ordering::Relaxed),
            )
        }));
    }
    let mut keys = Vec::new();
    let mut elapsed = 0.0f64;
    let mut rounds = 0;
    for task in tasks {
        let (key, ms, count) = task.await.unwrap();
        keys.push(key);
        elapsed = elapsed.max(ms);
        rounds = count;
    }
    keys.sort_by_key(|key| key.i);
    (keys, elapsed, rounds)
}

async fn timed_sign(
    keys: &[Keystore<Secp256k1>],
    signers: &HashSet<usize>,
    batch: usize,
    sid: &str,
) -> (f64, usize) {
    let db = Arc::new(DashMap::new());
    let notify = Arc::new(Notify::new());
    let barrier = Arc::new(Barrier::new(signers.len()));
    let mut tasks = Vec::new();
    for key in keys.iter().filter(|key| signers.contains(&key.i)) {
        let key = key.clone();
        let signers = signers.clone();
        let sid = sid.to_owned();
        let counter = Arc::new(AtomicUsize::new(0));
        let messenger = BenchmarkMessenger::new(db.clone(), notify.clone(), counter.clone());
        let barrier = barrier.clone();
        tasks.push(tokio::spawn(async move {
            // 分配输入与克隆 keystore 不计入 sign 的调用耗时。
            let offsets = vec![Scalar::default(); batch];
            let messages = vec![[0xA5; 32]; batch];
            barrier.wait().await;
            let start = Instant::now();
            let signatures = if batch == 1 {
                vec![
                    crate::sign(messenger, sid, signers, &key, Scalar::default(), [0xA5; 32])
                        .await
                        .unwrap(),
                ]
            } else {
                crate::sign_batch(messenger, sid, signers, &key, offsets, messages)
                    .await
                    .unwrap()
            };
            (
                signatures,
                start.elapsed().as_secs_f64() * 1000.0,
                counter.load(Ordering::Relaxed),
            )
        }));
    }
    let mut elapsed = 0.0f64;
    let mut rounds = None;
    let mut reference: Option<Vec<crate::EcdsaSignature>> = None;
    for task in tasks {
        let (signatures, ms, count) = task.await.unwrap();
        elapsed = elapsed.max(ms);
        if let Some(expected) = rounds {
            assert_eq!(count, expected);
        }
        rounds = Some(count);
        if let Some(expected) = &reference {
            for (a, b) in signatures.iter().zip(expected) {
                assert_eq!(a.r, b.r);
                assert_eq!(a.s, b.s);
                assert_eq!(a.v, b.v);
            }
        } else {
            reference = Some(signatures);
        }
    }
    (elapsed, rounds.unwrap())
}

#[test]
#[ignore = "release timing benchmark; run explicitly"]
fn sign_latency() {
    let samples: usize = std::env::var("OT_BENCH_SAMPLES")
        .unwrap_or_else(|_| "20".into())
        .parse()
        .unwrap();
    let warmup: usize = std::env::var("OT_BENCH_WARMUP")
        .unwrap_or_else(|_| "3".into())
        .parse()
        .unwrap();
    let label = std::env::var("OT_BENCH_LABEL").unwrap_or_else(|_| "unknown".into());
    let empty = std::env::var("OT_BENCH_EXPECT_EMPTY").is_ok_and(|s| s == "1");
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(8)
        .enable_all()
        .build()
        .unwrap();
    runtime.block_on(async {
        for (n, threshold) in [(2, 2), (3, 2), (3, 3)] {
            let session = format!("bench/{label}/{threshold}-of-{n}");
            let (keys, keygen_ms, keygen_rounds) = generate_keys(n, threshold, &session).await;
            assert!(keys.iter().all(|key| key.aux.is_empty() == empty));
            println!("KEYGEN,{label},{threshold}-of-{n},{keygen_ms:.6},{keygen_rounds}");
            let signers: HashSet<_> = if n == 3 && threshold == 2 {
                [1, 3].into_iter().collect()
            } else {
                (1..=n).collect()
            };
            for batch in [1, 4] {
                for index in 0..(warmup + samples) {
                    let sid = format!("{session}/batch={batch}/call={index}");
                    let (ms, rounds) = tokio::time::timeout(
                        std::time::Duration::from_secs(120),
                        timed_sign(&keys, &signers, batch, &sid),
                    )
                    .await
                    .unwrap();
                    if index >= warmup {
                        println!(
                            "TIMING,{label},{threshold}-of-{n},{batch},{},{ms:.6},{rounds}",
                            index - warmup
                        );
                    }
                }
            }
        }
    });
}
