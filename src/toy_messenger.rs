//! 测试用的内存 messenger. 实现 `TrMessenger` 接口, 通过共享 `DashMap`
//! 模拟多方异步收发. 仅用于单进程内的 tokio::spawn 测试, 非生产代码.
//!
//! 消息以 `(sid, topic, src, dst, seq)` 五元组哈希到 16 字节 key,
//! 由 `index()` 派生; 接收侧轮询直到 key 出现.

use std::{any::Any, collections::HashMap, sync::Arc};

use blake2::Blake2bVar;
use blake2::digest::{Update, VariableOutput};
use curve_abstract::TrMessenger;
use dashmap::DashMap;
use erreur::*;
use serde::{Deserialize, Serialize};
use tokio::time::{Duration, sleep};

type DePtr = *mut dyn Any;
type DeFn = Box<dyn Fn(&[u8], &mut dyn Any) -> Resultat<()>>;

pub struct ToyMessenger {
    db: Arc<DashMap<u128, Vec<u8>>>,
    tx: Vec<(u128, Vec<u8>)>,
    rx: HashMap<u128, (DePtr, DeFn)>,
}

unsafe impl Send for ToyMessenger {}

impl ToyMessenger {
    pub fn new(db: Arc<DashMap<u128, Vec<u8>>>) -> Self {
        Self {
            db,
            tx: Vec::new(),
            rx: HashMap::new(),
        }
    }
}

impl TrMessenger for ToyMessenger {
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
                .catch("DeserializationFailed", "ToyMessenger")?;
            Ok(())
        });
        let _ = self.rx.insert(key, (de_ptr, de_fn));
        self
    }

    async fn exchange(&mut self) -> Resultat<()> {
        // 发送: 将所有缓存的消息写入共享 DashMap.
        for (key, val) in self.tx.drain(..) {
            self.db.insert(key, val);
        }

        // 接收: 轮询直到所有已注册的 key 都可用.
        let keys: Vec<u128> = self.rx.keys().cloned().collect();
        for key in &keys {
            while !self.db.contains_key(key) {
                sleep(Duration::from_millis(50)).await;
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
    let mut hasher = Blake2bVar::new(16).unwrap();
    hasher.update(sid.as_bytes());
    hasher.update(b"|");
    hasher.update(topic.as_bytes());
    hasher.update(b"|");
    hasher.update(&src.to_le_bytes());
    hasher.update(&dst.to_le_bytes());
    hasher.update(&seq.to_le_bytes());
    let mut buf = [0u8; 16];
    hasher.finalize_variable(&mut buf).unwrap();
    u128::from_le_bytes(buf)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};

    const SID: &str = "test-session";
    const N: usize = 4;

    fn party_value(i: usize) -> Vec<u8> {
        let mut h = DefaultHasher::new();
        "114514".hash(&mut h);
        i.hash(&mut h);
        h.finish().to_le_bytes().to_vec()
    }

    /// P2P 群发: 每方向其余所有方发送, 同时接收所有方的消息
    async fn p2p_party(db: Arc<DashMap<u128, Vec<u8>>>, me: usize) {
        let mut ch = ToyMessenger::new(db);
        let my_val = party_value(me);
        let mut recv: [Vec<u8>; N + 1] = Default::default();

        for j in 1..=N {
            if j == me {
                continue;
            }
            ch.register_send(&my_val, SID, "p2p", me, j, 0)
                .register_recv(&mut recv[j], SID, "p2p", j, me, 0);
        }

        ch.exchange().await.unwrap();

        for j in 1..=N {
            if j == me {
                continue;
            }
            assert_eq!(recv[j], party_value(j), "party {me} recv from {j}");
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn test_p2p_exchange() {
        let db = Arc::new(DashMap::new());
        let handles: Vec<_> = (1..=N)
            .map(|i| tokio::spawn(p2p_party(db.clone(), i)))
            .collect();
        for h in handles {
            h.await.unwrap();
        }
    }

    /// 广播: 每方广播到 dst=0, 同时接收其余各方的广播
    async fn bcast_party(db: Arc<DashMap<u128, Vec<u8>>>, me: usize) {
        let mut ch = ToyMessenger::new(db);
        let my_val = party_value(me);
        let mut recv: [Vec<u8>; N + 1] = Default::default();

        ch.register_send(&my_val, SID, "bcast", me, 0, 0);
        for j in 1..=N {
            if j == me {
                continue;
            }
            ch.register_recv(&mut recv[j], SID, "bcast", j, 0, 0);
        }

        ch.exchange().await.unwrap();

        for j in 1..=N {
            if j == me {
                continue;
            }
            assert_eq!(recv[j], party_value(j), "party {me} bcast from {j}");
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn test_broadcast() {
        let db = Arc::new(DashMap::new());
        let handles: Vec<_> = (1..=N)
            .map(|i| tokio::spawn(bcast_party(db.clone(), i)))
            .collect();
        for h in handles {
            h.await.unwrap();
        }
    }

    /// 自定义结构体的序列化/反序列化测试 (广播)
    #[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
    struct Payload {
        num: i64,
        label: String,
    }

    impl Default for Payload {
        fn default() -> Self {
            Self {
                num: 0,
                label: String::new(),
            }
        }
    }

    fn make_payload(i: usize) -> Payload {
        let num = i as i64 * 114514;
        Payload {
            num,
            label: num.to_string(),
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn test_broadcast_struct() {
        let db = Arc::new(DashMap::new());
        let handles: Vec<_> = (1..=N)
            .map(|i| {
                let dbi = db.clone();
                tokio::spawn(async move {
                    let mut ch = ToyMessenger::new(dbi);
                    let my_val = make_payload(i);
                    let mut recv: [Payload; N + 1] = Default::default();

                    ch.register_send(&my_val, SID, "struct-bcast", i, 0, 0);
                    for j in 1..=N {
                        if j == i {
                            continue;
                        }
                        ch.register_recv(&mut recv[j], SID, "struct-bcast", j, 0, 0);
                    }

                    ch.exchange().await.unwrap();

                    for j in 1..=N {
                        if j == i {
                            continue;
                        }
                        let expected = make_payload(j);
                        assert_eq!(recv[j], expected, "party {i} struct from {j}");
                    }
                })
            })
            .collect();
        for h in handles {
            h.await.unwrap();
        }
    }
}
