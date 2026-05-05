# DSG 移植路线图

把 `simple-dkls23/src/dsg.rs` 移植到本仓库.
沿用 keygen 风格: 单个 `async fn sign(...)`, 用 `TrMessenger` + topic 路由,
不显式定义 `SignMsg1..4`.

## 边界

包含:

* MVP 4 轮签名, 输出 ECDSA $(r, s)$, 本地 verify.
* 2-of-2, 2-of-3, 3-of-3 测试.
* 假设全体 rank 为 0, 用 Lagrange.

不包含:

* BIP-32 / 子密钥派生本身. 派生由上游另起函数完成, 结果作为 sign 参数传入.
* refresh / rotation.
* `dsg_ot_variant.rs` (signing 时重跑 base OT 的变体).
* Birkhoff, malicious adversary 完整测试集.

## 源码映射

| 源 | 目标 |
|---|---|
| `simple-dkls23/src/dsg.rs` | `src/dsg/dsg_fn.rs` |
| `simple-dkls23/src/utils.rs` 中的 signing helpers | `src/dsg/helpers.rs` |
| `sl-oblivious/src/soft_spoken/soft_spoken_ot.rs` | `src/dsg/soft_spoken_ot.rs` |
| `sl-oblivious/src/soft_spoken/mul_poly.rs` | 同上文件内 |
| `sl-oblivious/src/rvole.rs` | `src/dsg/rvole.rs` |

## 三层依赖

```text
KeygenAux.pprf_seeds  (dkg/soft_spoken.rs 已产出)
  → 层 1: SoftSpoken OT extension  (随机 OT × L)
  → 层 2: RVOLE  (乘法转加法)
  → 层 3: signing 状态机  (presign + partial + combine)
```

PPRF 不是随机 OT, RVOLE 不是签名, presign 不绑定消息.

---

## 层 1: SoftSpoken OT extension

输入: `pprf_seeds.as_sender[j]: SenderOTSeed`, `pprf_seeds.as_receiver[j]: ReceiverOTSeed`.

参数:

$$
\kappa = 256, \quad \lambda_s = 128, \quad L = \kappa + 2\lambda_s = 768, \quad L' = L + S = 896, \quad \mathrm{OT\_WIDTH} = L_\text{batch} + \rho = 3.
$$

输出:

* Receiver: `Round1Output` 消息 + `ReceiverExtendedOutput { choices: L bits, v_x: [L][OT_WIDTH][KAPPA_BYTES] }`.
* Sender: `SenderExtendedOutput { v_0, v_1: [L][OT_WIDTH][KAPPA_BYTES] }`.

正确性: 对每个 $i \in [L]$, 设 Receiver 选择位为 $b_i$, 则
$\mathbf{v_x}[i][k] = \mathbf{v_{b_i}}[i][k]$ 在每个 OT_WIDTH 列上成立.

要点:

* GF($2^{128}$) 多项式乘 (`binary_field_multiply_gf_2_128`) 直接搬, 与曲线无关.
* KOS 一致性检查 $\chi_j = \mathrm{Hash}(u_1, \dots, u_\kappa)$: Fiat-Shamir, 不必字节兼容 sl-oblivious 的 `merlin::Transcript`, 用 `hash!` 宏即可.
* 位矩阵转置 $L'\times \kappa \leftrightarrow \kappa \times L'$ 直接搬.

---

## 层 2: RVOLE

接口:

```rust
RVOLEReceiver::new(sid, sender_seed, &mut msg1, rng) -> (state, b)
RVOLESender::process(sid, receiver_seed, &[a_0, a_1], &msg1, &mut msg2, rng) -> [c_0, c_1]
RVOLEReceiver::process(state, &msg2) -> [d_0, d_1]
```

正确性 (在 $\mathbb{Z}_n$):

$$
c_k + d_k = a_k \cdot b, \quad k \in \{0, 1\}.
$$

* $b = \langle g, \beta \rangle$, $\beta \overset{\$}{\leftarrow} \{0,1\}^L$, $g \in \mathbb{Z}_n^L$ 是 sid 派生的 gadget 向量.
* Alice 一致性检查在 $\rho = 1$ 个检查列上做, 由 RVOLE 内部 `mu_hash` 完成. 失败由 dsg 层封装为 ban-party. 数学见 [`notes/extot-dkls23-derand.md`](../../../notes/extot-dkls23-derand.md).

要点: hash domain 与 keygen / SoftSpoken 隔离, tag 用 `b"dsg/rvole/..."`.

---

## 层 3: signing 状态机

入口建议:

```rust
pub async fn sign(
    ch: impl TrMessenger,
    sid: String,
    signers: HashSet<usize>,
    keystore: &Keystore<Secp256k1>,
    additive_offset: Option<Scalar>,
    msg_hash: [u8; 32],
) -> Resultat<EcdsaSignature>
```

* `KeygenAux` 由 sign 内部从 `keystore.aux` 解出, 不暴露给调用方.
* `sid` 由调用方保证唯一, 不再做 per-party 采样和交换.
* `additive_offset`: 私钥偏移量 $\delta$, 上游 BIP-32 派生的结果. `None` 表示直接签 `keystore` 主密钥. sign 内部据此算 $\mathrm{PK}' = \mathrm{PK} + \delta G$.

### 本地变量

| 符号 | 含义 |
|---|---|
| $\phi_i$ | 本方 nonce 翻转, 用于聚合 |
| $r_i$, $R_i = r_i G$ | 本方 nonce 贡献 |
| $\lambda_i$ | signing subset $S$ 上的 Lagrange 系数 |
| $\zeta_i$ | 配对随机化偏移, $\sum_{i\in S}\zeta_i = 0$ |
| $\delta$, $\mathrm{PK}' = \mathrm{PK} + \delta G$ | 调用方传入的私钥偏移量与对应派生公钥 |
| $sk_i = \lambda_i x_i + \zeta_i + \delta / \lvert S \rvert$ | 重随机化的有效份额, 全体相加得到派生私钥 |
| $\chi_{i\to j}$ | 我作 RVOLE Receiver 对 $j$ 采样的 $b$ |
| $\psi_{i\to j} = \phi_i - \chi_{i\to j}$ | 我发给 $j$ 的标量 |

公式:

$$
\lambda_i = \prod_{j \in S \setminus \{i\}} \frac{j}{j - i}, \quad
\zeta_i = \sum_{\substack{j \in S \\ j < i}} v_{ji} - \sum_{\substack{j \in S \\ j > i}} v_{ij}, \quad
v_{ij} = \mathrm{Hash}(\text{seed}_{ij} \| sid).
$$

### Round 流

(0) 本地: 解出 `pprf_seeds` 与 `seeds`. 由 `additive_offset` 算 $\mathrm{PK}' = \mathrm{PK} + \delta G$.
采样 $\phi_i, r_i, \text{blind}_i$. 算 $R_i, \mathrm{commit}_i = \mathrm{Hash}(sid, R_i, \text{blind}_i)$.

(1) Round 1, broadcast. 发 $\mathrm{commit}_i$. 收齐后算
$\text{digest}_i = \mathrm{Hash}(sid, \mathrm{PK}', \text{all } (j, \mathrm{commit}_j))$.

(2) Round 2, p2p. 对每个 $j \in S \setminus \{i\}$, 用 `pprf_seeds.as_sender[j]` 起 `RVOLEReceiver`,
发 `mta_msg_1`. 保存 $(state_{i\to j}, \chi_{i\to j})$.

(3) Round 3, p2p. 本地算 $\zeta_i, sk_i, P_i = sk_i G, \psi_{i\to j}$.
对每个 $j$, 用 `pprf_seeds.as_receiver[j]` 跑 `RVOLESender::process(..., &[r_i, sk_i], ...)` 得 $[c_u, c_v]$,
算 $\Gamma_u = c_u G, \Gamma_v = c_v G$.
发: $(\text{mta\_msg\_2}, \text{digest}_i, P_i, R_i, \text{blind}_i, \Gamma_u, \Gamma_v, \psi_{i\to j})$.

(4) handle Round 3, 本地组 PreSignature.
对每个 $j$ 验 commit, 验 digest 一致, 跑 `state_{i\to j}.process(\text{mta\_msg\_2})` 得 $[d_u, d_v]$.
一致性检查:

$$
R_j \cdot \chi_{i\to j} \overset{?}{=} d_u G + \Gamma_u, \quad
P_j \cdot \chi_{i\to j} \overset{?}{=} d_v G + \Gamma_v.
$$

公钥还原: $\sum_{j\in S} P_j \overset{?}{=} \mathrm{PK}'$.

聚合 (令 $R = \sum_{j\in S} R_j$, $r_x = x(R) \bmod n$, $\phi^*_i = \phi_i + \sum_{j \neq i} \psi_{j\to i}$):

$$
s_0^{(i)} = r_x \cdot \Big( sk_i \phi^*_i + \sum_{j \neq i}(c_v^{j} + d_v^{j}) \Big), \quad
s_1^{(i)} = r_i \phi^*_i + \sum_{j \neq i}(c_u^{j} + d_u^{j}).
$$

(5) message binding, 本地. 输入 32 字节 hash $m$:

$$
s_0^{(i)} \mathrel{+}= m \cdot \phi_i.
$$

(6) Round 4, broadcast partial $(s_0^{(i)}, s_1^{(i)})$. 收齐后

$$
r = r_x, \quad s = \frac{\sum_{j\in S} s_0^{(j)}}{\sum_{j\in S} s_1^{(j)}}.
$$

(7) 本地 ECDSA verify:
$u_1 = m / s, u_2 = r / s, R'' = u_1 G + u_2 \mathrm{PK}'$, 比对 $x(R'') \bmod n \overset{?}{=} r$.

### 输出

```rust
pub struct EcdsaSignature { pub r: Scalar, pub s: Scalar }
```

DER / compact 编码留到上层.

---

## 风格适配

| simple-dkls23 / sl-oblivious | 本仓库 |
|---|---|
| `k256::Scalar`, `ProjectivePoint` | `svarog_secp256k1::Scalar`, `Point` |
| `Sha256` + 4 字节 label | `hash!` 宏 + 字面量 tag |
| `merlin::Transcript` | Blake2b chain (字符串 tag + 长度前缀) |
| `Pairs<T>`, `Vec` 索引 + `get_idx_from_id` | `HashMap<usize, T>`, 按对端 id 直接查 |
| `[[u8;..];..]` + bytemuck zero-copy | `Vec<Vec<u8>>` + `serde-pickle` |
| `u8` party id | `usize` party id |
| 显式 `RngCore + CryptoRng` 注入 | `Scalar::new_rand()` / `rand::rng()` |
| 显式 `SignMsg1..4` + per-round handler | `TrMessenger` + topic, 单个 `async fn sign` |
| `derivation_path::DerivationPath` | 不引入 |
| `k256::Signature` + `verify_prehash` | 自写 `(r, s)` + 验证 |

---

## 风险点

(1) SoftSpoken OT extension (~500 LoC) 按设计就属于签名阶段, keygen 只产 PPRF 基材.
本仓库 `dkg/soft_spoken.rs` 只实现到 PPRF, 与 `simple-dkls23` 一致.
dsg 移植中它是最重的一块, 没有它, RVOLE 没原料.

(2) Fiat-Shamir 不要试图字节兼容 `merlin::Transcript`. 只要本协议双方独立计算结果一致即可.

(3) `Point` 没有 `x()` 方法. 取 affine $x$: `to_bytes_long()` (65 字节) 取 `[1..33]`,
用 `Scalar::new_from_bytes` 自动 reduce 为 $r$.

(4) 方向: `pprf_seeds.as_sender[j]` 是 RVOLE Receiver 的 base, `as_receiver[j]` 是 RVOLE Sender 的 base.
原因: SoftSpoken OT Receiver 内部需要全表 (= 我作 PPRF Sender 的视角).
与 `simple-dkls23/src/dsg.rs:257, 334` 一致, 无需反向.

(5) signing subset $S \subseteq \Omega_k$, $|S| \ge \text{th}$. Lagrange 在份额空间, $\zeta$ 在 $\mathbb{Z}_n$ 直接相加.

(6) $\delta$ 必须由调用方在所有签名方之间一致, 否则 $\sum_i sk_i \neq$ 派生私钥. sign 不做这个一致性的协商或校验.

---

## 施工顺序

(1) `dsg/mod.rs`, `dsg/helpers.rs`.
单元测试: $\sum_{i\in S}\zeta_i = 0$, $\sum_{i\in S}\lambda_i x_i G = \mathrm{PK}$.

(2) `dsg/soft_spoken_ot.rs`. correctness test: Sender 同侧值 = Receiver 拿到的值.

(3) `dsg/rvole.rs`. correctness test: $c_k + d_k = a_k b$. 篡改 `mta_msg_2` 应被拒.

(4) `dsg/dsg_fn.rs`. 端到端 2-of-2 → 2-of-3 → 3-of-3.

(5) `dsg/dsg_fn.md`: 数学笔记, 等 (4) 通过后再写.
