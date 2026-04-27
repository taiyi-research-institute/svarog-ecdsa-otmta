# Keygen 数学原理笔记

本文档与 [dkg_fn.rs](dkg_fn.rs) 配套.
按依赖顺序: B (`seed_i_j`) → A (PPRF 扩展) → C (公钥还原自洽性校验).
chain code 直接由参数传入, 与密码学安全无关, 此处不展开.

---

## B. `seed_i_j`: 配对随机化种子

### 它解决什么问题

在签名的 MtA 步骤中, 每方都用 Lagrange 系数缩放自己的份额 $s_i$, 再参与两方乘法.
但 $\lambda_i \cdot s_i$ 本身就携带了 $s_i$ 的线性信息.
如果 MtA 的中间消息泄露, 对手方可以反推份额.

解决方法:
在每次签名前, 给每方的有效份额加一个随机偏移 $\zeta_i$,
**但这些偏移全局相消**, 不影响最终结果.

### 数学结构

对每对参与方 $(i, j)$ (约定 $i < j$),
keygen 时**低 id 的 $i$ 方**生成 32 字节随机数 $\text{seed}_{ij}$, 明文发给 $j$.
这个种子不需要加密, 它不是秘密, 只需要唯一性和随机性.

在签名时, 给定签名会话 ID $\text{sig\_id}$, 定义:

$$v_{ij} = \text{Hash}(\text{seed}_{ij} \| \text{sig\_id})$$

每方的偏移量 $\zeta_i$ 定义为:

$$\zeta_i = \underbrace{\sum_{j < i} v_{ji}}_{\text{rec 贡献}} - \underbrace{\sum_{j > i} v_{ij}}_{\text{sent 贡献}}$$

**关键性质**: $\sum_i \zeta_i = 0$.
因为每个 $v_{ij}$ 在 $i$ 方贡献 $-v_{ij}$, 在 $j$ 方贡献 $+v_{ij}$, 两者抵消.

所以 $\text{sk}_i = \lambda_i \cdot s_i + \zeta_i$ 是重随机化后的有效份额.
而 $\sum_i \text{sk}_i = \sum_i \lambda_i \cdot s_i = \text{私钥}$, 因为 $\sum \zeta_i = 0$.

### Keygen 实现要点

* 数据结构 `PairwiseSeeds { sent, rec }` 都是 `HashMap<usize, [u8; 32]>`, 以对端 id 作 key.
* Round 3 同一次 `exchange()` 里, 对每个 $j > i$ 的对端,
  $i$ 用 Blake2b 生成 32 字节种子写入 `sent_seeds[j]`,
  并通过路由 `keygen/r3/seed` 明文发给 $j$.
* 对每个 $j < i$ 的对端,
  $i$ 通过路由 `keygen/r3/seed` 收到 $j$ 的种子, 写入 `rec_seeds[j]`.
* 不做加密.
  这个种子本来就不需要保密,
  它只是双方签名时用来生成相同 $v_{ij}$ 的公共随机性.

---

## A. SoftSpoken PPRF 扩展

> **本节是数学背景概览. 详细的协议、类型、`build_pprf` / `eval_pprf` 算法以及参数表见 [soft_spoken.md](soft_spoken.md).**

### 背景: 为什么需要它

Base OT (EndemicOT) 给了双方 $\kappa$ 对密钥.
secp256k1 取 $\kappa = 256$, 对应源码常量 `LAMBDA_C`.

但签名里 MtA 需要 $L \gg \kappa$ 个扩展 OT 实例.
DKLS23 取 $L = \kappa + 2\lambda_s = 512$ (统计安全参数 $\lambda_s = 128$).

PPRF 扩展的作用是: 把 $\kappa$ 对 base OT 密钥"拉伸"成建立 $L$ 个扩展 OT 所需的基材.
这层是纯本地计算, 只需一次 `PPRFOutput` 交换.
真正的 $L$ 个扩展 OT 要到签名阶段, 由上层 `soft_spoken_ot.rs` (尚未移植) 把 PPRF 基材组合而成.

### 多棵小树的结构

SoftSpoken **不**采用"单棵深度 $\log_2 L$ 的 GGM 树"的抽象.
它把 $\kappa$ 对 base OT 按每 $K$ 位一组分块, 构造 $\kappa / K$ 棵**并行的小 GGM 树**.
源码里 $K = \text{SOFT\_SPOKEN\_K} = 4$, 共 $\kappa/K = 64$ 棵树.
每棵小树的叶子数 $Q = 2^K = 16$.

Sender 知道每棵树的全部 16 个叶子.
Receiver 在每棵树里有一个 punctured 下标 $y^*_j$ 不可知, 其余 15 个叶子可以重建.
$y^*_j$ 由 Receiver 在该树覆盖的 4 位 base OT 选择位决定.

### 到签名时的承接

PPRF 输出的 `SenderOTSeed` / `ReceiverOTSeed` 是基材, **不**等于最终 $L = 512$ 个扩展 OT.
签名阶段会把这 64 棵小树的叶子按 IKNP 风格组合成 $L$ 个随机 OT 实例,
再由 `rvole.rs` 组装成 MtA (RVOLE).

`extot-dkls23-derand.md` 里 "Step 1 随机 OT" 描述的抽象接口 $(\alpha^0_j, \alpha^1_j, \gamma_j)$,
对应的是上层 $L$ 个随机 OT 的产物, 而不是 PPRF 直接输出的叶子.
Keygen 阶段只把底座铺好, 签名时再拉出上层.

---

## C. 公钥还原自洽性校验

### 与 `simple-dkls23` Round 4 的对比

`simple-dkls23` 的 Round 4 做三件事:
广播 $S_j = s_j \cdot G$, 验证 $S_j$ 与 Feldman 承诺一致, 然后 Lagrange 还原公钥并校验.
还附带一轮 Schnorr DLog 证明绑定 `final_session_id` 与 `root_chain_code`.

本 port 把"广播 + 防恶意"这部分前置到了 Round 1, 设计上更轻量:

* DLog 证明的对象从"份额 $s_j$"改成"多项式系数 $f_j$".
  Round 1 里 `dlog_prove_batch` / `dlog_verify_batch` (见 `helpers.rs`) 一次性证明所有 $\text{polycom}[j][k]$.
* Feldman 一致性 $f_j(i) G = F_j(i)$ 由 `verify_fj_at_i` 检查 (`dkg_fn.rs:173`).
  这是"对方对自己的多项式承诺没说谎"的唯一保护层.
* `chain_code` 直接从参数传入, 没有共识 transcript, 也就不需要 Schnorr 证明里再绑链码.

防恶意的活在 Round 1 已经做完, 所以 keygen 末尾不再需要额外一轮 $S_i$ 广播.

### 公钥还原校验

Keygen 里"公钥"不是输入, 而是**输出**, 没有外部预期值可以比对.
但仍可以做一个**自洽性 sanity check**:
用同一份 `vss_scheme`, 沿两条不同路径推导公钥, 看是否相等.

* 路径 A: 各方常数项之和.

$$\text{PK}_A = \sum_{j \in \Omega_k} F_j(0) = \sum_{j \in \Omega_k} \text{polycom}[j][0]$$

  对应 `Keystore::public_key()`.

* 路径 B: 对所有方的 $X_j := x_j G$ 做 Lagrange 插值.

$$\text{PK}_B = \sum_{j \in \Omega_k} \lambda_j \cdot X_j, \quad X_j = \sum_{k \in \Omega_k} F_k(j) = \mathrm{eval\_xi\_com}(j, \text{vss\_scheme})$$

  $\lambda_j$ 是 keygen 全集 $\Omega_k$ 上的 Lagrange 系数.

由于多项式度数 $\text{th} - 1 < |\Omega_k|$, $\Omega_k$ 上的 Lagrange 插值给出 $\sum f(0) = $ 私钥, 两边乘 $G$ 即得 $\text{PK}_A = \text{PK}_B$.
这恒等式由 VSS 数学保证, 任何不等都说明 Lagrange / 多项式库或 `vss_scheme` 结构有 bug.

注意它不是恶意防御, 只是一道防 bug 的护栏:
对手的恶意行为 (假承诺 / 错份额) 应该已经被 Round 0 的 commit-reveal、Round 1 的 DLog 证明和 `verify_fj_at_i` 拦下.

实现位于 `dkg_fn.rs` 末尾 `keystore` 构造之后, 是一段纯本地计算, 不增加新一轮通信.

---

## 总结对照

| 部分 | 核心数学 | 在本仓库的位置 |
|---|---|---|
| `seed_i_j` | 配对随机偏移 $\zeta_i$, 全局相消 | `dkg_fn.rs` Round 3, 路由 `keygen/r3/seed` |
| PPRF 扩展 | $\kappa/K$ 棵 GGM 小树并行, 每棵 $2^K$ 叶子, all-but-one 求值 | `soft_spoken.rs` + [soft_spoken.md](soft_spoken.md) |
| 公钥还原校验 | 两条本地推导路径相等 ($\sum F_j(0) = \sum \lambda_j X_j$) | `dkg_fn.rs` `keystore` 构造后, 纯本地 |
