# Keygen 数学原理笔记

本文档与 [dkg_fn.rs](dkg_fn.rs) 配套, 记录当前 keygen 移植范围、关键数学结构和与 `simple-dkls23` 的差异.

依赖顺序为: B (`seed_i_j`) → A (PPRF 扩展) → C (公钥还原自洽性校验).
`chain_code` 由调用方直接传入, 不参与本协议的随机性生成或共识流程, 此处不展开.

## 当前移植状态

按当前工程范围, `keygen()` 的 MVP 移植已经完成.
它返回 `Keystore<Secp256k1>`, 其中 `aux` 字段序列化保存签名前置材料:

* `Keystore<Secp256k1>`: VSS 后得到的本方长期份额、全体公开承诺和外部传入的 `chain_code`.
* `KeygenAux.pprf_seeds`: 每个对端一组 EndemicOT + SoftSpoken PPRF 扩展得到的 all-but-one 种子材料.
* `KeygenAux.seeds`: 签名时派生份额随机偏移 $\zeta_i$ 的两方明文种子.

本阶段明确不包含:

* `keygen()` 多方端到端测试. 当前只确认底层 OT、PPRF 和 messenger 测试.
* 签名阶段, 包括 SoftSpoken OT 上层随机 OT、RVOLE、MtA 和 ECDSA 签名流程.
* refresh / rotation.

当前 keygen 的安全检查边界:

* Round 0/1 做 commit-reveal、系数 DLog proof、Feldman VSS 验证.
* `chain_code` 由调用方传入, 不做共识生成, 也不绑定额外的 Schnorr proof.
* 末尾保留本地 public-key sanity check, 用来发现实现 bug; 它不是额外的恶意安全证明轮.

---

## B. `seed_i_j`: 配对随机化种子

### 它解决什么问题

在签名的 MtA 步骤中, 每方会先用 Lagrange 系数缩放自己的份额 $s_i$, 再参与两方乘法.
但 $\lambda_i \cdot s_i$ 本身仍携带 $s_i$ 的线性信息.
如果 MtA 的中间值泄露, 对手方可能反推份额.

解决方法是在每次签名前给每方的有效份额加一个随机偏移 $\zeta_i$,
**但这些偏移全局相消**, 不影响最终结果.

### 数学结构

对每对参与方 $(i, j)$ (约定 $i < j$),
keygen 时**低 id 的 $i$ 方**生成 32 字节随机数 $\text{seed}_{ij}$, 明文发给 $j$.
这个种子不是秘密, 不需要加密; 它只需要在 keygen 会话内保持唯一且随机.

在签名时, 给定签名会话 ID $\text{sig\_id}$, 定义:

$$v_{ij} = \text{Hash}(\text{seed}_{ij} \| \text{sig\_id})$$

每方的偏移量 $\zeta_i$ 定义为:

$$\zeta_i = \underbrace{\sum_{j < i} v_{ji}}_{\text{rec 贡献}} - \underbrace{\sum_{j > i} v_{ij}}_{\text{sent 贡献}}$$

关键性质是 $\sum_i \zeta_i = 0$:
每个 $v_{ij}$ 在 $i$ 方贡献 $-v_{ij}$, 在 $j$ 方贡献 $+v_{ij}$, 两者正好抵消.

因此 $\text{sk}_i = \lambda_i \cdot s_i + \zeta_i$ 是重随机化后的有效份额.
又因为 $\sum \zeta_i = 0$,
所以 $\sum_i \text{sk}_i = \sum_i \lambda_i \cdot s_i = \text{私钥}$.

### Keygen 实现要点

* `PairwiseSeeds { sent, rec }` 内部都是 `HashMap<usize, [u8; 32]>`, 以对端 id 作 key.
* Round 3 同一次 `exchange()` 里, 对每个 $j > i$ 的对端,
  $i$ 用 Blake2b 生成 32 字节种子写入 `sent_seeds[j]`,
  并通过路由 `keygen/r3/seed` 明文发给 $j$.
* 对每个 $j < i$ 的对端,
  $i$ 通过路由 `keygen/r3/seed` 收到 $j$ 的种子, 写入 `rec_seeds[j]`.
* 不做加密.
  该种子只是双方在签名时生成相同 $v_{ij}$ 的公共随机性.

---

## A. SoftSpoken PPRF 扩展

> 本节只给数学背景概览. 详细协议、类型、`build_pprf` / `eval_pprf` 算法和参数表见 [soft_spoken.md](soft_spoken.md).

### 背景: 为什么需要它

Base OT (EndemicOT) 给双方 $\kappa$ 对密钥.
secp256k1 取 $\kappa = 256$, 对应源码常量 `LAMBDA_C`.

签名中的 MtA 需要 $L \gg \kappa$ 个扩展 OT 实例.
DKLS23 取 $L = \kappa + 2\lambda_s = 512$ (统计安全参数 $\lambda_s = 128$).

PPRF 扩展的作用是把 $\kappa$ 对 base OT 密钥"拉伸"成建立 $L$ 个扩展 OT 所需的基材.
这层是纯本地计算, 只需一次 `PPRFOutput` 交换.
真正的 $L$ 个扩展 OT 留到签名阶段, 由上层 `soft_spoken_ot.rs` (尚未移植) 根据 PPRF 基材组合生成.

### 多棵小树的结构

SoftSpoken 不采用"单棵深度 $\log_2 L$ 的 GGM 树"这一抽象.
它把 $\kappa$ 对 base OT 按每 $K$ 位一组分块, 构造 $\kappa / K$ 棵并行的小 GGM 树.
源码中 $K = \text{SOFT\_SPOKEN\_K} = 4$, 共 $\kappa/K = 64$ 棵树.
每棵小树的叶子数 $Q = 2^K = 16$.

Sender 知道每棵树的全部 16 个叶子.
Receiver 在每棵树里有一个 punctured 下标 $y^*_j$ 不可知, 其余 15 个叶子可以重建.
$y^*_j$ 由 Receiver 在该树覆盖的 4 位 base OT 选择位决定.

### 到签名时的承接

PPRF 输出的 `SenderOTSeed` / `ReceiverOTSeed` 是基材, 不等于最终 $L = 512$ 个扩展 OT.
签名阶段会把这 64 棵小树的叶子按 IKNP 风格组合成 $L$ 个随机 OT 实例,
再由 `rvole.rs` 组装成 MtA (RVOLE).

`extot-dkls23-derand.md` 里 "Step 1 随机 OT" 描述的抽象接口 $(\alpha^0_j, \alpha^1_j, \gamma_j)$,
对应的是上层 $L$ 个随机 OT 的产物, 不是 PPRF 直接输出的叶子.
Keygen 阶段只准备底层材料; 签名阶段再消费这些材料生成上层 OT.

---

## C. 公钥还原自洽性校验

### 与 `simple-dkls23` Round 4 的对比

`simple-dkls23` 的 Round 4 做三件事:
广播 $S_j = s_j \cdot G$, 验证 $S_j$ 与 Feldman 承诺一致, 然后 Lagrange 还原公钥并校验.
还附带一轮 Schnorr DLog 证明绑定 `final_session_id` 与 `root_chain_code`.

本 port 将这部分检查前置到 Round 1, 末尾不再额外广播 $S_i$:

* DLog proof 的对象从"份额 $s_j$"改成"多项式系数 $f_j$".
  Round 1 里 `dlog_prove_batch` / `dlog_verify_batch` (见 `helpers.rs`) 一次性证明所有 $\text{polycom}[j][k]$.
* Feldman 一致性 $f_j(i) G = F_j(i)$ 由 `verify_fj_at_i` 检查 (`dkg_fn.rs:173`).
  这保证对方发给我的份额与它承诺的多项式一致.
* `chain_code` 直接从参数传入, 没有共识 transcript, 也就不需要 Schnorr 证明里再绑链码.

恶意行为检查集中在 Round 0/1 完成, 所以 keygen 末尾只保留本地一致性检查.

### 公钥还原校验

Keygen 中"公钥"是输出而不是输入, 没有外部预期值可以比对.
但仍然可以用同一份 `vss_scheme` 沿两条路径推导公钥, 做一个本地自洽性检查.

* 路径 A: 各方常数项之和.

$$\text{PK}_A = \sum_{j \in \Omega_k} F_j(0) = \sum_{j \in \Omega_k} \text{polycom}[j][0]$$

  对应 `Keystore::public_key()`.

* 路径 B: 对所有方的 $X_j := x_j G$ 做 Lagrange 插值.

$$\text{PK}_B = \sum_{j \in \Omega_k} \lambda_j \cdot X_j, \quad X_j = \sum_{k \in \Omega_k} F_k(j) = \mathrm{eval\_xi\_com}(j, \text{vss\_scheme})$$

  $\lambda_j$ 是 keygen 全集 $\Omega_k$ 上的 Lagrange 系数.

由于多项式度数 $\text{th} - 1 < |\Omega_k|$, 在 $\Omega_k$ 上做 Lagrange 插值可以还原 $\sum f(0)$, 即私钥.
两边同乘 $G$ 得 $\text{PK}_A = \text{PK}_B$.
这个恒等式由 VSS 数学保证; 若两边不等, 通常说明 Lagrange / 多项式库或 `vss_scheme` 结构存在实现 bug.

注意, 这不是恶意安全检查, 只是一道防实现错误的护栏.
假承诺、错份额等恶意行为应当已经由 Round 0 的 commit-reveal、Round 1 的 DLog proof 和 `verify_fj_at_i` 拦下.

实现位于 `dkg_fn.rs` 中 `keystore` 构造之后, 是纯本地计算, 不增加通信轮次.

---

## 总结对照

| 部分 | 核心数学 | 在本仓库的位置 |
|---|---|---|
| VSS keygen | 每方生成 Shamir 多项式并交换 $f_i(j)$ 与 $F_i$ | `dkg_fn.rs` Round 0/1 |
| Commit + DLog proof | 先承诺, 后揭示; 证明知道所有 polynomial commitments 的离散对数 | `helpers.rs`, `dkg_fn.rs` Round 0/1 |
| Feldman verify | 验证收到的份额满足 $f_j(i)G = F_j(i)$ | `Secp256k1::verify_fj_at_i` |
| `Keystore` | 保存本方 `xi`, 全体 `vss_scheme`, 外部传入的 `chain_code` | `dkg_fn.rs` 构造 `Keystore` |
| `seed_i_j` | 配对随机偏移 $\zeta_i$, 全局相消 | `dkg_fn.rs` Round 3, 路由 `keygen/r3/seed` |
| PPRF 扩展 | $\kappa/K$ 棵 GGM 小树并行, 每棵 $2^K$ 叶子, all-but-one 求值 | `soft_spoken.rs` + [soft_spoken.md](soft_spoken.md) |
| 公钥还原校验 | 两条本地推导路径相等 ($\sum F_j(0) = \sum \lambda_j X_j$) | `dkg_fn.rs` `keystore` 构造后, 纯本地 |

## 下一步边界

后续若继续移植, 应从签名阶段消费 `Keystore` 和 `decode_keygen_aux(keystore.aux)` 开始:
`KeygenAux.pprf_seeds` 和 `KeygenAux.seeds` 只是签名前置材料,
还不是 DKLS23 签名时真正使用的扩展随机 OT / MtA 输出.

refresh / rotation 继续保持在范围外, 等基础 keygen + signing 路径跑通后再单独处理.
