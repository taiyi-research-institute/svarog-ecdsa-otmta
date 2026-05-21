# 编排: keygen + sign (silence-laboratories 实现路线)

本文按 silence-laboratories 的 `dkls23` 实现 (即上游 `simple-dkls23`) 描述 keygen + sign 的实际通信轮编排. 笔记 [00-mta-baseot.md](00-mta-baseot.md) 到 [06-rvole.md](06-rvole.md) 已经把每个子协议讲清楚, 本文只讲"什么在哪轮发", 不重述子协议内部细节.

## 协议参数

* 总参与方 $n$, 阈值 $t$, 签名参与方 $|S| \ge t$.
* 每方公开 Birkhoff 坐标 $(x_i, r_i)$, $x_i$ 互异, $r_i\ge 0$ 是阶 (常用 $r_i = 0$ 即退化为 Lagrange). 详见 [misc-birkhoff.md](misc-birkhoff.md).
* sid 分层:
  - $\mathrm{sid}_i$: 个人随机, R1 广播.
  - $\mathrm{sid}^*$: 全员协商, $\mathrm{sid}^* := H(\mathrm{sid}_1 \,\|\, \cdots \,\|\, \mathrm{sid}_n)$.
  - 子协议 sid: 用 $\mathrm{sid}^*$ 加 pair 信息派生, 例如 base OT 实例 $(i,j)$ 用 $H(\mathrm{sid}^*, i, j, \texttt{"base\_ot"})$.

## 子协议依赖

| 子协议 | 用途 | 笔记 |
|---|---|---|
| EndemicOT | 每对 $(i,j)$ 两个方向的 base OT (各 $\kappa$ 个) | [03-endemic-ot.md](03-endemic-ot.md) |
| PPRF / GGM 树 | 把 base OT 扩展成 SoftSpoken 所需的 ROT 种子 | [04-pprf.md](04-pprf.md) |
| Birkhoff VSS | 阈值秘密分享, $r_i=0$ 退化 Lagrange | [misc-birkhoff.md](misc-birkhoff.md), [misc-fiat-shamir.md](misc-fiat-shamir.md) |
| SoftSpoken | sign 阶段每次现摇的 ROT 扩展 | [05-softspoken.md](05-softspoken.md) |
| RVOLE | sign 阶段 OT-MtA, 含 χ 一致性检查 | [06-rvole.md](06-rvole.md), [misc-gadget.md](misc-gadget.md) |

-----

# Keygen — 4 轮

目标: 全员共同生成 ECDSA 公钥 $\mathrm{pk}$, 各方持有 Birkhoff 份额 $\xi_i := P(x_i)^{(r_i)}$ (全局秘密多项式 $P$ 在自己坐标处的 $r_i$ 阶导值), 且双向的 PPRF 种子已建好, 后续 sign 不再跑 base OT.

## R1. Bcast — 摇随机, 提交多项式

每方 $i$ 本地:

1. 摇 $\mathrm{sid}_i \in \{0,1\}^{256}$.
2. 摇 $t-1$ 次随机多项式 $P_i \in \mathbb{Z}_n[X]$.
3. 算 Feldman 公点向量 $\mathbf{F}_i := (P_i.\mathrm{coeff}_0 \cdot G, \dots, P_i.\mathrm{coeff}_{t-1}\cdot G)$.
4. 摇 blind $\rho_i \in \{0,1\}^{256}$, 算第一次 hash 承诺
   $$
   \mathrm{Com}_i^{(1)} := H(\mathrm{sid}_i, i, r_i, x_i, \mathbf{F}_i, \rho_i).
   $$

广播 $(\mathrm{sid}_i,\, x_i,\, r_i,\, \mathrm{Com}_i^{(1)})$.

收齐后本地:
* 验所有 $x_j$ 互异.
* 算 $\mathrm{sid}^* := H(\mathrm{sid}_1 \,\|\, \cdots \,\|\, \mathrm{sid}_n)$, 此后子协议 sid 全部从 $\mathrm{sid}^*$ 派生.

## R2. P2P + Bcast 同包 — EndemicOT 启动 + Feldman 揭示

每方 $i$ 对每个 $j\ne i$:

* **P2P 部分**: 启动 EndemicOT 实例 $(i\!\to\!j)$, 即 $i$ 作 EndemicOT Receiver, 摇 base OT 选择位向量 $\boldsymbol{\beta}^{(i,j)} \in \mathbb{B}^\kappa$, 算 $\mathrm{OTMsg1}^{(i\to j)}$.
* **Bcast 部分** (同包附带, 内容对全员一致):
  - $\mathbf{F}_i$ (Feldman 群承诺).
  - blind $\rho_i$ (供他方还原 $\mathrm{Com}_i^{(1)}$).
  - $n$ 条 Schnorr-style DLog 证明 (label `DLOG_PROOF1`, sid 用 $\mathrm{sid}^*$), 每条证明知道 $\mathbf{F}_i$ 的某个系数对应的离散对数. 见 [misc-fiat-shamir.md](misc-fiat-shamir.md).
  - 第二次 hash 承诺 $\mathrm{Com}_i^{(2)} := H(\mathrm{sid}^*, \mathrm{cc\_sid}_i, \rho_i^{(2)})$, 把待用的链码片 $\mathrm{cc\_sid}_i$ 先承诺. $\mathrm{cc\_sid}_i, \rho_i^{(2)}$ 本地新鲜采样.

每方收齐每个 $j$ 发来的 KeygenMsg2 后本地:
* 用 Bcast 部分还原 $\mathrm{Com}_j^{(1)} \stackrel{?}{=} H(\mathrm{sid}_j, j, r_j, x_j, \mathbf{F}_j, \rho_j)$.
* 验所有 DLog 证明.
* 算全局多项式群承诺 $\mathbf{F} := \{ \sum_{j} \mathbf{F}_j \}$. 此即 $P := \{\sum_j P_j\}$ 的群承诺, $\mathrm{pk} = \mathbf{F}.\mathrm{coeff}_0$ (常数项).

## R3. P2P + Bcast 同包 — EndemicOT 收尾 + PPRF + Birkhoff 散值

每方 $i$ 对每个 $j\ne i$ (基于在 R2 收到的 $\mathrm{OTMsg1}^{(j\to i)}$):

* **P2P 部分**:
  - 算 EndemicOT 实例 $(j\!\to\!i)$ 的 Sender 应答 $\mathrm{OTMsg2}^{(j\to i)}$ ($i$ 作 Sender). 同时本地拿到 $\kappa$ 对 base OT 输出密钥 $\{(\rho^0_\ell, \rho^1_\ell)\}_{\ell\in[\kappa]}$.
  - 用这些密钥作 PPRF Sender 端的 master seeds, 跑 `build_pprf` 算 $\mathrm{PPRFOutput}^{(i\to j)}$ — 即 GGM 树修正项 $\{t^\ell_{i,b}\}$, 见 [04-pprf.md](04-pprf.md).
  - 算 Birkhoff 散值 $d_{i\to j} := P_i^{(r_j)}(x_j)$, 即"我的多项式在 $j$ 的 Birkhoff 点处的 $r_j$ 阶导".
  - 仅 $i > j$ 时摇 pairwise seed $\sigma_{ij} \in \{0,1\}^{256}$, 单向发给 $j$. 用于 sign 阶段构造 $\zeta_i$ 再随机化 (满足 $\sum_i\zeta_i = 0$), 见下文 sign R0.

* **Bcast 部分** (同包附带):
  - $\mathbf{F}$ (本方算出的全局多项式承诺, 供 $j$ 校验跨方一致).
  - $\mathrm{cc\_sid}_i$ + $\rho_i^{(2)}$ (揭示 $\mathrm{Com}_i^{(2)}$).

每方收齐 KeygenMsg3 后本地:

1. 验 $\mathbf{F}_j$ 跟自己算的 $\mathbf{F}$ 一致 (跨方 Feldman 共识).
2. 还原 $\mathrm{Com}_j^{(2)} \stackrel{?}{=} H(\mathrm{sid}^*, \mathrm{cc\_sid}_j, \rho_j^{(2)})$.
3. 把 R2 自己发出去的 $\mathrm{OTMsg1}^{(i\to j)}$ 和 R3 收到的 $\mathrm{OTMsg2}^{(i\to j)}$ 配对, EndemicOT Receiver 端处理得到 base OT 选择密钥 $\{\rho^{\beta_\ell}_\ell\}_{\ell\in[\kappa]}$.
4. 用上述选择密钥跑 `eval_pprf`, 配合收到的 $\mathrm{PPRFOutput}^{(j\to i)}$, 算 PPRF Receiver 端的"全员叶子减去打孔点". 此即 sign 阶段 SoftSpoken Sender 持有的 $\Delta$-correlated 种子.
5. **Feldman/Birkhoff 验证**: 对每个 $j$, 验 $d_{j\to i}\cdot G$ 跟 $\mathbf{F}_j$ 在 $(r_i, x_i)$ 处的群求值一致 (即把 $\mathbf{F}_j$ 视作群多项式 $P_j$ 的承诺, 求其 $r_i$ 阶导后代入 $x_i$).
6. 聚合本方份额
   $$
   \xi_i := \sum_{j\in[n]} d_{j\to i} = P^{(r_i)}(x_i).
   $$
7. 算 $S_i := \xi_i\cdot G$.
8. 算根链码 $\mathrm{cc} := H(\mathrm{cc\_sid}_1 \,\|\, \cdots \,\|\, \mathrm{cc\_sid}_n)$.
9. 算 DLog 证明 (label `DLOG_PROOF2`, sid 用 $\mathrm{sid}^* \,\|\, \mathrm{cc}$): 证明知道 $S_i$ 的离散对数.

## R4. Bcast — 最终份额公开

广播 $(S_i,\, \pi_i^{(2)},\, \mathrm{pk})$, $\pi_i^{(2)}$ 是上一步算的 DLog 证明. $\mathrm{pk}$ 是本方算的 $\mathbf{F}.\mathrm{coeff}_0$, 供跨方共识.

收齐后本地:

* 验所有 $\pi_j^{(2)}$.
* 验各方算出的 $\mathrm{pk}$ 全员一致.
* Birkhoff 重构验证: 任取一个大小为 $t$ 的子集 $S\subseteq[n]$, 算 Birkhoff 系数 $\lambda^S_j$ (见 [misc-birkhoff.md](misc-birkhoff.md)), 验 $\sum_{j\in S}\lambda^S_j \cdot S_j \stackrel{?}{=} \mathrm{pk}$.

## Keyshare 输出

每方 $i$ 持有
$$
\mathrm{Keyshare}_i := \bigl(i, x_i, r_i, \xi_i, \{\text{PPRF Sender seeds vs }j\}_{j\ne i}, \{\text{PPRF Receiver seeds vs }j\}_{j\ne i}, \{\sigma_{ij}\}_{j\ne i}, \mathrm{pk}, \mathrm{cc}\bigr).
$$

注: 每对 $(i, j)$ 有**两组**独立的 PPRF 种子, 一组 $i$ 作 Sender 一组 $i$ 作 Receiver. sign 阶段两个方向都要用.

-----

# Sign — 4 轮

输入: 各方持 $\mathrm{Keyshare}_i$, 公开签名者集合 $S$ ($|S|\ge t$), 消息哈希 $m\in\mathbb{Z}_n$, 可选 BIP-32 偏移 $\Delta_{\mathrm{off}}\in\mathbb{Z}_n$.

整体思路是 ECDSA 公式
$$
s := k^{-1}(m + R.x\cdot\mathtt{sk})
$$
拆成 $s = s_0 / s_1$ 两个分量, 各方各自算 $s_{0,i}, s_{1,i}$ 后 Bcast 聚合. 内部用 $\phi_i$ 引入二次盲化, 配合 pairwise RVOLE 兑现非对角项. 见 [06-rvole.md](06-rvole.md) 解释为什么 RVOLE 兑现 $y+z := w\beta$ 而不是直接 $y+z := w\cdot x$.

## R0. 本地准备 (无通信)

每方 $i$ 本地:

1. 派生公钥 $\mathrm{pk}' := \mathrm{pk} + \Delta_{\mathrm{off}}\cdot G$, 平摊偏移 $\delta_{\mathrm{per}} := \Delta_{\mathrm{off}} / |S|$.
2. 摇签名 nonce 分片 $r_i \stackrel{\$}{\leftarrow}\mathbb{Z}_n^*$, 算 $R_i := r_i\cdot G$.
3. 摇 MtA 二次盲化 $\phi_i \stackrel{\$}{\leftarrow}\mathbb{Z}_n^*$. 关于公开 $k\phi \bmod n$ 的安全性见 [06-rvole.md](06-rvole.md) "兑现 MtA 关系" 一节.
4. 摇 hash blind $b_i \in \{0,1\}^{256}$, 算 $\mathrm{Com}(R_i) := H(\mathrm{sid}, R_i, b_i)$.
5. **同时启动 RVOLE Receiver 一侧**: 对每个 $j\in S \setminus \{i\}$:
   - 算 pair sid $\mathrm{sid}^{(j\to i)} := H(\mathrm{sid}, j, i, \texttt{"mta"})$.
   - 用 keygen 留下的 PPRF Sender seeds (我作 SoftSpoken Receiver 这一侧) 跑 `rvole_round1`, 摇 SoftSpoken 选择向量, 算 SoftSpoken Msg1 和 gadget-聚合后的 RVOLE 输入 $\beta_{j,i} := \langle \mathbf{g}, \boldsymbol{\beta}^{(j,i)} \rangle$. 见 [05-softspoken.md](05-softspoken.md), [misc-gadget.md](misc-gadget.md).

## R1. Bcast — $R_i$ 承诺

广播 $\mathrm{Com}(R_i)$. 收齐后本地算全局 digest
$$
d := H(\mathrm{sid}, \mathrm{pk}', \{\mathrm{Com}(R_j)\}_{j\in S}),
$$
用于后续跨方一致性绑定.

承诺先发再揭示, 防 last-actor 操纵 $R = \sum_j R_j$.

## R2. P2P — RVOLE Receiver Msg1

每方 $i$ 对每个 $j\in S\setminus\{i\}$ 发 $\mathrm{SoftSpokenMsg1}^{(j\to i)}$ 给 $j$. 同时收 $j$ 发给我的 $\mathrm{SoftSpokenMsg1}^{(i\to j)}$.

收齐后本地, **作 RVOLE Sender** (pair $i\to j$ 方向):

* 输入两路标量 $(r_i, \xi_i')$, 其中 $\xi_i' := \lambda_i^S \cdot\xi_i + \zeta_i + \delta_{\mathrm{per}}$.
  - $\lambda_i^S$ 是签名者集合 $S$ 上的 Birkhoff 系数 (使得 $\sum_{i\in S}\lambda_i^S\cdot \xi_i = \mathtt{sk}$).
  - $\zeta_i$ 是 pairwise 再随机化项, $\sum_{i\in S} \zeta_i = 0$, 由 keygen 留下的 $\{\sigma_{ij}\}$ 派生. 见 [helpers.rs](../src/dsg/helpers.rs) `compute_zeta_i`.
  - $\delta_{\mathrm{per}}$ 是平摊到本方的 BIP-32 偏移.
  - 满足 $\sum_{i\in S}\xi_i' = \mathtt{sk} + \Delta_{\mathrm{off}}$, 即派生密钥的本方份额.
* 跑 `rvole_round2` 算 $\mathrm{RVOLEMsg2}^{(i\to j)}$ (含 $\tilde a, \eta, \sigma$, 见 [06-rvole.md](06-rvole.md)), 同时算 Sender 自留分片 $(c^u_{i\to j}, c^v_{i\to j})$ 满足
  $$
  c^u_{i\to j} + d^u_{j\to i} := r_i \cdot\beta_{i,j}, \quad
  c^v_{i\to j} + d^v_{j\to i} := \xi_i' \cdot\beta_{i,j}.
  $$
* 算 $\Gamma$ 一致性点 $\Gamma^u_{i\to j} := c^u_{i\to j}\cdot G$, $\Gamma^v_{i\to j} := c^v_{i\to j}\cdot G$.
* 算 $\psi_{i\to j} := \phi_i - \beta_{i,j}$ (二次盲化的差值, 把 $\beta$ 抵消的工作留给全员聚合阶段).
* 算本方公钥分片 $\mathrm{pk}_i := \xi_i'\cdot G$.

## R3. P2P — RVOLE Sender Msg2 + 揭示

每方 $i$ 对每个 $j\in S\setminus\{i\}$, 在一个 P2P 包里同时发:

| 字段 | 内容 |
|---|---|
| `mta_msg2` | $\mathrm{RVOLEMsg2}^{(i\to j)}$ |
| `R_i, b_i` | $R_i$ 与 blind, 揭示 $\mathrm{Com}(R_i)$ |
| `pk_i` | $\mathrm{pk}_i = \xi_i'\cdot G$ |
| `gamma_u, gamma_v` | $\Gamma^u_{i\to j}, \Gamma^v_{i\to j}$ |
| `psi` | $\psi_{i\to j}$ |
| `digest` | $d$ (跨方共识检查) |

收齐 R3 后本地:

1. 验 $H(\mathrm{sid}, R_j, b_j) \stackrel{?}{=} \mathrm{Com}(R_j)$ (commit-reveal).
2. 验各方 digest 全员一致.
3. **完成 RVOLE Receiver** (pair $j\to i$): 跑 `round3_rvole($\mathrm{RVOLEMsg2}^{(j\to i)}$)`, 得 $(d^u_{j\to i}, d^v_{j\to i})$.
4. **验 $\Gamma$ 一致性** (RVOLE 没绑承诺时的椭圆曲线对账):
   $$
   \beta_{j,i}\cdot R_j \stackrel{?}{=} \Gamma^u_{j\to i} + d^u_{j\to i}\cdot G, \qquad
   \beta_{j,i}\cdot \mathrm{pk}_j \stackrel{?}{=} \Gamma^v_{j\to i} + d^v_{j\to i}\cdot G.
   $$
5. 累加 $R := \sum_{j\in S} R_j$, 取 $r_x := R.x \bmod n$ (即 ECDSA 的 $r$).
6. 验 $\sum_{j\in S} \mathrm{pk}_j \stackrel{?}{=} \mathrm{pk}'$ (派生公钥跨方一致).
7. 算
   $$
   \Phi_i := \phi_i + \sum_{j\ne i}\psi_{j\to i}, \quad
   U_i := \sum_{j\ne i}\bigl(c^u_{i\to j} + d^u_{j\to i}\bigr), \quad
   V_i := \sum_{j\ne i}\bigl(c^v_{i\to j} + d^v_{j\to i}\bigr).
   $$
8. 算部分签名
   $$
   s_{1,i} := r_i\cdot\Phi_i + U_i, \qquad
   s_{0,i} := r_x\cdot\bigl(\xi_i'\cdot\Phi_i + V_i\bigr) + m\cdot\phi_i.
   $$
   $s_0$ 是 ksPhi 分片, $s_1$ 是 kPhi 分片.

注: silence-laboratories 实现把"算 $s_{0,i}$ 时把 $m$ 混进去"留到 R4 发送前的本地步骤, 实现 pre-sign 接口 (R1-R3 跑完, R4 时才决定签什么消息). 协议层面等价.

## R4. Bcast — 部分签名汇总

广播 $(s_{0,i}, s_{1,i})$. 收齐后:
$$
s := \frac{\sum_{j\in S} s_{0,j}}{\sum_{j\in S} s_{1,j}} = k^{-1}(m + r_x\cdot\mathtt{sk}_{\mathrm{derived}}).
$$

工程加固: 本地跑一遍 ECDSA 标准验签, 失败即 abort. 论文层面不强制, 实现都加了.

输出: $(r, s) := (r_x, s)$.

-----

# 子协议跨轮嵌入速查

## Keygen

| 子协议 | R1 | R2 | R3 | R4 |
|---|---|---|---|---|
| EndemicOT (两方向并行) | | Msg1 (我作 Receiver) | Msg2 (我作 Sender), 同时处理对方的 Msg2 | |
| PPRF | | | `build_pprf` (我作 Sender 发 output) + `eval_pprf` (我作 Receiver 处理对方的 output) | |
| Birkhoff VSS | 摇 $P_i$ | $\mathbf{F}_i$ Bcast + 第一次 DLog 证明 | 散 $d_{i\to j}$, 收齐后聚合 $\xi_i$, Feldman 验证 | $S_i$ Bcast + 第二次 DLog 证明 |
| Hash commits | $\mathrm{Com}^{(1)}$ | $\mathrm{Com}^{(1)}$ open, $\mathrm{Com}^{(2)}$ | $\mathrm{Com}^{(2)}$ open | |

## Sign

| 子协议 | R0 | R1 | R2 | R3 | R4 |
|---|---|---|---|---|---|
| SoftSpoken (每签现摇) | 启动 Receiver | | Msg1 (作 Receiver) → 收到对方 Msg1 后作 Sender | | |
| RVOLE | | | Sender 处理 (Msg2 计算) | Msg2 发送 + Receiver 端完成 + $\Gamma$ 验证 | |
| $R_i$ commit-reveal | 算 $\mathrm{Com}(R_i)$ | Bcast commit | | reveal $(R_i, b_i)$ | |
| ECDSA 拼装 | 摇 $r_i, \phi_i$ | | 本地算 $\xi_i'$ | $\Phi_i, U_i, V_i, s_{0,i}, s_{1,i}$ | Bcast + 聚合 |
