# Keygen 剩余未移植部分的数学原理

按依赖顺序: B (seed_i_j) → A (PPRF 扩展) → C (Round 4 验证). D (chain code) 可选, 与密码学安全无关.

---

## B. `seed_i_j`: 配对随机化种子

### 它解决什么问题

在签名的 MtA 步骤中, 每方都用 Lagrange 系数缩放自己的份额 $s_i$, 再参与两方乘法. 但 $\lambda_i \cdot s_i$ 本身就携带了 $s_i$ 的线性信息. 如果 MtA 的中间消息泄露, 对手方可以反推份额.

解决方法: 在每次签名前, 给每方的有效份额加一个随机偏移 $\zeta_i$, **但这些偏移全局相消**, 不影响最终结果.

### 数学结构

对每对参与方 $(i, j)$ (约定 $i > j$), keygen 时 $i$ 方生成 32 字节随机数 $\text{seed}_{ij}$, 明文发给 $j$. 这个种子不需要加密, 它不是秘密, 只需要唯一性和随机性.

在签名时, 给定签名会话 ID $\text{sig\_id}$, 定义:

$$v_{ij} = \text{Hash}(\text{seed}_{ij} \| \text{sig\_id})$$

每方的偏移量 $\zeta_i$ 定义为:

$$\zeta_i = \underbrace{\sum_{j < i} v_{ji}}_{\text{rec\_seed 贡献}} - \underbrace{\sum_{j > i} v_{ij}}_{\text{sent\_seed 贡献}}$$

**关键性质**: $\sum_i \zeta_i = 0$, 因为每个 $v_{ij}$ 在 $i$ 方贡献 $-v_{ij}$, 在 $j$ 方贡献 $+v_{ij}$, 两者抵消.

所以 $\text{sk}_i = \lambda_i \cdot s_i + \zeta_i$ 是重随机化后的有效份额. 而 $\sum_i \text{sk}_i = \sum_i \lambda_i \cdot s_i = \text{私钥}$, 因为 $\sum \zeta_i = 0$.

### Keygen 实现要点

* 方 $i$ 对方 $j$ (当 `from_id > self.party_id`, 即 $j > i$): $i$ 生成 `seed_i_j`, 存入 `sent_seed_list`, 塞进 `KeygenMsg3.seed_i_j = Some(...)`.
* 方 $i$ 收到来自 $j$ (当 $j > i$) 的 `seed_j_i`: 存入 `rec_seed_list`.
* 赋值方向没有加密保护. 这个种子本来就不需要保密, 它只是双方签名时用来生成相同 $v_{ij}$ 的公共随机性.

---

## A. SoftSpoken PPRF 扩展

### 背景: 为什么需要它

Base OT (EndemicOT) 给了双方 $\kappa$ ($= 128$) 对密钥. 但签名时每次 MtA 需要 $m \gg \kappa$ 个 OT 实例, DKLS23 实际上需要 $m = \kappa + 2\lambda$ 个. PPRF 扩展的作用是: 把 $\kappa$ 对 base OT 密钥"拉伸"成 $m$ 对 OT 密钥. 这个拉伸是本地计算, 不需要新一轮通信, 通信只是 `PPRFOutput`, 比 $m$ 个密钥小得多.

### GGM 树

选一个 PRG: $G: \{0,1\}^\lambda \to \{0,1\}^{2\lambda}$, 记 $G(k) = (G_L(k),\, G_R(k))$.

构造深度为 $\log_2 m$ 的二叉树:

* 根节点 $k_\epsilon$ 是初始种子.
* 节点 $k_v$ 的左右子节点分别是 $G_L(k_v)$ 和 $G_R(k_v)$.
* 叶子共 $m$ 个, 叶子 $j$ 的值即为扩展 OT 实例 $j$ 的密钥.

### Sender 侧: `build_pprf`

Base OT 的 Sender 拥有 $\kappa$ 对密钥 $(k_0^{(\ell)},\, k_1^{(\ell)})$, 对应 Receiver 的选择位 $\beta_\ell \in \{0,1\}$.

Sender 利用这 $\kappa$ 对密钥构造完整 GGM 树, 知道所有 $m$ 个叶子 $(K_0^{(j)},\, K_1^{(j)})$.

**发给 Receiver 的 `PPRFOutput`**: Receiver 有选择位向量 $\beta = (\beta_1, \ldots, \beta_\kappa)$, 对应树中一条从根到某叶的路径. Sender 发送这条路径上每一层的**兄弟节点** (共 $\log_2 m$ 个), 这样 Receiver 就能重建除 $\beta$ 所指那一个叶子之外的所有叶子.

**存储**: `SenderOTSeed` = 完整 GGM 树 (紧凑表示为根密钥), 签名时用它重建任意 $(K_0^{(j)},\, K_1^{(j)})$.

### Receiver 侧: `eval_pprf`

Base OT 的 Receiver 有选择位 $\beta$ 和对应密钥 $k_{\beta_\ell}^{(\ell)}$.

用这些密钥加上 `PPRFOutput` 里的兄弟节点, 从上到下重建 GGM 树上除路径 $\beta$ 以外的所有子树, 得到所有叶子 $K_{\beta_j}^{(j)}$. 每个实例只知道 Receiver 选中的那一侧.

**存储**: `ReceiverOTSeed` = 选择位向量 $\beta$ + 每个实例的 $K_{\beta_j}^{(j)}$.

### 最终状态

扩展完成后, 每对 $(i, j)$ 之间对 $m$ 个 OT 实例建立了如下相关性:

| 方 | 拥有 |
|---|---|
| OT Sender ($i$ 发给 $j$) | $(K_0^{(1)}, K_1^{(1)}), \ldots, (K_0^{(m)}, K_1^{(m)})$ |
| OT Receiver ($j$ 收自 $i$) | $\beta^{(1)}, \ldots, \beta^{(m)}$ 及对应 $K_{\beta^{(j)}}^{(j)}$ |

这是 `extot-dkls23-derand.md` 里 "Step 1 随机 OT" 里的 $(\alpha^0_j,\, \alpha^1_j,\, \gamma_j)$. Keygen 已经把这个表全部建好了, 签名时直接用.

---

## C. Round 4: `big_s_i` 验证与 `check_secret_recovery`

### 问题背景

到 Round 3 结束时, 每方已经计算出自己的份额 $s_i = \sum_j F_j(x_i)$, 其中 $F = \sum_j F_j$ 是所有方多项式的和, $x_i$ 是该方的 Lagrange 插值横坐标 (在本实现里就是参与方编号).

但没有人能独自验证别人的 $s_j$ 是否正确, 直接发 $s_j$ 会泄露秘密份额. 所以改为发布 $S_j = s_j \cdot G$, 椭圆曲线上的公开值.

### 第一步: 验证 $S_i$ 与公共多项式 $F$ 的一致性

每个人对 $S_j$ 的正确值有独立的预期: 因为 $F$ 的系数承诺 $\{F_k = f_k \cdot G\}_{k=0}^{t-1}$ 是公开的 (通过 Feldman VSS), 所以:

$$S_j \stackrel{?}{=} \sum_{k=0}^{t-1} x_j^k \cdot F_k$$

这是把曲线上的多项式在 $x_j$ 处求值. 左边是对方声称的, 右边是根据公开承诺计算的, 两者必须相等.

### 第二步: `check_secret_recovery` 验证 Lagrange 插值还原公钥

如果各方的 $S_i$ 全部正确, 那么对整个 $t$-参与方集合做 Lagrange 插值, 结果必须等于公钥:

$$\text{PK} \stackrel{?}{=} \sum_{i=0}^{t-1} \lambda_i \cdot S_i, \quad \lambda_i = \prod_{j \neq i} \frac{x_j}{x_j - x_i}$$

这是 Feldman VSS 公开可验证性的直接推论: $\sum \lambda_i \cdot s_i = F(0) = \text{私钥}$, 两边同乘 $G$ 即得.

### 第三步: DLog 证明

仅凭 $S_i$ 的值还无法防止一方伪造, 他可以声称任意 $S_i$, 只要通过上面的检验. DLog 证明 (Schnorr 证明) 要求每方证明自己确实知道 $s_i$ 使得 $S_i = s_i \cdot G$, 否则无法生成有效证明.

在 `simple-dkls23` 里, DLog 证明的 transcript 中包含了 `final_session_id` 和 `root_chain_code`, 这同时确保了所有人对同一个链码达成共识. 任何一方若在前面的步骤里广播了不同的链码, 这里的证明就会验不过.

---

## 总结对照

| 部分 | 核心数学 | 笔记是否覆盖 |
|---|---|---|
| `seed_i_j` | 配对随机偏移 $\zeta_i$, 全局相消 | 概念覆盖 (`extot-dkls23-derand.md` Step 1), 但未与代码关联 |
| PPRF 扩展 | GGM 树, all-but-one 求值, $\kappa$ 种子 → $m$ OT 密钥对 | 未覆盖 |
| Round 4 验证 | Feldman 群多项式求值 + Lagrange 插值还原 + Schnorr 证明 | 未覆盖 |
