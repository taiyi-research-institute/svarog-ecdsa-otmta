# 再随机化 $\zeta_i$

Pre-sign 阶段每方衍生分片 $x'_i := \lambda(i,S) x_i + \zeta_i + \nabla x \cdot |S|^{-1}$ 里的中间项. 见 `07-orchestration.md` Pre-sign Round 1 (2).

## 问题

Pre-sign Round 2, 每方喂给 RVOLE Sender 的输入是 $(r_i, x'_i)$. $r_i$ 在每次签名里是新鲜的, 这没问题. 若 $x'_i$ 里没有 $\zeta_i$, 它在 $S$ 和 $\nabla x$ 固定时完全确定. 这意味着, 同一签名者集合下, 每次 RVOLE Sender 都喂同一个长期值进去.

RVOLE Sender 的 SoftSpoken 一致性检查给恶意 Receiver 的作弊概率上界是 $2^{-S}$ 每次, 但在跨签名场景里, "有效泄露" 能够累积. 短期看不出来, 长期下 Receiver 可以慢慢抠出 $x_i$ 的比特.

工程上的对策: 在 $x'_i$ 上再叠一层每签 fresh 的盲化 $\zeta_i$, 让 RVOLE Sender 喂出去的值在每次签名里都是 fresh 随机数.

## 全局约束

$\zeta_i$ 是本方私有, 但全员加起来必须满足 $\sum_{i\in S}\zeta_i = 0$. 

## 构造

Keygen Round 3 时, 每对 $i > j$ 摇了对称盲化项 $\epsilon_{i,j} \in \mathbb{B}^{256}$, 双方都存. Sign 时双方对称地从这一颗种子派生一个只供这次签名用的标量:
$$
\zeta_{i,j} := \mathrm{Hash}(\epsilon_{\max(i,j),\min(i,j)}, \mathrm{sid}, S) \in \mathbb{Z}_n. \tag{zeta-ij}
$$

然后用一个反对称权重把所有 pairwise $\zeta_{i,j}$ 拼成 $\zeta_i$:
$$
\zeta_i := \sum_{j\in S\setminus\{i\}} \mathrm{sgn}(i,j)\cdot \zeta_{i,j}, \quad
\mathrm{sgn}(i,j) := \begin{cases} +1 & i > j \\ -1 & i < j \end{cases}. \tag{zeta}
$$

妙处 1: 全局加起来是 0

原因: 对每对 $\{i, j\}$, 较大编号那方加 $+\zeta_{i,j}$, 较小编号那方加 $-\zeta_{i,j}$. 全员求和时抵消掉.

妙处 2: 不需要通信

原因: 每对 $\zeta_{i,j}$ 只用到 keygen 时已经共享的 $\epsilon_{i,j}$ 和公开的 $\mathrm{sid}, S$. 双方独立算同样的值, sign 阶段不需要为此发任何消息.

## 理论 vs 工程

DKLS23 论文证明 sign 在任意多签下安全, 严格意义上不需要 $\zeta_i$. 本文的技巧是一项额外的加固, 使得多次 RVOLE 一致性检查的 union bound 永远拿不到 $x_i$ 的任何比特, 因为 Receiver 看到的输入每次都已经被新鲜的 $\zeta_i$ 混淆掉.

什么是 union bound? 简单理解就是, 多次执行协议, 每次泄露一点点信息, 累积起来就极大地降低了破解信息的难度.