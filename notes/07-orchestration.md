协议参数

* 总参与方 $n$, 阈值 $t$, 签名参与方 $|S| \ge t$.
* 本文 Lagrange 插值直接用参与方编号 $i$ 作为求值点 (视作 $\mathbb{Z}_n^*$ 元素), 不另立坐标记号.
* `sid` 是协议外部输入, 全员事先约定, 协议内部不再协商.
* 子协议 sid 从 `sid` 和参与方编号派生而来. 例如 base OT 实例 $(i,j)$ 用
$$
\mathrm{Hash}(\mathtt{sid}, i, j, \texttt{"base\_ot"}). \tag{subsid-example}
$$

# Keygen — 4 轮

目标: 全员共同生成 ECDSA 公钥 $Y$, 各方持有 Shamir 份额 $x_i := P(i)$ (全局秘密多项式 $P$ 在自己编号处的求值), 且双向的 PPRF 种子已建好, 后续 sign 不再跑 base OT.

## Round 1. Feldman 承诺

每个参与方 $i$ 在本地:

(1) 摇 $t-1$ 次随机多项式 $P_i \in \mathbb{Z}_n[X]$. 记系数为 $c_{i,0}$ 到 $c_{i,t-1}$.

(2) 算 Feldman 向量 $\mathbf{F}_i := (c_{i,0} \cdot G, \cdots, c_{i,t-1}\cdot G)$.

(3) 摇盲化 $\varepsilon_{1,i} \in \mathbb{B}^{256}$, 计算第一次 hash 承诺
$$
\mathrm{Com}_{1,i} := \mathrm{Hash}(\mathrm{sid}, i, \mathbf{F}_i, \varepsilon_{1,i}).
$$

(exchange) 广播 $\mathrm{Com}_{1,i}$.

## Round 2. 启动 Endemic OT, 揭示 Feldman 承诺.

每个参与方 $i$ 对其他参与方 $j\ne i$:

(1) 调用 Endemic OT, $i$ 作为 EndemicOT Receiver, 详见 `03-endemic-ot.md` Round 1.
* 摇 base OT 选择位向量 $\boldsymbol{\beta}_{i,j} \in \mathbb{B}^\kappa$,
* 计算两个群元素 $R_{0,i,j}, R_{1,i,j}$. 

(2) 为 $P_i$ 的每个系数制作 DLog 证明. 详见 `misc-fiat-shamir.md`.

(exchange)

* P2P 发送 $R_{0,i,j}, R_{1,i,j}$.
* 广播上一轮生成的 $\mathbf{F}_i$, $\varepsilon_i$, 供其他方揭开 $\mathrm{Com}_{1,i}$.
* 广播 DLog 证明.

(3) 收齐所有 $j$ 的通信内容, 做这些检验工作:
* 重新计算 $\mathrm{Com}_{1,j}$, 比对与 Round 1 所收到的是否相等.
* 验证所有 DLog 证明.

(4) 聚合. 计算全局多项式承诺 $ \mathbf{F}:=\sum_j \mathbf{F}_j $. 这就是全局多项式 $P:=\sum_j P_j$ 的群承诺. 私钥为常数项 $P(0)$, 公钥为常数项 $\mathbf{F}(0)$.

## Round 3. Endemic OT 收尾, PPRF 建树, Shamir 散值.

每个参与方 $i$ 对其他参与方 $j\ne i$:

(1) 执行 Endemic OT Sender. 详见 `03-endemic-ot.md` Round 2.
* 取 $j$ 在 Round 2 发来的 $R_{0,j,i}, R_{1,j,i}$, 算 Sender 应答 $M_{0,j,i}, M_{1,j,i}$.
* 计算 $\kappa$ 对 Base OT 密钥 $\rho^0_{\ell,j,i}, \rho^1_{\ell,j,i}$ ($\ell\in[\kappa]$). 

(2) 构建和证明 PPRF 树. 详见 `04-pprf.md` BuildPPRF 和 ProvePPRF 部分. 得到 $\kappa/K$ 棵 GGM 树. 第 $\ell$ 棵树有
* 除第一层以外, 每一层有选 0 修正值 $\vec{t}_{\ell,0}$ 和选 1 修正值 $\vec{t}_{\ell,1}$.
* 证明材料 $\tilde t_{\ell,j,i}, \tilde s_{\ell,j,i}$.
* 本地保留 master seeds, 作为 sign 阶段 SoftSpoken Receiver 一侧的种子.

(3) 算 Shamir 散值 $d_{i,j} := P_i(j)$.

(4) 仅当 $i > j$, 摇对称盲化项 $\epsilon_{i,j} \in \mathbb{B}^{256}$.

(exchange)

* P2P 发送 $M_{0,j,i}, M_{1,j,i}$, 所有 $\vec{t}_{\ell,*}$, $\tilde t_{\ell,j,i}, \tilde s_{\ell,j,i}$, $d_{i,j}$.
* 仅当 $i > j$, P2P 发送 $\epsilon_{i,j}$.
* 广播 $\mathbf{F}$.

(5) 做这些检验工作:
* 验证来自 $j$ 的 $\mathbf{F}$ 等于自己算的 $\mathbf{F}$.
* 验证 $d_{j,i} \cdot G \stackrel{?}{=} \mathbf{F}_j(i)$.

(6) 执行 Endemic OT Receiver. 具体来说, 消费自己创造的 $R_{*,i,j}$ 以及参与方 $j$ 发来的 $R_{*,i,j}$, 计算 $\kappa$ 个 Base OT 密钥 $\rho^{\beta_\ell}_{\ell,i,j}$ ($\ell\in[\kappa]$).

(7) 执行 EvalPPRF, 用上述密钥配合 $j$ 发来的 $\tilde t_{\ell,i,j}, \tilde s_{\ell,i,j}$, 算"打孔后的全员叶子". 此即 sign 阶段 SoftSpoken Sender 一侧的种子 ($i$ 持 $\Delta$ 部分).

(8) 聚合本方份额
$$
x_i := \sum_{j\in [n]} d_{j,i} = P(i).
$$

## Round 4. 公开最终份额.

每个参与方 $i$:

(1) 算份额对应群点 $S_i := x_i \cdot G$ 以及相应的 DLog 证明 $\pi_i$.

(exchange) 广播 $S_i$, $\pi_i$, $Y$.

(2) 做这些检验:
* 检验所有 $\pi_j$.
* 检验所有 $Y$ 一致.
* Lagrange 重构验公钥:  
$$
\begin{align*}
\lambda(j,S) &:= \prod_{k\in S\setminus\{j\}} \frac{-k}{j - k}, \tag{coef}\\
Y &\phantom{:}\stackrel{?}{=} \sum_{j\in S}\lambda(j,S) \cdot S_j.
\end{align*}
$$

## Keyshare 输出

每方 $i$ 持有
* 编号 $i$. 这同时也是多项式的输入.
* 插值私钥分片 $x_i$. 满足 $x=\sum_{j\in S}\lambda(j,S)\cdot x_i$.
* 针对 $j\ne i$ 的 PPRF 种子, 双向.

-----

# Pre-sign 有 3 轮

目标: 把跟消息 $m$ 无关的所有协议步骤一次性跑完, 产出每方的 PreSignature. 之后绑定任意 $m$ 输出签名只需一轮广播 (见下文 # Sign).

输入: 
* 各方的 Keyshare
* 签名者集合 $S$, 要求 $|S|\ge t$.
* BIP-32 私钥偏移量 $\nabla x$, 默认为 0.

(无需消息哈希 $m$. $m$ 推迟到 Sign 阶段绑.)

ECDSA 签名公式回顾:
* $R := (\sum_i r_i) G$, $r$ 是 $R$ 的横坐标.
* $s := (k\phi)^{-1}(m\phi+rx'\phi)$, 是 ECDSA MtA. 其中 $x'=x+\nabla x$.

## Round 1. 摇 nonce, 提交 $R_i$.

每个参与方 $i$:

(1) 摇随机
* 摇 nonce 分片 $r_i \stackrel{\$}{\leftarrow} \mathbb{Z}_n^*$
* 摇盲化分片 $\phi_i \stackrel{\$}{\leftarrow} \mathbb{Z}_n^*$ 用于随机 MtA.
* 承诺 $R_i := r_i \cdot G$.

(2) 计算衍生分片:
$$
x'_i := \lambda(i,S)\cdot x_i + \zeta_i + \nabla x \cdot |S|^{-1}.
$$
三项分别是:
1. 拉格朗日插值后的私钥分片,
2. 前一项是恒定的, 多次签名后泄露风险上升, 为此我们给它施加随机掩码. 我们采用 "rerand" 技巧使各方掩码之和为 0, 详见 `misc-rerand.md`.
3. BIP-32 偏移量, 均摊到每个签名方.

(3) 算本方公钥分片 $Y_i := x'_i \cdot G$. 算派生公钥 $Y' := Y + \nabla x \cdot G$.

(4) 摇盲化 $\varepsilon_{R,i} \in \mathbb{B}^{256}$, 算 $R_i$ 承诺
$$
\mathrm{Com}_{R,i} := \mathrm{Hash}(\mathrm{sid}, i, R_i, \varepsilon_{R,i}).
$$

(exchange) 广播 $\mathrm{Com}_{R,i}$.

(5) 计算全员 transcript hash $d$, 将在 Round 3 维护各方的一致性.
$$
d := \mathrm{Hash}(\mathrm{sid}, Y', \mathrm{Com}_{R,1}, \cdots, \mathrm{Com}_{R,|S|}).
$$

## Round 2. SoftSpoken Receiver 和 RVOLE Sender

每个参与方 $i$ 对其他签名者 $j\in S\setminus\{i\}$:

(1) 调用 SoftSpoken, $i$ 作为 Receiver.
* 摇 SoftSpoken 选择位 $\vec{\beta}_{j,i} \in \mathbb{B}^L$,
* 算 SoftSpoken Receiver 应答: 矩阵 $u_{j,i}$ 加 Fiat-Shamir 响应 $\tilde\beta_{j,i}, \tau_{j,i}$.

(2) 算 gadget 聚合标量 $\beta_{j,i} := \langle \mathbf{g}, \boldsymbol{\beta}_{j,i}\rangle \in \mathbb{Z}_n$. 详见 `misc-gadget.md`.

(exchange) P2P 发送 $u_{j,i}, \tilde\beta_{j,i}, \tau_{j,i}$.

(3) 调用 RVOLE, $i$ 作为 Sender:
* 算 $L$ 个 SoftSpoken OT 密钥对 $\rho^0_{\ell,i,j}, \rho^1_{\ell,i,j}$ ($\ell\in[L]$).
* 算修正矩阵 $\tilde a_{i,j}$, 响应 $\eta_{i,j}$, 哈希校验 $\mu_{i,j}$.
* 算 Sender 自留分片 $y^\mathtt{r}_{i,j}, y^\mathtt{x}_{i,j}$. 满足
$$
\begin{align*}
y^\mathtt{r}_{i,j} + z^\mathtt{r}_{i,j} &= r_i \cdot \beta_{i,j}, \\
y^\mathtt{x}_{i,j} + z^\mathtt{x}_{i,j} &= x'_i \cdot \beta_{i,j}. 
\end{align*}
$$
这里 $z^\mathtt{r}_{i,j}, z^\mathtt{x}_{i,j}$ 是 Receiver 自留分片, 此时还没出现, 我们将在 Round 3 算出来.

(4) 算 $\Gamma$ 一致性点 $\Gamma^\mathtt{r}_{i,j} := y^\mathtt{r}_{i,j} \cdot G$, $\Gamma^\mathtt{x}_{i,j} := y^\mathtt{x}_{i,j} \cdot G$. 这两项用于约束

(5) 算 $\phi$ 专用的偏移 $\psi_{i,j} := \phi_i - \beta_{i,j}$.

## Round 3. RVOLE Receiver, 揭示 $R_i$, 验 $\Gamma$.

每个参与方 $i$ 对其他签名者 $j\in S\setminus\{i\}$:

(exchange) P2P 发送这些:
* RVOLE Sender 应答 $\tilde a_{i,j}, \eta_{i,j}, \mu_{i,j}$.
* 承诺 $\mathrm{Com}_{R,i}$ 的揭示, 即 $R_i, \varepsilon_{R,i}$.
* 本方公钥分片 $Y_i$.
* 一致性约束 $\Gamma^\mathtt{r}_{i,j}, \Gamma^\mathtt{x}_{i,j}$.
* 偏移量 $\psi_{i,j}$.
* 一致性约束 $d$.

(1) 做这些检验工作:
* 重新计算 $\mathrm{Com}_{R,j}$, 比对与 Round 1 所收到的是否相等.
* 各方发来的 $d$ 相等.

(2) 调用 RVOLE Receiver 端: 消费 $j$ 发来的 $\tilde a_{j,i}, \eta_{j,i}, \mu_{j,i}$, 得本方 Receiver 分片 $z^\mathtt{r}_{j,i}, z^\mathtt{x}_{j,i}$.

(3) 验 $\Gamma$ 一致性. 对每个 $j\ne i$:
$$
\beta_{j,i} \cdot R_j \stackrel{?}{=} \Gamma^\mathtt{r}_{j,i} + z^\mathtt{r}_{j,i} \cdot G, \quad
\beta_{j,i} \cdot Y_j \stackrel{?}{=} \Gamma^\mathtt{x}_{j,i} + z^\mathtt{x}_{j,i} \cdot G.
$$
RVOLE 协议本身不保证输入的乘法分片是下游协议所需的. 这就需要靠 $\Gamma$ 把 RVOLE 的输入 $r_j, x'_j$ 跟此前广播的 $R_j, Y_j$ 绑住.

(4) 聚合.
* 此时形成 ECDSA 签名的第一字段, 即
$$
\begin{align*}
R &:= R_i + \sum_{j\ne i} R_j, \\
r &:= R.\mathrm{x} \bmod n.
\end{align*}
$$

* 验派生公钥是否一致, 即 $\sum_{j\in S}Y_j \stackrel{?}{=} Y'$.
* 聚合
$$
\begin{align*}
\Phi_i &:= \phi_i + \sum_{j\ne i}\psi_{j,i}, \\
   V^\mathtt{r}_i &:= \sum_{j\ne i}(y^\mathtt{r}_{i,j} + z^\mathtt{r}_{j,i}), \\
   V^\mathtt{x}_i &:= \sum_{j\ne i}(y^\mathtt{x}_{i,j} + z^\mathtt{x}_{j,i}). \\
\end{align*}
$$
* 算 PreSignature 的两个分量. $s_{1,i}$ 是最终值, $s_{0,i}^\circ$ 是 $m$-未绑的部分.
$$
s_{1,i} := r_i \cdot \Phi_i + V^\mathtt{r}_i, \quad
s_{0,i}^\circ := r_x \cdot (x'_i \cdot \Phi_i + V^\mathtt{x}_i).
$$

## Pre-sign 输出

每方 $i$ 持有
$$
\mathrm{PreSignature}_i := \bigl(r,\, s_{1,i},\, s_{0,i}^\circ,\, \phi_i\bigr).
$$

其中
* $r := r_x \bmod n$, 是 ECDSA 签名的 $r$ 字段, 全员一致.
* $s_{1,i}$ 已经是最终值, 待 Sign 阶段直接广播.
* $s_{0,i}^\circ$ 是未绑 $m$ 的中间值, 待 Sign 阶段叠加 $m\phi_i$.
* $\phi_i$ 本方私有, 用于 Sign 时绑 $m$.

警告: PreSignature 一次性消费. 同一份 PreSignature 用两条不同 $m$ 绑定会立即泄露 $\phi_i$, 进而泄露 $x'$ 的本方分片. 用户要保证 "已绑过的 PreSignature 立刻销毁".

-----

# Sign 仅有 1 轮

目标: 用消息哈希 $m$ 绑定 PreSignature, 输出 ECDSA 签名 $(r, s)$.

输入:
* 每方持有自己的 PreSignature.
* 消息哈希 $m \in \mathbb{Z}_n$.

## Round 1. 绑 $m$ 并汇总.

每方 $i$:

(1) 算 $s_{0,i} := s_{0,i}^\circ + m \cdot \phi_i$.

(exchange) 广播 $(s_{0,i}, s_{1,i})$.

(2) 收齐所有 $j$ 的部分签名后, 算
$$
s := \frac{\sum_{j\in S}s_{0,j}}{\sum_{j\in S}s_{1,j}}.
$$
展开化简等于合法 ECDSA $s$ 字段.

(3) 工程加固: 本地跑一遍 ECDSA 标准验签, 失败即 abort.

输出: $(r, s)$.
