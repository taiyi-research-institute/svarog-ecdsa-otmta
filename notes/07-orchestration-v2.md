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
* 仅当 $i > j$, P2P 地发送 $\epsilon_{i,j}$.
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

(exchange)
* 广播 $S_i$, $\pi_i$, 

(2) 为 $S_i$ 制作 DLog 证明 $\pi_i$ (用 $\mathrm{sid}$ 作 Fiat-Shamir transcript). 详见 `misc-fiat-shamir.md`.

(exchange) 广播 $S_i, \pi_i, Y$.

(3) 做这些检验:
* 检验所有 $\pi_j$.
* 检验所有 $Y$ 一致.
* Lagrange 重构验公钥:  

(3) 收齐所有 $j$ 的通信内容, 做这些检验工作:
* 验所有 $\pi_j$.
* 验各方 $Y$ 全员一致.
* Lagrange 重构验公钥: 任取一个大小为 $t$ 的子集 $S\subseteq[n]$, 算 Lagrange 系数并检验:

$$
\begin{align*}
\lambda(j,S) &:= \prod_{k\in S\setminus\{j\}} \frac{-k}{j - k}, \tag{coef}\\
Y &\phantom{:}\stackrel{?}{=} \sum_{j\in S}\lambda^S_j \cdot S_j.
\end{align*}
$$

## Keyshare 输出

每方 $i$ 持有
* 编号 $i$. 这同时也是多项式的输入.
* 插值私钥分片 $x_i$. 满足 $x=\sum_{j\in S}\lambda(j,S)\cdot x_i$.
* 针对 $j\ne i$ 的 PPRF 种子, 双向.

-----

# Sign 4 轮

目标: 协作生成 ECDSA 签名 $(r, s)$.
* $R := (\sum_i r_i) G$, $r$ 是 $R$ 的横坐标.
* $s := (k\phi)^{-1}(m\phi+rx'\phi)$, 是 ECDSA MtA. 其中 $x'=x+\nabla x$.

输入: 
* 各方的 Keyshare
* 签名者集合 $S$, 要求 $|S|\ge t$.
* 消息哈希 $m\in\mathbb{Z}_n$.
* BIP-32 私钥偏移量 $\nabla x$, 默认为 0.

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
第一项是拉格朗日插值, 第二项是再随机项, 第三项是 BIP-32 偏移量均摊到每个签名方.

(3) 算本方公钥分片 $Y_i := x'_i \cdot G$. 算派生公钥 $Y' := Y + \Delta_\mathrm{off} \cdot G$.

(4) 摇盲化 $\varepsilon_{R,i} \in \mathbb{B}^{256}$, 算 $R_i$ 承诺
$$
\mathrm{Com}_{R,i} := \mathrm{Hash}(\mathrm{sid}, i, R_i, \varepsilon_{R,i}).
$$

(exchange) 广播 $\mathrm{Com}_{R,i}$.

(5) 收齐所有 $j$ 的 $\mathrm{Com}_{R,j}$ 后, 算全员 transcript digest
$$
d := \mathrm{Hash}(\mathrm{sid}, Y', \mathrm{Com}_{R,1}, \cdots, \mathrm{Com}_{R,n}).
$$
$d$ 在 Round 3 用作跨方一致性绑定.

## Round 2. RVOLE 第一轮: 互发 SoftSpoken 应答.

每个参与方 $i$ 对其他签名者 $j\in S\setminus\{i\}$:

(1) 调用 RVOLE, $i$ 作 Receiver. 利用 keygen 留下的"针对 $j$ 的 PPRF Sender 种子" ($i$ 作 SoftSpoken Receiver 一侧). 摇 SoftSpoken 选择位 $\boldsymbol{\beta}_{j,i} \in \mathbb{B}^L$, 算 SoftSpoken Receiver 应答: 矩阵 $u_{j,i}$ 加 Fiat-Shamir 响应 $\tilde\beta_{j,i}, \tau_{j,i}$. Fiat-Shamir 把 SoftSpoken 的 Round 1 和 Round 3 压成一发. 详见 `05-softspoken.md`.

(2) 算 gadget 聚合标量 $\beta_{j,i} := \langle \mathbf{g}, \boldsymbol{\beta}_{j,i}\rangle \in \mathbb{Z}_n$. 详见 `misc-gadget.md`.

(exchange) P2P 发送 $u_{j,i}, \tilde\beta_{j,i}, \tau_{j,i}$.

(3) 收齐所有 $j$ 发来的 $u_{i,j}, \tilde\beta_{i,j}, \tau_{i,j}$ 后, $i$ 作 RVOLE Sender (pair $(i,j)$ 中 $i$ 是 Sender, $j$ 是 Receiver):
* 跑 SoftSpoken Sender 端处理, 得 $L$ 个扩展 OT 密钥对 $\rho^0_{\ell,i,j}, \rho^1_{\ell,i,j}$ ($\ell\in[L]$).
* 跑 `rvole_round2`, 输入 $(r_i, x'_i)$ 两路, 算 RVOLE Sender 应答: 修正矩阵 $\tilde a_{i,j}$, Sender 响应 $\eta_{i,j}$, 哈希校验 $\mu_{i,j}$. 同时算 Sender 自留分片 $c^u_{i,j}, c^v_{i,j}$. 满足
$$
c^u_{i,j} + d^u_{i,j} = r_i \cdot \beta_{i,j}, \quad
c^v_{i,j} + d^v_{i,j} = x'_i \cdot \beta_{i,j}.
$$
其中 $d^u_{i,j}, d^v_{i,j}$ 是 $j$ 在 Round 3 算出的 Receiver 端分片. 详见 `06-rvole.md`.

(4) 算 $\Gamma$ 一致性点 $\Gamma^u_{i,j} := c^u_{i,j} \cdot G$, $\Gamma^v_{i,j} := c^v_{i,j} \cdot G$.

(5) 算二次盲化偏移 $\psi_{i,j} := \phi_i - \beta_{i,j}$.

## Round 3. RVOLE 第二轮, 揭示 $R_i$, 验 $\Gamma$.

每个参与方 $i$ 对其他签名者 $j\in S\setminus\{i\}$:

(exchange) P2P 发送 ($i\to j$ 方向, 单包打满):
* RVOLE Sender 应答 $\tilde a_{i,j}, \eta_{i,j}, \mu_{i,j}$.
* $R_i$ 揭示对 $R_i, \varepsilon_{R,i}$, 供 $j$ 还原 $\mathrm{Com}_{R,i}$.
* 本方公钥分片 $Y_i$.
* $\Gamma^u_{i,j}, \Gamma^v_{i,j}$.
* $\psi_{i,j}$.
* digest $d$.

(1) 收齐所有 $j$ 的通信内容, 做这些检验工作:
* 重新计算 $\mathrm{Com}_{R,j}$, 比对与 Round 1 所收到的是否相等.
* 各方发来的 digest 全员相等.

(2) 完成 RVOLE Receiver 端: 跑 `round3_rvole` 处理 $j$ 发来的 $\tilde a_{j,i}, \eta_{j,i}, \mu_{j,i}$, 得本方 Receiver 分片 $d^u_{j,i}, d^v_{j,i}$.

(3) 验 $\Gamma$ 一致性. 对每个 $j\ne i$:
$$
\beta_{j,i} \cdot R_j \stackrel{?}{=} \Gamma^u_{j,i} + d^u_{j,i} \cdot G, \quad
\beta_{j,i} \cdot Y_j \stackrel{?}{=} \Gamma^v_{j,i} + d^v_{j,i} \cdot G.
$$
RVOLE 协议本身不绑承诺, 这里靠 $\Gamma$ 把 RVOLE 的输入 $r_j, x'_j$ 跟此前广播的 $R_j, Y_j$ 绑住.

(4) 聚合.
* 累加 $R := R_i + \sum_{j\ne i} R_j$, 取 $r_x := R.x \bmod n$. 这就是 ECDSA 签名的 $r$.
* 验 $\sum_{j\in S}Y_j \stackrel{?}{=} Y'$, 即派生公钥跨方一致.
* 算
$$
\Phi_i := \phi_i + \sum_{j\ne i}\psi_{j,i}, \quad
U_i := \sum_{j\ne i}(c^u_{i,j} + d^u_{j,i}), \quad
V_i := \sum_{j\ne i}(c^v_{i,j} + d^v_{j,i}).
$$
* 算部分签名两个分量
$$
s_{1,i} := r_i \cdot \Phi_i + U_i, \quad
s_{0,i} := r_x \cdot (x'_i \cdot \Phi_i + V_i) + m \cdot \phi_i.
$$

注: silence-laboratories 实现把 $m$ 混入 $s_{0,i}$ 这一步留到 Round 4 发送前的本地步骤, 实现 pre-sign 接口 (R1-R3 跑完, R4 时才决定签什么消息). 协议层面等价.

## Round 4. 汇总部分签名.

(exchange) 广播 $s_{0,i}, s_{1,i}$.

(1) 收齐所有 $j$ 的部分签名后, 算
$$
s := \frac{\sum_{j\in S}s_{0,j}}{\sum_{j\in S}s_{1,j}}.
$$
展开化简等于 $k^{-1}(m + r_x \cdot u_\mathrm{derived})$, 即合法 ECDSA $s$ 字段.

(2) 工程加固: 本地跑一遍 ECDSA 标准验签, 失败即 abort.

输出: $(r, s) := (r_x, s)$.

-----

# 跨轮分布速查

## Keygen

| 子协议 | Round 1 | Round 2 | Round 3 | Round 4 |
|---|---|---|---|---|
| EndemicOT | | $R_{0,i,j}, R_{1,i,j}$ 出 (作 Receiver) | $M_{0,j,i}, M_{1,j,i}$ 出 (作 Sender) + 处理对方的 $M_{0,i,j}, M_{1,i,j}$ | |
| PPRF | | | `BuildPPRF` + `ProvePPRF` 出 $\tilde t, \tilde s$ (作 Sender) + `EvalPPRF` 处理对方的 $\tilde t, \tilde s$ (作 Receiver) | |
| Shamir + Lagrange | 摇 $P_i$, 算 $\mathbf{F}_i, \mathrm{Com}_{1,i}$ | 揭示 $\mathbf{F}_i, \varepsilon_{1,i}$ + DLog 证明 | 散 $d_{i,j} = P_i(j)$, 聚合 $x_i = P(i)$, Feldman 验 | $S_i$ 广播 + DLog 证明 + Lagrange 重构验公钥 |

## Sign

| 子协议 | Round 1 | Round 2 | Round 3 | Round 4 |
|---|---|---|---|---|
| SoftSpoken (每签现摇) | | $u_{j,i}, \tilde\beta_{j,i}, \tau_{j,i}$ 出 (作 Receiver) + 处理对方的对应消息作 Sender | | |
| RVOLE | | Sender 端算 $\tilde a, \eta, \mu, c^x, c^v$ | $\tilde a, \eta, \mu$ P2P 出 + Receiver 端完成 + $\Gamma$ 验 | |
| $R_i$ commit-reveal | $\mathrm{Com}_{R,i}$ Bcast | | $(R_i, \varepsilon_{R,i})$ P2P 揭示 | |
| ECDSA 拼装 | 摇 $r_i, \phi_i$, 算 $x'_i, Y_i$ | 算 $\Gamma^u_{i,j}, \Gamma^v_{i,j}, \psi_{i,j}$ | 聚合算 $\Phi_i, U_i, V_i, s_{0,i}, s_{1,i}$ | Bcast + 聚合得 $s$ |
