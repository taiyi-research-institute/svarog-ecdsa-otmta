编排: 从 pairwise RVOLE 到 ECDSA 签名

## 铺垫: 回顾 ECDSA MtA

ECDSA 签名公式:
$$
\begin{align*}
R &:= \left(k\stackrel{\$}{\leftarrow}\mathbb{Z}^*_n\right) G, \\
s &:= k^{-1}\cdot(m + R.x\cdot \mathtt{sk}) \pmod n.
\end{align*}
$$

MPC 下要算 $s$, 不能暴露 $k$ 和 $\mathtt{sk}$. 为此引入随机标量 $\phi$, 把原始公式改写为
$$
s := (k\phi)^{-1}\cdot(m\phi + R.x\cdot\mathtt{sk}\cdot\phi) \pmod n.
$$

协议结束时, 公开 $k\phi \pmod n$ . 不公开 $\mathtt{sk}\cdot\phi \pmod n$, 各方持有 $\mathtt{sk}\cdot\phi$ 的加法分片.

TODO: $k\phi \pmod n$ 的难度是大整数分解. 分解 $k\phi$ 和 $k\phi \pmod n$ 的难度一样吗? 我知道大整数分解的难度比 AES 和 群离散对数低好几个数量级. 这是否会带来短板?

我们约定:
* 各方持有 $\mathtt{sk}_i$, 满足 $\mathtt{sk} = \sum_i \mathtt{sk}_i$. 这个 $\mathtt{sk}_i$ 是通过 Lagrange 或 Birkhoff 插值得到的.
* 每次签名, 每方现摇 $r_i, \phi_i$.
* 公开 $R_i = r_i G$, 累加得 $R = (\sum r_i)G$, 即 $k = \sum r_i$.
* 本文的编号 $i$ 用于索引一个参与方.

记全局 $\Phi := \sum_i \phi_i$. 我们要算的 $k\Phi$ 展开:

$$
k\Phi = \left(\sum_i r_i\right)\left(\sum_j \phi_j\right)
= \underbrace{\sum_i r_i\phi_i}_{\text{对角项}} 
+ \underbrace{\sum_{i\ne j} r_i\phi_j}_{\text{非对角项}}.
$$

第 $i$ 方在本地计算他的对角项, 无需通信. 非对角项 $r_i\phi_j$ ($i\ne j$) 需要两方协作. 经典做法是 MtA.

$\mathtt{sk}\cdot\Phi$ 同理, 不再赘述.

-----

-----

## 记号梳理

$T$-方 ECDSA 签名, 每对参与方 $i\ne j$ 需要跑两次 RVOLE: 一次 $i$ 当 Sender, 一次 $i$ 当 Receiver.

我们约定: 本文变量的复合下标 $i,j$ 来自 Receiver 编号为 $i$, Sender 编号为 $j$ 的 RVOLE 调用. 具体有 4 个变量:

* $y_{i,j}$ 由 Sender $j$ 持有.
* $z_{i,j}$ 由 Receiver $i$ 持有.
* $r_j$ 或 $\mathtt{sk}_j$ 由 Sender $j$ 持有.
* $\beta_{i,j}$ 由 Receiver $i$ 持有.

它们满足 MtA 关系:
$$
y_{i,j} + z_{i,j}:=r_j\cdot \beta_{i,j}.
$$

## Step $\Phi$.

参与方 $i$ 计算并发给参与方 $j$ :
$$
\psi_{i,j} := \phi_i - \beta_{i,j}.
$$
第 $j$ 方收齐所有 $\psi_{i\to j}$ ($i\ne j$), 形成
$$
\begin{align*}
\Phi_j &:= \phi_j + \sum_{i\ne j}\psi_{i,j} \\
&= \phi_j + \sum_{i\ne j}(\phi_i - \beta_{i,j}) \\
&= \Phi - \sum_{i\ne j}\beta_{i,j}.
\end{align*}
$$
注意: $\phi_i$ 和 $\beta_{i,j}$ 都是仅有参与方 $i$ 知道的均匀随机数, 所以 $\psi_{i\rightarrow j}$ 对参与方 $j$ 来说就是均匀随机数.

## Step $\Gamma$.

RVOLE 只负责保证 Sender 在执行协议时输入了某个 $r_j$, 不负责保证这个 $r_j$ 跟 Sender 此前广播的承诺 $R_j = r_jG$ 是同一个. $\mathtt{sk}_j$ 同理, 不再赘述.

我们不妨把加法关系搬到椭圆曲线群上验. Sender $j$ 在发出 RVOLE 消息时, 也捎带发出:
$$
\Gamma_{i,j}:=y_{i,j}\cdot G.
$$
Receiver $i$ 收到后验:
$$
\beta_{i,j}\cdot R_j
\stackrel{?}{=}
z_{i,j}\cdot G + \Gamma_{i,j}.
$$

这相当于把下式搬到椭圆曲线上.
$$
r_j\cdot\beta_{i,j} \stackrel{?}{=} y_{i,j}+z_{i,j}.
$$
妙处: $\Gamma_{i,j}$ 必须配合此前承诺的 $R_j$.

## Step R1. 第 $j$ 方本地聚合

对 RVOLE 输出的所有 nonce 分片进行累加.
$$
U_j := \left\{\sum_{k\ne j} y_{k,j}\right\}
+ \left\{\sum_{k\ne j} z_{j,k}\right\}.
$$

式中第一项是 $j$ 当 RVOLE Sender 时跟其他 $k$ 协作产生的 $c$ 份额;
第二项是 $j$ 当 RVOLE Receiver 时跟其他 $k$ 协作产生的 $d$ 份额.

最后, 计算 $\mathtt{kPhi}$ 份额, 广播出去:
$$
\mathtt{kPhi}_j = r_j\cdot\Phi_j + U_j.
$$

## Step R2. 全局聚合: $\beta$ 抵消, 净额 $k\Phi$

把所有参与方的 $\mathtt{kPhi}$ 份额加起来.

(第一项)

$$
\begin{align*} 
\sum_j r_j\Phi_j &= \sum_j r_j\Phi - \sum_j r_j\sum_{i\ne j}\beta_{i,j} \\
&= k\Phi - \sum_{i\ne j} r_j\beta_{i,j}.
\end{align*}
$$


(第二项)

$$
\begin{align*} 
\sum_j U_j &= \sum_{i\ne j} y_{i,j}+z_{i,j} \\
&= \sum_{i\ne j} r_j\cdot \beta_{i,j}.
\end{align*}
$$

两项相加, $\sum_{i\ne j} r_j\cdot \beta_{i,j}$ 被抵消, 净额 $k\Phi$.

## Step S1, S2. 照搬上述推导

把上面 $r_j$ 全部替换成 $\mathtt{sk}_j$, 仿照 $U_j$ 定义 $V_j$, 推导照搬, 得
$$
\sum_j\left(\mathtt{sk}_j\cdot\Phi_j + V_j\right) = \mathtt{sk}\cdot\Phi.
$$

第 $j$ 方计算自己的 $\mathtt{ksPhi}_j$ 分片. 
其结构比 $\mathtt{kPhi}_j$ 分片复杂一点, 需要给上式等号左边引入 $R.x$ 和 $m\cdot \phi_j$, 得到:
$$
\mathtt{ksPhi}_j := m\cdot \phi_j + R.x\cdot \left(\mathtt{sk}_j\cdot\Phi_j + V_j\right)
$$

所有参与方聚合得到

$$
\begin{align*}
\mathtt{ksPhi} &:= \sum_j \mathtt{ksPhi}_j \\
&= m\left\{\sum_j \cdot\phi_j\right\}
+ R.x\left\{\sum_j\mathtt{sk}_j\cdot\Phi_j + V_j\right\} \\
&= \Phi(m+ R.x\cdot\mathtt{sk}).
\end{align*}
$$

## Step S3. ECDSA s 字段.

$$
\begin{align*}
s &:= \dfrac{\mathtt{ksPhi}}{\mathtt{kPhi}} \\
&= \dfrac{\Phi(m+ R.x\cdot\mathtt{sk})}{k\Phi} \\
&= k^{-1}(m+ R.x\cdot\mathtt{sk}).
\end{align*}
$$

