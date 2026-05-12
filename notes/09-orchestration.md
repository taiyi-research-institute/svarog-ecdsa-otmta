编排: 从 pairwise RVOLE 到 ECDSA 签名

# 铺垫

回顾 RVOLE 接口. 一次调用涉及两方:
* Sender: 提供秘密输入 $x_a\in\mathbb{Z}_n$.
* Receiver: 内部摇随机标量 $\chi\in\mathbb{Z}_n$, 私有持有, 不暴露给 Sender.

产出加法分片. Sender 持有 $c\in\mathbb{Z}_n$, Receiver 持有 $d\in\mathbb{Z}_n$, 满足
$$
c + d = x_a\cdot\chi \pmod n.
$$

(注 1)

$\chi = \sum_j g_j\beta_j$, 是随机比特向量 $\boldsymbol\beta$ (长度为 $L=512$ 位)
经 gadget 聚合而成.
$\chi$ 等价于 `06-rvole-derand.md` 里的 $\beta$, 换字母只是为了避免在 T 方场景下跟其他随机标量混淆.

## 记号约定

T 方做 ECDSA 签名, 每对 $i \ne j$ 跑两次 pairwise RVOLE: 一次 $i$ 当 Sender, 一次反过来.
同一个参与方在不同的 RVOLE 调用里, 既可能是 Sender 也可能是 Receiver.

约定: 复合下标 $i,j$ 指 Receiver 编号为 $i$, Sender 编号为 $j$ 的那次 RVOLE 调用.

具体有四个变量:
* $c_{i,j}$: 由 Sender $j$ 持有.
* $d_{i,j}$: 由 Receiver $i$ 持有.
* $r_j$: 由 Sender $j$ 持有.
* $\chi_{i,j}$: 由 Receiver $i$ 持有. 

它们满足关系:
$$
c_{i,j} + d_{i,j} = r_j\cdot\chi_{i,j} ~.
$$

## 改写 ECDSA 签名公式, 引出 MtA 的能力边界

这一节其实是在回顾 `00-mta-baseot.md` 的第一节.

回顾原始公式
$$
s = k^{-1}\cdot(m + R.x\cdot \mathtt{sk}) \pmod n.
$$

其中 $k\in\mathbb{Z}_n^*$ 是临时密钥 (ephemeral key, Nonce).
$r$ 是椭圆曲线点 $R=kG$ 的横坐标.

MPC 下要算 $s$, 不能暴露 $k$ 和 $\mathtt{sk}$.
为此引入随机标量 $\phi$, 把原始公式改写为
$$
s = (k\phi)^{-1}\cdot(m\phi + R.x\cdot\mathtt{sk}\cdot\phi) \pmod n.
$$

协议结束时, 公开 $k\phi$;
不公开 $\mathtt{sk}\cdot\phi$, 各方持有 $\mathtt{sk}\cdot\phi$ 的加法分片.

我们约定:
* 各方持有 $\mathtt{sk}_i$, 满足 $\mathtt{sk} = \sum_i \mathtt{sk}_i$.
这个 $\mathtt{sk}_i$ 是通过 Lagrange 或 Birkhoff 插值得到的.
* 每次签名, 每方现摇 $r_i, \phi_i$.
* 公开 $R_i = r_i G$, 累加得 $R = (\sum r_i)G$, 即 $k = \sum r_i$.
* 本文的编号 $i$ 用于索引一个参与方.

记全局 $\Phi := \sum_i \phi_i$. 我们要算的 $k\Phi$ 展开:

$$
k\Phi = \left(\sum_i r_i\right)\left(\sum_j \phi_j\right)
= \underbrace{\sum_i r_i\phi_i}_{\text{对角项}} 
+ \underbrace{\sum_{i\ne j} r_i\phi_j}_{\text{非对角项}}.
$$

第 $i$ 方在本地计算他的对角项, 无需通信.
非对角项 $r_i\phi_j$ ($i\ne j$) 需要两方协作. 经典做法是 MtA.

## 对 RVOLE 的结果进行桥接

在 RVOLE 的一次调用里, 设 Receiver 为 $i$, Sender 为 $j$, 兑现的关系是:
$$
c_{i,j} + d_{i,j} := r_j\cdot\chi_{i,j}.
$$

其中 $r_j$ 是 Sender $j$ 的 Nonce 份额, $\chi_{i,j}$ 是 Receiver $i$ 现摇的随机标量.
注意这里 $\phi_j$ 没出现, 我们要的非对角项是 $r_i\phi_j$, RVOLE 给的却是 $r_j\chi_{i,j}$.

这就需要桥接. 第 $i$ 方给第 $j$ 方多发一条标量
$$
\psi_{i\to j} = \phi_i - \chi_{i,j} \pmod n.
$$

第 $j$ 方学不到 $\phi_i$ 或 $\chi_{i,j}$. 因为 $\psi_{i\to j}$ 在 $j$ 看来是均匀随机的.

## 在哪里调 RVOLE? 一对参与方调几次?

ECDSA 签名里, 每对 $(i,j)$ ($i\ne j$) 的非对角项有两类要算:
$r_i\phi_j$ (Nonce 跟 mask 配对) 和 $\mathtt{sk}_i\phi_j$ (密钥分片跟 mask 配对).

实现上把它们打包成一次 RVOLE 调用, 取 batch 维度 $\ell = L_\mathrm{batch} = 2$:
Sender $j$ 同时输入 $(r_j, \mathtt{sk}_j)$, Receiver $i$ 共用同一份 $\chi_{i,j}$,
分别拿到 $(c^{(u)}_{i,j}, c^{(v)}_{i,j})$ 和 $(d^{(u)}_{i,j}, d^{(v)}_{i,j})$, 满足
$$
c^{(u)}_{i,j} + d^{(u)}_{i,j} = r_j\cdot\chi_{i,j},\quad
c^{(v)}_{i,j} + d^{(v)}_{i,j} = \mathtt{sk}_j\cdot\chi_{i,j}.
$$

下文为简洁起见, 公式里只写 $u$ 一路 ($r_j$). $v$ 一路 ($\mathtt{sk}_j$) 完全对称.

# 正文

## Step $\Gamma$. RVOLE 乘法关系一致性检查

RVOLE 内部的 $\rho$-检查只能保证 Sender 在执行协议时输入了某个 $r_j$,
但不能保证这个 $r_j$ 跟 Sender 此前广播的承诺 $R_j = r_jG$ 是同一个.
同理 $v$ 一路要把 $\mathtt{sk}_j$ 跟 $\mathtt{pk}_j = \mathtt{sk}_j G$ 绑定.

桥接做法是把加法关系搬到椭圆曲线群上验. Sender $j$ 跟 RVOLE 的 `mta_msg2` 一起广播
$$
\Gamma^{(u)}_{i,j} := c^{(u)}_{i,j}\cdot G, \quad \Gamma^{(v)}_{i,j} := c^{(v)}_{i,j}\cdot G.
$$

Receiver $i$ 收到后验:
$$
\chi_{i,j}\cdot R_j \stackrel{?}{=} d^{(u)}_{i,j}\cdot G + \Gamma^{(u)}_{i,j}, \quad
\chi_{i,j}\cdot \mathtt{pk}_j \stackrel{?}{=} d^{(v)}_{i,j}\cdot G + \Gamma^{(v)}_{i,j}.
$$

$R_j$ 和 $\mathtt{pk}_j$ 都是 Sender 在签名前几轮广播过的, Receiver 直接拿来用.
两个等式分别等价于 $c^{(u)}_{i,j}+d^{(u)}_{i,j}=r_j\chi_{i,j}$ 和 $c^{(v)}_{i,j}+d^{(v)}_{i,j}=\mathtt{sk}_j\chi_{i,j}$,
任何一项不通过则中止协议并抓出 Sender $j$. 用 $\Gamma$ 而非揭露 $c$ 是为了不暴露 Sender 的加法分片.

注意 $\chi_{i,j}$ 是 Receiver 私有的, 这个检查 Sender 看不到.
但 $\Gamma$ 一旦广播就被 Sender 锁死, 无法事后撒谎.

## Step R1. 第 $j$ 方本地聚合

第 $j$ 方收齐所有 $\psi_{i\to j}$ ($i\ne j$), 形成
$$
\begin{align*}
\Phi_j &:= \phi_j + \sum_{i\ne j}\psi_{i\to j} \\
&= \phi_j + \sum_{i\ne j}(\phi_i - \chi_{i,j}) \\
&= \Phi - \sum_{i\ne j}\chi_{i,j}.
\end{align*}
$$

然后, 对 RVOLE 输出的所有 nonce 分片进行累加.
$$
U_j := \left\{\sum_{k\ne j} c_{k,j}\right\}
+ \left\{\sum_{k\ne j} d_{j,k}\right\}.
$$

式中第一项是 $j$ 当 RVOLE Sender 时跟其他 $k$ 协作产生的 $c$ 份额;
第二项是 $j$ 当 RVOLE Receiver 时跟其他 $k$ 协作产生的 $d$ 份额.

最后, 计算 $\mathtt{kPhi}$ 份额, 广播出去:
$$
\mathtt{kPhi}_j = r_j\cdot\Phi_j + U_j.
$$

## Step R2. 全局聚合: $\chi$ 抵消, 净额 $k\Phi$

把所有参与方的 $\mathtt{kPhi}$ 份额加起来.

(第一项)

$$
\begin{align*} 
\sum_j r_j\Phi_j &= \sum_j r_j\Phi - \sum_j r_j\sum_{i\ne j}\chi_{i,j} \\
&= k\Phi - \sum_{i\ne j} r_j\chi_{i,j}.
\end{align*}
$$


(第二项)

$$
\begin{align*} 
\sum_j U_j &= \sum_{i\ne j} c_{i,j}+d_{i,j} \\
&= \sum_{i\ne j} r_j\cdot \chi_{i,j}.
\end{align*}
$$

两项相加, $\sum_{i\ne j} r_j\cdot \chi_{i,j}$ 被抵消, 净额 $k\Phi$.

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

