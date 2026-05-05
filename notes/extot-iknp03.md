以下是 iknp03 半诚实安全的算法骨架. 需要再加 KOS/SoftSpokenOT 等一致性检查手段.

## 用 Base OT 为 Payload OT 生成种子

消息长度为 $\lambda$, OT 询问个数为 $\kappa$. 有几个 OT 询问, 就有几个选择位. 很多实现取 $\lambda=\kappa$.

Bob 随机摇 $2\kappa$ 个随机消息, 记为 $k^0$ 和 $k^1$.
范围: $k^0_i$ 是 $\lambda$-比特的正整数, $k^1_i$ 同理.

Alice 随机摇 $\kappa$ 个选择, 记为 $s$.
范围: $s_i\in\left\{0,1\right\}$.

Alice 通过朴素 OT 从 Bob 获得 $k^{s_i}_i$.

种子就是如下张量
$$
{k}:=\left\{\cdots,~k^{s_i}_i~,\dots\right\}.
$$

种子可以长期保留, 也就是在 keygen 阶段执行.

## 交换 Payload OT 密钥

### 单次 (1-bit) 询问的原理

Alice 和 Bob 约定一个哈希函数 $F: \left\{0,1\right\}^\lambda \rightarrow \left\{0,1\right\}$. 实现上可以选择 AES-CTR, ChaCha20 等.

Bob 计算如下两个长度为 $\kappa$ 的向量:
$$
\begin{align}
{t}^0&=\left\{ \cdots, ~F\left(k^0_i\right)~, \cdots \right\},\\
{t}^1&=\left\{ \cdots, ~F\left(k^1_i\right)~, \cdots \right\}.\\
\end{align}
$$

Alice 计算如下一个长度为 $\kappa$ 的向量:
$$
{t}=\left\{ \cdots, ~F\left(k^{s_i}_i\right)~, \cdots \right\}.
$$

Bob 计算并发送如下向量, 式中 "$\oplus$" 是按位异或. $b$ 是 Bob 的选择, 既然长度为 1, 那就把它平铺 (复制元素) 到长度 $\kappa$.
$$
{u}={t}^0 \oplus {t}^1 \oplus b. \tag{uvec}
$$

Bob 这么做相当于用
$\left({t}^0 \oplus {t}^1\right)$
对 $b$ 进行异或加密.

Alice 计算如下向量, 式中 " $\cdot$ " 是按位与.
$$
{q} = {t} \oplus
\left(s\cdot {u}\right).
$$

验算一下可知,
当 $s_i=0$ 时, ${q}_i={t}^0_i$ ;
当 $s_i=1$ 时, ${q}_i={t}^0_i \oplus b$ . 也就是说,
$$
q={t}^0\oplus(s\cdot{b}).
$$

Alice 分别为0选项和1选项计算如下密钥.
$$
K^0=\mathtt{Hash}(q),~~
K^1=\mathtt{Hash}(q\oplus s).
$$

验算一下.
* 当 $b=0$ 时, $K^0=\mathtt{Hash}(t_0)$, $K^1=\mathtt{Hash}(t_0\oplus s)$,
* 当 $b=1$ 时, $K^0=\mathtt{Hash}(t_0\oplus s)$, $K^1=\mathtt{Hash}(t_0)$.
* 无论 $b$ 取何值, 恰有一个密钥等于 $\mathtt{Hash}(t_0)$.

小结: 本节描述了单次 (1-bit) OT 询问中的密钥交换的原理. 这种密钥交换基于异或运算的消去律, 而不是像 base OT 那样基于椭圆曲线. 前者比后者更便宜, 而且同等比特长度下的安全性是相同的.

### 多次 (m-bit) OT 询问的原理

Alice 和 Bob 约定一个哈希函数 $F: \left\{0,1\right\}^\lambda \rightarrow \left\{0,1\right\}^m$. 实现上可以选择 AES-CTR, ChaCha20 等.

Bob 计算如下两个 $\kappa$ 行, $m$ 列的布尔矩阵 $t^0, t^1$. 矩阵的第 $i$ 行为:
$$
{t}^0_{i,*}=F\left(k^0_i\right),~~ {t}^1_{i,*}=F\left(k^1_i\right).
$$

Alice 计算如下一个长度为 $\kappa$ 行, $m$ 列的布尔矩阵 $t$. 矩阵的第 $i$ 行为:
$$
{t}_{i,*}=F\left(k^{s_i}_i\right).
$$

Bob 计算并发送如下矩阵.
$$
{u}={t}^0 \oplus {t}^1 \oplus b. \tag{umat}
$$

上式中 $b$ 是 Bob 的选择向量, $b\in\left\{0,1\right\}^m$. 我们把向量 $b$ 当成 $1\times m$ 形状的矩阵, 重复 $\kappa$ 行就可以做按位运算.

Alice 计算如下矩阵.
$$
{q} = {t} \oplus \left(s\cdot {u}\right). \tag{qmat}
$$

Alice 分别为0选项和1选项计算密钥向量 $K^0, K^1$. 向量的第 $j$ 个元素为
$$
K^0_j=\mathtt{Hash}(q_{*,j}),~~
K^1_j=\mathtt{Hash}(q_{*,j}\oplus s).
$$

小结: 这就是 iknp03 的实施方式. 它实际上是上一节的批量版本.

### 变量的生命周期

种子 $k$, 以及相应的选项 $s$ 可以长期保留. 也就是说可以放进keystore.

矩阵 $t^0, t^1$ 是一次性的.
如果复用, 那么对于Bob的两场询问 $b, b'$, Alice就可以算
$$
b\oplus b'=u\oplus u'.
$$

这虽然没有直接泄露 $b$ 或 $b'$ 中的任何一个, 但是泄露了二者的异或值.
