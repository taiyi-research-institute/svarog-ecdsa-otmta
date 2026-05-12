# 铺垫

回顾 `05-softspoken.md`: SoftSpoken 扩展产出 $L$ 对随机 OT 密钥. 对第 $j$ 实例,
* Sender 持有传输密钥 $\mathcal{K}^0_j, \mathcal{K}^1_j$, 不知 Receiver 选哪一边.
* Receiver 持有所选密钥 $\mathcal{K}^{\beta_j}_j$, 其中 $\beta_j\in\mathbb{B}$ 是他的随机选择位.

拿到这对密钥后, 用它兑现 VOLE 关系, 即 $y_a + y_b = x_a\cdot\beta$.
其中 $\beta$ 是 Receiver 内部的随机标量.
有即将提到的两条技术路线, 在功能上是等价的.

兑现的为何 <mark>不是 MtA ($y_a + y_b = x_a\cdot x_b$)?</mark> 见正文末尾讨论.

简要回答: OT 扩展场景下, Receiver 的选择向量 $\boldsymbol\beta$ 是现摇的随机位,
gadget 聚合出的 $\beta = \sum_j g_j \beta_j$ 故意做成跟 $x_b$ 无关. 这是 DKLS23 的安全设计选择.
详见 `07-gadget.md`.

## 朴素路线: "把密钥当密钥", 对消息进行加密.

Sender 构造 OT 消息:
$$
\begin{align*}
M^0_j &= r_j \stackrel{\$}{\leftarrow}\mathbb{Z}_n,\\
M^1_j &= r_j + x_a\cdot g_j \pmod{n}.
\end{align*}
$$

把密钥直接加到消息上, 形成密文:
$$
\begin{align*}
C^0_j &= \mathcal{K}^0_j + M^0_j, \\
C^1_j &= \mathcal{K}^1_j + M^1_j.
\end{align*}
$$

Receiver 用所持的 $\mathcal{K}^{\beta_j}_j$ 解开 $C^{\beta_j}_j$, 得
$$
M^{\beta_j}_j = r_j + \beta_j\cdot x_a\cdot g_j.
$$

Sender 和 Receiver 分别聚合出自己的加法秘密份额. 聚合采用 gadget 方式, 详见 `07-gadget.md`.
$$
\begin{align*}
y_a &= -\sum_j  r_j \pmod{n}, \\
y_b &= \sum_j M^{\beta_j}_j \pmod{n}.
\end{align*}
$$

验算: $y_a + y_b = x_a\cdot\sum_j g_j\beta_j = x_a\cdot\beta$.

通信量: 对每个 OT 槽位, Sender 发 2 个密文 $C^0_j, C^1_j$.

## 另类路线: 把密钥直接解读为随机数

我们把 $\mathcal{K}^0_j$ 直接解读为随机数 $\alpha^0_j\in\mathbb{Z}_n$.
同理, 把 $\mathcal{K}^1_j$ 解读为随机数 $\alpha^1_j\in\mathbb{Z}_n$.

对每个 OT 实例 $j$, 也就是 gadget 分解后的第 $j$ 分量,

Sender 发送修正量:
$$
\tilde a_j = \alpha^0_j - \alpha^1_j + x_a \pmod{n}.
$$

Receiver 使用修正量:
$$
\alpha^{\beta_j}_j + \beta_j\cdot\tilde a_j = \alpha^0_j + \beta_j\cdot x_a.
$$

聚合后同样 $y_a + y_b = x_a\cdot\beta$.

通信量: 对每个 OT 槽位, Sender 发送 1 个标量 $\tilde a_j$.

## DKLS23 采用 "另类路线" 的理由

两路线功能上完全等价, 都把 "随机 OT" 翻译成 "携带 $x_a$ 的 VOLE 关系".
差别只在 "怎么脱掉 OT 密钥的随机性":
* 朴素路线: 另外摇一个 $r_j$ 当盲化项, 把 $x_a$ 嵌进 $M^1_j$. 用 $\mathcal{K}$ 当加法掩码.
* 另类路线: 跳过 $r_j$, 让 $\mathcal{K}$ 自身充当随机 $\alpha$. $x_a$ 只嵌进 $\tilde a_j$.

另类路线的好处:
* 通信省一半.
* gadget 向量 $g_j$ 推迟到聚合阶段. Sender 所发送的消息不依赖 gadget 向量.
* 批量场景下优势放大: 批量 $N$ 签名场景下, 带宽占用随 $N$ 线性增长.
详见 `08-rvole.md` 对于多路扩展的讨论.

-----

# 正文

DKLS23 论文中的 "去随机化" 是一种 OT-based RVOLE 技术. 本文描述去随机化如何兑现 RVOLE 关系:
$$
z_a + z_b = x_a \cdot \beta \pmod{n}
$$

其中 $x_a$ 是 Sender 的秘密输入. $\beta$ 是 Receiver 现摇的随机选择向量经 gadget 聚合得到的标量, 跟 Receiver 持有的任何秘密无关 (详见 `07-gadget.md`). $z_a, z_b$ 是 Sender 和 Receiver 各自生成的加法份额.

<mark>注意 RVOLE 不是 ECDSA MtA.</mark>

RVOLE 只兑现 $x_a\cdot\beta$, 不兑现 $x_a\cdot x_b$.
从 $\beta$ 到 $x_b$ 的桥接由调用方在 RVOLE 之外的结构里完成.

## Step 1. 建立相关性

我们不再把 OT 密钥当成密钥来用, 而是对每个 OT 槽位 $j$:
* Sender 把 $\mathcal{K}^0_j$ 直接解读为随机数 $\alpha^0_j\in\mathbb{Z}_n$. 同理, 把 $\mathcal{K}^1_j$ 解读为随机数 $\alpha^1_j\in\mathbb{Z}_n$.
* Receiver 做出随机选择 $\beta_j\in\mathbb{B}$.

记 Receiver 的随机值 $\beta$ 是所有 $\beta_j$ 的二进制合成 (或者 gadget 合成).
显然这个 $\beta$ 是均匀随机的, Receiver 不向 Sender 暴露 $\beta$.

## Step 2. 去随机化

签名时 Sender 知道了实际的输入 $x_a$. Sender 构造如下修正向量, 发给 Receiver.

$$
\tilde{a}_{j} = \alpha^0_{j} - \alpha^1_{j} + x_a \pmod{n}.
$$

Sender 计算自己的加法份额.
$$
z_a = -\sum_j 2^j \cdot \alpha^0_j \pmod n. \tag{za}
$$

Receiver 计算自己的加法份额
$$
\begin{align*}
t_j &= \gamma_j+\beta_j\cdot\tilde{a}_j, \\
z_b &= \sum_j 2^j \cdot t_j \pmod{n}. 
\end{align*}
\tag{zb}
$$

为了便于理解, 本文采用二进制合成. 实际上也可以采用 gadget 合成, 详见 `07-gadget.md`.

※ 这一步的本质是兑现 RVOLE 关系, 即

$$
z_a + z_b = x_a\cdot \beta. \tag{za+zb}
$$

证明如下:

先考察 $t_j$. 里面有 0/1 系数 $\beta_j$, 对其进行分类讨论或许能发现新的意义. 实际上,
* 当 $\beta_j=0$ 时, 括号部分 $=\gamma_j+0\cdot\tilde{a}_j=\alpha^0_j$.
* 当 $\beta_j=1$ 时, 括号部分 $=\gamma_j+1\cdot\tilde{a}_j=\alpha^0_j+x_a$.

也就是说,

$$
t_j=\alpha^0_j+\beta_j\cdot x_a. \tag{zb.tj}
$$

再整理 $z_b$.

$$
\begin{align}
z_b&=\sum_j 2^j\cdot(\alpha^0_j+\beta_j\cdot x_a)\\
&=\sum_j 2^j \cdot \alpha^0_j + \left(\sum_j 2^j\cdot\beta_j\right)\cdot x_a \\
&= -z_a+\beta\cdot x_a \quad. \\
\phantom{=}\tag*{$\blacksquare$}
\end{align}
$$

## 安全隐患与 Sender 一致性检查

去随机化引入了新的攻击面: 恶意 Sender 可能对不同的 OT 实例 $j$ 使用不同的 $x'_a \neq x_a$, 破坏聚合关系 $z_a + z_b = x_a\cdot\beta$ 的正确性. 

这和 KOS15 防 Receiver 作弊是对称的问题:
* KOS15: 防 Receiver 在不同行用不同 $\beta'$ ---- 用 $\chi$ 做一致性检查.
* 防 Sender 在不同行用不同 $x'_a$ ---- 新增 Sender 一致性检查.

### 前提: OT 实例扩展为多维

前面的描述中, 每个 OT 实例只携带一个标量 (功能维度).
为了实施检查, 每个 OT 实例额外携带 $\rho$ 个检查维度.
也就是说, 我们让第 $j$ 个 OT 实例有 $1+\rho$ 个值:

* Sender 持有功能维度 $(\alpha^0_j, \alpha^1_j)$, 以及检查维度 $(\alpha^{0(k)}_j, \alpha^{1(k)}_j)$ 对于 $k\in[\rho]$.
* Receiver 对所有维度相同采用相同的选择位 $\beta_j$.
他得到功能维度 $\gamma_j = \alpha^{\beta_j}_j$, 以及检查维度 $\gamma^{(k)}_j = \alpha^{\beta_j(k)}_j$.

$\beta_j$ 共享是关键: 同一个选择位把功能维度和检查维度绑定在一起.

### Sender 发送修正矩阵

我们可以设置 $\rho$ 个维度用于检查 Sender $x_a$ 的一致性. 这些维度的结构和逻辑是相同的.

对于每个维度 $k$, Sender 采集随机 $x_a^{(k)}\stackrel{\$}{\leftarrow}\mathbb{Z}_n$. 然后对每个 OT 实例 $j$:

* 在功能维度嵌入 $x_a$, 即
$$\tilde{a}_j = \alpha^0_j - \alpha^1_j + x_a.\tag{aj-functional}$$

* 在检查维度嵌入 $x_a^{(k)}$, 即
$$\tilde{a}^{(k)}_j = \alpha^{0(k)}_j - \alpha^{1(k)}_j + x_a^{(k)}.\tag{aj-check}$$

Sender 将所有的 $\tilde{a}^{(k)}_j$ 发给 Receiver.
$k$ 的范围是从 0 到 $\rho$, 用于索引一条功能检查消息.
$j$ 的范围是从 1 到 $m$, 用于索引一个 OT 实例.

### 聚合

沿用 Step 2 的推导, 对检查维度同理可得:

$$
w^{(k)}_j = \gamma^{(k)}_j + \beta_j \cdot \tilde{a}^{(k)}_j = \alpha^{(k)}_j + \beta_j \cdot x_a^{(k)}.
$$

Sender 和 Receiver 对检查维度做和功能维度相同的聚合:

$$
\begin{align*}
\quad z^{(k)}_a &= -\sum_j 2^j \cdot \alpha^{(k)}_j,\\
z^{(k)}_b &= \sum_j 2^j \cdot w^{(k)}_j.
\end{align*}
$$

由于 $\beta_j$ 共享, 检查维度与功能维度满足相同结构的关系:

$$
z^{(k)}_a + z^{(k)}_b = \beta \cdot x_a^{(k)}.
$$

### 挑战

$$
\theta^{(k)} = \mathrm{Hash}\left(\tilde{a}^{(k)}_*\right), \quad k\in[\rho].
$$

哈希输入: Sender 发给 Receiver 的整个修正矩阵 (功能列 + 检查列). 由于 Receiver 也持有 $\tilde{A}$, 双方独立算出相同的 $\theta$. 这是 Fiat-Shamir 变换, 参见 [fiat-shamir.md](./fiat-shamir.md).

### Sender 发送响应

$$
\eta^{(k)} = x_a^{(k)} + \theta^{(k)} \cdot x_a, \quad k\in[\rho].
$$

$$
\sigma^{(k)} = -z^{(k)}_a - \theta^{(k)} \cdot z_a, \quad k\in[\rho].
$$

$\sigma^{(k)}$ 的实质是 Sender 的私有聚合份额经挑战加权后的线性组合. 展开写就是 $\sigma^{(k)} = \sum_j 2^j\cdot\alpha^{0(k)}_j + \theta^{(k)} \cdot \sum_j 2^j\cdot\alpha^0_j$. Sender 知道所有 $\alpha^0$ 值, 因此可以计算 $\sigma^{(k)}$. 注意 Sender 不需要知道 $\beta$.

### Receiver 验证

$$
z^{(k)}_b + \theta^{(k)} \cdot z_b \;\stackrel{?}{=}\; \sigma^{(k)} + \beta \cdot \eta^{(k)}.
\tag{verify}
$$

※ 正确性证明:

$$
\begin{align}
\text{LHS}
&= (z^{(k)}_b) + \theta^{(k)}\cdot(z_b) \\
&= (-z^{(k)}_a + \beta\,x_a^{(k)}) + \theta^{(k)}(-z_a + \beta\,x_a) \\
&= \left(-z^{(k)}_a - \theta^{(k)}\,z_a\right) + 
   \beta\left( (x_a^{(k)} + \theta^{(k)}\,x_a) \right) \\
&= \sigma^{(k)}+\beta\eta^{(k)} \quad. 
\end{align}
\tag{v.proof}
$$

$$
\phantom{=}\tag*{$\blacksquare$}
$$

-----

# 安全性和效率讨论

## 为什么能抓住作弊

如果恶意 Sender 对不同的 $j$ 使用了不同的 $x'_j \neq x_a$,
那么根据公式 "zb.tj" 以及附近的相关公式, $z_a + z_b$ 不再等于 $\beta \cdot x_a$, 而是

$$
z_a + z_b = \sum_j 2^j\cdot\beta_j\cdot x'_j
$$

根据公式 "v.proof", 公式 "verify" 成立, 当且仅当公式 "za+zb" 成立. 而恶意 Sender 破坏了公式 "za+zb" 之中 $\beta_j=1$ 时的关系.
* 对于 $\beta_j = 0$ 的位, Sender 的作弊不影响 $t_j$.
* 对于 $\beta_j = 1$ 的位, 只要存在某个 $x'_j \neq x_a$, 那么通过验证的概率不超过 $1/n$. 做 $\rho$ 次独立检查, 通过验证的概率不超过 $n^{-\rho}$, 可忽略不计.

※ 为什么 Sender 无法自适应地选择 $\sigma^{(k)}$ 和 $\eta^{(k)}$ 来通过检查? 因为 Sender 不知道 $\beta_j$ (OT 安全性保证), 无法预测 Receiver 的 $z_b$, 也就无法调整响应来抵消偏差.

## 为什么 SoftSpoken OT 不能提前到 Keygen.

表面看起来是个效率问题, 其实等价于 "为什么不能复用 SoftSpoken OT 密钥".
这么看就变成了安全问题.

### 在 derand 路线里不行

在 derand 路线里, 显然不能复用 OT 密钥. Sender 发两个修正
$$
\begin{align*}
\tilde a_j  &= \alpha^0_j - \alpha^1_j + x_a, \\
\tilde a_j' &= \alpha^0_j - \alpha^1_j + x_a'.
\end{align*}
$$
Receiver 直接相减: $\tilde a_j' - \tilde a_j = x_a' - x_a$. 泄露 Sender 输入之差.

### 在朴素路线里不行

在朴素路线里, 每次现摇 $r_j$ 盲化项, 即使密钥复用, $C^0_{j'} - C^0_j = r_{j'} - r_j$ 是均匀随机, 单纯信息论意义上的 OT 安全没破.

看起来很美好. 但在 DKLs23 协议层面, $\beta$ 必须每次新鲜.
β 是 Receiver 的随机选择向量, 跟 OT 槽位绑定. 复用 OT 槽位等于复用 β.

如果复用 $\beta$,
那么两次 RVOLE 输出 $(y_a, y_b), (y_a', y_b')$ 所产生的 $x_a\cdot\beta, x_a'\cdot\beta$,
就共享同一个 $\beta$.
ECDSA 签名外层暴露 $s_0, s_1$ 之后 (ECDSA `s` 字段的加法分片, 对协议参与方可见), 多签耦合分析能撬出 $\beta$ 的信息.

笔者暂时不知道 "多签耦合分析" 到底是怎样的漏洞. 暂且放下.

## Keygen 真正摊销的是什么

Keygen: Base OT (EndemicOT, 椭圆曲线重活) + PPRF (symmetric, 中等).
输出 `SenderOTSeed` / `ReceiverOTSeed` 存进 `Keyshare`.
这两个 seed 编码了一个长期 $\Delta$-correlation.

Sign: 每次签名都进行 SoftSpoken OT, 吃 Keygen 留下的 seed + 现摇的 `session_id` + 现摇的 $\beta$, 跑一次 SoftSpoken 扩展, 产出 $L$-对 (pair) 新鲜的扩展 OT 密钥. 紧接着跑 derand.

所以摊销到 Keygen 的是椭圆曲线那一层 (Base OT, 几百次 EC 操作). SoftSpoken 扩展每次 Sign 都跑, 但全是 symmetric op (PRG / Hash / XOR / GF($2^{128}$) 乘法), 速度跟 EC 不在一个数量级.