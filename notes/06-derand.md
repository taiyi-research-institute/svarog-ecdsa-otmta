dkls23 论文中的 "去随机化" 是一种 MtA 技术. 本文描述 DKLS23 的去随机化步骤如何实现 MtA:

$$
y_a + y_b = x_a \cdot x_b \pmod{n}
$$

其中 $x_a, x_b$ 分别是 Alice 和 Bob 持有的秘密值, 是 MtA 协议的输入.
$y_a, y_b$ 是他们生成的秘密值, 是 MtA 协议的输出.

回顾 `00-mta-baseot.md` 里的协议: Alice 准备 OT 消息时, 必须已知自己的输入 $x_a$.

$$
m[j,0] = r_k; \quad m[j,1] = r_j + x_a \cdot 2^j \pmod{n}
$$

在 MPC ECDSA 签名场景中, OT 扩展是计算量最大的部分.
其涉及 $\kappa$ 次 Base OT, $2n$ 个扩展 OT 实例, 以及相应的一致性检查. 这是一堆重活.

以下方法能把 OT 的重活提前到 Keygen 阶段. 在 Sign 的时候根本不做 OT.
思路是在 Keygen 阶段协商一个 "随机关联性", 在 Sign 阶段修正这个关联性.
名称 "去随机化" 就是指 "修正关联性".

## Step 1. 随机 OT (Keygen)

OT 消息不再编码任何实际秘密, 只编码均匀分布的随机数. 随机数一旦生成和交换, 就建立了所谓的 "随机关联性", 而这些随机数就叫 "随机关联种子".

随机 OT 的具体实施方式详见 `05-softspoken.md`.
它对于本文的能力边界是: 对于第 $j$ 个 OT 实例,
* Alice 持有随机数 $\alpha^0_j, \alpha^1_j\in\mathbb{Z}_n$. 这是两个 OT 消息.
* Bob 做出随机选择 $\beta_j\in\mathbb{B}$, 得到 OT 消息 $\gamma_j=\alpha^{\beta_j}_j$.

Bob 的选择 $\beta_j$ 是随机的, 不是任何秘密输入的位分解. 这些可以在 Keygen 的时候做, 存入 Keystore.

记 Bob 的随机值 $\beta = \sum_j \beta_j \cdot 2^j$. 这个 $\beta$ 是随机的, 与 $x_b$ 无关.

## Step 2. Alice 去随机化 (Sign)

签名时 Alice 知道了实际的输入 $x_a$. 构造如下修正向量, 发给 Bob.

$$
\tilde{a}_{j} = \alpha^0_{j} - \alpha^1_{j} + x_a \pmod{n}.
$$

Alice 计算自己的份额

$$
z_a = -\sum_j 2^j \cdot \alpha_j^0 \pmod n. \tag{za}
$$

Bob 计算自己的份额

$$
\begin{align}
t_j &= \gamma_j+\beta_j\cdot\tilde{a}_j \\
z_b &= \sum_j 2^j \cdot t_j \pmod{n}. 
\end{align}
\tag{zb}
$$

※ 这一步的本质是对 $x_a\cdot \beta$ 进行 MtA, 即

$$
z_a + z_b = x_a\cdot \beta. \tag{za+zb}
$$

证明如下:

先考察 $t_j$. 里面有 0/1 系数 $\beta_j$, 对其进行分类讨论或许能发现新的意义. 实际上,
* 当 $\beta_j=0$ 时, 括号部分 $=\gamma_j+0\cdot\tilde{a}_j=a^0_j$.
* 当 $\beta_j=1$ 时, 括号部分 $=\gamma_j+1\cdot\tilde{a}_j=a^0_j+x_a$.

也就是说,

$$
t_j=a^0_j+\beta_j\cdot x_a. \tag{zb.tj}
$$

再整理 $z_b$.

$$
\begin{align}
z_b&=\sum_j 2^j\cdot(a^0_j+\beta_j\cdot x_a)\\
&=\sum_j 2^j \cdot a^0_j + \left(\sum_j 2^j\cdot\beta_j\right)\cdot x_a \\
&= -z_a+\beta\cdot x_a \quad. \\
\phantom{=}\tag*{$\blacksquare$}
\end{align}
$$

公式 zb 还可以改用 gadget. 详见 `08-gadget.md`.

## Step 3: Bob 去随机化 (Sign)

Bob 计算如下修正值, 发给 Alice.

$$
\delta = x_b - \beta.
$$

Alice 计算如下秘密份额.

$$
y_a = z_a+x_a\cdot\delta.
$$

Bob 得到如下秘密份额.

$$
y_b = z_b.
$$

※ 此时 $y_a+y_b = x_a\cdot x_b$. 证明:

$$
\begin{align}
y_a + y_b &= z_a + x_a \cdot \delta + z_b \\
&= x_a \cdot \beta + x_a \cdot \delta \\
&= x_a \cdot \beta + x_a \cdot x_b - x_a \cdot \delta. \\
&= x_a \cdot x_b. \\
\phantom{=}\tag*{$\blacksquare$}
\end{align}
$$

## 安全隐患与 Alice 一致性检查

去随机化引入了新的攻击面: 恶意 Alice 可能对不同的 OT 实例 $j$ 使用不同的 $x'_a \neq x_a$, 破坏 MtA 的正确性. 

这和 KOS15 防 Bob 作弊是对称的问题:
* KOS15: 防 Bob 在不同行用不同 $\beta'$ ---- 用 $\chi$ 做一致性检查.
* 防 Alice 在不同行用不同 $x'_a$ ---- 新增 Alice 一致性检查.

### 前提: OT 实例扩展为多维

前面的描述中, 每个 OT 实例只携带一个标量 (功能维度).
为了实施检查, 每个 OT 实例额外携带 $\rho$ 个检查维度.
也就是说, 我们让第 $j$ 个 OT 实例有 $1+\rho$ 个值:

* Alice 持有功能维度 $(\alpha^0_j, \alpha^1_j)$, 以及检查维度 $(\alpha^{0(k)}_j, \alpha^{1(k)}_j)$ 对于 $k\in[\rho]$.
* Bob 对所有维度相同采用相同的选择位 $\beta_j$.
他得到功能维度 $\gamma_j = \alpha^{\beta_j}_j$, 以及检查维度 $\gamma^{(k)}_j = \alpha^{\beta_j(k)}_j$.

$\beta_j$ 共享是关键: 同一个选择位把功能维度和检查维度绑定在一起.

### Alice 发送修正矩阵

我们可以设置 $\rho$ 个维度用于检查 Alice $x_a$ 的一致性. 这些维度的结构和逻辑是相同的.

对于每个维度 $k$, Alice 采集随机 $x_a^{(k)}\stackrel{\$}{\leftarrow}\mathbb{Z}_n$. 然后对每个 OT 实例 $j$:

* 在功能维度嵌入 $x_a$. 
即 $\tilde{a}_j = \alpha^0_j - \alpha^1_j + x_a$.
我们也可以把 $\tilde{a}_j$ 视为 $\tilde{a}^{(0)}_j$.
* 在检查维度嵌入 $x_a^{(k)}$.
即 $\tilde{a}^{(k)}_j = \alpha^{0(k)}_j - \alpha^{1(k)}_j + x_a^{(k)}$.

Alice 将所有的 $\tilde{a}^{(k)}_j$ 发给 Bob. $k$ 的范围是从 0 到 $\rho$, 用于索引一条功能检查消息. $j$ 的范围是从 1 到 $m$, 用于索引一个 OT 实例.

### 聚合

沿用 Step 2 的推导, 对检查维度同理可得:

$$
w^{(k)}_j = \gamma^{(k)}_j + \beta_j \cdot \tilde{a}^{(k)}_j = \alpha^{0(k)}_j + \beta_j \cdot x_a^{(k)}.
$$

Bob 对检查维度做和功能维度相同的聚合:

$$
z^{(k)}_b = \sum_j 2^j \cdot w^{(k)}_j, \quad z^{(k)}_a = -\sum_j 2^j \cdot \alpha^{0(k)}_j.
$$

由于 $\beta_j$ 共享, 检查维度与功能维度满足相同结构的关系:

$$
z^{(k)}_a + z^{(k)}_b = \beta \cdot x_a^{(k)}.
$$

### 挑战

$$
\theta^{(k)} = \mathrm{Hash}\left(\tilde{a}^{(k)}_*\right), \quad k\in[\rho].
$$

哈希输入: Alice 发给 Bob 的整个修正矩阵 (功能列 + 检查列). 由于 Bob 也持有 $\tilde{A}$, 双方独立算出相同的 $\theta$. 这是 Fiat-Shamir 变换, 参见 [fiat-shamir.md](./fiat-shamir.md).

### Alice 发送响应

$$
\eta^{(k)} = x_a^{(k)} + \theta^{(k)} \cdot x_a, \quad k\in[\rho].
$$

$$
\sigma^{(k)} = -z^{(k)}_a - \theta^{(k)} \cdot z_a, \quad k\in[\rho].
$$

$\sigma^{(k)}$ 的实质是 Alice 的私有聚合份额经挑战加权后的线性组合. 展开写就是 $\sigma^{(k)} = \sum_j 2^j\cdot\alpha^{0(k)}_j + \theta^{(k)} \cdot \sum_j 2^j\cdot\alpha^0_j$. Alice 知道所有 $\alpha^0$ 值, 因此可以计算 $\sigma^{(k)}$. 注意 Alice 不需要知道 $\beta$.

### Bob 验证

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

### 为什么能抓住作弊

如果恶意 Alice 对不同的 $j$ 使用了不同的 $x'_j \neq x_a$,
那么根据公式 "zb.tj" 以及附近的相关公式, $z_a + z_b$ 不再等于 $\beta \cdot x_a$, 而是

$$
z_a + z_b = \sum_j 2^j\cdot\beta_j\cdot x'_j
$$

根据公式 "v.proof", 公式 "verify" 成立, 当且仅当公式 "za+zb" 成立. 而恶意 Alice 破坏了公式 "za+zb" 之中 $\beta_j=1$ 时的关系.
* 对于 $\beta_j = 0$ 的位, Alice 的作弊不影响 $t_j$.
* 对于 $\beta_j = 1$ 的位, 只要存在某个 $x'_j \neq x_a$, 那么通过验证的概率不超过 $1/n$. 做 $\rho$ 次独立检查, 通过验证的概率不超过 $n^{-\rho}$, 可忽略不计.

※ 为什么 Alice 无法自适应地选择 $\sigma^{(k)}$ 和 $\eta^{(k)}$ 来通过检查? 因为 Alice 不知道 $\beta_j$ (OT 安全性保证), 她无法预测 Bob 的 $z_b$, 也就无法调整响应来抵消偏差.

