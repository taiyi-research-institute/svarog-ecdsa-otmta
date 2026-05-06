dkls23 论文中的 "去随机化" 是一种 MtA 技术. 本文描述 DKLS23 的去随机化步骤如何实现 MtA:

$$
y_a + y_b = x_a \cdot x_b \pmod{n}
$$

其中 $x_a, x_b$ 分别是 Alice 和 Bob 持有的秘密值, 是 MtA 协议的输入.
$y_a, y_b$ 是他们生成的秘密值, 是 MtA 协议的输出.

回顾 [base-ot-mta.md](./base-ot-mta.md) 里的基础 OT-MtA 协议:
Alice 准备 OT 消息时, 必须已知自己的输入 $x_a$.

$$
m[j,0] = r_k; \quad m[j,1] = r_j + x_a \cdot 2^j \pmod{n}
$$

在 MPC ECDSA 签名场景中, OT 扩展是计算量最大的部分. 其涉及 $\kappa$ 次 Base OT, $2n$ 个扩展 OT 实例, 以及相应的一致性检查. 这是一堆重活.

以下方法能把 OT 的重活提前到 Keygen 阶段. 在 Sign 的时候根本不做 OT. 思路是在 Keygen 阶段协商一个 "随机关联性", 在 Sign 阶段修正这个关联性. 名称 "去随机化" 就是指 "修正关联性".

## Step 1. 随机 OT (Keygen)

OT 消息不再编码任何实际秘密, 只编码均匀分布的随机数. 随机数一旦生成和交换, 就建立了所谓的 "随机关联性", 而这些随机数就叫 "随机关联种子".

随机 OT 的具体实施方式如下. 这里不赘述 OT 的实施过程, 只规定: 对于第 $j$ 个 OT 实例,
* Alice 持有随机数 $\alpha^0_j, \alpha^1_j\in\mathbb{Z}_n$. 这是两个 OT 消息.
* Bob 做出随机选择 $\beta_j\in\{0,1\}$, 得到 OT 消息 $\gamma_j=\alpha^{\beta_j}_j$.

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

前面的描述中, 每个 OT 实例只携带一个标量 (功能维度). 为了实施检查, 每个 OT 实例额外携带 $\rho$ 个检查维度. 即第 $j$ 个 OT 实例有 $1+\rho$ 个值:

* Alice 持有功能维度 $(\alpha^0_j, \alpha^1_j)$, 以及检查维度 $(\alpha^{0(k)}_j, \alpha^{1(k)}_j)$ 对于 $k\in[\rho]$.
* Bob 的选择位 $\beta_j$ **对所有维度相同**. 他得到功能维度 $\gamma_j = \alpha^{\beta_j}_j$, 以及检查维度 $\gamma^{(k)}_j = \alpha^{\beta_j(k)}_j$.

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

## $\ell$ 路向量化 (RVOLE 接口)

DKLS23 把若干路 MtA 打包成一个 RVOLE 调用. 接口需求是: Alice 一次性持有 $\ell$ 个秘密 $x_{a,1}, \ldots, x_{a,\ell}$, 与 Bob 唯一的 $x_b$ 同时做 $\ell$ 路 MtA, 即

$$
y_{a,\ell'} + y_{b,\ell'} = x_{a,\ell'} \cdot x_b, \quad \ell' \in [\ell].
$$

工程上 $\ell = L_\text{batch} = 2$ (`rvole.rs` `L_BATCH`). 来源: ECDSA 签名一次会话需要并行做两路 MtA, 一路求 $K$, 一路求 $\Phi$ (见后续 dsg 笔记).

向量化的核心观察: 这 $\ell$ 路 MtA 共享同一个 Bob 选择向量 $\beta$, 因此可以共享同一批底层随机 OT 实例和同一份 SoftSpoken OT 扩展输出. 唯一变化是把 $\mathrm{OT\_WIDTH}$ 从 $1+\rho$ 扩到 $\ell+\rho$, 并把 derand / 检查的相应公式做参数化.

### 共享同一个 $\beta$ 的多维 OT

每个 OT 实例携带 $\ell + \rho$ 个值. Alice 的两侧消息记为:

* 功能维度: $(\alpha^{0,(\ell')}_j, \alpha^{1,(\ell')}_j)$ for $\ell' \in [\ell]$.
* 检查维度: $(\alpha^{0,(k)}_j, \alpha^{1,(k)}_j)$ for $k \in [\rho]$.

Bob 用同一个 $\beta_j$ 选: $\gamma^{(\ell')}_j = \alpha^{\beta_j,(\ell')}_j$, $\gamma^{(k)}_j = \alpha^{\beta_j,(k)}_j$.

这一切都由前文"前提: OT 实例扩展为多维"提供, 只是把功能维度从 1 路扩到 $\ell$ 路.

### Step 2 / Step 3 平行扩展

对每个 $\ell' \in [\ell]$, Alice 嵌入 $x_{a,\ell'}$:

$$
\tilde{a}^{(\ell')}_j = \alpha^{0,(\ell')}_j - \alpha^{1,(\ell')}_j + x_{a,\ell'}.
$$

对每个 $k \in [\rho]$, Alice 仍嵌入随机 $x_a^{(k)}\stackrel{\$}{\leftarrow}\mathbb{Z}_n$ (与单路时相同).

Step 2 聚合得到:

$$
z^{(\ell')}_a + z^{(\ell')}_b = \beta \cdot x_{a,\ell'}, \quad
z^{(k)}_a + z^{(k)}_b = \beta \cdot x_a^{(k)}.
$$

Step 3 修正值仍是单一一个 $\delta = x_b - \beta$ (Bob 只发一份), 但 Alice 对每路 $\ell'$ 各算一份份额:

$$
y_{a,\ell'} = z^{(\ell')}_a + x_{a,\ell'} \cdot \delta, \quad
y_{b,\ell'} = z^{(\ell')}_b.
$$

### 一致性检查的双下标挑战

挑战不再是"每 $k$ 一个", 而是"每 $(k, \ell')$ 对一个". Fiat-Shamir 派生:

$$
\theta^{(k,\ell')} = \mathrm{Hash}\left(\tilde{a}^{(*,*)}_*, \;k, \;\ell'\right), \quad k \in [\rho], \ell' \in [\ell].
$$

哈希输入: Alice 发给 Bob 的整个修正矩阵 (功能 $\ell$ 列 + 检查 $\rho$ 列).

Alice 对每个 $k \in [\rho]$ 发送一份响应 $(\eta^{(k)}, \sigma^{(k)})$:

$$
\eta^{(k)} = x_a^{(k)} + \sum_{\ell' \in [\ell]} \theta^{(k,\ell')} \cdot x_{a,\ell'}.
$$

$$
\sigma^{(k)} = -z^{(k)}_a - \sum_{\ell' \in [\ell]} \theta^{(k,\ell')} \cdot z^{(\ell')}_a.
$$

Bob 验证 (一个 $k$ 一个等式, 共 $\rho$ 个等式):

$$
z^{(k)}_b + \sum_{\ell' \in [\ell]} \theta^{(k,\ell')} \cdot z^{(\ell')}_b \;\stackrel{?}{=}\; \sigma^{(k)} + \beta \cdot \eta^{(k)}. \tag{verify-vec}
$$

正确性证明与前文 "v.proof" 完全平行: 把 $z^{(*)}_a + z^{(*)}_b$ 关系代入 LHS, 提取 $\beta$ 项, 即得 RHS.

※ 为什么挑战要双下标? 因为有 $\ell$ 路并行, 单路里"挑战 $\theta^{(k)}$ 把检查维度与单一功能维度绑在一起"现在要绑 $\ell$ 个功能维度. $\theta^{(k,\ell')}$ 给每对独立挑战, 才能让恶意 Alice 在任一对 $(k, \ell')$ 上偷换都被抓到.

※ 检查数量: 单一一致性检查方程内含 $\ell + 1$ 个 $\theta$ 加权项 (1 个检查 + $\ell$ 个功能), 但仍只有 $\rho$ 个独立等式. 抓作弊概率上界仍是 $n^{-\rho}$, 与 $\ell$ 无关.

### 工程实现要点

* 工程参数 $\rho = 1, \ell = 2$, 故 `RVOLEOutput.eta` 长度为 1, `theta` 是 $1 \times 2$ 矩阵, `mu_hash` 是单一 64 字节摘要.
* `RVOLEOutput.eta[k]` 字段在协议过程中两段含义:
    * 先存随机 $x_a^{(k)}$, 用于嵌入检查维度的修正值;
    * 再覆写为响应 $\eta^{(k)} = x_a^{(k)} + \sum_{\ell'} \theta^{(k,\ell')} \cdot x_{a,\ell'}$ 发给 Bob.
* $\sigma^{(k)}$ 不直接发送, 而是 Alice 在本地用 $\alpha^0$ 计算, 与 Bob 用 $\gamma$ 计算的对应值一起放进 mu_hash 里做 Fiat-Shamir 比对. 即代码里 `mu_hash` 的内部循环.
* gadget 向量 (见 [extot-dkls23-gadget.md](./extot-dkls23-gadget.md)) 替换二进制权重 $2^j$ 后, 上述所有 $\sum_j 2^j\cdot$ 一律替换成 $\sum_j g_j\cdot$, 其余结构不变. RVOLE 实际用的就是 gadget 版本.

### 代码位置

* `rvole.rs`: `RVOLEOutput { a_tilde, eta, mu_hash }` 即上述协议的全部出站消息.
* `rvole.rs`: `RVOLESender::process` 实现 Step 2 + 一致性检查响应; 接受 `&[Scalar; L_BATCH]` 即 $\ell$ 路 Alice 输入.
* `rvole.rs`: `RVOLEReceiver::process` 实现 Step 2 Bob 侧 + 一致性检查验证 + Step 3 Bob 自己的 $\delta$ 推导, 返回 `[Scalar; L_BATCH]` 即 $\ell$ 路 Bob 份额.
* `rvole.rs`: `generate_gadget_vec` 派生 $\mathbf{g}$.
