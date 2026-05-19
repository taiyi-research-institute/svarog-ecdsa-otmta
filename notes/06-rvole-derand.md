# 铺垫

回顾 `05-softspoken.md`: SoftSpoken 扩展产出 $L$ 对随机 OT 密钥. 对第 $j$ 实例,
* Sender 持有传输密钥 $\rho^0_j, \rho^1_j$, 不知 Receiver 选哪一边.
* Receiver 持有所选密钥 $\rho^{\beta_j}_j$, 其中 $\beta_j\in\mathbb{B}$ 是他的随机选择位.

拿到这些密钥后, 兑现随机 MtA 关系
$$
y_a + y_b := x_a\cdot\beta,
$$

而不是 ECDSA MtA 关系 $y_a + y_b := x_a\cdot x_b$.

下游协议负责消除 $\beta$. 这是 DKLs23 为了安全而做的选择. TODO: 和直接做 MtA 相比, 安全在哪?

兑现 MtA 关系有以下两种思路.

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
C^0_j &= \rho^0_j + M^0_j, \\
C^1_j &= \rho^1_j + M^1_j.
\end{align*}
$$

Receiver 用所持的 $\rho^{\beta_j}_j$ 解开 $C^{\beta_j}_j$, 得
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

我们把 $\rho^0_j$ 直接解读为随机数 $\alpha^0_j\in\mathbb{Z}_n$. 同理, 把 $\rho^1_j$ 解读为随机数 $\alpha^1_j\in\mathbb{Z}_n$.

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
* 朴素路线: 另外摇一个 $r_j$ 当盲化项, 把 $x_a$ 嵌进 $M^1_j$. 用 $\rho$ 当加法掩码.
* 另类路线: 跳过 $r_j$, 让 $\rho$ 自身充当随机 $\alpha$. $x_a$ 只嵌进 $\tilde a_j$.

另类路线的好处:
* 通信省一半.
* gadget 向量 $g_j$ 推迟到聚合阶段. Sender 所发送的消息不依赖 gadget 向量.
* 批量场景下优势放大: 批量 $N$ 签名场景下, 带宽占用随 $N$ 线性增长.
详见 `08-rvole.md` 对于多路扩展的讨论.

-----

# 正文

RVOLE 有 OT 实例 $j$, 检查编号 $k$, 负载编号 $i$ 三个维度. 这些维度搅在一起会 overwhelm 我们的认知. 所以, 下文首先描述最简洁的情况, 然后把这些维度一点一点加上去.

## 简化版: 兑现一个 MtA 关系

本节兑现单个 MtA 关系
$$
z_a + z_b := x_a \cdot \beta \pmod{n}.
$$

其中, 
* $x_a$ 是 Sender 的秘密输入.
* $\beta=\sum_{j\in[L]} \beta_t\cdot g_j$ 是 Receiver 的随机选择的加权聚合.
聚合方式详见 `07-gadget.md`.
* $z_a, z_b$ 是 Sender 和 Receiver 各自生成的加法份额.

### (Round 1) Sender -> Receiver

Sender 把 OT 密钥 $\rho^0_j$ 转换为随机标量 $\alpha^0_j\in\mathbb{Z}_n$. 同理, 把 $\rho^1_j$ 转换为随机标量 $\alpha^1_j\in\mathbb{Z}_n$.

Sender 构造修正项:
$$
\tilde{a}_{j} = \alpha^0_{j} - \alpha^1_{j} + x_a \pmod{n}.
$$

Sender 计算自己的加法份额:
$$
z_a = -\sum_j g_j \cdot \alpha^0_j \pmod n.
$$

Sender 发送 $\tilde{a}_j$, 本地保存 $z_a$.

### (Round 2) Receiver 完成

Receiver 对每个 $j$ 计算自己的份额:
$$
\begin{align*}
t_j &:= \alpha^{\beta_j}_j+\beta_j\cdot\tilde{a}_j, \\
\textrm{a.k.a.~} t_j &= \alpha^0_j + \beta_j \cdot x_a.
\end{align*}
$$
Receiver 计算 $z_b$ 份额:
$$
z_b := \sum_j g_j \cdot t_j \pmod{n}.
$$

读者如需验算 $z_a+z_b\stackrel{?}{=}x_a\cdot \beta$, 请模仿 `00-mta-baseot.md` 自行完成.

-----

## 完全版: 兑现多个 MtA 关系

恶意 Sender 可能对不同的 OT 实例 $j$ 使用不同的 $x'_a \neq x_a$, 破坏聚合关系 $z_a + z_b = x_a\cdot\beta$ 的正确性. 

为此, 我们约定每个 OT 实例携带

* $N_1$ 个负载用于下游 ECDSA MtA, 以及
* $N_2$ 个负载用于本协议的校验. 

也就是说, 完全版的协议兑现如下 $N_1+N_2$ 个 MtA 关系:
$$
z_{a,k}+z_{b,k}:= x_{a,k}\cdot \beta;
\quad
k\in[N_1+N_2].
$$
其中,
$$
x_{a,k}:=\begin{cases}
x_a,& 1\le k \le N_1, \\
\stackrel{\$}{\leftarrow} \mathbb{Z}_n, & N_1 < k \le N_1+N_2.
\end{cases}
$$

### (Round 1) Sender -> Receiver

对每个 OT 实例 $j$ 和负载 $k$, Sender 对 OT 密钥进行衍生, 得到:
$$
\alpha^b_{j,k}:=\mathrm{Hash}\left(
\mathtt{sid},j,k, \rho^b_j
\right);
\quad
b\in\mathbb{B}.
$$
对每个 OT 实例 $j$ 和负载 $k$, Sender 计算修正项:
$$
\tilde{a}_{j,k} := \alpha^0_{j,k}-\alpha^1_{j,k}+x_{a,k}.
$$
对每个**功能**负载 $k$, Sender 计算加法份额:
$$
z_{a,k}:=-\sum_j g_j\cdot \alpha^0_{j,k} ~.
$$
对每个**校验**负载 $k$, Sender 计算挑战:
$$
\theta_k:=\mathrm{Hash}(\tilde{a}_{*,k}).
\tag{challenge}\label{challenge}
$$
对每个**校验**负载 $k$, Sender 计算 eta-响应:
$$
\eta_k := x_{a,k}+\sum_{i\in[N_1]}\theta_k\cdot x_{a,i} ~. \tag{resp-eta}\label{resp-eta}
$$
对每个 OT 实例 $j$ 和**校验**负载 $k$, Sender 计算 mu-响应:
$$
\begin{align*}
\mu_{j,k} &:= \alpha^0_{j,k}
+\sum_{i\in[N_1]}\theta_{k,i}\cdot \alpha^0_{j,i}, \\

\mu &:= \mathrm{Hash}(\mathtt{sid},j,k,\dots
,\mu_{j,k},\dots).
\end{align*}
\tag{resp-mu}\label{resp-mu}
$$
Sender 本地保存 $z_{a,k}$, 发送 $\tilde{a}_{j,k}$, $\eta_k$, $\mu_{j,k}$.

### (Round 2) Receiver 结束

Receiver 随机摇一个 $L$-比特串 $\vec{\beta}\in\mathbb{B}^L$. 这就是 Receiver 的随机选择.

对每个 OT 实例 $j$ 和负载 $k$, Receiver 对 OT 密钥进行衍生, 得到
$$
\alpha^{\beta_j}_{j,k}:=\mathrm{Hash}\left(
\mathtt{sid},j,k, \rho^{\beta_j}_j
\right).
$$
对每个 OT 实例 $j$ 和负载 $k$, Receiver 计算
$$
\begin{align*}
t_{j,k} &:= \alpha^{\beta_j}_{j,k}+\beta_j\cdot \tilde{\alpha}_{j,k}, \\
&= \alpha^0_{j,k}+\beta_j\cdot x_{a,k}.
\end{align*}
$$
基于 Sender 发来的 $\tilde{a}$, Receiver 也采用公式 $\eqref{challenge}$ 计算挑战.
$$
\theta_k:=\mathrm{Hash}(\tilde{a}_{*,k}).
$$
对每个 OT 实例 $j$ 和校验负载 $k$, Receiver 在本地计算 $\hat\mu_{j,k}$ 和 $\hat{\mu}$.
$$
\begin{align*}
\hat\mu_{j,k} &:= t_{j,k} 
+ \left\{\sum_{i\in[N_1]} \theta_{k,i}\cdot t_{j,i} \right\}
- \beta_j\cdot\eta_k, \\

\mu &:= \mathrm{Hash}(\mathtt{sid},j,k,\dots
,\hat\mu_{j,k},\dots).
\end{align*}
$$
然后检验 $\hat\mu\stackrel{?}{=}\mu$.

如果检验通过, 那么 Receiver 对每个功能负载 $k$ 计算本地份额
$$
z_{b,k} := \sum_{j}g_j\cdot t_{j,k} ~.
$$
Receiver 本地保存 $z_{b,k}$.

-----

## 讨论: Keygen 真正摊销的是什么

Keygen: Base OT (EndemicOT, 椭圆曲线重活) + PPRF (对称加密, 中等).
输出 `SenderOTSeed` / `ReceiverOTSeed` 存进 `Keyshare`.
这两个 seed 编码了一个长期 $\Delta$-correlation.

Sign: 每次签名都进行 SoftSpoken OT, 吃 Keygen 留下的 seed + 现摇的 `session_id` + 现摇的 $\beta$, 跑一次 SoftSpoken 扩展, 产出 $L$-对 (pair) 新鲜的扩展 OT 密钥. 紧接着跑 derand.

所以摊销到 Keygen 的是椭圆曲线那一层 (Base OT, 几百次 EC 操作). SoftSpoken 扩展每次 Sign 都跑, 但全是对称操作 (PRG / Hash / XOR / GF($2^{128}$) 乘法), 速度跟 EC 不在一个数量级.