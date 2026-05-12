## $\ell$ 路向量化 (RVOLE 接口)

DKLS23 把若干路 OT-based RVOLE 打包成一个调用.

接口边界: Sender 一次性持有 $\ell$ 个秘密 $x_{a,1}, \ldots, x_{a,\ell}$, 跟 Receiver 现摇的随机标量 $\beta$ 同时做 $\ell$ 路 VOLE:

$$
z^{(\ell')}_a + z^{(\ell')}_b = x_{a,\ell'} \cdot \beta, \quad \ell' \in [\ell].
$$

$\beta$ 是 Receiver 内部的随机数, 跟 Receiver 的任何秘密无关.
RVOLE 协议本身不会把 $\beta$ 校正成 $x_b$ 或类似的东西. $\beta$ 的去向由调用方负责.
详见 `06-rvole-derand.md` 和 `09-orchestration.md`.

工程上 $\ell = 2$.
来源: ECDSA 签名一次会话里, Sender 一侧同时输入 $[r_s, \mathtt{sk}_s]$,
一路给 $r_s\beta$ ($u$ 通道), 一路给 $\mathtt{sk}_s\beta$ ($v$ 通道).
这两路怎么拼成最终签名, 见 `09-orchestration.md`.

### 共享同一个 $\beta$ 的多维 OT

每个 OT 实例携带 $\ell + \rho$ 个值. Sender 的两侧消息记为:

* 功能维度: $(\alpha^{(0,\ell')}_j, \alpha^{(1,\ell')}_j)$ for $\ell' \in [\ell]$.
* 检查维度: $(\alpha^{(0,k)}_j, \alpha^{(1,k)}_j)$ for $k \in [\rho]$.

Receiver 用同一个 $\beta_j$ 选出
$$
\begin{align*}
\gamma^{(\ell')}_j &= \alpha^{(\beta_j,\ell')}_j \\
\gamma^{(k)}_j &= \alpha^{(\beta_j,k)}_j.
\end{align*}
$$

### Step 2 平行 derand

对每个 $\ell' \in [\ell]$, Sender 嵌入 $x_{a,\ell'}$:
$$
\tilde{a}^{(\ell')}_j = \alpha^{(0,\ell')}_j - \alpha^{(1,\ell')}_j + x_{a,\ell'}.
$$

对每个 $k \in [\rho]$, Sender 仍嵌入随机 $x_a^{(k)}\stackrel{\$}{\leftarrow}\mathbb{Z}_n$
(与单路时相同):
$$
\tilde{a}^{(k)}_j = \alpha^{(0,k)}_j - \alpha^{(1,k)}_j + x_a^{(k)}.
$$

仿照 `06-rvole-derand.md`, Sender 进行 gadget 加权, 得到自身份额:
$$
\begin{align*}
z^{(\ell')}_a &= -\sum_j g_j \cdot \alpha^{(0,\ell')}_j, \\
z^{(k)}_a &= -\sum_j g_j \cdot \alpha^{(0,k)}_j.
\end{align*}
$$

仿照 `06-rvole-derand.md` 公式 "zb.tj", Receiver 对每个 $j$ 计算相应的 $t$:
$$
\begin{align*}
t^{(\ell')}_j &= \gamma^{(\ell')}_j + \beta_j \cdot \tilde{a}^{(\ell')}_j, \\
t^{(k)}_j &= \gamma^{(k)}_j + \beta_j \cdot \tilde{a}^{(k)}_j,
\end{align*}
$$

再 gadget 加权:
$$
\begin{align*}
z^{(\ell')}_b &= \sum_j g_j \cdot t^{(\ell')}_j, \\
z^{(k)}_b &= \sum_j g_j \cdot t^{(k)}_j.
\end{align*}
$$

聚合得到 $\ell + \rho$ 个 VOLE 关系:
$$
\begin{align*}
z^{(\ell')}_a + z^{(\ell')}_b &= \beta \cdot x_{a,\ell'}, \\
z^{(k)}_a + z^{(k)}_b &= \beta \cdot x_a^{(k)}.
\end{align*}
$$

这就是 RVOLE 调用的输出.
$\beta$ 保持随机, 不会被校正成 $x_b$.
$\beta$ 怎么在 ECDSA 外层被代数抵消, 详见 `09-orchestration.md`.

### 一致性检查的双下标挑战

挑战不再是 "每 $k$ 一个", 而是 "每 $(k, \ell')$ 对一个". Fiat-Shamir 派生:

$$
\theta^{(k,\ell')} = \mathrm{Hash}\left(\tilde{a}^{(*,*)}_*, \;k, \;\ell'\right), \quad k \in [\rho], \ell' \in [\ell].
$$

哈希输入: Sender 发给 Receiver 的整个修正矩阵 (功能 $\ell$ 列 + 检查 $\rho$ 列).

Sender 对每个 $k \in [\rho]$ 发送一份响应 $(\eta^{(k)}, \sigma^{(k)})$:

$$
\begin{align*}
\eta^{(k)} &= x_a^{(k)} + \sum_{\ell' \in [\ell]} \theta^{(k,\ell')} \cdot x_{a,\ell'}. 
\tag{eta} \\
\sigma^{(k)} &= -z^{(k)}_a - \sum_{\ell' \in [\ell]} \theta^{(k,\ell')} \cdot z^{(\ell')}_a \\
&= \left\{ \sum_j g_j \alpha^{(0,k)}_j \right\}
 + \left\{ \sum_{\ell'} \theta^{(k,\ell')}\cdot \sum_j g_j\alpha^{(0,\ell')}_j\right\} \\
&= \sum_j g_j\cdot \left\{
    \sum_{\ell'} \theta^{(k,\ell')} \alpha^{(0,\ell')}_j
\right\} \\
&:= \sum_j g_j h_{j,k} ~.
\tag{sigma}
\end{align*}
$$

Receiver 对每个 $k \in [\rho]$ 验证:

$$
z^{(k)}_b + \sum_{\ell' \in [\ell]} \theta^{(k,\ell')} \cdot z^{(\ell')}_b \;\stackrel{?}{=}\; \sigma^{(k)} + \beta \cdot \eta^{(k)}. \tag{verify-vec}
$$

正确性证明与前文 "v.proof" 完全平行: 把 $z^{(*)}_a + z^{(*)}_b$ 关系代入 LHS, 提取 $\beta$ 项, 即得 RHS.

※ 为什么挑战要双下标?

在功能维度数 $\ell=1$ 的情况里, 每个挑战绑定单一功能维度.
如今 $\ell>1$, 需要让每个挑战绑定所有功能维度.
如此, 恶意 Sender 在任何 $(k, \ell')$ 上偷换都能被抓到.

※ 有几个检查?

$\rho$ 个, 与 $\ell$ 无关. 详见公式 verify-vec.

-----

## 改进路线: 哈希链

SilenceLab 的代码里没有采用前文 verify-vec 的路线,
而是用 hash-commit 把一致性检查换了个形态.
两个方案共用同一个 $\eta^{(k)}$ 和 $\theta$. 
差别全在 "用什么把 Receiver 端的 $\beta$ 抵消干净".

Sender 计算并发送 $H_a := \mathrm{Hash}( h_{*,*} )$.
本文公式 "sigma" 的末尾定义了 $h_{j,k}$.

Receiver 逐行算 $\mathtt{rcv}_{j,k}$, 减去 $\beta_j\cdot\eta^{(k)}$ (注意这里 $\beta_j$ 是 OT 的单 bit 选择, 不是 gadget 聚合后的 $\mathbb{Z}_n$ 标量 $\beta$):
$$
\begin{align*}
\mathtt{rcv}_{j,k}
&:= t^{(k)}_j + \sum_{\ell'} \theta^{(k,\ell')}\cdot t^{(\ell')}_j - \beta_j\cdot\eta^{(k)} \\
%
&\stackrel{(\dagger)}{=}
   \left( \alpha^{(0,k)}_j + \beta_j\cdot x_a^{(k)} \right)
 + \sum_{\ell'} \theta^{(k,\ell')}\cdot \left( \alpha^{(0,\ell')}_j + \beta_j\cdot x_{a,\ell'} \right)
 \\
 &\phantom{{}={}}- \beta_j\cdot \left( x_a^{(k)} + \sum_{\ell'} \theta^{(k,\ell')}\cdot x_{a,\ell'} \right) \\
%
&= \alpha^{(0,k)}_j + \sum_{\ell'} \theta^{(k,\ell')}\cdot\alpha^{(0,\ell')}_j \\
&\phantom{{}={}} + \beta_j\cdot \left( x_a^{(k)} + \sum_{\ell'} \theta^{(k,\ell')}\cdot x_{a,\ell'} \right)
 - \beta_j\cdot \left( x_a^{(k)} + \sum_{\ell'} \theta^{(k,\ell')}\cdot x_{a,\ell'} \right) \\
%
&= \alpha^{(0,k)}_j + \sum_{\ell'} \theta^{(k,\ell')}\cdot\alpha^{(0,\ell')}_j \\
&= h_{j,k} ~.
\end{align*}
$$

第 $(\dagger)$ 步把 $t^{(k)}_j, t^{(\ell')}_j$ 按 `06-rvole-derand.md` 公式 "zb.tj" 化简成 $\alpha^{(0,*)}_j + \beta_j\cdot x_a^{(*)}$ 的形式, 同时把 $\eta^{(k)}$ 按公式 "eta" 展开. 整理后 $\beta_j$-项完全相消, 剩 $h_{j,k}$.

然后算 $H_b := \mathrm{Hash}( \mathtt{rcv}_{*,*} )$, 比对 $H_a \stackrel{?}{=} H_b$.

※ 门道: 抓作弊的颗粒度不同.

* $\sigma$: 收尾后只剩 1 条标量等式. 作弊 Sender 用 $x'_{j,\ell'} = x_{a,\ell'} + \Delta x_{j,\ell'}$, 等式两边差 $\sum_{\ell'} \theta^{(k,\ell')} \cdot \sum_j g_j \beta_j \Delta x_{j,\ell'}$. 只要这个**加权总和**为零就过关.
* $H_a$ vs $H_b$: 锁住整个矩阵, 禁不起任何刻意修改.
