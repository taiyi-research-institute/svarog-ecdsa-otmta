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

Receiver 用同一个 $\beta_j$ 选: $\gamma^{(\ell')}_j = \alpha^{\beta_j,(\ell')}_j$, $\gamma^{(k)}_j = \alpha^{\beta_j,(k)}_j$.

### Step 2 平行 derand

对每个 $\ell' \in [\ell]$, Sender 嵌入 $x_{a,\ell'}$:

$$
\tilde{a}^{(\ell')}_j = \alpha^{0,(\ell')}_j - \alpha^{1,(\ell')}_j + x_{a,\ell'}.
$$

对每个 $k \in [\rho]$, Sender 仍嵌入随机 $x_a^{(k)}\stackrel{\$}{\leftarrow}\mathbb{Z}_n$ (与单路时相同).

聚合得到 $\ell + \rho$ 个 VOLE 关系:

$$
z^{(\ell')}_a + z^{(\ell')}_b = \beta \cdot x_{a,\ell'}, \quad
z^{(k)}_a + z^{(k)}_b = \beta \cdot x_a^{(k)}.
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
\eta^{(k)} = x_a^{(k)} + \sum_{\ell' \in [\ell]} \theta^{(k,\ell')} \cdot x_{a,\ell'}.
$$

$$
\sigma^{(k)} = -z^{(k)}_a - \sum_{\ell' \in [\ell]} \theta^{(k,\ell')} \cdot z^{(\ell')}_a.
$$

Receiver 对每个 $k \in [\rho]$ 验证:

$$
z^{(k)}_b + \sum_{\ell' \in [\ell]} \theta^{(k,\ell')} \cdot z^{(\ell')}_b \;\stackrel{?}{=}\; \sigma^{(k)} + \beta \cdot \eta^{(k)}. \tag{verify-vec}
$$

正确性证明与前文 "v.proof" 完全平行: 把 $z^{(*)}_a + z^{(*)}_b$ 关系代入 LHS, 提取 $\beta$ 项, 即得 RHS.

※ 为什么挑战要双下标? 在功能维度数 $\ell=1$ 的情况里, 每个挑战绑定单一功能维度.
如今 $\ell>1$, 需要让每个挑战绑定所有功能维度.
如此, 恶意 Sender 在任何 $(k, \ell')$ 上偷换都能被抓到.

※ 有几个检查? $\rho$ 个, 与 $\ell$ 无关. 详见公式 verify-vec.
