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
