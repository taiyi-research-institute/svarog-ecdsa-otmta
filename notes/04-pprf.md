# PPRF 算法和数据结构笔记

本文仅讨论 $p=2$ 的情况.

## 设置

伪随机数生成器 (PRG), 在工程中就是哈希函数, 定义为
$\mathrm{Ha}: \mathbb{B}^\lambda\rightarrow\mathbb{B}^{2\lambda}$ . 
我们把输出切分为长度相等的两块,
左边记为 $\mathrm{HaL}(\cdot)$, 右边记为为 $\mathrm{HaR}(\cdot)$.

GGM 树是一棵完美二叉树, 深度为 $k$, 叶子数 $q=2^k$.
第 $i$ 层有 $2^i$ 个节点, 节点在层内的编号为 $y\in [2^i]$, 节点内容记为 $\mathcal{T}^i_y$.

每个内部节点有两个孩子, 
$$
\mathcal{T}^{i+1}_{2y}=\mathrm{HaL}(\mathcal{T}^i_y),\; \mathcal{T}^{i+1}_{2y+1}=\mathrm{HaR}(\mathcal{T}^i_y).
$$

Receiver 持有打孔点 $y\in[2^k]$, 目标是学到 $\left\{\mathcal{T}^k_z: z\neq y\right\}$,
但不知道 $\left\{\mathcal{T}^k_y\right\}$.

## Base OT 中的角色

Receiver 沿着树走到打孔点的节点下标记为 $y_1, y_2, \dots, y_k$. 这条路径叫做 active path.
其中 $y_{i+1}=2y_i+\bar{\beta}_i$, $\beta_i\in \mathbb{B}$ 是第 $i$ 层 base OT 的选择位 (= Receiver 解出的非打孔方向), $\bar{\beta}_i = 1 - \beta_i$ 即该层的打孔方向.
显然 $y_k=y$.

Receiver 在第 $i+1$ 层 "想去" 的节点下标是 $2y_i + \beta_i$, 也就是 active path 节点的兄弟.

第 $i$ 个 base OT 的接口 ($0 \le i < k$):

* Sender 输入/输出: 两个随机串 $\rho^i_0, \rho^i_1\in \mathbb{B}^\lambda$.
* Receiver 输入: 选择位 $\beta_i\in \mathbb{B}$.
* Receiver 输出: $\rho^i_{\beta_i}$ .

直观上, $\rho^i_b$ 相当于第 $i+1$ 层 "所有 $b$ 侧孩子的合成密钥". Receiver 拿到兄弟方向那一侧的合成密钥, 从中可以解出兄弟节点本身.

> 记号说明: $\rho^i_b$ 即 `notes/03-endemic-ot.md` 中 endemic OT 的输出密钥 $\rho_b$, 上标 $i$ 是 base OT 实例编号 ($0\le i < k$, $k = \log Q$).

## Sender 进行 BuildPPRF

Sender 拥有所有 $k$ 个 base OT 的两侧串 $\{(\rho^i_0, \rho^i_1)\}$, 实例编号 $0\le i < k$.

Sender 初始化第 1 层:
$$
\mathcal{T}^1_0 := \rho^0_0, \quad \mathcal{T}^1_1 := \rho^0_1. \tag{first-layer}
$$

注意这棵树有一个用不上的根节点, 我们视其为第 0 层.

Sender 基于第 $i$ 层构建第 $i+1$ 层.
对第 $i$ 层 ($1\le i < k$) 的第 $z \in [2^i]$ 节点, Sender 计算:
$$
\mathcal{T}^{i+1}_{2z} := \mathrm{HaL}(\mathcal{T}^i_z), \quad \mathcal{T}^{i+1}_{2z+1} := \mathrm{HaR}(\mathcal{T}^i_z). \tag{next-layer}
$$

Sender 为除初始化层之外的每一层计算一对修正值 $t^i_0, t^i_1$.
对第 $i$ 层 ($1\le i < k$), Sender 计算:

$$
t^i_b := \rho^i_b \oplus \bigoplus_{z \in [2^i]} \mathcal{T}^{i+1}_{2z + b}. \tag{correction}
$$

Sender 输出这棵树, 记为 $G: z \mapsto \mathcal{T}^k_z$.
注意: 输出不是传输, 传输也不是输出, 不要看到 "输出" 就产生 "告诉另一方" 的联想.

## Sender 进行 ProvePPRF

仅有上述 BuildPPRF 还不够: 恶意 Sender 可以把某层修正值 $t^i_b$ 替换成乱数,
让 Receiver 顺着错误的 $\mathcal{T}^{i+1}_{2y_i + \beta_i}$ 一路向下,
最终得到一棵跟 Sender 不一致的子树, 而 Receiver 自己察觉不到.
为此 DKLS23 (论文 Fig.14) 在 BuildPPRF 末尾追加一段 "叶子层一致性证明".

记一个独立于 $\mathrm{Ha}$ 的哈希 $\mathrm{Ha}': \mathbb{B}^\lambda\rightarrow \mathbb{B}^{2\lambda}$,
工程上仍由同一个底层 PRG 派生, 只是用不同的 domain-separation 标签.

Sender 对每个叶子算一个长度 $2\lambda$ 的标签:
$$
\tilde s_z := \mathrm{Ha}'(\mathcal{T}^k_z), \quad z \in [q]. \tag{sz-tag}
$$

然后输出两个 $2\lambda$-比特串:
* $\tilde t := \bigoplus_{z \in [q]} \tilde s_z$, 是对所有叶子节点的异或承诺.
* $\tilde s := H\bigl(\tilde s_0 \,\|\, \tilde s_1 \,\|\, \cdots \,\|\, \tilde s_{q-1}\bigr)$, 是对所有叶子节点的哈希承诺.

## Receiver 进行 EvalPPRF

Receiver 选择 $\beta = (\beta_0, \beta_1, \dots, \beta_{k-1}) \in \mathbb{B}^k$，对应的打孔点下标为

$$
y = \sum_{i=0}^{k-1} \bar{\beta}_i \cdot 2^{k-1-i}, \tag{position}
$$

活动路径为: $y_1 = \bar{\beta}_0$，$y_{i+1} = 2y_i + \bar{\beta}_i$.

第 1 层: Receiver 从 base OT 0 拿到 $\rho^0_{\beta_0}$, 按定义这就是 $\mathcal{T}^1_{\beta_0}$. Receiver 拿不到兄弟节点 $\mathcal{T}^1_{\bar{\beta}_0}$. 注意看仔细, 第一处 $\mathcal{T}^1_{\beta_0}$ 没有 overbar, 第二处 $\mathcal{T}^1_{\bar{\beta}_0}$ 有.

逐层扩展, $i=1\dots,k-1$:

(a) 复制已知子树. 对每个 $z \in [2^i] \setminus \{y_i\}$:

$$
\mathcal{T}^{i+1}_{2z} := \mathrm{HaL}(\mathcal{T}^i_z), \quad \mathcal{T}^{i+1}_{2z+1} := \mathrm{HaR}(\mathcal{T}^i_z). \tag{copy}
$$

(b) 恢复 active path 的兄弟节点. Sender 端 $t^i_{\beta_i}$ 满足如下等式. 
$$
t^i_{\beta_i} = \rho^i_{\beta_i} \oplus \bigoplus_{z \in [2^i]} \mathcal{T}^{i+1}_{2z + \beta_i}.
$$

理解上式的关键直觉是: 异或运算的加法与减法是等价的, 我们可以把异或项挪动到等式的任意一边.

Receiver 已知 $t^i_{\beta_i}$, $\rho^i_{\beta_i}$, 以及求和中除 $z = y_i$ 项之外的所有项. 移项得:
$$
\mathcal{T}^{i+1}_{2 y_i + \beta_i} = 
t^i_{\beta_i} \oplus \rho^i_{\beta_i} 
\oplus \bigoplus_{z \neq y_i} \mathcal{T}^{i+1}_{2z + \beta_i}
\tag{infer}
$$

(c) 更新 active path 指针/游标/迭代器, 即计算
$$y_{i+1} := 2 y_i + \bar{\beta}_i. \tag{cursor}$$
Receiver 仍不知道 $\mathcal{T}^{i+1}_{y_{(i+1)}}$. 

最终输出: 打孔位置 $y$, 整条 active path 都被打孔的树 $G^*$.

## Receiver 进行 VerifyPPRF

紧接 EvalPPRF, Receiver 要校验 Sender 的 $(\tilde t, \tilde s)$ 一致.

Receiver 只算得出 $z\ne y$ 的标签
$$\tilde s_z := \mathrm{Ha}'(\mathcal{T}^k_z). \tag{infer-sz}$$

缺的那一项 $\tilde s_y$ 可以从 $\tilde t$ 解出:
$$
\tilde s_y := \tilde t \oplus \bigoplus_{z \ne y} \tilde s_z. \tag{infer-sy}
$$

补齐后, Receiver 重算
$$
\tilde s^* := H\bigl(\tilde s_0 \,\|\, \tilde s_1 \,\|\, \cdots \,\|\, \tilde s_{q-1}\bigr).
\tag{infer-s}
$$
并验 $\tilde s^* \stackrel{?}{=} \tilde s$. 不等则中止.

这套 Proof/Verify 策略的精神在于:
Sender 不知道 Receiver 要给哪个叶子打孔.
对每棵树, Sender 猜中的概率仅有 $1/q$; 但 Sender 必须猜中所有 $\kappa/K$ 棵树才能骗过 Receiver.
Receiver 在任何一棵树上验不过, 都会「有内鬼, 终止交易」.
如此, Sender 骗过 Receiver 的概率很渺茫.

## 通信成本

- base OT：$k$ 个 $\binom{2}{1}$-OT
- Sender → Receiver 的修正值：$2(k-1)$ 个 $\lambda$ 比特串
- ProvePPRF 输出: $\tilde t, \tilde s$ 两个 $2\lambda$ 比特串, 共 $4\lambda$
- 总扩展通信约 $2(k-1)\lambda + 4\lambda = 2(k+1)\lambda$ 比特，得到 $q = 2^k$ 大小的 PPRF

