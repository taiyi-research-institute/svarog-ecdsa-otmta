# PPRF 算法和数据结构笔记

本文仅讨论 $p=2$ 的情况.

## 设置

伪随机数生成器 (PRG), 在工程中就是哈希函数, 定义为
$\mathrm{Ha}: \left\{0,1\right\}^\lambda\rightarrow\left\{0,1\right\}^{2\lambda}$ . 
我们把输出切分为长度相等的两块,
左边记为 $\mathrm{HaL}(\cdot)$, 右边记为为 $\mathrm{HaR}(\cdot)$.

GGM 树是一棵完美二叉树, 深度为 $k$, 叶子数 $q=2^k$.
第 $i$ 层有 $2^i$ 个节点, 节点在层内的编号为 $y\in [2^i]$, 节点内容记为 $s_y^i$.

每个内部节点有两个孩子, 
$$
s_{2y}^{i+1}=\mathrm{HaL}(s_y^i),\; s_{2y+1}^{i+1}=\mathrm{HaR}(s_y^i).
$$

Receiver 持有打孔点 $y\in[2^k]$, 目标是学到 $\left\{s_z^k: z\neq y\right\}$,
但不知道 $\left\{s_y^k\right\}$.

代码位置:
* `soft_spoken.rs`: SoftSpoken 参数 `LAMBDA_C`, `SOFT_SPOKEN_K`, `SOFT_SPOKEN_Q`, `NUM_TREES` (第 15-24 行).
* `soft_spoken.rs`: PPRF 数据结构 `PPRF`, `PPRFOutput`, `SenderOTSeed`, `ReceiverOTSeed` (第 26-105 行).
* `soft_spoken.rs`: GGM 子节点展开 `prg_expand` (第 113-119 行).

## Base OT 中的角色

Receiver 沿着树走到打孔点的节点下标记为 $y_1, y_2, \dots, y_k$. 这条路径叫做 active path.
其中 $y_{i+1}=2y_i+x_i$, $x_i\in \left\{0,1\right\}$ 表示第 $i$ 层给左边还是右边打孔.
显然 $y_k=y$.

Receiver 在第 $i+1$ 层 "想去" 的节点下标是 $2y_i + \bar{x}_i$, 也就是 active path 节点的兄弟.

第 $i$ 个 base OT 的接口 ($0 \le i < k$):

* Sender 输入/输出: 两个随机串 $K_0^i, K_1^i\in \left\{0,1\right\}^\lambda$.
* Receiver 输入: 选择位 $\bar{x}_i\in \left\{0,1\right\}$.
* Receiver 输出: $K_{\bar{x}_i}^i$ .

直观上, $K^i_b$ 相当于第 $i+1$ 层 "所有 $b$ 侧孩子的合成密钥". Receiver 拿到兄弟方向那一侧的合成密钥, 从中可以解出兄弟节点本身.

代码位置:
* `soft_spoken.rs`: `build_pprf` 使用 `SenderOutput.otp_enc_keys[j * SOFT_SPOKEN_K + i]` 读取 base OT 两侧密钥 (第 149-181 行).
* `soft_spoken.rs`: `eval_pprf` 使用 `ReceiverOutput.choice_bits` 和 `ReceiverOutput.otp_dec_keys` 读取 Receiver 的选择位与已知密钥 (第 213-254 行).
* `endemic_ot.rs`: base OT 输出类型 `SenderOutput`, `ReceiverOutput` (第 86-100 行).

## Sender 进行 BuildPPRF

Sender 拥有所有 $k$ 个 base OT 的两侧串 $\{(K^i_0, K^i_1)\}$, 实例编号 $0\le i < k$.

Sender 初始化第 1 层:
$$
s^1_0 := K^0_0, \quad s^1_1 := K^0_1.
$$

注意这棵树有一个用不上的根节点, 我们视其为第 0 层.

Sender 基于第 $i$ 层构建第 $i+1$ 层.
对第 $i$ 层 ($1\le i < k$) 的第 $z \in [2^i]$ 节点, Sender 计算:
$$
s^{i+1}_{2z} := \mathrm{HaL}(s^i_z), \quad s^{i+1}_{2z+1} := \mathrm{HaR}(s^i_z).
$$

Sender 为除初始化层之外的每一层计算一对修正值 $t^i_0, t^i_1$.
对第 $i$ 层 ($1\le i < k$), Sender 计算:

$$
t^i_b := K^i_b \oplus \bigoplus_{z \in [2^i]} s^{i+1}_{2z + b}.
$$

Sender 输出这棵树, 记为 $G: z \mapsto s^k_z$.
注意: 输出不是传输, 传输也不是输出, 不要看到 "输出" 就产生 "告诉另一方" 的联想.

代码位置:
* `soft_spoken.rs`: `build_pprf` (第 149-202 行).
* `soft_spoken.rs`: PRG 展开 `prg_expand` (第 113-119 行).
* `soft_spoken.rs`: leaf proof 与聚合证明 `leaf_proof`, `aggregate_proof` (第 121-137 行).

## Receiver 进行 EvalPPRF

Receiver 选择 $x = (x_0, x_1, \dots, x_{k-1}) \in \{0,1\}^k$，对应的打孔点下标为

$$
y = \sum_{i=0}^{k-1} x_i \cdot 2^{k-1-i},
$$

活动路径为: $y_1 = x_0$，$y_{i+1} = 2y_i + x_i$.

第 1 层: Receiver 从 base OT 0 拿到 $K_{\bar{x}_0}^0$, 按定义这就是 $s_{\bar{x}_0}^1$. Receiver 拿不到兄弟节点 $s_{x_0}^1$. 注意看仔细, 第一处 $s_{\bar{x}_0}^1$ 有 overbar, 第二处 $s_{x_0}^1$ 没有.

逐层扩展, $i=1\dots,k-1$:

(a) 复制已知子树. 对每个 $z \in [2^i] \setminus \{y_i\}$:

$$
s^{i+1}_{2z} := \mathrm{HaL}(s^i_z), \quad s^{i+1}_{2z+1} := \mathrm{HaR}(s^i_z).
$$

(b) 恢复 active path 的兄弟节点. Sender 端 $t^i_{\bar{x}_i}$ 满足如下等式. 
$$
K^i_{\bar{x}_i} \oplus \bigoplus_{z \in [2^i]} s^{i+1}_{2z + \bar{x}_i} = t^i_{\bar{x}_i}.
$$

理解这个公式的关键直觉是: 异或运算的加法与减法是等价的, 我们可以把异或项挪动到等式的任意一边.

Receiver 已知 $t^i_{\bar{x}_i}$, $K^i_{\bar{x}_i}$, 以及求和中除 $z = y_i$ 项之外的所有项. 移项得:
$$
s^{i+1}_{2 y_i + \bar{x}_i} = t^i_{\bar{x}_i} \oplus K^i_{\bar{x}_i} \oplus \bigoplus_{z \neq y_i} s^{i+1}_{2z + \bar{x}_i}
$$

(c) 更新 active path 指针/游标/迭代器, 即计算 $y_{i+1} := 2 y_i + x_i$. Receiver 仍不知道 $s^{i+1}_{y_{(i+1)}}$. 

最终输出: 打孔位置 $y$, 整条 active path 都被打孔的树 $G^*$.

代码位置:
* `soft_spoken.rs`: `eval_pprf` (第 213-308 行).
* `soft_spoken.rs`: 初始已知节点与 punctured 下标 `y_star` (第 222-228 行).
* `soft_spoken.rs`: 逐层展开、补缺、更新 `y_star` (第 230-274 行).
* `soft_spoken.rs`: `t_tilda` / `s_tilda` 一致性校验 (第 276-302 行).

## 通信成本

- base OT：$k$ 个 $\binom{2}{1}$-OT
- Sender → Receiver 的修正值：$2(k-1)$ 个 $\lambda$ 比特串
- 总扩展通信约 $2(k-1)\lambda$ 比特，得到 $q = 2^k$ 大小的 PPRF

代码位置:
* `soft_spoken.rs`: 每棵树的修正值 `PPRF.t` 长度为 `SOFT_SPOKEN_K - 1` (第 26-45 行).
* `soft_spoken.rs`: `PPRFOutput` 包含 `NUM_TREES` 棵树 (第 49-60 行).
* `dkg_fn.rs`: keygen Round 3 发送 `PPRFOutput` 的路由 `keygen/r3/pprf` (第 277-289 行).
