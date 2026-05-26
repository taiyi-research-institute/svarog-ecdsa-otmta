# 回顾: Base OT 和 PPRF 建树.

SoftSpoken OT 很繁杂. 先重温 Base OT 和 PPRF 的能力边界.

## Base OT 建底

跑 $\kappa = 256$ 个 1-2 base OT 实例.

对每个实例 $i$,
* Sender 输出两侧密钥, $(\rho^i_0, \rho^i_1)$.
其中 $\rho^i_0\in\mathbb{B}^\lambda$, $\rho^i_1$ 同理.
* Receiver 输出选择位 $\beta_i$ 和相应的密钥 $\rho^i_{\beta_i}$.

## PPRF 建树

PPRF 建树的目的是把 1-2 OT 升级为 1-Q OT.

1-2 Base OT Sender 成为 PPRF Sender. PPRF Sender 将 1-2 Base OT 密钥分成大小为 $2K=8$ 的组, 用这些密钥生成 $\kappa / K=64$ 棵 GGM 树. 每棵树有 $Q=2^K=16$ 个叶子节点, 这 $Q$ 个叶子节点就是 PPRF Sender 密钥. 记第 $x$ 节点为 $\mathcal{T}_{i,x}$.

1-2 Base OT Receiver 成为 PPRF Receiver. PPRF Receiver 也得到 $\kappa / K=64$ 棵 GGM 树, 但每棵树有 $Q-1$ 个叶子. 记所缺叶子编号为 $\delta_i$.

Receiver 把所有打孔叶子的编号当成 $K$-比特串, 依次拼接成为比特串 $\Delta\in\mathbb{B}^\kappa$.

# 正题: SoftSpoken 扩展

SoftSpoken 原始论文是三轮: Receiver 承诺, Sender 挑战, Receiver 响应. 这是很典型的 Sigma-协议, 自然而然就可以用 Fiat-Shamir 变换改造成一轮 Receiver 到 Sender.

## Receiver 到 Sender

⚠️ SoftSpoken Receiver 是 PPRF Sender. 本节 Receiver 如果不特别注明, 就是 SoftSpoken Receiver.

### (1) 计算 $u$ 矩阵.

对第 $i$ 棵树的第 $x$ 片叶子进行哈希, 得到 $r_{i,x} = \mathrm{PRG}(\mathcal{T}_{i,x})$, 这是长度为 $L'=640$ 的比特串.

把真实选项 $\beta$ 和随机选项 $\beta^\mathrm{ext}$ 拼接为 $\hat\beta$.

计算 $u$ 矩阵, 第 $i$ 行:
$$
u_i = \hat\beta \oplus \bigoplus_x r_{i,x}. \tag{umat}
$$

### (2) 计算 Fiat-Shamir 挑战 $\chi$.
$$
\chi := \mathrm{XOF}(\mathtt{sid}, u) \in \left(\mathbb{GF}(2^{128})\right)^M. \tag{chi}
$$
实践采用 $M = L/S = 512/128 = 4$. 这是为了使用 $\mathbb{GF}(2^{128})$ 即 AES 的硬件指令.

### (3) 计算密钥前体 $v$ 矩阵.

矩阵的行索引 $i'\in[\kappa]$ 对应一个 "Base OT 槽位". 其中 $i'=i\cdot K + b$, $i$ 是 PPRF 树编号, $b$ 是该树叶子编号的第 $b$ 比特位. 💡 注意我的用词, 这里的 "Base OT" 并不是椭圆曲线 OT, 而是套了一层 PPRF 之后的.

矩阵的列索引 $j'\in[L']$ 对应一个 "Extended OT 实例". 前 $L$ 列是真实 OT 实例. 后 $S$ 列用于 Fiat-Shamir 一致性检查, 检查后丢弃.

按行计算 $v$ 矩阵, 这里行号 $i' = i\cdot K + b$:
$$
v_{i',*} = \bigoplus_x \mathrm{bit}_b(x)\cdot r_{i,x}. \tag{vmat}
$$

### (4) 计算 Fiat-Shamir 响应 $\tau$ 和 $\tilde\beta$.

把每行 $v_{i',*}$ 切成 $M+1$ 段, 每段 $S$ 比特. 前 $M$ 段记为 $\hat v_{i',1}, \ldots, \hat v_{i',M}$. 最后一段记为 $v^\mathrm{ext}_{i'}$. 我们把这些比特串视为有限域 $\mathbb{GF}(2^{128})$ 上的元素, 其加法为按位异或, 乘法为卷积, 详见 `misc-f2k.md`.

然后算 $\tau$ 矩阵, 第 $i'$ 行:
$$
\tau_{i'} = \left\{
    \bigoplus_{j\in[M]} \chi_j \cdot\hat v_{i',j}
\right\}
\oplus v^\mathrm{ext}_{i'}. \tag{tau-mat}
$$

类似地, 我们把 OT 选项也切成 $M+1$ 段, 每段 $S$ 比特, 记为 $\hat\beta_1$, $\dots$, $\hat\beta_M$, $\hat\beta^\mathrm{ext}$.

然后算 $\tilde\beta$ 向量:
$$
\tilde\beta = \left\{
    \bigoplus_{j\in[M]} \chi_j\cdot\hat\beta_j
\right\}
\oplus \beta^\mathrm{ext}. \tag{beta-tilde}
$$

### (✉️) 通信

把 $u$, $\tau$, $\tilde\beta$ 发给 Sender.

### (5) 计算 Receiver 密钥 $\rho_j$.

对矩阵 $v$ 进行转置, 取前 $L=512$ 行, 也就是丢掉一致性检查位. 第 $j$ 行的哈希就是第 $j$ OT 实例的 Receiver 密钥. 形式化表达:
$$
\rho_j = \mathrm{Hash}\left(\left(v^{\intercal}\right)_{j,*}\right).
\tag{receiver-key}
$$

Hash 这一下不能省. 这是为了 Sender 密钥的安全性. 详见本文 Sender 密钥部分.

## Sender 本地

⚠️ SoftSpoken Sender 是 PPRF Receiver. 本节 Sender 如果不特别注明, 就是 SoftSpoken Sender.

### (1) 计算 $w$ 矩阵.

对第 $i$ 棵树, Sender 知道打孔叶子编号 $\delta_i$. 但 Sender 不知道它的内容 $\mathcal{T}_{i,\delta_i}$, 自然也就无法知道相应的 $r_{i,\delta_i}$ .

叶子编号是 $K$-比特串. 取这串里的某个比特位 $b\in[K]$, Sender 用它的 $Q-1$ 个叶子和收到的 $u_i$, 计算 $w$ 矩阵的第 $(i'=i\cdot K + b)$ 行.

$$
w_{i',*} = \left\{
    \bigoplus_x \mathrm{bit}_b(\delta_i\oplus x)\cdot r_{i,x}
\right\} ~\oplus~ \mathrm{bit}_b(\delta_i)\cdot u_i.
\tag{wmat}
$$

其中函数 $\mathrm{bit}_b()$ 定义为提取输入的第 $b$ 比特, 索引 $x$ 遍历树的所有叶子节点. 

如此, 每棵树给 $w$ 矩阵贡献 $K$ 行, 整个 $w$ 矩阵共有 $\kappa$ 行.

### (引理) Sender $w$ 和 Receiver $v$ 的关系

$$
w_{i',*} = v_{i',*} \oplus \mathrm{bit}_b(\delta_i)\cdot\hat\beta.
\tag{wv-eq}
$$
这里 $i$ 是树索引, 第 $i$ 棵树的打孔叶子编号为 $\delta_i$, 编号的第 $b$ 比特为 $\mathrm{bit}_b (\delta_i)$, 矩阵的行索引为 $i'=i\cdot K+b$.


证明: 讨论 $\mathrm{bit}_b (\delta_i)$ 的两种情况.

当 $\mathrm{bit}_b(\delta_i) = 0$ 时, wmat 的第一项 (花括号部分) 为 $v_{i',x}$, 第二项为 0. 等式 wv-eq 成立.

当 $\mathrm{bit}_b(\delta_i) = 1$ 时. 考察此时的 wmat:
* 第一项 $=\bigoplus_{\left[\mathrm{bit}_b(x)=0\right]} r_{i,x}$.
* 第二项 $=u_i=\hat\beta\oplus\bigoplus_x r_{i,x}$, 也就是把全部 $r_{i,*}$ 连同 $\hat\beta$ 一并带入.
* 两项里 $\mathrm{bit}_b(x)=0$ 的部分被异或运算抵消掉, 留下 $\mathrm{bit}_b(x)=1$ 的部分 (即 $v_{i',*}$) 与 $\hat\beta$. $\blacksquare$

### (2) Fiat-Shamir 验证.

Sender 也采用公式 chi 得到挑战 $\chi$. 然后验证如下等式, 目的是防止 Receiver 采用不一致的 OT 选项 $\hat\beta$.
$$
\left\{
    \bigoplus_{j\in[M]} \chi_j\cdot\hat w_{i',j}
\right\}
\oplus w^\mathrm{ext}_{i'}
\stackrel{?}{=}
\tau_{i'}\oplus\Delta_{i'}\cdot\tilde\beta.
\tag{verify}
$$

这里 $\Delta_{i'}$ 是 bitvec $\Delta$ 的第 $i'$ 比特. 验证不过即 abort.

### (3) 计算 Sender 本地密钥 $\rho^b_{j}$.

对矩阵 $w$ 进行转置, 取前 $L=512$ 行, 也就是丢掉一致性检查位. 然后,
$$
\begin{align*}
\rho^0_j &= \mathrm{Hash}\left(
    \left(w^{\intercal}\right)_{j,*} 
\right),\\
\rho^1_j &= \mathrm{Hash}\left(
    \left(w^{\intercal}\right)_{j,*} \oplus \Delta
\right).\\
\end{align*}
\tag{sender-key}
$$

## 讨论

我们似乎把 1-2 OT 转成 1-$2^K$ OT, 又转回实例数更多的 1-2 OT. 中间那一层转换, 也就是 PPRF, 有何收益?

收益主要是签名时节约带宽. umat 大小: $\kappa/K \cdot L'$ = 5120 Byte. 如果退化到 KOS, 则 umat 大小: $\kappa\cdot L'$ = 20480 Byte. $N$ 人签名时, 互发 $(N-1)N$ 个 umat, PPRF 带来的收益会被放大.
