## 回顾: Base OT 和 PPRF 建树.

SoftSpoken OT 很繁杂. 先重温 Base OT 和 PPRF 的能力边界.

### Base OT 建底

跑 $\kappa = 256$ 个 1-out-of-2 base OT 实例.

对每个实例 $i$,
* Sender 输出两侧密钥, $(K^i_0, K^i_1)$.
其中 $K^i_0\in\mathbb{B}^\lambda$, $K^i_1$ 同理. 他将成为 PPRF Sender.
* Receiver 输出选择位 $\bar x_i$ 和相应的密钥 $K^i_{\bar x_i}$. 他将成为 PPRF Receiver.

### PPRF 建树

PPRF Sender 将密钥分成大小为 $2K=8$ 的组. 用这些密钥生成 $\kappa / K=64$ 棵 GGM 树.

对每棵树 $i$,
* Sender 有 $Q=2^K=16$ 个叶子节点, 记第 $x$ 节点为 $\mathcal{T}_{i,x}$.
* Receiver 有 $Q-1$ 个叶子, 每棵树缺少一个打孔点 $\delta_i$.

Receiver 把所有打孔点的下标当成 $K$-比特串, 依次拼接成为比特串 $\Delta\in\mathbb{B}^\kappa$.

## 正题: SoftSpoken 扩展

阅读建议: 如果第一遍读 Step 2 不懂, 就继续读 Step 3 和 "考察" 部分.
这三部分不能孤立看待, 必须串起来才能读懂.

### Step 1. Receiver 计算和发送 $u$.

Receiver 把每个叶子延长到 $L'=640$ 比特: $r_{i,x} = \mathrm{PRG}(\mathcal{T}_{i,x})$.
把真实选项 $\beta$ 和随机选项 $\beta^\mathrm{ext}$ 拼接为 $\hat\beta$. 然后计算 $u$ 向量.

$$
\begin{align*}
u_i &= \hat\beta \oplus \bigoplus_x r_{i,x}.
\tag{uvec}
\end{align*}
$$

把 $u = (u_0, \ldots, u_{\kappa/K})$ 发给 Sender.

### Step 2. Sender 本地计算 $w$ 矩阵

对第 $i$ 棵树, Sender 知道打孔点的编号 $\delta_i$.
但 Sender 不知道其内容 $\mathcal{T}_{i,\delta_i}$, 自然也就无法知道相应的 $r_{i,\delta_i}$ .

对叶子编号的第 $b$ 比特 (一共 $K$ 比特), Sender 用它的 $Q-1$ 个叶子和收到的 $u_i$, 计算 $w$ 矩阵的第 $(i'=i\cdot K + b)$ 行.

$$
w_{i',*} = \left\{
    \bigoplus_x \mathrm{bit}_b(\delta_i\oplus x)\cdot r_{i,x}
\right\} ~\oplus~ \mathrm{bit}_b(\delta_i)\cdot u_i.
\tag{wmat}
$$

其中函数 $\mathrm{bit}_b()$ 定义为提取输入的第 $b$ 比特, 索引 $x$ 遍历树的所有叶子节点. 

如此, 每棵树给 $w$ 矩阵贡献 $K$ 行, 整个 $w$ 矩阵共有 $\kappa$ 行.

### Step 3. Receiver 本地计算 $v$ 矩阵, 计算并发送 Fiat-Shamir 响应

双方各自从 $u$ 派生 $\chi = (\chi_0, \ldots, \chi_{M-1})$, 共 $M = L/S$ 个 $\mathbb{F}_{2^S}$ 元素. 实践参数下 $M = 512/128 = 4$.
派生方式例如:
$$
\chi := \mathrm{XOF}(\mathtt{sid}, u) \in \left(\mathbb{F}_{2^S}\right)^M.
$$

Receiver 在本地计算 $v$ 矩阵, 第 $(i'=i\cdot K + b)$ 行的计算方式如下:
$$
v_{i',*} = \bigoplus_x \mathrm{bit}_b(x)\cdot r_{i,x}.
\tag{vmat}
$$

把每行 $v_{i',*}$ 横切成 $M+1$ 段, 每段 $S$ 比特:
前 $M$ 段记为 $\hat v_{i',0}, \ldots, \hat v_{i',M-1}$, 每段视为 $\mathbb{F}_{2^S}$ 元素,
末段 $S$ 比特记为 $v^\mathrm{ext}_{i'}$.

下文公式中的 "$\cdot$" 是 $\mathbb{F}_{2^S}$ 上的乘法 (代码里走 `binary_field_multiply_gf_2_128`). 如果有一侧操作数是单比特, 则退化为按位 AND.
"$\oplus$" 是 $\mathbb{F}_{2^S}$ 上的加法, 即按位 XOR.

然后计算 $t$ 矩阵, 第 $i'$ 行如下:
$$
t_{i'} = \left\{
    \bigoplus_{j\in[M]} \chi_j \cdot\hat v_{i',j}
\right\}
\oplus v^\mathrm{ext}_{i'}.
$$

Receiver 还要计算 $\tilde\beta$ 向量, 其中 $\hat\beta_j$ 是真选项 $\beta$ 的第 $j$ 段 ($j\in[M]$, 每段 $S$ 比特):
$$
\tilde\beta = \left\{
    \bigoplus_{j\in[M]} \chi_j\cdot\hat\beta_j
\right\}
\oplus \beta^\mathrm{ext}.
$$

最后把 $\tilde\beta, t$ 发给 Sender.

### 考察公式 "wmat" 和 "vmat" 的意义

借助 $\mathrm{bit}_b(\delta_i\oplus x) = \mathrm{bit}_b(\delta_i)\oplus\mathrm{bit}_b(x)$, 分两种情况.

**Case A:** $\mathrm{bit}_b(\delta_i) = 0$.

第一项 $=\bigoplus_x \mathrm{bit}_b(x)\cdot r_{i,x} = v_{i',*}$, 第二项 $=0$. 故 $w_{i',*} = v_{i',*}$.

**Case B:** $\mathrm{bit}_b(\delta_i) = 1$.

按 vmat 定义, $r_{i,\delta_i}$ 对 $v_{i',*}$ 有贡献; 但 Sender 缺这个叶子, 无法直接算.

考察此时的 wmat:
* 第一项 $=\bigoplus_{\left[\mathrm{bit}_b(x)=0\right]} r_{i,x}$,
也就是 $v_{i',*}$ 的 "补集".
* 第二项 $=u_i=\hat\beta\oplus\bigoplus_x r_{i,x}$,
也就是把全部 $r_{i,*}$ 连同 $\hat\beta$ 一并带入.
* 两项里 $\mathrm{bit}_b(x)=0$ 的部分相消,
留下 $\mathrm{bit}_b(x)=1$ 的部分 (即 $v_{i',*}$) 与 $\hat\beta$.
故有 $w_{i',*} = v_{i',*}\oplus\hat\beta$.

**汇总:**

$$
w_{i',*} = v_{i',*} \oplus \mathrm{bit}_b(\delta_i)\cdot\hat\beta.
\tag{wv-eq}
$$

### Step 4. Sender 进行 Fiat-Shamir 验证

Sender 验证如下等式, 目的是防止 Receiver 采用不一致的 $\hat\beta$.
$$
\left\{
    \bigoplus_{j\in[M]} \chi_j\cdot\hat w_{i',j}
\right\}
\oplus w^\mathrm{ext}_{i'} \stackrel{?}{=} t_{i'}\oplus\Delta_{i'}\cdot\tilde\beta.
$$

这里 $\Delta_{i'}$ 是 bitvec $\Delta$ 的第 $i'$ 比特.

### Step 5. 派生最终的 OT 密钥

#### 转置前的形状

Sender 持有的 $w$, 以及 Receiver 持有的 $v$, 都是 $\kappa\times L'$ 布尔矩阵.

* 行下标 $i'\in[\kappa]$ 对应一个 "扩展 base OT 槽位".
其中 $i'=i\cdot K + b$, $i$ 是 PPRF 树编号, $b$ 是该树叶子下标的第 $b$ 比特位.
* 列下标 $j'\in[L']$ 对应一个 "输出 OT 通道".
前 $L$ 列是真实 OT 通道 ($\hat v$ 那一段, 详见 vmat 附近).
后 $S$ 列是 Step 4 一致性检查的槽位, 检查后丢弃.

按 wv-eq 拉到单元格层面:
$$
w_{i', j'} = v_{i', j'} \oplus \Delta_{i'}\cdot\hat\beta_{j'}.
$$

#### 转置, 取前 L 行

把 $w, v$ 转置. 取前 $L=512$ 行 (即丢掉一致性检查的槽位), 第 $j$ 行是长 $\kappa$ 的比特串:

* 记 $\zeta_j := w^\intercal_{j,*}$, 为 Sender 所持有;
* 记 $\psi_j := v^\intercal_{j,*}$, 为 Receiver 所持有.

把前文的单元格等式拉到行向量层面, 不难发现二者满足 IKNP 形式的 $\Delta$-correlation:

$$
\zeta_j = \psi_j \oplus \beta_j\cdot\Delta, \quad j\in[L].
\tag{leaf-eq}
$$

#### 计算密钥

对 $w^\intercal$, $v^\intercal$ 的每一行 $j$,

* Sender 计算两侧密钥
$$
\mathcal{K}^0_j := \mathrm{Hash}(\zeta_j), \quad
\mathcal{K}^1_j := \mathrm{Hash}(\zeta_j \oplus \Delta) ~;
$$

* Receiver 计算他所选的密钥
$$
\mathcal{K}_j := \mathrm{Hash}(\psi_j) ~.
$$

由 leaf-eq, 当 $\beta_j=0$ 时 $\psi_j=\zeta_j$; 当 $\beta_j=1$ 时 $\psi_j=\zeta_j\oplus\Delta$. 两侧用同一个 Hash, Receiver 的 $\mathcal{K}_j$ 恰等于 Sender 的 $\mathcal{K}^{\beta_j}_j$.

至此完成 SoftSpokenOT 的密钥交换.
