# SoftSpoken OT 扩展协议

本文讨论的是 SoftSpokenOT 协议本身, 即把 PPRF 给出的若干棵 GGM 小树, 组合成 $L$ 个独立随机 1-out-of-2 OT 实例的过程. 论文出处 https://eprint.iacr.org/2022/192 .

读完本文之前可以先看 [pprf.md](./pprf.md) 复习上游, [extot-kos15.md](./extot-kos15.md) 复习一致性检查的来源, 以及 [extot-dkls23-derand.md](./extot-dkls23-derand.md) 复习下游消费方式.

## 它在协议栈里的位置

* 上游: PPRF 给 Sender 全部 $Q$ 个叶子, 给 Receiver $Q-1$ 个叶子, Receiver 缺一个叶子 (per tree, 一共 $\kappa/K$ 棵树). 其中 $K = 4$, $Q = 2^K = 16$, $\kappa = 256$, 故树的棵数为 $64$.
* 本文: 把这 $64$ 棵小树的叶子组合成 $L = \kappa + 2\lambda_s = 512$ 个 1-out-of-2 随机 OT 实例, 每个实例携带 $\mathrm{OT\_WIDTH} = \ell + \rho$ 个 $\kappa$ 比特消息.
* 下游: 这 $L$ 个随机 OT 直接对接 [extot-dkls23-derand.md](./extot-dkls23-derand.md) 里 Step 1 的 $(\alpha^0_j, \alpha^1_j, \gamma_j)$ 接口.

## 角色翻转

关键澄清: SoftSpoken OT 扩展的 Sender / Receiver 与底层 PPRF 的 Sender / Receiver 角色相反.

* SoftSpoken OT Receiver = PPRF Sender. 持有所有叶子.
* SoftSpoken OT Sender = PPRF Receiver. 每棵树缺一个叶子.

原因: KOS 风格里 OT 扩展 Receiver 持有选择向量 $\beta$, 它需要"对 base 完全可见"才能构造 $u$ 矩阵. 这恰好是 PPRF Sender 的视角.
反过来, OT 扩展 Sender 是被验方, 它持有秘密 $\delta$ (= PPRF Receiver 的 punctured 下标, 重组后即 KOS 中那个长 $\kappa$ 比特的种子 $s$).

代码里的命名也反映了这层翻转: `SoftSpokenOTReceiver::process` 接收 `&SenderOTSeed` (全叶子), `SoftSpokenOTSender::process` 接收 `&ReceiverOTSeed` (Q-1 叶子).

## 与 KOS15 的对应关系

SoftSpoken OT 扩展可以看作 KOS 的"小域版本":

| 项目 | KOS15 | SoftSpokenOT |
|---|---|---|
| base OT 个数 | $\kappa$ | $\kappa/K$ |
| base OT 类型 | 1-out-of-2 | 1-out-of-$Q$ (all-but-one) |
| 选择字母表 | $\{0,1\}$ | $[Q]$, 即 $K$ 比特 |
| Sender 秘密 | $s\in \{0,1\}^\kappa$ | $\delta\in [Q]^{\kappa/K}$ |
| 对应"$s$"形式 | 直接 | $\delta$ 按 $K$ 比特展开为 $\mathrm{packed\_nabla}\in \{0,1\}^\kappa$ |
| OT 扩展条数 | $m$ | $L'$ |
| 一致性检查 | 单条挑战 $\boldsymbol{\chi}\in\mathbb{F}_{2^\kappa}^m$ | $M$ 条挑战 $\boldsymbol{\chi}\in\mathbb{F}_{2^S}^M$ |

工程上选 $K = 4$ 是一个 sweet spot. $K$ 越大, base OT 越少, 但每棵树的叶子数 $Q = 2^K$ 指数膨胀. $K = 4$ 平衡了 base OT 通信开销和 PPRF 展开开销.

## 几个关键长度

* $L = \kappa + 2\lambda_s = 512$. 这是真正交付下游的随机 OT 条数. 多出的 $2\lambda_s$ 比特是 gadget 向量需要的, 见 [extot-dkls23-gadget.md](./extot-dkls23-gadget.md).
* $S = 128$. Fiat-Shamir 一致性检查所在的小域 $\mathbb{F}_{2^S}$ 的比特宽度.
* $L' = L + S = 640$. 协议内部使用的扩展长度. 后 $S$ 比特填新鲜随机, 不携带 Receiver 的真实选择.
* $M = L / S = 4$. 一致性检查里挑战标量的个数.

注意 $L'$ 不等于 $(M+1) \cdot S$, 也就是说协议里把 $L'$ 切成 $M+1 = 5$ 段, 前 $M$ 段对应 $L = M \cdot S$, 第 $M+1$ 段是新鲜随机的"额外"段. Fiat-Shamir 检查时, 前 $M$ 段经 $\boldsymbol{\chi}$ 加权聚合, 第 $M+1$ 段直接 XOR 进结果.

直观: 一致性检查会"吞掉" $S$ 比特熵 (敌手蒙混过关概率 $2^{-S}$), 所以需要在 $L$ 之外多准备一段 $S$ 比特熵作为"消化项". 否则真正的 OT 输出就会被一致性检查泄露.

## 协议步骤

### 1. Receiver 端: PRG 展开和 $u$ 矩阵

Receiver 持有 `otp_enc_keys[i][x]` for $i \in [\kappa/K], x \in [Q]$. 这是 $64 \times 16 = 1024$ 个 $\kappa$ 比特种子.

对每对 $(i, x)$, 用 PRG 把种子展开成长度 $L'$ 的串:

$$
r_{x,i} = \mathrm{PRG}(\mathrm{otp\_enc\_keys}[i][x]) \in \{0,1\}^{L'}.
$$

Receiver 把真选择向量 $\beta \in \{0,1\}^L$ 与一段新鲜随机 $\beta^\mathrm{ext} \in \{0,1\}^S$ 拼成长度 $L'$ 的扩展选择向量:

$$
\hat{\beta} = \beta \,\|\, \beta^\mathrm{ext} \in \{0,1\}^{L'}.
$$

对每棵树 $i$, 计算

$$
u_i = \hat{\beta} \;\oplus\; \bigoplus_{x \in [Q]} r_{x,i} \;\in\; \{0,1\}^{L'}.
$$

发给 Sender. 通信量: $\kappa/K \times L'/8 = 64 \times 80 = 5120$ 字节.

※ 这步与 KOS 公式 "umat" 形似但有结构差异: KOS 里 $u_i = t^0_i \oplus t^1_i \oplus b$ 只用两侧叶子, 而这里需要把 $Q$ 侧叶子全部 XOR 起来.

### 2. Sender 端: 重建 $w$ 矩阵

Sender 对每棵树 $i$, 知道除 $\delta_i$ 之外的所有 $r_{x,i}$. 把 $\delta_i \in [Q]$ 按 $K$ 比特拆开为 $(\delta_{i,0}, \ldots, \delta_{i,K-1}) \in \{0,1\}^K$.

Sender 构造矩阵 $w$, 行下标 $i' = i \cdot K + b$ ($i \in [\kappa/K], b \in [K]$), 列下标 $L'$ 比特:

$$
w_{i',*} = \bigoplus_{x \in [Q]} \mathrm{bit}_b(\delta_i \oplus x) \cdot r_{x,i} \;\oplus\; \mathrm{bit}_b(\delta_i) \cdot u_i.
$$

其中 $\mathrm{bit}_b(\cdot)$ 取整数的第 $b$ 个比特, "$\cdot$" 是 0/1 系数与 $L'$ 比特向量的按位与.

写成"等效 IKNP 关系"形式. 定义 Receiver 端可计算的对应矩阵:

$$
v_{i',*} = \bigoplus_{x \in [Q]} \mathrm{bit}_b(x) \cdot r_{x,i}.
$$

代入 $u_i = \hat{\beta} \oplus \bigoplus_x r_{x,i}$, 利用 $\delta_i \oplus x$ 跑遍 $[Q]$ 等价于 $x$ 跑遍 $[Q]$, 化简可得 (验算略):

$$
w_{i',*} = v_{i',*} \;\oplus\; \mathrm{packed\_nabla}_{i'} \cdot \hat{\beta}, \tag{w-eq}
$$

其中 $\mathrm{packed\_nabla}_{i'} = \mathrm{bit}_b(\delta_i)$ 是 $\delta$ 按 $K$ 比特展开后的 $\kappa$ 比特串的第 $i'$ 位.

公式 "w-eq" 就是 KOS 的 "qmat" 关系 $q_{i,*} = t^0_{i,*} \oplus s_i \cdot b$ 在 SoftSpoken 视角下的对应物. 后续 Fiat-Shamir 检查正是基于这层对应.

※ 注意这里 Sender 角色对应 KOS 里的 Alice, $\hat{\beta}$ 对应 KOS 里的 $b$, $\mathrm{packed\_nabla}$ 对应 KOS 里的 $s$. 角色翻转的细节在前面"角色翻转"一节已经澄清.

### 3. Fiat-Shamir 一致性检查

#### 派生挑战

双方对全部 $u_i$ 做哈希派生挑战标量 (Fiat-Shamir 变换, 见 [fiat-shamir.md](./fiat-shamir.md)):

$$
\boldsymbol{\chi} = (\chi_1, \ldots, \chi_M) \in \mathbb{F}_{2^S}^M, \quad \chi_j = \mathrm{Hash}(\mathrm{sid} \,\|\, j \,\|\, \mathrm{Hash}(u)).
$$

其中 $M = L / S = 4$.

#### 切段

把 $L'$ 比特向量看成 $M + 1$ 段 $S$ 比特子向量. 记 Receiver 切分:

$$
\hat{\beta} = \hat{\beta}_1 \,\|\, \cdots \,\|\, \hat{\beta}_M \,\|\, \beta^\mathrm{ext}, \quad
v_{i',*} = \hat{v}_{i',1} \,\|\, \cdots \,\|\, \hat{v}_{i',M} \,\|\, v^\mathrm{ext}_{i'}.
$$

Sender 同样切分 $w$:

$$
w_{i',*} = \hat{w}_{i',1} \,\|\, \cdots \,\|\, \hat{w}_{i',M} \,\|\, w^\mathrm{ext}_{i'}.
$$

#### Receiver 发送 $(x, t)$

$$
x = \bigoplus_{j=1}^M \chi_j \cdot \hat{\beta}_j \;\oplus\; \beta^\mathrm{ext} \;\in\; \{0,1\}^S.
$$

$$
t_{i'} = \bigoplus_{j=1}^M \chi_j \cdot \hat{v}_{i',j} \;\oplus\; v^\mathrm{ext}_{i'} \;\in\; \{0,1\}^S, \quad i' \in [\kappa].
$$

注意 "$\chi_j \cdot \hat{\beta}_j$" 等是 $\mathbb{F}_{2^S}$ 上的乘法, 即 GF$(2^{128})$ 上的多项式乘法. 见 [f2k.md](./f2k.md).

通信量: $x$ 占 $S/8 = 16$ 字节; $t$ 占 $\kappa \times S/8 = 4096$ 字节.

#### Sender 验证

对每行 $i' \in [\kappa]$ 验证:

$$
\bigoplus_{j=1}^M \chi_j \cdot \hat{w}_{i',j} \;\oplus\; w^\mathrm{ext}_{i'} \;\stackrel{?}{=}\; t_{i'} \;\oplus\; \mathrm{packed\_nabla}_{i'} \cdot x. \tag{verify}
$$

正确性: 把公式 "w-eq" 切段代入 LHS 的每段, 与 RHS 对应段刚好对上 (推导见后).

任何一行不等, Sender 中止协议并把 Receiver 拉黑.

※ 推导细节. 把 LHS 按段展开:

$$
\begin{align}
\text{LHS}
&= \bigoplus_{j=1}^M \chi_j \cdot (\hat{v}_{i',j} \oplus \mathrm{packed\_nabla}_{i'} \cdot \hat{\beta}_j) \;\oplus\; (v^\mathrm{ext}_{i'} \oplus \mathrm{packed\_nabla}_{i'} \cdot \beta^\mathrm{ext}) \\
&= \underbrace{\bigoplus_{j=1}^M \chi_j \cdot \hat{v}_{i',j} \oplus v^\mathrm{ext}_{i'}}_{=\;t_{i'}} \;\oplus\; \mathrm{packed\_nabla}_{i'} \cdot \underbrace{\left( \bigoplus_{j=1}^M \chi_j \cdot \hat{\beta}_j \oplus \beta^\mathrm{ext} \right)}_{=\;x} \\
&= t_{i'} \;\oplus\; \mathrm{packed\_nabla}_{i'} \cdot x.
\end{align}
$$

第一步用了公式 "w-eq" 以及 $\mathrm{packed\_nabla}_{i'}$ 与 $\chi_j$ 的乘法可交换性 (前者是标量比特, 等价于 0 或 1; 后者在 $\mathbb{F}_{2^S}$ 上).

#### 抓作弊原理

恶意 Receiver 若在不同棵树之间, 或在 $L'$ 的不同位置之间使用不一致的 $\hat{\beta}$, 等价于公式 "w-eq" 不再成立. 此时公式 "verify" 的概率 $\le 2^{-S}$. 直觉与 [extot-kos15.md](./extot-kos15.md) 末尾相同.

### 4. 转置 + 行哈希得 $L$ 个随机 OT

#### 转置

Sender 把 $w$ 从 $\kappa \times L'$ 转置成 $L' \times \kappa$, 取前 $L$ 行 (后 $S$ 行已经被 Step 3 消化掉了, 直接丢弃). 记转置后行为 $\zeta_j \in \{0,1\}^\kappa$, $j \in [L]$.

Receiver 同样把 $v$ 转置, 取前 $L$ 行, 记为 $\psi_j$.

由公式 "w-eq" 转置后得:

$$
\zeta_j = \psi_j \;\oplus\; \beta_j \cdot \mathrm{packed\_nabla}, \quad j \in [L]. \tag{leaf-eq}
$$

注意这里 $\beta_j$ 是 Receiver 真实选择向量 $\beta$ 的第 $j$ 位.

#### 派生 $\mathrm{OT\_WIDTH}$ 个 $\kappa$ 比特消息

对每个 $j \in [L]$ 和每个 $k \in [\mathrm{OT\_WIDTH}]$:

* Sender 计算两侧消息:

$$
\begin{align}
v_0[j][k] &= \mathrm{Hash}(\mathrm{sid} \,\|\, j \,\|\, \zeta_j)[k], \\
v_1[j][k] &= \mathrm{Hash}(\mathrm{sid} \,\|\, j \,\|\, \zeta_j \oplus \mathrm{packed\_nabla})[k].
\end{align}
$$

* Receiver 计算自己拿到的那侧:

$$
v_x[j][k] = \mathrm{Hash}(\mathrm{sid} \,\|\, j \,\|\, \psi_j)[k].
$$

由公式 "leaf-eq", 当 $\beta_j = 0$ 时 $\psi_j = \zeta_j$, 故 $v_x[j] = v_0[j]$; 当 $\beta_j = 1$ 时 $\psi_j = \zeta_j \oplus \mathrm{packed\_nabla}$, 故 $v_x[j] = v_1[j]$. 这正是 1-out-of-2 OT 关系.

## 输出与下游接口

* 一次 SoftSpoken OT 扩展产出 $L = 512$ 个 1-out-of-2 随机 OT 实例.
* 每个实例携带 $\mathrm{OT\_WIDTH} = \ell + \rho$ 个 $\kappa$ 比特消息. 工程参数:
    * $\ell = L_\text{batch} = 2$ 个槽位是 RVOLE 的功能维度, 一次性做两路并行 MtA.
    * $\rho = 1$ 个槽位是 Alice 一致性检查的检查维度.
* 把 $\kappa$ 比特字符串 $v_0[j][k]$ 解释为 $\mathbb{Z}_n$ 上的标量, 即 $\alpha^{0,(k)}_j := v_0[j][k] \bmod n$. 同理 $\alpha^{1,(k)}_j := v_1[j][k] \bmod n$, $\gamma^{(k)}_j := v_x[j][k] \bmod n$.
* 这些 $(\alpha^{0,(k)}_j, \alpha^{1,(k)}_j, \gamma^{(k)}_j)$ 三元组直接对接 [extot-dkls23-derand.md](./extot-dkls23-derand.md) Step 1 的接口. 其中 $k = 0$ 视为功能维度的入口.

## 通信成本和参数总览

单次扩展 (Receiver → Sender 一轮) 总通信:

| 项 | 形状 | 字节数 |
|---|---|---|
| $u$ | $\kappa/K \times L'/8$ | $64 \times 80 = 5120$ |
| $x$ | $S/8$ | $16$ |
| $t$ | $\kappa \times S/8$ | $256 \times 16 = 4096$ |
| 合计 | | $\approx 9.2$ KB |

代码位置:

* `soft_spoken_ot.rs`: `SoftSpokenOTReceiver::process` (Step 1 + Step 3 Receiver 侧 + Step 4 Receiver 侧).
* `soft_spoken_ot.rs`: `SoftSpokenOTSender::process` (Step 2 + Step 3 Sender 侧 + Step 4 Sender 侧).
* `soft_spoken_ot.rs`: `Round1Output { u, x, t }` 即上表三项.
* `soft_spoken_ot.rs`: `transpose_bool_matrix` 实现 Step 4 的 $\kappa \times L' \to L' \times \kappa$ 转置.
* `mul_poly.rs`: `binary_field_multiply_gf_2_128` 即 $\mathbb{F}_{2^{128}}$ 上的乘法, 用在 Step 3 的 $\chi_j \cdot \hat{*}_j$.
* `params.rs`: $\mathrm{LAMBDA\_C} = 256$, $\mathrm{SOFT\_SPOKEN\_K} = 4$, $\mathrm{SOFT\_SPOKEN\_Q} = 16$, $L = 512$, $L' = 640$, $S = 128$, $M = 4$, $\mathrm{OT\_WIDTH} = 3$.
