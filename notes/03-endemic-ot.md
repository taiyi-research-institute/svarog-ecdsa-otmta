# Endemic OT 数学原理

参考: Masny-Rindal, "Endemic Oblivious Transfer", Fig. 8, https://eprint.iacr.org/2019/706.pdf.

## 1. 理想功能

Endemic OT 一次并行执行 $\kappa$ 个 1/2 OT 实例.
其中 $\kappa$ 为曲线标量比特数, 对 secp256k1 而言取 $\kappa = 256$.
对每个实例 $i \in [0, \kappa)$:
* Sender 输出一对密钥 $\rho_0, \rho_1$, 但无法确定 $w$.
* Receiver 持有选择比特 $w=0,1$, 输出密钥 $\rho$.
* Receiver 无法获得 $\rho_{1 - w}$.

"Endemic" 的含义:
Sender 输出的两个密钥都是协议执行过程中"自然产生"的随机值, 而不是 Sender 自选的任意明文.
这对于后续只需要 OT 种子的协议, 例如 OT extension, PPRF, 已经足够.

## 2. 符号

* 既然不同实例之间没有关联, 那么索引 $i$ 就省略.
* $\mathbb{G}$: 椭圆曲线群, 阶 $q$, 生成元 $G$.
* $\mathrm{H}: \mathbb{B}^* \to \mathbb{B}^*$: 根据上下文, 既可以表示哈希本身, 也可以表示哈希到 $\mathbb{Z}_q$ 标量.
* $\mathrm{HG}: \mathbb{B}^* \to \mathbb{G}$: 所谓的 Hash-to-curve.

## 3. 协议

-----

### Round 1: Receiver 到 Sender.

Receiver 对每个 $i$:

(1) 采样选择位 $w=0,1$, 采样盲化项 $t_b \overset{\char36}{\leftarrow} \mathbb{Z}_q$.

(2) 采样随机群元素 $R_{1-w}=\mathrm{HG}(...)$. 重点在于, 点是随机的, 但点的离散对数是未知的.

(3) 计算 $R_w$.

$$
R_w=t_b \cdot G - \mathrm{H}(\text{tag}_h, w, i, \text{sid}, R_{1-w}) \cdot G.
$$

(4) 发送 $R_0, R_1$. 保存 $(w, t_b)$.

小结一下. 上述构造的关键恒等式:

$$
R_w + \mathrm{H}(\text{tag}_h, w, i, \text{sid}, R_{1-w}) \cdot G = t_b \cdot G. \tag{tbG}
$$

-----

### Round 2: Sender 到 Receiver.

Sender 对每个 $i$:

(1) 收到 $R_0, R_1$. 不知道哪个是 $R_w$, 也就是不知道 $w$ 是几.

(2) "平等" 地对待 $R_0, R_1$, 计算如下消息.

$$
M_{b,0} = R_0 + \mathrm{H}(\text{tag}_h, 0, i, \text{sid}, R_1) \cdot G,\\
M_{b,1} = R_1 + \mathrm{H}(\text{tag}_h, 1, i, \text{sid}, R_0) \cdot G.
$$

(3) 采样 $t_{a,0}, t_{a,1} \overset{\char36}{\leftarrow}  \mathbb{Z}_q$, 计算

$$
M_{a,0} = t_{a,0} \cdot G, \\
M_{a,1} = t_{a,1} \cdot G.
$$

(4) 生成 Sender 密钥

$$
\rho_0 = \mathrm{H}(\text{tag}_\rho, i, t_{a,0} \cdot M_{b,0}), \\
\rho_1 = \mathrm{H}(\text{tag}_\rho, i, t_{a,1} \cdot M_{b,1}).
$$

(5) 发送 $M_{a,0}, M_{a,1}$. 保存 $\rho_0, \rho_1$.

-----

### Receiver 结束

Receiver 对每个 $i$ 计算

$$
\rho_w = \mathrm{H}(\text{tag}_\rho, i, t_b \cdot M_{a, w}).
$$

## 4. 正确性

对 Receiver 的选择位 $w$, 根据恒等式 "tbG", 有 $M_{b, w} = t_b \cdot G$. 于是

$$
\begin{align*}
&\phantom{{}={}}t_{a, w} \cdot M_{b, w} \\
&= t_{a, w} \cdot t_b \cdot G \\
&= t_b \cdot (t_{a, w} \cdot G) \\
&= t_b \cdot M_{a, w}. \\
\end{align*}
$$

两侧哈希函数的输入完全一致, 因此
$$\rho_w ~{\text{(Seen by Sender)}} = \rho_w ~{\text{(Seen by Receiver)}}.$$

## 5. 安全性分析

谈到二选一 OT 协议的安全性, 我们主要关心 Sender 的互补密钥 $\rho_{1-w}$ 是否泄露.
考虑到计算 $\rho_{1-w}$ 的一个关键步骤是计算 $t_{a, 1-w} \cdot M_{b, 1-w}$, 而 $M_{b, 1-w}$ 是可以从 transcript 计算的; 因此 $\rho_{1-w}$ 的安全性取决于 $t_{a, 1-w}$.

> 我差点写 "$\rho_{1-w}$ 泄露等价于 $t_{a, 1-w}$ 泄露". 
> 但这并不严谨. 后者并没泄露, 而是被绕过了.
> 所以我把措辞改成 "安全性取决于".

观察协议的 transcript (通俗理解为 "聊天记录"), 我们知道 $t_{a, 1-w}$ 直接泄露的唯一途径就是求解 $M_{a,1-w}$ 的离散对数. 排除这个路子, 剩下的路子必然在因子 $M_{b, 1-w}$ 里. 这个因子里有两个加项:

* $\mathrm{H}(...)\cdot G$. 双方都能计算.
* $R_{1-w}$, 安全性怎么保证?

第一个加项是必然泄露的, 那么安全性就全都寄托在 $R_{1-w}$ 身上. 因此, 协议要求 Receiver 不可以知道 $R_{1-w}$ 的离散对数.

否则, 如果她知道一个 $s$ 使得 $R_{1-w}=sG$. 那么有

$$
\begin{align*}
\textrm{part of }\rho_{1-w}&=t_{a, 1-w} \cdot M_{b, 1-w} \\
&= t_{a, 1-w} \cdot \left( s + \mathrm{H}(\dots) \right)\cdot G \\
&= t_{a, 1-w} \cdot G \cdot \left( s + \mathrm{H}(\dots) \right) \\
&= M_{a,1-w}  \cdot \left( s + \mathrm{H}(\dots) \right).
\end{align*}
$$

至此, $M_{a,1-w}$ 是 Sender 发来的, $s$ 是 Receiver 知道的, $\mathrm{H}(\dots)$ 是双方都能算的.
Receiver 利用前述信息绕过了只有 Sender 才知道的 $t_{a, 1-w}$, 直接解出 $t_{a, 1-w} \cdot M_{b, 1-w}$.

写到这里, 我意识到一个问题: Sender 怎么知道 Receiver 是用 hash-to-group 而不是 $sG$ 算的 $R_{1-w}$? 借助 AI 通读原始论文, 我得到一个说服我的解释:

在 DKLS23 的实际用法里, endemic OT 只是 OT extension 的 base,
上层 extension 协议有额外的一致性检查防止 Receiver 的作弊.
因此 base OT 只需要半诚实安全, 而不需要对抗全恶意 Receiver.
