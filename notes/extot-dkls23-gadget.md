## gadget 向量替代二进制权重

前文使用 $2^j$ 作为权重把 $\beta_j$ 聚合成 $\hat{x}_b$, 也把 $t_j$ 聚合成 $z_b$. 此处 $j$ 的范围是 $1$ 到 $m$, 取 $m=\kappa$ (这里 $\kappa=|n|$ 表示模数比特数). 称这种为**朴素二进制方案**.

DKLS23 实际采用的是**随机 gadget 方案**: 用公开的随机向量 $\mathbf{g}=(g_1,\ldots,g_m)\in\mathbb{Z}_n^m$ 替代 $2^j$, 同时把 $m$ 从 $\kappa$ 增加到 $\kappa+2\lambda_s$, 其中 $\lambda_s$ 是统计安全参数, 通常取 80.

形式上前文协议保持不变, 仅做如下记号替换:

$$
2^j\;\longmapsto\;g_j,\qquad m=\kappa\;\longmapsto\;m=\kappa+2\lambda_s.
$$

具体地,

$$
\hat{x}_b=\sum_j g_j\cdot\beta_j,\quad
z_a=-\sum_j g_j\cdot\alpha^0_j,\quad
z_b=\sum_j g_j\cdot t_j.
$$

$\mathbf{g}$ 是公开参数, 协议双方都可见, 实践中通过 sid 派生:

$$
g_j=\mathrm{Hash}(\mathrm{sid}\,\|\,\texttt{"gadget"}\,\|\,j)\bmod n.
$$

前文的公式 "za+zb", "v.proof" 等的证明全部沿用, 不受影响.

### 与朴素二进制的区别

为了把"差别"讲清楚, 先引入一个新记号 $\boldsymbol{\beta}$, 定义为 Bob 在 $m$ 个 OT 实例中所有选择位拼成的**比特向量**:

$$
\boldsymbol{\beta}=(\beta_1,\beta_2,\ldots,\beta_m)\in\{0,1\}^m.
$$

注意 $\boldsymbol{\beta}$ 和已有的 $\hat{x}_b=\sum_j g_j\beta_j\in\mathbb{Z}_n$ 是两个不同的对象:

* $\boldsymbol{\beta}$ 是 $m$ 比特的 0/1 向量, 是 OT 层面的原始选择. 共 $2^m$ 种取值.
* $\hat{x}_b$ 是 $\mathbb{Z}_n$ 上的标量, 是 $\boldsymbol{\beta}$ 经 gadget 加权求和得到的"压缩值", 也就是 Bob 在底层随机 MtA 中的等效输入. 共 $n$ 种取值, $|\hat{x}_b|\approx\kappa$ 比特.

后文反复出现的"$\boldsymbol{\beta}\to\hat{x}_b$ 映射"指的就是 $\boldsymbol{\beta}\mapsto\sum_j g_j\beta_j$ 这个加权求和.

两种方案外表只差三个细节: $g_j$ 取值、$m$ 大小、$\mathbf{g}$ 是否随机. 实质区别在 $\boldsymbol{\beta}\to\hat{x}_b$ 这个映射的多对一程度.

* **朴素二进制**: 映射是双射. $2^\kappa$ 个候选 $\boldsymbol{\beta}$ 一一对应 $2^\kappa$ 个 $\hat{x}_b$. 给定 $\hat{x}_b$, 立即从二进制展开解出 $\boldsymbol{\beta}$.
* **随机 gadget**: 映射多对一. 候选数 $2^m=2^{\kappa+2\lambda_s}$, 像空间 $\mathbb{Z}_n$ 大小 $\approx 2^\kappa$. 由抽屉原理, 平均每个 $\hat{x}_b$ 对应约 $2^{2\lambda_s}$ 个 $\boldsymbol{\beta}$.

更精确地, 由 leftover hash lemma:

$$
\bigl(\mathbf{g},\,\hat{x}_b\bigr)\;\stackrel{s}{\approx}\;\bigl(\mathbf{g},\,U\bigr),\quad U\stackrel{\$}{\leftarrow}\mathbb{Z}_n.
$$

统计距离 $\leq \frac{1}{2}\sqrt{n/2^m}=\frac{1}{2}\cdot 2^{-\lambda_s}$, 可忽略. 等价表述: **即便公开 $\mathbf{g}$, $\hat{x}_b$ 的分布与 $\mathbb{Z}_n$ 上均匀随机数在统计上几乎不可区分**, 也就是 $\hat{x}_b$ 几乎不携带 $\boldsymbol{\beta}$ 的信息.

直观: $\boldsymbol{\beta}$ 有 $m$ 比特熵, $\hat{x}_b$ 容纳 $\kappa$ 比特, 多出来的 $2\lambda_s$ 比特是被 leftover hashing 压缩掉的, 信息论意义上不可恢复.

### gadget 防的是什么

回顾 Step 3. Bob 把 $\delta=x_b-\hat{x}_b$ 发给 Alice. 这意味着 $\hat{x}_b$ 通过 $\delta$ 进入 Alice 的视图, 只是被 $x_b$ 当作一次性掩码遮住.

孤立单次 MtA 调用、$x_b$ 新鲜随机, $\delta$ 就是均匀随机, $\hat{x}_b$ 没有泄露. 此时朴素二进制其实是安全的. 但实际部署中有以下场景, $\hat{x}_b$ 在 Alice 视图中并非完全随机:

* **$x_b$ 跨调用复用**. 例如 ECDSA 中 $x_b$ 是 Bob 的密钥分片, 跨签名共用. 多次的 $\delta_i = x_b - \hat{x}_{b,i}$ 之间的差 $\delta_i - \delta_{i'} = \hat{x}_{b,i'} - \hat{x}_{b,i}$ 直接泄露 $\hat{x}_b$ 之差.
* **$x_b$ 通过其它通道泄露**. ECDSA 中 $x_b$ 同时被用于公钥提交 $X_b = x_b\cdot G$、一致性检查里的 $\Gamma$ 项. 这些公开值让 Alice 间接学到 $x_b$ 的信息, 进而学到 $\hat{x}_b$ 的信息.
* **UC 协议组合**. RVOLE 嵌入外层 ECDSA 时, 外层 simulator 在做 hybrid 论证时常常需要把 $\hat{x}_b$ 当成"已经泄露给敌手"来推进. 此时内层一致性检查的可靠性必须不依赖 $\hat{x}_b$ 保密.

以上每个场景下, $\boldsymbol{\beta}$ 在 Alice 视图中的剩余熵都是论证可靠性的关键. 注意这里说的是 $\boldsymbol{\beta}$ 的熵, 不是 $\hat{x}_b$ 的熵 ---- 一致性检查 (公式 "verify") 在每个 $j$ 位上具体用到的是 $\beta_j$, 即 $\boldsymbol{\beta}$ 的某一比特.

* **朴素二进制下**, $\boldsymbol{\beta}\to\hat{x}_b$ 双射. $\hat{x}_b$ 一旦泄露 $\boldsymbol{\beta}$ 立即被解出. 公式 "verify" 的可靠性论证依赖 Alice 无法预测 $\beta_j$ (见前文 ※), 此时直接塌掉 ---- Alice 知道每个 $\beta_j$, 可以精确选择只在 $\beta_j=0$ 的位作弊, 检查永远通过.
* **随机 gadget 下**, 即便 $\hat{x}_b$ 完全泄露给 Alice, $\boldsymbol{\beta}$ 仍有约 $2^{2\lambda_s}$ 个候选. Alice 想精确预测某个 $\beta_j$, 概率上界由 leftover hash lemma 给到 $2^{-\lambda_s}$, 可忽略.

※ 一个比喻: 朴素二进制相当于 "原文 = 哈希值", 哈希一漏原文也漏. 随机 gadget 相当于 "原文比哈希值长 $2\lambda_s$ 比特", 哈希漏了原文还剩 $2\lambda_s$ 比特不可恢复熵. leftover hash lemma 严格量化了这个直觉.

※ 这一节回答了一个看似自相矛盾的问题: "$\hat{x}_b$ 已经通过 $\delta$ 给了 Alice, 还谈什么 $\beta_j$ 保密?" 答案是: $\hat{x}_b$ 是 $\kappa$ 比特, $\boldsymbol{\beta}$ 是 $m$ 比特, gadget 让两者之间相差 $2\lambda_s$ 比特熵 ---- 这部分熵是 $\hat{x}_b$ 完全泄露也带不走的. 可靠性论证依赖的是 $\boldsymbol{\beta}$ 的分量 $\beta_j$, 而不是聚合后的 $\hat{x}_b$.

### 代价与权衡

代价: OT 实例数从 $\kappa$ 增加到 $\kappa+2\lambda_s$. 在 $\kappa=256, \lambda_s=80$ 时, $m$ 从 256 增到 416, 增加 62.5%. 通信量和 OT 计算量成正比增加.

好处: 一致性检查的可靠性从"假设 $\hat{x}_b$ 完全保密"放宽到"即便 $\hat{x}_b$ 完全泄露, $\boldsymbol{\beta}$ 仍有 $2\lambda_s$ 比特剩余熵". 这是信息论级别的加固, 不依赖计算困难假设, 也不需要为 $\hat{x}_b$ 是否经由外层泄露做额外论证. 在 UC 框架下做协议组合时, 这个让步特别值.

### 实现注意

* $\mathbf{g}$ 必须**在 Alice 提交修正矩阵 $\tilde{a}_*$ 之前**就被固定. 从 sid 派生最干净, 既不需要存储, 也避免"谁选的"这种争议.
* 不能让 Alice 自选 $\mathbf{g}$. 否则她可以选成 $g_j=2^j$ (且只用前 $\kappa$ 行) 把映射变成双射, 抽干 $\boldsymbol{\beta}$ 剩余熵.
* $g_j$ 是 $\mathbb{Z}_n$ 上的标量, 不是 0/1, 后续聚合按 scalar 参与运算, 不要错把它当 bit 处理.
