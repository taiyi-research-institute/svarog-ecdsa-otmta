## 原始的 Sigma 协议

```
Commitment:  Pierre -> Vincent: R
Challenge:   Pierre <- Vincent: e
Response:    Pierre -> Vincent: z
Verify:      Vincent: verify(R, e, z) ?= true
```

举例: 离散对数证明.

具体来说: Pierre 对于其公开的 $Q$, 要证明自己知道一个秘密 $x$, 满足 $Q=xG$.

```
Pierre: r = rand()
Pierre -> Vincent: R = rG

Vincent: e = rand()
Pierre <- Vincent: e

Pierre: z = r + ex
Pierre -> Vincent: z

Vincent: zG ?= R + eQ
```

为什么安全: $e$ 是随机的, Pierre 无法预测 $e$.

关键的时序: Pierre 必须先知道 $R$ 才能再知道 $e$.

## Fiat-Shamir 变换是为了解决什么问题?

原始的 Sigma 协议需要三轮通信, 因此必须在线交互.
Fiat-Shamir 变换使协议只需要一轮通信仍能保证安全, 从而转换为非交互的.

```
Commitment, challenge, and response:
Pierre: R = rG; e = Hash(R, 一些公开信息); z = r+ex;
Pierre -> Vincent: R, z

Verify:
Vincent: zG ?= R + eQ
```

### Fiat-Shamir 为什么安全?

表面上看, Pierre 现在可以自己选 $r, R$ 来控制 $e$. 这会不会让他更容易作弊?

我们假设哈希函数是接近 RO 模型的. 虽然 Pierre 现在能自行算出 $e$, 但他仍然在知道 $R$ 之后才知道 $e$, 并且不可能先知道 $e$ 再知道 $R$. 也就是说, Sigma 协议中的关键时序并没有被破坏.

这里 "知道 $R$" 并不是一件平凡的事. 严格地说, 它指的是 "知道一个能通过验证的 $R$". 如果 Pierre 安分守己 (是个诚实的证明者), 那么 "知道 $R$" 的确是一件平凡的事, 其代价不过就是摇一个随机数而已. 但如果 Pierre 不安分, 先找到一个对自己有利的 $e$, 那么他只有通过暴力穷举才能找到 $R$.

Fiat-Shamir 变换的代价是, 把原始 Sigma 协议的 "统计安全" 降格为 "计算安全". 为什么说这是降格 ?

Sigma 协议里的 $e$ 是 Vincent 真正随机生成的, Pierre 无论有多强的计算能力都无法预测. 这就是 "统计安全". 换成 RO 哈希以后, 安全性依赖 "目前不存在能破解哈希的计算能力" 这个假设. 这就是 "计算安全".


## 附: 什么样的哈希函数是接近 RO 的?

随机预言机模型 (Random Oracle Model, RO Model)

这里不罗列 RO 的理论定义, 罗列我们更关心的问题: 什么样的哈希函数是接近 RO 的?

第一层: 基础抗性

* 抗碰撞/抗第二原像: 难以找到两个输入, 得到同一个输出.
* 单向性: 给定输出, 难以找到输入.

第二层: 统计性质

* 输出均匀性: 对任意固定输入, 输出在统计上接近均匀分布.
* 雪崩效应: 翻转输入的任意一位, 输出大约有一半的位发生变化.
* 位独立性: 输出的任意两位, 在输入变化时, 各自独立地随机翻转.

第三层: 无记忆性, 上下文无关性

哈希函数的每个输出只取决于当前输入, 不泄露任何关于 "之前问过什么" 或者 "为什么这么问" 的信息. 稍微精确地描述一下, 就是:

$H(x_k)$ 的分布，无论是否知道 $H(x_1), \ldots, H(x_{k-1})$, 都是均匀分布.

举个反例: SHA-256(m||填充||后缀) 可从 SHA-256(m) 直接算出. 这就是有记忆性的, 不够好. 这个攻击方式叫 Merkle-Damgard.
