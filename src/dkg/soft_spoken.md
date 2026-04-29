# SoftSpoken PPRF (all-but-one)

参考: Roy, "SoftSpokenOT", Fig. 13 & 14, https://eprint.iacr.org/2022/192.pdf.

本文档与 [soft_spoken.rs](soft_spoken.rs) 配套.
高一层的 keygen 数学背景见 [dkg_fn.md](dkg_fn.md) Section A.

> 一图胜千言: 打开 [soft_spoken_tree.html](soft_spoken_tree.html) 看一棵小树长什么样.
> 下文涉及"叶子"、"路径"、"修正对" 时, 图示比文字直观得多.

---

## 1. 通俗讲: 核心意图

用 PRG 把 base OT 的"$\kappa$ 对密钥"拉伸成"$Q^{\kappa/K}$ 个叶子", 但是 Receiver 必须留下若干叶子永远算不出.

PRG 没有秘密, 谁都能算. 真正卡住 Receiver 的, 是每一层依赖一对 base OT 密钥, 而 Receiver 在 base OT 那里只拿到其中一侧.
这个"少一片叶子"的特性, 正好是 1-out-of-$Q$ OT 的语义, 后面 SoftSpoken OT 扩展全靠它.

## 2. 通俗讲: 树的结构

把它想成 PRG 长出的家谱树:

* 树根有两个, 来自 base OT 第 0 对的 $(\rho_0, \rho_1)$.
* 每一层都用 PRG 把当前所有节点展开为左/右两个孩子.
* 每一层还会再用一对 base OT 密钥, 把"全部左孩子之异或"和"全部右孩子之异或"分别 OTP 加密, 得到一对**修正值** $t_i$ 公开发给 Receiver.
* 这样走 $K$ 层, 共 $Q = 2^K$ 个叶子.

Sender 视角全知全能, 拿到所有 $Q$ 个叶子.
Receiver 在 base OT 每一对里只能拿到与选择位 $\beta_i$ 对应那一侧.
于是树里有一条**纵向"红色路径"**: 从根开始, 每一层都偏向 $1 - \beta_i$ 那一侧, 这条路径上的节点 Receiver 全算不出.
路径终点那片叶子, 叫 punctured leaf $y^*$, 它是 Receiver 永远的盲区.
路径**之外**的所有节点, Receiver 借助 $t_i$ 都能逐层重建.

这就是 "all-but-one PRF" 的字面意思: 全部叶子里少了一个.

## 3. 通俗讲: Receiver 怎么从修正值反推

每一层 Sender 公开的修正对 $(t_i[0], t_i[1])$ 长这样:

$$t_i[\beta] = \rho_\beta \oplus \bigoplus_{\text{所有 } \beta\text{-侧孩子}}$$

Receiver 自己手里有 $\rho_{\beta_i}$.
两边异或, 就得到 "本层所有 $\beta_i$-侧孩子之异或".

但 Receiver 已经算出来了一堆 $\beta_i$-侧孩子 (除了红色路径上那个).
继续异或减掉, 剩下的恰好就是**红色路径在本层的下一个节点**.

如此一来, 红色路径在每一层都把"未知游标"再往下推一层.
路径越走越窄 (从 $2^i$ 个未知压到 1 个), 最终停在唯一一片叶子 $y^*$ 上.

而 $y^*$ 那片叶子需要 $\rho_{1 - \beta_K}$ 才能解, Receiver 没有, 所以它永远是盲区.

## 4. 通俗讲: 为什么还要 `s_tilda` / `t_tilda`

光有叶子还不够: 万一 Sender 偷偷把某个叶子换掉呢?
Receiver 可以重算自己 7 个能算的叶子, 与 Sender 给的对一下就行.
但 $y^*$ 那片他没法重算, 也就没法直接对一下.

所以 Sender 额外发两段 64 字节的指纹:

* `s_tilda`: 全部叶子 prove 之**哈希**.
* `t_tilda`: 全部叶子 prove 之**异或**.

`t_tilda` 让 Receiver 反推缺失的 $\tilde{s}_{y^*}$ (减掉自己能重算的 7 个, 剩下就是它);
`s_tilda` 让 Receiver 把所有 prove 一起再哈希一次, 跟 Sender 给的对比.
任何一片叶子被偷换, 哈希就对不上.
异或暴露的只是集合性质, 不会泄露任何单个叶子的 prove 值.

---

## 5. 参数对照

| 名称 | 源码常量 | 值 | 含义 |
|---|---|---|---|
| $\kappa$ | `LAMBDA_C` | 256 | 计算安全参数, secp256k1 标量比特数 |
| $K$ | `SOFT_SPOKEN_K` | 4 | 每棵小树深度 |
| $Q$ | `SOFT_SPOKEN_Q` | 16 | 每棵小树叶子数, $Q = 2^K$ |
| | `NUM_TREES` | 64 | 小树数量, $\kappa / K$ |
| | `LAMBDA_C_BYTES` | 32 | 单个叶子字节长度 |

第 $j$ 棵小树消耗 base OT 下标 $jK, \ldots, jK + K - 1$ 共 $K$ 对密钥.
总计 $64 \times 4 = 256 = \kappa$ 对, 与 base OT 容量正好对齐.

> 图示用 $K = 3$ (8 个叶子) 是为了画面清晰; 真实代码 $K = 4$ (16 个叶子). 树的形状一样, 多一层而已.

## 6. 类型对照

`PPRF` (单棵树, 走线消息):

* `t: Vec<(Vec<u8>, Vec<u8>)>`. 长度 $K - 1 = 3$, 每项是该层的一对 OTP 修正值.
* `s_tilda: Vec<u8>`. 64 字节. 叶子 prove 的聚合哈希.
* `t_tilda: Vec<u8>`. 64 字节. 叶子 prove 的异或累加器.

`PPRFOutput`:

* `trees: Vec<PPRF>`. 长度 64. 一次单方向 (Sender → Receiver) 的整段通信载荷.

`SenderOTSeed` (Sender 本地保留):

* `otp_enc_keys[j][y]`. 第 $j$ 棵树第 $y$ 个叶子, 32 字节.

`ReceiverOTSeed` (Receiver 本地保留):

* `random_choices[j]`. punctured 下标 $y^*_j \in [Q]$, 1 字节存.
* `otp_dec_keys[j][y]`. 同 `SenderOTSeed`; 但 $y = y^*_j$ 处保持全 0.

## 7. 哈希原语

三个标签互斥, 共用同一会话 id $\sigma$ (函数参数 `sid`):

* PRG (内部展开): $G(s) = \mathrm{Hash}(\text{"abo-pprf-prg"} \| \sigma \| s) \to (\text{left}, \text{right})$, 每侧 32 字节. 源码 `prg_expand`.
* 叶子 prove: $\tilde{s}_y = \mathrm{Hash}(\text{"abo-pprf-proof"} \| \sigma \| s_y) \to 64$ 字节. 源码 `leaf_proof`.
* 聚合哈希: $\mathrm{Hash}(\text{"abo-pprf-hash"} \| \sigma \| \tilde{s}_0 \| \cdots \| \tilde{s}_{Q-1}) \to 64$ 字节. 源码 `aggregate_proof`.

底层全部是 Blake2b 变长输出.

## 8. `build_pprf` 算法 (Sender)

对每棵树 $j$:

(1) 初始化第 0 层. 取 base OT 第 $jK$ 对的两个密钥 $(\rho_0, \rho_1)$, 写入 $s^{(0)}[0]$ 和 $s^{(0)}[1]$.

(2) 对 $i = 1, 2, \ldots, K - 1$, 每层做两件事.

先 PRG 展开. 第 $i$ 层有 $2^i$ 个已填充种子, 每个用 PRG 展开为下一层一对孩子:

$$
(s^{(i+1)}[2y], s^{(i+1)}[2y + 1]) = G(s^{(i)}[y]), \quad y \in [0, 2^i).
$$

再算修正对. 取 base OT 第 $jK + i$ 对密钥 $(\rho_0, \rho_1)$, 用全部左/右孩子的异或做 OTP 掩盖:

$$
t_i[0] = \rho_0 \oplus \bigoplus_{y \in [0, 2^i)} s^{(i+1)}[2y], \quad
t_i[1] = \rho_1 \oplus \bigoplus_{y \in [0, 2^i)} s^{(i+1)}[2y + 1].
$$

把 $(t_i[0], t_i[1])$ 装入 `pprf.t[i - 1]`.

(3) 走完 $K - 1$ 次迭代后, $s^{(K)}$ 是 $Q$ 个叶子, 全部写入 `sender_seed.otp_enc_keys[j]`.

(4) 对每个叶子算 $\tilde{s}_y = \mathrm{leaf\_proof}(s^{(K)}[y])$.
XOR 累加到 `t_tilda`, 再聚合哈希得到 `s_tilda`.

## 9. `eval_pprf` 算法 (Receiver)

对每棵树 $j$:

(1) 第 0 层. 取 Receiver 第 $jK$ 位选择位 $\beta_0$, 把 base OT 给到的密钥 $\rho_{\beta_0}$ 放在 $s^{(0)}_*[\beta_0]$.
设 $y^* = 1 - \beta_0$ 为本层未知下标.

(2) 对 $i = 1, 2, \ldots, K - 1$:

先 PRG 展开. 对所有已知 $s^{(i)}_*[y]$ ($y \neq y^*$) 用相同 PRG, 填入 $s^{(i+1)}_*[2y]$ 和 $s^{(i+1)}_*[2y + 1]$.
通向 $y^*$ 的两个位置 $2y^*$ 和 $2y^* + 1$ 暂留空.

再补缺. 取 Receiver 第 $jK + i$ 位选择位 $\beta_i$ 和对应密钥 $\rho_{\beta_i}$.
从 Sender 给的修正对挑 $\beta_i$ 一侧:

$$
x = t_i[\beta_i] \oplus \rho_{\beta_i} = \bigoplus_{y \in [0, 2^i)} s^{(i+1)}[2y + \beta_i].
$$

把所有已知 $\beta_i$-侧孩子异或减掉, 剩下的正好是缺口位置:

$$
x \oplus = \bigoplus_{y \neq y^*} s^{(i+1)}_*[2y + \beta_i] \implies s^{(i+1)}_*[2y^* + \beta_i] = x.
$$

注意 $2y^* + (1 - \beta_i)$ 仍未知, 成为下一层新的未知下标:

$$
y^*_{\text{new}} = 2y^* + (1 - \beta_i).
$$

(3) 走完 $K - 1$ 次迭代后, $s^{(K)}_*$ 共 $Q$ 个位置, 只有终态 $y^*$ 一个不可知.

(4) 一致性校验.

对所有 $y \neq y^*$ 重算 $\tilde{s}_y = \mathrm{leaf\_proof}(s^{(K)}_*[y])$.

利用 Sender 的恒等式 $\text{t\_tilda} = \bigoplus_y \tilde{s}_y$ 反推缺失值:

$$
\tilde{s}_{y^*} = \text{t\_tilda} \oplus \bigoplus_{y \neq y^*} \tilde{s}_y.
$$

把 $Q$ 个 $\tilde{s}_y$ 喂进 `aggregate_proof`, 与 `pprf.s_tilda` 比对; 不等则 throw `InvalidPPRFProof`.

(5) 校验通过则写入 `receiver_seed.random_choices[j] = y^*` 与 `receiver_seed.otp_dec_keys[j] = s^{(K)}_*`.

## 10. 与 `dkg_fn.rs` 的衔接

Round 3 同一次 `exchange()` 里:

(1) 方 $i$ 处理 $j$ 发来的 base OT msg1, 得 `SenderOutput`.

(2) 派生配对 sid: `format!("{}/pprf/{}-{}", sid, i.min(j), i.max(j))`. 双方派生的字符串相同.

(3) `build_pprf(&pair_sid, &sender_out, ...)` 输出 `(SenderOTSeed, PPRFOutput)`.
`SenderOTSeed` 落进 `as_pprf_sender[j]`; `PPRFOutput` 走路由 `keygen/r3/pprf` 发给 $j$.

(4) `exchange()` 之后, 方 $i$ 处理 $j$ 的 base OT msg2 得 `ReceiverOutput`,
再 `eval_pprf(&pair_sid, &recv_out, &others_pprf_output[&j], ...)` 得 `ReceiverOTSeed` 落进 `as_pprf_receiver[j]`.

base OT 的中间产物 (`SenderOutput` / `ReceiverOutput`) 在 PPRF 扩展后即可丢弃,
与 simple-dkls23 keyshare 的设计一致 (那里只保留 `seed_ot_senders` / `seed_ot_receivers`).

## 11. 仍未移植

PPRF 输出还不是签名直接用的随机 OT.
上层 `soft_spoken_ot.rs` 把 64 棵小树的叶子按 IKNP 风格组合成 $L = 512$ 个随机 OT, 再由 `rvole.rs` 组装成 MtA (RVOLE).
这两层在本仓库尚未移植.
