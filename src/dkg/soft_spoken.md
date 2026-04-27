# SoftSpoken PPRF (all-but-one)

参考: Roy, "SoftSpokenOT", Fig. 13 & 14, https://eprint.iacr.org/2022/192.pdf.

本文档与 [soft_spoken.rs](soft_spoken.rs) 配套, 描述其中的类型与算法.
高一层的 keygen 数学背景见 [dkg_fn.md](dkg_fn.md) Section A.

## 1. 用途

把 base OT (EndemicOT) 输出的 $\kappa = 256$ 对密钥, 经一层 PPRF 拉伸为 64 棵并行 GGM 小树.

* Sender 持有所有树的全部 16 个叶子.
* Receiver 持有每棵树的 15 个叶子, 加一个 punctured 下标 $y^*_j$.

签名时上层 SoftSpoken OT 扩展把这些叶子组合成 $L = \kappa + 2\lambda_s = 512$ 个随机 OT (本仓库待移植).

## 2. 参数

| 名称 | 源码常量 | 值 | 含义 |
|---|---|---|---|
| $\kappa$ | `LAMBDA_C` | 256 | 计算安全参数, secp256k1 标量比特数 |
| $K$ | `SOFT_SPOKEN_K` | 4 | 每棵小树深度 |
| $Q$ | `SOFT_SPOKEN_Q` | 16 | 每棵小树叶子数, $Q = 2^K$ |
| | `NUM_TREES` | 64 | 小树数量, $\kappa / K$ |
| | `LAMBDA_C_BYTES` | 32 | 单个叶子字节长度 |

第 $j$ 棵小树 ($j \in [0, 64)$) 消耗 base OT 下标 $jK, jK + 1, \ldots, jK + K - 1$ 共 $K$ 对密钥.
总计 $64 \times 4 = 256 = \kappa$ 对, 与 base OT 容量正好对齐.

## 3. 类型对照

`PPRF` (单棵树, 走线消息):

* `t: Vec<(Vec<u8>, Vec<u8>)>`. 长度 $K - 1 = 3$, 每项 $(t_i[0], t_i[1])$ 是第 $i$ 层的 OTP 修正对.
* `s_tilda: Vec<u8>`. 64 字节 ($2\lambda_c$). 所有叶子 prove 值的聚合哈希, 用于一致性校验.
* `t_tilda: Vec<u8>`. 64 字节. 所有叶子 prove 值的异或累加器, 让 Receiver 反推缺失的那个 prove 值.

`PPRFOutput`:

* `trees: Vec<PPRF>`. 长度 64. 单方向 Sender → Receiver 的整段通信载荷.

`SenderOTSeed` (Sender 本地保留):

* `otp_enc_keys[j][y]`. 第 $j$ 棵树第 $y$ 个叶子, 32 字节. Sender 全部知道.

`ReceiverOTSeed` (Receiver 本地保留):

* `random_choices[j]`. punctured 下标 $y^*_j \in [Q]$, 用 1 字节存 (4 位即可).
* `otp_dec_keys[j][y]`. 同 `SenderOTSeed`; 但 $y = y^*_j$ 处保持全 0 (Receiver 不可知).

## 4. 哈希原语

三个标签互斥, 共用同一会话 id $\sigma$ (函数参数 `sid`):

* PRG (内部展开): $G(s) = \mathrm{Hash}(\text{"abo-pprf-prg"} \| \sigma \| s) \to (\text{left}, \text{right})$, 每侧 32 字节. 源码: `prg_expand`.
* 叶子 prove: $\tilde{s}_y = \mathrm{Hash}(\text{"abo-pprf-proof"} \| \sigma \| s_y) \to 64$ 字节. 源码: `leaf_proof`.
* 聚合哈希: $\mathrm{Hash}(\text{"abo-pprf-hash"} \| \sigma \| \tilde{s}_0 \| \cdots \| \tilde{s}_{Q-1}) \to 64$ 字节. 源码: `aggregate_proof`.

底层全部是 Blake2b 变长输出.

## 5. `build_pprf` 算法

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

(3) 走完 $K - 1$ 次迭代后, $s^{(K)}$ 是 $Q = 16$ 个叶子, 全部写入 `sender_seed.otp_enc_keys[j]`.

(4) 对每个叶子算 $\tilde{s}_y = \mathrm{leaf\_proof}(s^{(K)}[y])$. XOR 累加到 `t_tilda`, 再聚合哈希得到 `s_tilda`.

## 6. `eval_pprf` 算法

对每棵树 $j$:

(1) 第 0 层. 取 Receiver 第 $jK$ 位选择位 $\beta_0$, 把 base OT 给到的密钥 $\rho_{\beta_0}$ 放在 $s^{(0)}_*[\beta_0]$.
设 $y^* = 1 - \beta_0$ 为本层未知下标.

(2) 对 $i = 1, 2, \ldots, K - 1$:

先 PRG 展开. 对所有已知 $s^{(i)}_*[y]$ ($y \neq y^*$) 用相同的 PRG, 填入 $s^{(i+1)}_*[2y]$ 和 $s^{(i+1)}_*[2y + 1]$.
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

## 7. 安全直觉

(a) Receiver 为何学不到 $y^*$ 处的叶子.

每层修正对 $t_i[\beta_i]$ 自带"全部 $\beta_i$-侧孩子异或"的形式.
Receiver 知道除 $y^*$ 外所有 $\beta_i$-侧孩子, 减掉之后只能恢复 $2y^* + \beta_i$ 这一个;
$2y^* + (1 - \beta_i)$ 仍未知, 因为 Receiver 没有 $\rho_{1 - \beta_i}$ (这是 base OT 的另一侧密钥, 只有 Sender 知道).
随着层数推进, 未知"游标"在树里逐层下走, 最终唯一地落在 $y^*$ 那个叶子上.

(b) `t_tilda` 为何安全.

`t_tilda` 是"所有叶子 prove 之异或", 暴露的只是集合性质, 不暴露任意单个叶子的 prove 值.
Receiver 用它把缺失的 prove 算出来, 然后与 `s_tilda` 比对; Sender 任何对单个叶子的伪造都会被聚合哈希察觉.

## 8. 与 `dkg_fn.rs` 的衔接

Round 3 同一次 `exchange()` 里:

(1) 方 $i$ 处理 $j$ 发来的 base OT msg1, 得 `SenderOutput`.

(2) 派生配对 sid: `format!("{}/pprf/{}-{}", sid, i.min(j), i.max(j))`. 双方派生的字符串相同.

(3) `build_pprf(&pair_sid, &sender_out, ...)` 输出 `(SenderOTSeed, PPRFOutput)`.
`SenderOTSeed` 落进 `as_pprf_sender[j]`; `PPRFOutput` 走路由 `keygen/r3/pprf` 发给 $j$.

(4) `exchange()` 之后, 方 $i$ 处理 $j$ 的 base OT msg2 得 `ReceiverOutput`,
再 `eval_pprf(&pair_sid, &recv_out, &others_pprf_output[&j], ...)` 得 `ReceiverOTSeed` 落进 `as_pprf_receiver[j]`.

base OT 的中间产物 (`SenderOutput` / `ReceiverOutput`) 在 PPRF 扩展后即可丢弃,
与 simple-dkls23 keyshare 的设计一致 (那里只保留 `seed_ot_senders` / `seed_ot_receivers`).

## 9. 仍未移植

PPRF 输出还不是签名直接用的随机 OT.
上层 `soft_spoken_ot.rs` 把 64 棵小树的叶子按 IKNP 风格组合成 $L = 512$ 个随机 OT, 再由 `rvole.rs` 组装成 MtA (RVOLE).
这两层在本仓库尚未移植.
