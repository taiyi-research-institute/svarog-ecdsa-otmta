# DSG / Sign 移植路线图

本文档记录把 `simple-dkls23` 的 signing 流程移植到 `svarog-ecdsa-otmta` 的计划.
这里沿用 DKLS23 代码里的命名 `dsg` (distributed signing), 对外可以暴露为 `sign`.

配套图: [dsg_fn_roadmap.html](dsg_fn_roadmap.html).

## 当前边界

当前 keygen MVP 已经完成, signing 应从消费 `KeygenOutput` 开始.

输入材料:

* `Keystore<Secp256k1>`: 本方长期份额 `xi`, 全体 `vss_scheme`, `chain_code`.
* `PairPPRFSeeds`: keygen 阶段 EndemicOT + PPRF 得到的 all-but-one 种子.
* `PairwiseSeeds`: 签名时派生份额随机偏移 $\zeta_i$ 的明文 pairwise seeds.

本阶段暂不做:

* refresh / rotation.
* child key derivation / BIP32. MVP 先签主公钥, 令 `additive_offset = 0`.
* `dsg_ot_variant.rs` 路线. 该路线在 signing 时重跑 OT; 本仓库 keygen 已经产出 PPRF seeds, 优先移植 `dsg.rs` 路线.

## 源码映射

主要参考源:

| 源文件 | 作用 | 移植目标 |
|---|---|---|
| `simple-dkls23/src/dsg.rs` | 使用 keygen 产出的 PPRF seeds 做 signing | 主参考 |
| `simple-dkls23/src/dsg_ot_variant.rs` | signing 时额外跑 OT 的变体 | 暂不移植, 仅作对照 |
| `simple-dkls23/src/constants.rs` | `DSG_LABEL`, `PAIRWISE_MTA_LABEL`, `PAIRWISE_RANDOMIZATION_LABEL` 等 domain separators | 在本仓库用 hash tags / 常量重建 |
| `simple-dkls23/src/utils.rs` | nonce commitment, `mta_session_id`, signing helpers | 按当前 `helpers.rs` 风格重写 |
| `simple-dkls23/src/dkg.rs` `Keyshare` | signing 输入类型 | 替换为 `KeygenOutput` / 新的 `SignKey` |

目标文件建议:

| 目标文件 | 内容 |
|---|---|
| `src/dsg/mod.rs` | 模块出口 |
| `src/dsg/dsg_fn.rs` | signing 状态机、消息类型、presign/partial/combine |
| `src/dsg/soft_spoken_ot.rs` | PPRF seeds 到上层随机 OT 的转换 |
| `src/dsg/rvole.rs` | RVOLE / MtA 层 |
| `src/dsg/helpers.rs` | signing hash domain、nonce commitment、session id、ECDSA helpers |
| `src/dsg/dsg_fn.md` | 数学笔记, 等实现过程中逐步补 |

## 总体依赖

Signing 的依赖顺序是:

```text
KeygenOutput
  -> PairPPRFSeeds
  -> soft_spoken_ot.rs
  -> rvole.rs
  -> dsg_fn.rs presign
  -> partial signature
  -> final ECDSA signature
```

最容易迷路的点:

* `PairPPRFSeeds` 不是最终随机 OT, 只是 SoftSpoken OT 的基材.
* RVOLE 不是签名本身, 它只提供 MtA 所需的乘法相关 additive shares.
* `PreSignature` 还没有绑定消息; `PartialSignature` 才绑定 message hash.
* `combine_signatures` 只做本地聚合和最终 ECDSA 校验.

## 阶段 1: SoftSpoken OT

目标: 消费 keygen 输出的 `SenderOTSeed` / `ReceiverOTSeed`, 生成 RVOLE 需要的随机 OT 材料.

需要定义的接口可以先贴近 `simple-dkls23`:

```rust
pub struct Round1Output {
    // Receiver -> Sender 的上层 OT 消息
}

pub struct Round2Output {
    // Sender -> Receiver 的上层 OT 响应或校验材料
}
```

但最终接口应以 RVOLE 的调用方式为准:

```rust
RVOLEReceiver::new(sid, sender_seed_for_peer, &mut msg1, rng)
RVOLESender::process(sid, receiver_seed_for_peer, inputs, &msg1, &mut msg2, rng)
RVOLEReceiver::process(&msg2)
```

实现要点:

* 每个 pairwise 对端都必须使用独立 `sid`.
* 方向要和 keygen 中的 `as_sender` / `as_receiver` 对齐:
  * 我作为 RVOLE Receiver 给对方发 msg1 时, 使用我保存的 `as_sender[j]` 还是 `as_receiver[j]`, 需要通过源代码和测试确认.
  * `simple-dkls23/src/dsg.rs` 中 `handle_msg1` 使用 `seed_ot_senders`, `handle_msg2` 使用 `seed_ot_receivers`; 移植时以这个方向为基准.
* 先实现最小正确性测试: 双方通过 SoftSpoken OT 得到匹配的随机 OT 矩阵 / 向量.

完成标准:

* 单独的 SoftSpoken OT correctness test 通过.
* 对每个非 punctured 位置, Receiver 的材料与 Sender 对应材料一致.
* 方向测试覆盖 `i < j` 和 `i > j`.

## 阶段 2: RVOLE / MtA

目标: 用 SoftSpoken OT 得到 DKLS signing 需要的乘法相关 additive shares.

签名里每个 pairwise MtA 同时服务两个乘法输入:

```text
u: r_i  * phi_j
v: sk_i * phi_j
```

源代码对应:

* `RVOLEReceiver::new(...)` 生成 msg1 和本地 `chi_i_j`.
* `RVOLESender::process(..., &[r_i, sk_i], msg1, msg2)` 输出 `[c_u, c_v]`.
* `RVOLEReceiver::process(msg2)` 输出 `[d_u, d_v]`.

应满足的抽象关系:

```text
c_u + d_u = r_sender  * chi_receiver
c_v + d_v = sk_sender * chi_receiver
```

`dsg.rs` 里后续一致性检查使用:

```text
R_j  * chi_i_j == G * d_u + gamma_u
PK_j * chi_i_j == G * d_v + gamma_v
```

实现要点:

* `Scalar` / `Point` 使用 `svarog_secp256k1`, 不引入 `k256`.
* RVOLE 内部用到的 hash domain 要固定, 不复用 keygen 的 hash tag.
* 先不做性能优化, 先保留清楚的数据结构和测试.

完成标准:

* 2-party RVOLE correctness test 通过.
* 错误 msg2 / 错误 proof 能被拒绝.
* 输出可直接喂给 signing consistency checks.

## 阶段 3: Signing 状态机

目标: 移植 `simple-dkls23/src/dsg.rs` 的 round flow, 但输入类型改为当前仓库的 keygen 输出.

建议定义:

```rust
pub struct SignKey {
    pub keystore: Keystore<Secp256k1>,
    pub pprf_seeds: PairPPRFSeeds,
    pub seeds: PairwiseSeeds,
}

pub struct SignState {
    pub key: SignKey,
    pub participants: Vec<usize>,
    ...
}
```

消息类型:

| 消息 | 路由 | 内容 |
|---|---|---|
| `SignMsg1` | broadcast | `session_id`, `commitment_r_i` |
| `SignMsg2` | p2p | `final_session_id`, RVOLE msg1 |
| `SignMsg3` | p2p | RVOLE msg2, `digest_i`, `pk_i`, `R_i`, commitment opening, consistency data |
| `SignMsg4` | broadcast / collect | partial signature shares |

Round flow:

1. `new`
   * 生成 `sid_i`, `phi_i`, `r_i`, `blind_factor`.
   * 计算 `R_i = r_i G`.
   * commitment: `H("dsg/commitment", sid_i, R_i, blind_factor)`.
   * MVP: `derived_public_key = keystore.public_key()`, `additive_offset = 0`.

2. Round 1 / `SignMsg1`
   * 广播 `sid_i` 和 `commitment_r_i`.
   * 收齐 signing subset 的 `SignMsg1`.
   * 检查 session id / commitment 去重.
   * 计算 `final_session_id`.
   * 计算 `digest_i`, 作为本次 presign transcript digest.

3. Round 2 / `SignMsg2`
   * 为每个对端创建 RVOLE receiver msg1.
   * 保存 `RVOLEReceiver` 和 `chi_i_j`.
   * p2p 发送 `SignMsg2`.

4. Round 3 / `SignMsg3`
   * 计算 signing subset 上的 Lagrange 系数:
     $$\lambda_i = \prod_{j \in S, j \ne i}\frac{j}{j-i}$$
   * 计算 pairwise randomization:
     $$\zeta_i = \sum_{j < i} v_{ji} - \sum_{j > i} v_{ij}$$
   * 计算有效份额:
     $$sk_i = \lambda_i \cdot x_i + \zeta_i + additive\_offset$$
   * 对收到的 RVOLE msg1 运行 sender process, 输入 `[r_i, sk_i]`.
   * 发送 RVOLE msg2 和 consistency check 材料.

5. Presign / `handle_msg3`
   * 验 `final_session_id`, nonce commitment, `digest_i`.
   * 处理收到的 RVOLE msg2.
   * 验 RVOLE consistency checks.
   * 聚合:
     ```text
     R = R_i + sum_j R_j
     sum_u = sum pairwise u shares
     sum_v = sum pairwise v shares
     phi = phi_i + sum_j psi_j_i
     s_0 = r_x * (sk_i * phi + sum_v)
     s_1 = r_i * phi + sum_u
     ```
   * 输出 `PreSignature`.

6. Message binding
   * 输入 32-byte message hash.
   * `partial.s_0 = m * phi_i + pre.s_0`
   * `partial.s_1 = pre.s_1`

7. Combine
   * 检查所有 partial 的 `final_session_id`, public key, `R`, message hash 一致.
   * `s = sum(s_0) / sum(s_1)`.
   * `r = x(R) mod n`.
   * 输出 ECDSA signature.

## 阶段 4: ECDSA 输出与验证

目标: 先得到最小可用签名类型, 再考虑 DER / compact 编码.

建议 MVP:

```rust
pub struct EcdsaSignature {
    pub r: Scalar,
    pub s: Scalar,
}
```

需要补的底层能力:

* 从 `Point` 取 affine x 坐标并 reduce 到 `Scalar`.
* `Scalar` 求逆已有 `inv_vt` / `inv_ct`.
* ECDSA verify 可以先写本地测试辅助:
  ```text
  u1 = m / s
  u2 = r / s
  R' = u1 G + u2 PK
  check x(R') == r
  ```
* 等 MVP 通过后, 再决定是否接 DER 编码或外部 verify API.

## 阶段 5: 测试顺序

不要第一步就写完整 signing E2E. 建议测试顺序:

1. `soft_spoken_ot` 单元测试.
2. `rvole` 单元测试.
3. `get_zeta_i` 测试: 所有参与方 $\sum_i \zeta_i = 0$.
4. Lagrange subset 测试: $\sum_i \lambda_i x_i G = PK$.
5. 2-of-2 presign 测试.
6. 2-of-2 sign + verify 测试.
7. 2-of-3 sign + verify 测试.
8. 3-of-3 sign + verify 测试.

当前明确先不写:

* key refresh / rotation signing 测试.
* BIP32 child-key signing 测试.
* malicious adversary full test suite.

## 重要实现差异

从 `simple-dkls23` 搬过来时要特别注意:

| simple-dkls23 | svarog-ecdsa-otmta |
|---|---|
| `Keyshare.s_i` | `Keystore.xi` |
| `Keyshare.public_key` | `Keystore::public_key()` |
| `seed_ot_senders` / `seed_ot_receivers` Vec | `PairPPRFSeeds.as_sender` / `as_receiver` HashMap |
| `sent_seed_list` / `rec_seed_list` Vec | `PairwiseSeeds.sent` / `rec` HashMap |
| `u8` party id | `usize` party id |
| `k256::Scalar` / `ProjectivePoint` | `svarog_secp256k1::Scalar` / `Point` |
| `Sha256` labels | 本仓库 `hash!` / Blake2b 风格 hash tags, 需要统一 |
| BIP32 offset 默认存在 | MVP 暂设 `additive_offset = 0` |

## 第一批 TODO

1. 新增 `src/dsg/mod.rs`, 并在 `src/lib.rs` 暴露 `dsg`.
2. 新增 `src/dsg/helpers.rs`, 先实现:
   * `hash_commitment_r_i`
   * `verify_commitment_r_i`
   * `mta_session_id`
   * `sign_final_session_id`
   * `sign_digest_i`
   * `derive_pairwise_zeta`
   * `lagrange_for_subset`
3. 新增 `src/dsg/soft_spoken_ot.rs`, 只实现随机 OT 扩展和测试.
4. 新增 `src/dsg/rvole.rs`, 只实现 RVOLE 和测试.
5. 新增 `src/dsg/dsg_fn.rs`, 写消息类型和空状态机骨架.
6. 等 2-of-2 sign 通过后, 再把数学笔记整理到 `src/dsg/dsg_fn.md`.

## 暂定完成定义

Signing MVP 完成时应满足:

* 给定一次 keygen 输出的 signing subset, 能完成 presign.
* 给定 32-byte message hash, 能生成并 combine 出 ECDSA signature.
* 本地 verify 通过.
* 2-of-2, 2-of-3, 3-of-3 测试通过.
* 不包含 refresh / rotation / BIP32 / malicious full security tests.
