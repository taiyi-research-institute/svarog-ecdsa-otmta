# 项目: svarog-ecdsa-otmta

DKLS23 门限 ECDSA 的 Rust 实现 + 个人精读笔记. 主要工作是 (a) 给代码补中文注释, (b) 让代码和笔记的记号/结构对齐.

## 仓库布局

```
notes/   00..09 + misc-*  顺序读
src/
  dkg/   端到端 keygen: endemic_ot → pprf → dkg_orch
  dsg/   端到端 sign:    soft_spoken_ot → rvole → dsg_orch
  hash.rs / toy_messenger.rs / lib.rs
```

## 测试与构建

```bash
cargo build --release
cargo test  --release -- --test-threads=1                # 14/14, ~1.5s
cargo test  --release test_sign -- --test-threads=1      # 3 个端到端签名集成测试
```

端到端 sign 集成测试在 `src/dsg/dsg_orch.rs::tests` (2-of-2, 2-of-3, 3-of-3), release 模式各 0.4–0.6s, 含完整 ECDSA 验签.

## 命名/记号约定 (代码与笔记已对齐)

- **base OT 输出密钥**: $\rho$ (代码 `rho_0_list, rho_1_list`); 上标 $i$ 表 OT 实例号
- **base OT 选择位**: $\beta_i$ (= 代码 `beta_i`) = **非打孔方向 (Receiver 实际拿到的那一侧)**;
  $\bar\beta_i = 1 - \beta_i$ = 打孔方向
- **PPRF 叶子**: $\mathcal{T}_{i,x}$, 树编号 $i$, 叶子下标 $x$
- **SoftSpoken 扩展 OT 输出**: 同样记 $\rho_j$ (notes/05 Step 5), 下标空间 $j \in [L=512]$, 与 base OT 的 $i \in [\kappa=256]$ 区分
- 不再使用旧记号 $K^i_b, \mathcal{K}^b_j, x_i$ 等

## 模块状态

| 模块 | 注释 | 重构 |
|---|---|---|
| `dkg/endemic_ot.rs`     | ✅ 中文 | ✅ round1/2/3 已脱类名成模块自由函数; `EndemicOTSender` 空类删除; `EndemicOTSenderKeys = {rho_0_list, rho_1_list}` 扁平化 |
| `dkg/pprf.rs`           | ✅ 中文 | ✅ 原 `soft_spoken.rs` 改名; `PPRF.t` 拆成 `t_left/t_right` |
| `dkg/dkg_orch.rs`       | ✅ 中文 | 调用点已跟随 endemic_ot 重构 |
| `dsg/soft_spoken_ot.rs` | ✅ 中文 | ✅ 输出扁平化: `v_0/v_1/v_x` 从 `[L][OT_WIDTH][32]` → `[L][32]`; `randomize_row` 只做"破 Δ-correlation" hash; 新增 `pub fn expand_seed(sid, j, seed, width)` 给调用方按需派生多通道 |
| `dsg/rvole.rs`          | ✅ 中文 | ✅ `OT_WIDTH = L_BATCH + RHO` 常量移至此处 (应用层概念); 内部用 `expand_seed` 派生 `v_*_ext` |
| `dsg/dsg_orch.rs`       | ✅ 中文 | ✅ `sign(...)` 的 `offset: Option<Scalar>` 改为 `offset: Scalar`, 删 `unwrap_or` |

## 笔记状态

| 文件 | 状态 |
|---|---|
| `00-mta-baseot.md` ~ `02-kos15.md` | 已读, 未改 |
| `03-endemic-ot.md` | 已对齐 $\rho$ 记号 |
| `04-pprf.md`       | ✅ $K \to \rho$; $x \to \beta$; β/β̄ 语义翻转跟代码一致 (现 $\beta_i$ = base OT 选择位 = 非打孔方向; (cursor) 公式 $y_{i+1} = 2y_i + \bar{\beta}_i$ ↔ 代码 `2*yi + (1 - beta_i)`) |
| `05-softspoken.md` | ✅ base OT 接口 $K^i_b \to \rho^i_b$; Step 5 派生密钥 $\mathcal{K}^b_j \to \rho^b_j$ |
| `06-rvole-derand.md`, `07-gadget.md`, `08-rvole.md`, `09-orchestration.md` | 待审 |

## 设计决策记录

- **SoftSpoken 内部的 `randomize_row` Hash 不能省**: 它跨越 "correlated OT → random OT" 的安全分界 (否则 Δ 会通过下游消息泄漏). 放在 OT 抽象层内部, 让所有调用方拿到的就是干净的 random OT, 不必各自论证"我没漏 Δ".
- **`OT_WIDTH = L_BATCH + RHO = 3` 是应用层概念**, 属于 RVOLE 一次签名要并行的标量乘数 (`L_BATCH=2`) 加一致性检查列 (`RHO=1`). 因此从 `soft_spoken_ot.rs` 挪到 `rvole.rs`. SoftSpoken 输出回归 notes/05 Step 5 描述的"每槽一条 $\rho_j$".
- **commit msg 风格**: 用户偏好极简, 例如 `"05 softspoken"`, `"pprf notes and code"`; 但 `Co-authored-by: Copilot <223556219+Copilot@users.noreply.github.com>` 必须保留.

## 待办

- 审 `notes/06-rvole-derand.md`, `07-gadget.md`, `08-rvole.md`, `09-orchestration.md` 的记号与代码对齐
- 审 `src/dsg/rvole.rs` 与 notes/06、08 的公式编号对应是否完整
- 审 `src/dsg/dsg_orch.rs` 与 notes/09 编排步骤的对齐
