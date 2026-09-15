//! 分布式签名生成 (DSG).
//!
//! 子模块结构与笔记的对应关系:
//! * [`softspoken_ot`] - SoftSpoken OT 扩展, 对应 `notes/05-softspoken.md`.
//!                        每次签名都要重跑 (使用本次 OT Setup 生成的 PPRF seed +
//!                        新鲜 sid + 新鲜 $\boldsymbol\beta$).
//! * [`gf2pow128`]      - $\mathbb{GF}(2^{128})$ 元素乘法, SoftSpoken 一致性检查
//!                        用. 运行时分派 PCLMUL / PMULL / 软件实现.
//! * [`rvole`]          - OT-based Random VOLE (含 Sender 一致性检查), 对应
//!                        `notes/06-rvole.md` (derand + $\ell$ 路向量化, 实现
//!                        使用绑定 OT 记录的挑战与流式哈希校验） +
//!                        `notes/misc-gadget.md` (gadget 替代 $2^j$).
//! * [`helpers`]        - mta sid 派生, $R_i$ 哈希承诺, pairwise 再随机化
//!                        $\zeta_i$ (满足 $\sum_i\zeta_i=0$).
//! * [`dsg_orch`]       - 两轮 OT Setup 后的三轮签名编排, 对应 `notes/07-orchestration.md`.
//!                        2026-929：回传完整聚合点，并验证签名重构的点与之相等。

mod gf2pow128;
pub(crate) mod helpers;
mod rvole;
pub(crate) mod softspoken_ot;

mod dsg_orch;
pub use dsg_orch::*;
