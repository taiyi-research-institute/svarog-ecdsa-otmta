//! 分布式签名生成 (DSG).
//!
//! 子模块结构与笔记的对应关系:
//! * [`soft_spoken_ot`] - SoftSpoken OT 扩展, 对应 `notes/05-softspoken.md`.
//!                        每次签名都要重跑 (吃 keygen 留下的 PPRF seed +
//!                        新鲜 sid + 新鲜 $\boldsymbol\beta$).
//! * [`gf2pow128`]      - $\mathbb{GF}(2^{128})$ 元素乘法, SoftSpoken 一致性检查
//!                        用. 运行时分派 PCLMUL / PMULL / 软件实现.
//! * [`rvole`]          - OT-based Random VOLE (含 Sender 一致性检查), 对应
//!                        `notes/06-rvole.md` (derand + $\ell$ 路向量化, 实现
//!                        走哈希链变体, 用 `mu_hash` 链式哈希) +
//!                        `notes/misc-gadget.md` (gadget 替代 $2^j$).
//! * [`helpers`]        - mta sid 派生, $R_i$ 哈希承诺, pairwise 再随机化
//!                        $\zeta_i$ (满足 $\sum_i\zeta_i=0$).
//! * [`dsg_orch`]       - 4 轮签名编排, 对应 `notes/07-orchestration.md`.
//!                        最后一步包含本地 ECDSA 验签自检.

mod gf2pow128;
pub(crate) mod helpers;
mod rvole;
pub(crate) mod softspoken_ot;

mod dsg_orch;
pub use dsg_orch::*;
