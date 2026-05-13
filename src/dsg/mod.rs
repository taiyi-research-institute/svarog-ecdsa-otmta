//! 分布式签名生成 (DSG).
//!
//! 子模块结构与笔记的对应关系:
//! * [`soft_spoken_ot`] - SoftSpoken OT 扩展, 对应 `notes/05-softspoken.md`.
//!                        每次签名都要重跑 (吃 keygen 留下的 PPRF seed +
//!                        新鲜 sid + 新鲜 $\boldsymbol\beta$).
//! * [`rvole`]          - OT-based Random VOLE (含 Sender 一致性检查), 对应
//!                        `notes/06-rvole-derand.md` (单路 derand) +
//!                        `notes/07-gadget.md` (gadget 替代 $2^j$) +
//!                        `notes/08-rvole.md` ($\ell$ 路向量化, 实现走 §改进
//!                        路线: 哈希链, 用 `mu_hash` 链式哈希).
//! * [`helpers`]        - mta sid 派生, $R_i$ 哈希承诺, pairwise 再随机化
//!                        $\zeta_i$ (满足 $\sum_i\zeta_i=0$).
//! * [`dsg_orch`]       - 4 轮签名编排, 对应 `notes/09-orchestration.md`.
//!                        最后一步包含本地 ECDSA 验签自检.

mod helpers;
mod soft_spoken_ot;
mod rvole;

mod dsg_orch;
pub use dsg_orch::*;
