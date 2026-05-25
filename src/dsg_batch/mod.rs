//! 批量分布式签名生成 (Batch DSG).
//!
//! 与 [`crate::dsg`] 的关键区别只有一处: 每对 (i, j) 之间的 RVOLE 一次性承载
//! $2N$ 个负载维度 (一笔签名 $\to$ 一对 $(r_i^{(s)}, \mathrm{sk}_i^{(s)})$,
//! $N$ 笔 $\to$ $2N$), 而 SoftSpoken OT 扩展和 $\chi_{i,j}$ 跨 $N$ 笔共享.
//!
//! 子模块结构与 [`crate::dsg`] 平行:
//! * [`rvole`]    - 变长 bsize 的批量 RVOLE.
//!                  SoftSpoken OT 那层直接复用 `dsg::softspoken_ot`.
//! * [`helpers`]  - 批量 $R_i^{(s)}$ 哈希承诺, per-sig sid 派生 ($\zeta$ 重随机化用),
//!                  R1 之后的全局 digest.
//! * [`batch_orch`] - 4 轮批量签名编排.

mod helpers;
mod rvole;

mod dsg_batch_orch;
pub use dsg_batch_orch::*;
