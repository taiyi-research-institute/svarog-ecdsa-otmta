//! 分布式密钥生成 (DKG).
//!
//! 子模块结构与笔记的对应关系:
//! * [`endemic_ot`]  - Base OT (Endemic OT 构造), 对应 `notes/03-endemic-ot.md`.
//! * [`soft_spoken`] - Build/Eval/Verify PPRF (all-but-one PRF), 对应
//!                     `notes/04-pprf.md`. 把 base OT 输出"拉伸"成签名时
//!                     SoftSpoken OT 扩展所需的 seed.
//! * [`helpers`]     - 哈希承诺 + Schnorr DLog 批量证明 (Fiat-Shamir).
//! * [`dkg_orch`]    - 4 轮 DKG 编排: VSS 承诺 / 揭示 + DLog 证明 + base OT
//!                     + PPRF + pairwise seeds. 主要对应 `notes/09-orchestration.md`
//!                     的 keygen 部分; `PairwiseSeeds` 是工程添加, 笔记未覆盖,
//!                     用于签名时构造 $\sum_i\zeta_i = 0$ 的再随机化.

mod endemic_ot;
mod helpers;
mod pprf;
pub use pprf::{SenderOTSeed, ReceiverOTSeed};

mod dkg_orch;
pub use dkg_orch::*;
