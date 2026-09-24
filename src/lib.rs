//! 基于 OT-based MtA 的 DKLS23 门限 ECDSA 实现。
//!
//! 本库提供分布式密钥生成、单笔签名、批量签名和重分享。
//! 调用接口从 crate 根重导出，可通过 `use svarog_ecdsa_otmta::*` 引入。
//! 协议补丁与消息兼容性说明见仓库中的 `PATCHES-2026.md`。

#![allow(nonstandard_style)]
// 协议中的矩阵和有序族沿用显式下标，便于对照公式检查。
#![allow(clippy::needless_range_loop)]

#[macro_use]
mod hash;

mod rng;

#[cfg(test)]
mod toy_messenger;

mod dkg;
pub use dkg::*;

mod dsg;
pub use dsg::*;

mod dsg_batch;
pub use dsg_batch::*;

mod reshare;
pub use reshare::*;
