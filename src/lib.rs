//! `svarog-ecdsa-otmta`: 基于 OT-based MtA 的 DKLS23 门限 ECDSA 实现.
//!
//! 模块组织 (与 `notes/` 目录一一对应):
//! * [`dkg`]   - 分布式密钥生成 (Distributed Key Generation), 见 `notes/02..04`.
//! * [`dsg`]   - 分布式签名生成 (Distributed Signature Generation),
//!               见 `notes/05..09`.
//!
//! 顶层重导出 `dkg::*` 和 `dsg::*`, 调用方只需 `use svarog_ecdsa_otmta::*`.

#![allow(nonstandard_style)]

#[macro_use]
mod hash;

mod toy_messenger;

mod dkg;
pub use dkg::*;

mod dsg;
pub use dsg::*;
