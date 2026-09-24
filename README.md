# svarog-ecdsa-otmta

本库实现基于 OT-based MtA 的 DKLS23 门限 ECDSA，包含分布式密钥生成、
单笔签名、批量签名和重分享。
曲线接口、Shamir 份额运算和 secp256k1 实现使用 crates.io 上的 Svarog 代数库。
协议补丁和验证范围见 [PATCHES-2026.md](PATCHES-2026.md)。

## 使用

```toml
[dependencies]
svarog-ecdsa-otmta = "0.4.0"
```

调用接口从 crate 根导出，调用方提供消息传输实现，并管理会话编号与参与方配置。
哈希编码约定见 [HASH-ENCODING.md](HASH-ENCODING.md)，
签名轮次见 [SIGN-ROUNDS.md](SIGN-ROUNDS.md)。

## 版本与兼容性

`0.4.0` 从 `sign-heavy` 分支发布，密钥生成保留两轮，每次签名重新执行两轮 OT Setup，
随后完成三轮签名；单笔与批量签名均采用这一流程。
密钥生成返回的 `Keystore::aux` 为空，签名时的 OT/PPRF 资料仅用于本次调用。
`0.3.0` 来自 `patch2026`，在密钥生成阶段初始化 OT，并将资料保存到 `aux`。
两种版本的协议消息流程不同，各参与方必须使用一致的版本。

签名期初始化允许使用不含 OT 辅助资料的份额。
旧 GG18 keystore 仍需由调用方转换为本库的 `Keystore` 结构，
并确认参与方编号、门限、公钥、份额及链码一致；本库不提供旧文件格式转换器。

## 发布检查

脚本依次检查格式、测试、Clippy、API 文档、打包和发布预演，任一步失败都会停止。
测试使用四个并行测试线程，所有依赖均按 `Cargo.lock` 解析。
CI 在 `sign-heavy` 的推送及合并请求上执行相同检查。

```bash
scripts/prepublish.sh
```

提交前可用 `scripts/prepublish.sh --allow-dirty` 检查工作区修改。
正式发布前提交修改，在干净工作区完成检查，然后执行 `cargo publish --locked`。
将发布提交和 `0.4.0` 标签推送到远端，以便核对源码与 crates.io 发布包。

## 许可证

本库采用 `MIT OR Apache-2.0` 双许可证，使用者可任选其一。
完整文本分别见 [LICENSE-MIT](LICENSE-MIT) 和 [LICENSE-APACHE](LICENSE-APACHE)。
依赖库继续遵循各自的许可证。
