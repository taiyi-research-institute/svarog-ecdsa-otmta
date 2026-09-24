# svarog-ecdsa-otmta

本库实现基于 OT-based MtA 的 DKLS23 门限 ECDSA，包含分布式密钥生成、
单笔签名、批量签名和重分享。
曲线接口、Shamir 份额运算和 secp256k1 实现使用 crates.io 上的 Svarog 代数库。
协议补丁、消息兼容性与验证范围见 [PATCHES-2026.md](PATCHES-2026.md)。

## 使用

```toml
[dependencies]
svarog-ecdsa-otmta = "0.3.0"
```

调用接口从 crate 根导出，具体说明见生成的 API 文档。
调用方提供消息传输实现，并管理会话编号与参与方配置。
哈希编码约定见 [HASH-ENCODING.md](HASH-ENCODING.md)，
签名轮次见 [SIGN-ROUNDS.md](SIGN-ROUNDS.md)。

## 发布分支

`0.3.0` 从 `patch2026` 分支准备发布，包含 `PATCHES-2026.md` 中记录的协议补丁。
该版本的发布来源以最终提交和 `v0.3.0` 标签为准。
本地 `main` 维护的 `0.2.0` 与此分支存在差异，发布时应核对当前分支及版本。

## 发布检查

脚本检查格式、测试、Clippy、API 文档、打包和发布预演，任一步失败都会停止。
测试使用四个并行测试线程，所有依赖均按 `Cargo.lock` 解析。
打包及预演需要访问 crates.io，默认要求待打包文件已提交。

```bash
scripts/prepublish.sh
```

在提交前检查本地修改时，可显式传入 `--allow-dirty`。
该选项仅放宽打包与预演对未提交修改的限制，脚本始终保留 `--dry-run`。
CI 在 `patch2026` 的推送及合并请求上执行默认检查。

```bash
scripts/prepublish.sh --allow-dirty
```

## 正式发布

先将发布准备修改提交到 `patch2026`，在干净工作区重跑默认检查。
核对最终提交后创建 `v0.3.0` 标签，并执行下面的命令上传该版本。
发布完成后，将对应提交和标签推送到远端，确保源码可追溯。

```bash
cargo publish --locked
```

## 许可证

本库采用 `MIT OR Apache-2.0` 双许可证，使用者可任选其一。
完整文本分别见 [LICENSE-MIT](LICENSE-MIT) 和 [LICENSE-APACHE](LICENSE-APACHE)。
依赖库继续遵循各自的许可证。
