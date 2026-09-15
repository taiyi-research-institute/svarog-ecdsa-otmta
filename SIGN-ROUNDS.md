# 三轮签名编排

按笔记 `07-orchestration.tex` 的第一轮交换步骤，nonce 承诺与 SoftSpoken Receiver 消息同轮发送。
SoftSpoken Receiver 的本地计算只使用会话、已有 PPRF 物料与新采样的选择串，不依赖对端的 nonce 承诺。
收齐两类消息后才计算承诺摘要，nonce 承诺的开启仍放在下一轮。

| 签名阶段 | 交换内容 |
| --- | --- |
| 第 1 轮 | nonce 承诺、SoftSpoken Receiver 消息及证明 |
| 第 2 轮 | RVOLE 回复、承诺摘要与开启、公开份额点、乘法一致性点及偏移 |
| 第 3 轮 | 部分签名；patch2026 与 sign-heavy 还携带完整聚合 nonce 点 |

单笔 sign 与批量 sign_batch 均采用相同三轮结构。
main、patch2026 在初始化后用三轮签名；sign-heavy 每次先做两轮 OT Setup，共五轮。
现有签名集成测试通过通信器计数，断言每个参与方的实际 exchange 次数，防止退回多余轮次。

消息主题和轮间结构名称已随编排调整，通信各方须使用相同版本。
keygen 的轮数及数据结构没有因本次合并而改变，OT Setup 也没有与签名消息继续合并。

`sign-heavy` 已合入 2026 年论文补丁，使用补丁的 OT 参数、记录绑定和完整 nonce 检查。
每次签名重新生成辅助资料，keygen 与 reshare 返回的 keystore.aux 仍为空。
