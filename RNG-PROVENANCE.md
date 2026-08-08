# 随机数溯源审计报告

作者：Fable 5， `winston-wen` 逐字多轮校对。

## 审计范围

本报告只审**我方自有代码**的随机数调用点：

| 仓库 | 范围 |
|---|---|
| `svarog-ecdsa-otmta` | 全部 `src/` |
| `svarog-algebra` | `svarog-secp256k1`、`svarog-lagrange`、`svarog-curve25519` |

`rand` / `getrandom` / glibc / Linux 内核 / CPU 硬件不在本报告范围内——那几层是公共基础设施，其原理、验证方法与参考文献见 [RNG-PRIMER.md](RNG-PRIMER.md)（下称 PRIMER），本报告引用时直接标注其节号。

**审计基准**：

| 项 | 值 |
|---|---|
| 审计基线 | 本仓库 commit `a53154b`；`svarog-algebra` commit `d4b34f3` |
| 修复引入 | `svarog-algebra` commit `618d5ba`；本仓库改动见 §4，行号以修复后为准 |
| rustc | 1.96.0，host `x86_64-unknown-linux-gnu` |
| glibc / kernel | 2.43；7.0.0-28-generic，`CONFIG_VDSO_GETRANDOM=y` |
| CPU | AMD Ryzen 7 5700X（Zen 3），`/proc/cpuinfo` 显示已启用 `rdrand` + `rdseed` 功能 |

---

## 0. 结论摘要

审计前的假设是随机数入口有三类：椭圆曲线随机标量、大整数随机、Rust 随机字节数组。实测：**密码学入口只有两类**（随机标量、随机字节数组），大整数一类不存在；另有两个非协议性入口。

| # | 入口 | 定义位置 | 用途 |
|---|---|---|---|
| 1 | `Scalar::new_rand()` | `svarog-secp256k1/src/scalar.rs:44` | 协议秘密 |
| 2 | `fill_random()` | `svarog-ecdsa-otmta/src/rng.rs` | 协议秘密 |
| 3 | `Context::new()` 的 32 字节盲化种子 | `svarog-secp256k1/src/context.rs:22` | 仅侧信道盲化 |
| 4 | `HashMap` 的 SipHash key | Rust `std`，非我方代码 | 非密码学 |
| — | ~~`rug::rand::RandState` / GMP~~ | 依赖图上存在，零调用（§1.5） | — |

**关键结论**：四个入口全部收敛到同一个函数 `getrandom::fill()` → glibc `getrandom(2)`。整个项目**只有一个熵入口**，没有自制 PRNG，没有时间戳、PID 之类的兜底路径，没有弱随机源。

**唯一严重发现**（§3.1）：`rand::rng()` 返回的 `ThreadRng` 不在 `fork(2)` 时重新播种，fork 后父子进程会产生逐字节相同的签名 nonce。**已修复并验证**（§4）。其余发现均为低危或备案性质。

---

## 1. 调用点清单

排除 `#[cfg(test)]` 后的完整清单，行号为修复后的当前状态。涉及的常量：`KAPPA = 256`，`L_BYTES = 64`，`L_PRIME_BYTES = 80`，`NUM_CHECKS = 1`。

### 1.1 `svarog-ecdsa-otmta`——随机标量

全部经由 `Scalar::new_rand()`。

| 位置 | 语义 | 单次协议内的次数 |
|---|---|---|
| [dkg_orch.rs:50](src/dkg/dkg_orch.rs#L50) | Shamir 多项式常数项 $u_i$ | 1 |
| [dkg_orch.rs:274](src/dkg/dkg_orch.rs#L274) | pairwise seed $\mathrm{seed}_{i,j}$ 的原像 | 每个 $j > i$ 一次 |
| [helpers.rs:81](src/dkg/helpers.rs#L81) | DLog Schnorr 证明的 nonce $k$ | 每个多项式系数一次 |
| [endemic_ot.rs:26](src/dkg/endemic_ot.rs#L26) | Endemic OT Receiver 盲化项 $t_b$ | 256 / 每 peer |
| [endemic_ot.rs:114-115](src/dkg/endemic_ot.rs#L114-L115) | Endemic OT Sender 的 $t_a^0, t_a^1$ | 512 / 每 peer |
| [dsg_orch.rs:57](src/dsg/dsg_orch.rs#L57) | MtA 随机分片 $\phi_i$ | 1 / 每签名 |
| [dsg_orch.rs:60](src/dsg/dsg_orch.rs#L60) | 签名 nonce 分片 $r_i$ | 1 / 每签名 |
| [dsg_orch.rs:62](src/dsg/dsg_orch.rs#L62) | $\mathrm{Com}(R_i)$ 的盲化项 | 1 / 每签名 |
| [rvole.rs:76](src/dsg/rvole.rs#L76) | RVOLE 一致性检查 $\eta^{(k)}$ | `NUM_CHECKS` = 1 |
| [dsg_batch/rvole.rs:68](src/dsg_batch/rvole.rs#L68) | 同上（batch 版） | 1 |
| [dsg_batch_orch.rs:71-72](src/dsg_batch/dsg_batch_orch.rs#L71-L72) | 批量 $\phi^{(s)}, r^{(s)}$ | `n_sigs` 各一次 |
| [dsg_batch_orch.rs:75](src/dsg_batch/dsg_batch_orch.rs#L75) | 批量承诺盲化 | `n_sigs` |
| [reshare_orch.rs:176](src/reshare/reshare_orch.rs#L176) | additive re-split 的前 $N-1$ 份 | $N-1$ |

其中 $r_i$ 与 $\phi_i$ 是全项目安全性最敏感的随机数：$r_i$ 是 ECDSA 签名 nonce 的加性分片，跨签名复用即可解出私钥。

### 1.2 `svarog-ecdsa-otmta`——随机字节数组

全部经由 [src/rng.rs](src/rng.rs) 的 `fill_random()`。

| 位置 | 长度 | 语义 |
|---|---|---|
| [dkg_orch.rs:98](src/dkg/dkg_orch.rs#L98) | 32 B | Round-1 承诺盲化 `my_com0_blind` |
| [endemic_ot.rs:25](src/dkg/endemic_ot.rs#L25) | 32 B | Endemic OT 的 256 个选择位 $w$ |
| [endemic_ot.rs:34](src/dkg/endemic_ot.rs#L34) | 32 B × 256 | hash-to-curve 的 nonce（保证 $R_{1-w}$ 离散对数未知） |
| [softspoken_ot.rs:28](src/dsg/softspoken_ot.rs#L28) | 16 B | SoftSpoken 扩展选项 $\beta^{\mathrm{ext}}$（$\hat\beta$ 的后 $S = 128$ 位） |
| [rvole.rs:32](src/dsg/rvole.rs#L32) | 64 B | RVOLE Receiver 的 $\beta \in \mathbb{B}^{L}$，$L = 512$ |
| [dsg_batch/rvole.rs:25](src/dsg_batch/rvole.rs#L25) | 64 B | 同上（batch 版） |

另有 4 处 `rand::rng()` 位于 `#[cfg(test)]`（`rvole.rs:304`、`endemic_ot.rs:309`、`softspoken_ot.rs:424`、`softspoken_ot.rs:447`），用于构造测试用的假 OT 种子。测试不 fork，不受 §3.1 影响，保持原样。

### 1.3 `svarog-algebra`

| 位置 | 语义 | 在本仓库依赖路径上 |
|---|---|---|
| `svarog-secp256k1/src/scalar.rs:44` | `Scalar::new_rand()`——§1.1 全部调用点的实现 | 是 |
| `svarog-secp256k1/src/context.rs:22` | `Context::new()` 的侧信道盲化种子，每线程一次 | 是 |
| `svarog-lagrange/src/polynomial.rs:21` | `generate_shares()` 生成 Shamir 多项式系数 $a_1 \dots a_{th-1}$ | 是 |
| `svarog-curve25519/src/scalar.rs:28` | curve25519 的 `Scalar::new_rand()` | 否 |

`polynomial.rs:21` 值得单独指出：它生成的是 Shamir 秘密分享的多项式系数，属于协议秘密，但位于上游、经泛型 `C::ScalarT::new_rand()` 调用。审计时容易漏掉，修复时本仓库也够不到——这直接决定了 §4 的修复策略。

### 1.4 不消耗熵的部分

DKLS23 的设计意图，值得备案：

* PPRF / GGM 建树（[softspoken_pprf.rs](src/dkg/softspoken_pprf.rs)）消耗零新鲜随机数，所有 $\mathcal{T}^i_y$ 由 base OT 种子经 Blake2b PRG 展开；
* SoftSpoken 扩展里的 $r_{i,x}$ 同样由 `prg_expand()`（[softspoken_ot.rs:362](src/dsg/softspoken_ot.rs#L362)）从 PPRF 叶子推出，不吃熵。

熵消耗因此集中在 Keygen 的 base OT，Sign 阶段极省（§2）。

### 1.5 依赖图上存在但零调用的路径

本仓库依赖 `rug` 1.30 → `gmp-mpfr-sys` 1.7，但 GMP 的随机数接口（`RandState` / `mpz_urandomm`）在本仓库与 `svarog-algebra` 的依赖路径上零调用。`RandState` 只出现在 `svarog-algebra` 的 `classgroup` / `cl-playground`——DMZ21 时期的弃用遗留，不在本仓库依赖图中。本仓库 `src/` 里 `rug::Integer` 仅用于 [dkg_orch.rs:45](src/dkg/dkg_orch.rs#L45) 的 `ui: Option<Integer>` 入参。

这是好结果：GMP 的随机数发生器（Mersenne Twister）不是密码学安全的，它没有参与任何密码学操作。

---

## 2. 熵预算

| 阶段 | 每方消耗 |
|---|---|
| Keygen，每对 peer | Endemic OT 主导：$256 \times (32 + 32)$ B（Receiver 侧）$+\ 512 \times 32$ B（Sender 侧）$\approx 32$ KiB |
| Keygen，与 peer 数无关 | $u_i$ + 承诺盲化 + 每系数一个 DLog nonce，$O(10^2)$ B |
| Sign，每笔签名 | 3 个标量 = 96 B |
| Sign，每 peer | $\beta$ 64 B + $\beta^{\mathrm{ext}}$ 16 B + $\eta$ 32 B ≈ 112 B |

Keygen 的 base OT 是唯一的消耗大户；签名路径极省。即使在熵受限环境（无盘嵌入式、刚启动的 VM）中，签名也不构成压力，风险集中在首次 Keygen。

---

## 3. 发现与风险

按严重度排序。

### 3.1 🔴 `ThreadRng` 不在 fork 时重新播种——已修复

`rand` 的 `ThreadRng` 是每线程一份的用户态 ChaCha12 缓存（PRIMER §4.3），其文档自述：

> `ThreadRng` is not automatically reseeded on fork.

最小复现：

```
parent pre-fork : 76dad39c59edd813
parent post-fork: 82d7a112cbe76d4e
child  post-fork: 82d7a112cbe76d4e     ← 与父进程逐字节相同
```

作为对照，vDSO 层是 fork 安全的（PRIMER §3.4），问题完全出在 `rand` 的用户态缓存。事实上，整条链上输出重复只有一种产生方式——key 与计数器同时被复制（PRIMER §5.2），而 `ThreadRng` 恰好对此不设防。

对本项目的影响：若签名节点在 `ThreadRng` 初始化之后 fork（prefork 服务器、daemonize、容器 supervisor），两个分支会产生相同的 $r_i$（§1.1）。ECDSA 的 nonce 复用直接泄露私钥。修复见 §4。

### 3.2 🟡 依赖图上有两条独立的 `rand` 栈

```
rand v0.10.1  └── svarog-ecdsa-otmta                        （本仓库 src/ 直接依赖）
rand v0.9.3   └── svarog-secp256k1 └── svarog-ecdsa-otmta   （Scalar::new_rand 所在）
```

两者各有独立的 thread-local 状态。后果：

* 任何“重播种”补救必须做两次，漏一条即前功尽弃——这是 §4 不采用 `reseed()` 方案的直接原因；
* 二进制链入两份 ChaCha12 实现（`chacha20` crate 与 `rand_chacha`）；
* 审计时容易只看 `Cargo.toml` 里的 `rand = "0.10.1"` 而漏掉 0.9.3。

建议：推动 `svarog-secp256k1` 升级到 `rand` 0.10，统一为一条栈。注意 0.9 → 0.10 的 API 更名（`OsRng` → `SysRng`，`TryRngCore` → `TryRng`），对照表见 PRIMER §4.2。

### 3.3 🟢 `Scalar::new_rand()` 的模偏差——可忽略，仅备案

`svarog-secp256k1/src/scalar.rs` 的 `new_from_bytes()` 对 256-bit 均匀采样只做一次条件减法（$x \ge n$ 时取 $x - n$），不做拒绝采样，故落在 $[0,\ 2^{256} - n)$ 的值概率翻倍：

$$2^{256} - n \approx 2^{128.35}, \qquad \text{统计距离} \approx \frac{2^{256} - n}{2^{256}} \approx 2^{-127.65}$$

远低于可利用阈值（对比 secp256k1 的 128-bit 安全强度）。无需修改。

### 3.4 🟢 失败即 panic，无静默降级

`rand` 在初始播种或再播种失败时直接 `panic!`，不存在退回时间戳、PID 之类弱种子的路径。修复新增的 `fill_random()` 与 `new_rand()` 沿用同一失败语义（`.expect("OS random number generator failure")`）。这是正确的失败模式：宁可崩溃，不用可预测的数签名。

### 3.5 🟢 未触发 `/dev/urandom` 回退路径

`getrandom` crate 仅在 `getrandom(2)` 返回 `ENOSYS` 或 `EPERM`（被 seccomp 拦截）时改读 `/dev/urandom`（PRIMER §4.1）。本机实测未触发——strace 全程零次 `/dev/urandom` 的 `openat`（§5）。部署到严格 seccomp profile 的容器时需复测：若 `getrandom` 被拦而 `/dev/urandom` 又不在 mount namespace 里，进程会直接 panic。

---

## 4. 已实施的修复（2026-08-06）

### 4.1 方案选择

未采用“fork 后补调 `rand::rng().reseed()`”，理由有二：其一，依赖调用方记得做，而 fork 可能发生在第三方库或运行时内部；其二，由 §3.2，`rand` 0.9 那条栈是 `svarog-secp256k1` 的传递依赖，本仓库根本引不到。

采用：**协议随机性彻底绕开 `ThreadRng`，直接走 OS RNG**。性能上可行的依据是 PRIMER §3.3——`getrandom(3)` 常态由 vDSO 在用户态服务，不进内核。

### 4.2 上游 `svarog-algebra`（commit `618d5ba`）

| 文件 | 改动 |
|---|---|
| `svarog-secp256k1/src/scalar.rs:44` | `Scalar::new_rand()` 改用 `OsRng` |
| `svarog-secp256k1/src/context.rs:22` | 侧信道盲化种子改用 `UnwrapErr(OsRng)` |
| `svarog-curve25519/src/scalar.rs:28` | 同样的 `new_rand()`（对称处理，不在本仓库路径上） |

第一处杠杆最大：同时覆盖 §1.1 全部 13 个调用点，以及 §1.3 那个本仓库够不到的 `polynomial.rs:21`。

`classgroup::rug_seeded_rng()` 有同样问题，但该 crate 已弃用、当前无法编译（`Cargo.lock` 锁 rand 0.10，源码仍用 0.9 API）、亦不在依赖路径上，不予处理。

### 4.3 本仓库

新增 [src/rng.rs](src/rng.rs) 作为唯一入口：

```rust
pub(crate) fn fill_random(dst: &mut [u8]) {
    SysRng
        .try_fill_bytes(dst)
        .expect("OS random number generator failure");
}
```

§1.2 的 6 个调用点全部改走它，并删除对应的 `use rand::Rng;`。

### 4.4 验证

对修复后的 `Scalar::new_rand()` 做 fork 实验：

```
parent post-fork: 24e0685348289f4c34f96abdeb4beec8f663622a0be19dfd3f0254b4a338a434
child  post-fork: 5725ff01ba67860a8d551de2884344f8e5f307b7edfe46697b97a6321ce860a7
```

父子分叉，问题消除。全量测试 22 项通过，无编译警告。

### 4.5 代价

每个随机标量从一次内存读变为一次 vDSO 调用。§5 的修复前后对照显示系统调用计数完全一致（每线程 1 次）——逐次调用被 vDSO 吸收在用户态，稳态 syscall 频率的上限由内核 reseed 周期（60 s）决定。22 项测试耗时无可观测变化。

---

## 5. 实测证据

### 5.1 全量测试的系统调用计数

```sh
strace -f -e trace=getrandom,openat -o trace.txt \
    ./target/debug/deps/svarog_ecdsa_otmta-… --test-threads=1
# test result: ok. 22 passed
```

修复前后各测一次，计数一致：

| 指标 | 修复前 | 修复后 |
|---|---|---|
| 发起 `getrandom` 的线程数 | 10 | 10 |
| 每线程 `getrandom` 次数 | 1 | 1 |
| 32 B 调用（vDSO 换 key） | 9 | 9 |
| 8 B `GRND_NONBLOCK`（`std` HashMap） | 1 | 1 |
| `/dev/urandom` 的 `openat` | 0 | 0 |
| 二进制中 `rdrand` / `rdseed` 指令 | 0 | 0 |

即：22 项测试跑完整 DKG + 签名 + reshare，消耗上万个随机标量，从内核实际取走的熵共 $9 \times 32 = 288$ 字节。修复前后计数一致的原因见 §4.5。

### 5.2 单个测试的最小闭环

```sh
strace -f -e trace=getrandom,mmap … dsg::rvole::tests::rvole_correctness
```

```
mmap(NULL, 4096, PROT_READ|PROT_WRITE, MAP_DROPPABLE|MAP_ANONYMOUS, -1, 0)  ← vDSO state
getrandom("…", 8, GRND_NONBLOCK) = 8    ← std HashMap，非密码学
getrandom("…", 32, 0) = 32              ← 全部协议随机性的唯一来源
```

整个 RVOLE 协议（512 路 OT、$\beta \in \mathbb{B}^{512}$、SoftSpoken 扩展）的全部熵来自这 32 字节。

---

## 6. 复核方法

平台层的验证手法见 PRIMER 附录 A；以下针对本仓库。

**穷举调用点**（区分生产与测试代码）：

```sh
for f in $(find src -name "*.rs"); do
    t=$(grep -n "mod tests" $f | head -1 | cut -d: -f1)
    grep -n "new_rand()\|fill_random(\|rand::rng()" $f | while IFS=: read ln rest; do
        [ -z "$t" ] || [ "$ln" -lt "$t" ] && echo "PROD  $f:$ln" || echo "test  $f:$ln"
    done
done
```

**确认依赖图上的 `rand` 栈数**：

```sh
cargo tree -i rand@0.9.3
cargo tree -i rand@0.10.1
```

**确认 GMP 随机数零调用**（应为空）：

```sh
grep -rn "RandState\|urandom\|random_below\|random_bits" --include="*.rs" src/
```

**fork 安全性**：按 §4.4，`libc::fork()` 前后各取一次 `Scalar::new_rand()` 比对；对照实验代码见 PRIMER 附录 A。
