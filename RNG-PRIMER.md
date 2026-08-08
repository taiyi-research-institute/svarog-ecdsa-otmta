# 随机数是怎么来的：从硅片到 Rust

一篇自底向上的教材。读完应当能回答：当 Rust 代码调用 `getrandom` 或 `rand::rng()` 时，从晶体管到返回的字节数组之间发生了什么，以及每一环的安全论证是什么。

配套的审计报告见 [RNG-PROVENANCE.md](RNG-PROVENANCE.md)，只审 `svarog-ecdsa-otmta` 与 `svarog-algebra` 两个仓库的调用点。本篇讲它们脚下的公共基础设施，不涉及仓库自身代码。

**验证环境**。本文的实测数据、反汇编、源码行号均取自：

| 项 | 值 |
|---|---|
| CPU | AMD Ryzen 7 5700X（Zen 3），`rdrand` + `rdseed` 可用 |
| kernel | 7.0.0-28-generic，`CONFIG_VDSO_GETRANDOM=y` |
| glibc | Ubuntu GLIBC 2.43 |
| rustc | 1.96.0，host `x86_64-unknown-linux-gnu` |

引用的 crate 版本：`rand` 0.10.1 / 0.9.3，`rand_core` 0.9.5，`getrandom` 0.4.2 / 0.3.4。凡写行号处均可在本机 `$CARGO_HOME/registry/src/` 下复核。

---

## 0. 总览

**“从物理世界采集随机”的频率，远低于“软件消耗随机数”的频率。** 因此整条链是一串级联的确定性随机数发生器（DRBG）：每一级向下一级索要一把短种子，用密码学算法拉长成大量输出；输出到一定量或收到失效信号后，再要一把新种子。

自底向上共四级：

| 级 | 算法 | 种子来源 | 换种时机 |
|---|---|---|---|
| 硅片 | AES-256 CTR_DRBG | 片上噪声源，经调理器压缩 | AMD：至多 2048 个 32-bit 输出；Intel：至多 511 个 128-bit 块 |
| 内核 | ChaCha20，fast key erasure | 熵池（BLAKE2s 提取，含 `RDSEED`、中断时序等） | 启动初期约每 uptime/2 秒，2 分钟后固定 60 s |
| vDSO | ChaCha20，fast key erasure | `getrandom(2)` 系统调用 | 内核 generation 计数变化时 |
| Rust `ThreadRng` | ChaCha12 | `getrandom` | 每输出 64 KiB |

每一级都满足：只要其种子对攻击者未知、且所用算法是安全的 PRF，其输出与均匀随机计算不可区分。于是整条链的安全性归约到两点——**最底层种子确实含足够的熵**，和 **AES / ChaCha 没有被攻破**。第 1—4 层依次讲各级的实现，第 5 层给出整体的安全性讨论。

---

# 第 1 层：硅片

## 1.1 三段式结构

x86 CPU 内置的随机数发生器，Intel 与 AMD 都是同一个三段式流水线，直接对应 NIST SP 800-90 系列划分的三个角色：

```
噪声源 (Noise Source)  →  调理器 (Conditioner)  →  DRBG
物理不可预测              压缩为满熵                高速拉长
SP 800-90B               SP 800-90B §6.4          SP 800-90A §10.2.1
```

* **噪声源**：刻意设计得不稳定的模拟电路，输出不可预测但质量差——有偏、有相关。
* **调理器**：用密码学 MAC 把大量低质量噪声压缩成少量满熵数据。
* **DRBG**：确定性算法，把种子拉长成高速随机流。

只有第一段是物理随机，后两段都是确定性算法。

## 1.2 噪声源：两条工艺路线

这是全链唯一接触物理世界的地方，也是两家唯一的实质分歧。

**AMD：环形振荡器的时钟抖动。** 本机走这条路。出处是 AMD 白皮书 *AMD Random Number Generator*（2017-06-27），描述 RYZEN / EPYC 中 Cryptographic Co-Processor (CCP) 5.0 的 RNG：

> The RNG uses **16 separate ring oscillator chains** as a noise source. Each chain consists of a different **prime number of inverters** in a free-running configuration which capture **natural clock jitter**. The smallest chain consists of 3 inverters while the largest has 59. During each cycle of RNG operation, the 16 ring oscillators are sampled generating 16 bits of noise.

环形振荡器是奇数个反相器首尾成环：信号绕环一圈必然取反，电路无稳态，只能以“绕环一圈的传播延迟”为半周期自激振荡——不接外部时钟。传播延迟不是常数：其中温度、电压引起的是缓慢的确定性漂移，而晶体管热噪声等引起的是逐周期的随机涨落（jitter）。**对熵有贡献的只是随机分量**；它随周期数累积，使振荡相位相对采样时刻做随机游走。定时采样 16 条链的瞬时电平即得 16 bit 原始噪声。反相器个数取互不相同的素数（3 到 59），使各链固有周期两两互质，避免通过衬底耦合发生注入锁定（injection locking）——锁定即意味着 16 条链退化为 1 条。

**Intel：锁存器的亚稳态解析。** 官方文档 *Intel DRNG Software Implementation Guide*（Rev 2.2，2025-09）§3.2.1 只说到：

> The Intel hardware noise source runs asynchronously on a **self-timed circuit** and uses **transistor noise within the silicon** to output a random stream of bits.

电路级细节见 Intel 委托 Cryptography Research（今 Rambus）所做的第三方评估（Hamburg–Kocher–Marson，2012）。熵源核心是一个 set 与 reset 输入短接的 RS-NOR 锁存器：

1. 拉高 R/S，把锁存器强推到“两个输出都为 0”的非法状态；
2. 撤销 R/S，锁存器进入**亚稳态**——两个交叉耦合反相器处于对称平衡点；
3. 它最终倒向 0 或 1，倒向哪边由此刻电路中的热噪声决定。

这就是“半导体电荷热运动随机数”的电路实现：亚稳态电路是把热噪声放大成一个数字比特的放大器。该评估还指出熵源带反馈偏置，持续把电路压回平衡点附近，抵消工艺偏差造成的恒偏。

**原始噪声为何不能直接用？** AMD 白皮书给出假设：

> The RNG architecture is built assuming that each bit of noise output has a **min-entropy of 0.5 bits**, meaning that each 16-bit sample may have as little as 8 bits of entropy.

即保守假设每个原始比特只含 0.5 bit 的 min-entropy。把 256 bit 原始噪声直接当 256-bit 密钥用，实际强度只有 128 bit，且偏差结构未知。因此必须调理。

## 1.3 调理器：AES-CBC-MAC

两家参数几乎一致。AMD 原文：

> During operation, **512 total bits** of noise samples are collected and fed into an **AES-256 CBC-MAC** construct as specified in NIST SP 800-90B section 6.4.2. According to NIST's guidance, this construct produces **128-bits of "full entropy"** since the input string was considered to have 256 (2×128) bits of assessed entropy. This entire process is repeated **3 times to generate a 384-bit seed** to be used by the CTR_DRBG.

核算：512 bit 原始噪声 × 0.5 min-entropy = 256 bit 评估熵，压缩为 128 bit 输出——输入评估熵为输出长度的 2 倍，这正是 NIST 对 vetted conditioner 输出记为满熵的条件。Intel 同样是 512 → 128 bit。

调理器用密码学 MAC 而非统计学去偏（如 von Neumann 校正），原因是：统计方法只能消除已知形式的偏差，而密码学 MAC 对任意结构的偏差都有效——只要求输入的总 min-entropy 达标。

## 1.4 DRBG 与产量上限

调理器吞吐低——每收集 512 bit 原始噪声，才产出一个 128-bit 满熵数据块（§1.3 的熵账），远跟不上软件取数的需求。因此流水线末级接一个 SP 800-90A §10.2.1 的 `CTR_DRBG`，把短种子拉长成高速输出流。

`CTR_DRBG` 本质上是一个**自驱动的迭代器**。按生命周期自顶向下过一遍：

**状态与播种。** 内部状态是三元组 $(K, V, c)$：$K$ 是块密码（block cipher）的密钥；$V$ 是一个块宽（AES 下 128 bit）的计数器；$c$ 是额度计数器（标准称 reseed counter），与 $(K, V)$ 各自独立。播种就是用调理器产出的满熵数据刷新 $(K, V)$、并把 $c$ 清零（标准里种子经 update 函数混入，效果等同整体换新）。因此种子长度 = 密钥长 + 块长：AMD 用 AES-256，种子 $256 + 128 = 384$ bit——这正是 §1.3 里调理器要跑三轮、攒出 384 bit 的原因。

**每次迭代。** $V$ 自增一，输出一个块 $E_K(V)$，即 128 bit——块密码的 CTR 模式，名字的来历。注意 $V$ 的职责不是计量产出（那是 $c$ 的事），而是保证同一把 $K$ 名下喂给 $E_K$ 的输入永不重复。

**产出去向。** 迭代产出写入片上的**输出 FIFO**（AMD 原文：“…stored in a FIFO buffer. This buffer enables fast burst reads of random numbers when needed”）。`RDRAND` 从 FIFO 取数，按 16/32/64 bit 粒度消费——一个 128-bit 块对应 4 个 32-bit 值（AMD 以此粒度计数）或 2 个 64-bit 值（Intel）。指令本身不驱动迭代：Intel 文档写明 `RDRAND`/`RDSEED` 由各核微码处理、经内部总线到 DRNG 模块，指令触及的只是 FIFO。

**驱动方式：谁发起 generate 请求。** 迭代分批进行，一批在标准里叫一次 generate 请求；单批交付的输出量至多 $2^{19}$ bit，即 64 KiB = 4096 个块（SP 800-90A 表 3 的 max_number_of_bits_per_request；硬件实际的批粒度未见于文档）。标准模型里请求由实例化 DRBG 的软件发起；本硬件没有软件调用方，发起者是 DRBG 自身的控制逻辑：FIFO 有空位就执行下一批，满了就闲置，不存在“生成了放不下就丢”。

旁证：AMD 文档说 DRBG 空闲（idle）时会提前自行重播种——闲置状态确实存在。反证：若迭代永远不停，单种子的迭代额度（见下）在微秒级即耗尽。如果遇到 FIFO 被读空、迭代还没来得及补充的情况，那么 `RDRAND` 以 CF=0 报失败——§1.5 失败语义的出处。

**批尾自更新：谁调用 update。** update 是 DRBG 的内部子程序，不对外暴露；全程只有三处调用，都是 DRBG 调自己——播种、重播种、每批 generate 收尾。批尾这次的动作：多加密两到三个计数器值，用所得 keystream 整体覆盖 $(K, V)$，同时 $c$ 加一。两点澄清：

其一，被 keystream 覆盖的只有 $(K, V)$，$c$ 是独立寄存器，只做加一与清零，keystream 碰不到它。

其二，$V$ 被覆盖成随机值不妨碍后续迭代——CTR 模式的正确性只要求 “同一把 $K$ 所关联的 $V$ 不重复”，批内 $V$ 严格自增、批尾 $K$ 与 $V$ 同时换新，这个不变量恰好被维持；换了钥匙，计数器从哪个值起步都行。旧 $(K, V)$ 就地销毁，从新状态无法反推已交付的输出——标准称 backtracking resistance，§2.3 的 fast key erasure 与此同一思想。

**额度耗尽。** $c$ 到达上限后必须重新播种。计数口径标准与硬件不同：标准按 generate 请求次数计，硬件按产出量计（如 AMD 按 32-bit 值计满 2048 个即停）。到点后的行为：AMD 停止输出、等调理器攒出新种子；Intel 自动重播种，对调用方透明。

两家参数对照：

| | AMD | Intel |
|---|---|---|
| 块密码 | AES-256 | AES（密钥长度官方未给出；CRI 评估 Ivy Bridge 为 AES-128） |
| 种子长度 | 384 bit（$256 + 128$） | 官方未给出（按 AES-128 推算为 $128 + 128 = 256$ bit） |
| 单种子迭代额度 | 512 个块（按 32-bit 粒度计 2048 个值） | 511 个块（即 1022 个 64-bit `RDRAND` 值） |
| 额度耗尽后 | 停止输出，直至重新播种 | 自动重新播种，对调用方透明 |

**上限的动机。** 这些额度是为**抵抗预测**：缩短单个种子的存活窗口，使内部状态即便泄露，影响也被限制在几百个块之内。它们远严于标准本身的要求——SP 800-90A 允许每个种子响应至多 $2^{48}$ 次 generate 请求，那才是留了生日界余量的天花板（§5.3）。

## 1.5 `RDRAND` 与 `RDSEED`：取的是流水线的不同级

AMD 白皮书 “Software Visibility” 表：

| MMIO 寄存器 | 内容 | x86 指令 |
|---|---|---|
| `TRNG_OUT` | CTR_DRBG 的 32-bit 输出 | `RDRAND` |
| `TRNG_SEED` | CBC-MAC 输出的 32-bit 调理后熵 | `RDSEED` |
| `TRNG_RAW` | 16-bit 原始噪声样本 | 无（仅供统计分析） |

* `RDRAND` 取 DRBG 输出——快，几乎总能成功，但是确定性算法的产物；
* `RDSEED` 取调理器输出——慢，且常失败，因为调理器可能尚未攒够 512 bit 噪声。

Intel 侧对应关系相同；其 `RDSEED` 出自 SP 800-90C RBG3(XOR) 合规的增强型 NRBG。两条指令都以 **CF 标志位**报告成败：CF=1 有效，CF=0 表示熵源暂时供不上。Linux 的封装（`arch/x86/include/asm/archrandom.h`，本机可查）：

```c
#define RDRAND_RETRY_LOOPS	10

static inline bool __must_check rdrand_long(unsigned long *v)
{
	bool ok;
	unsigned int retry = RDRAND_RETRY_LOOPS;
	do {
		asm volatile("rdrand %[out]"
			     : "=@ccc" (ok), [out] "=r" (*v));
		if (ok)
			return true;
	} while (--retry);
	return false;
}

static inline bool __must_check rdseed_long(unsigned long *v)
{
	bool ok;
	asm volatile("rdseed %[out]"
		     : "=@ccc" (ok), [out] "=r" (*v));
	return ok;
}
```

`"=@ccc"` 是 GCC 的条件码输出约束——把 CF 取出来当布尔返回值。注意重试策略的差别：`RDRAND` 重试 10 次（Intel 推荐值），`RDSEED` 一次不中就放弃——它的失败是常态，自旋硬等没有意义。

## 1.6 在线健康检查

噪声源是模拟电路，会老化，也可能被攻击（控制温度、电压把振荡器逼入锁定）。硬件因此内建 SP 800-90B（最终版 §4.4）规定的两项连续健康测试：

* **Repetition Count**（§4.4.1）：同一 16-bit 样本连续重复超过阈值即报错；
* **Adaptive Proportion**（§4.4.2）：4096 样本窗口内同一值出现次数超过阈值即报错。

（AMD 白皮书引用的编号 §6.5.1.2 是 90B 2012 草案的编号，内容与最终版 §4.4 对应。）阈值按假定熵率（8 bit / 16-bit 样本）与误报率 $2^{-30}$ 计算。检测失败时 RNG 停止输出并向 AMD Secure Processor 发中断——宁可不出数，不出坏数。

---

# 第 2 层：内核

## 2.1 信任模型：`RDRAND` 只是输入之一

内核完全有能力把 `RDRAND` 直接转发给用户，但它不想这么做。这是因为，CPU 内置 RNG 是不可审计的黑盒，若其有缺陷或后门，从外部无法察觉。Linux 的策略是 **把它当作众多熵源之一混入自己的池子**——即便 CPU RNG 完全失效，只要其他熵源尚存，系统仍安全；反之 CPU RNG 可靠时，它显著加速初始化。

与此相关的唯一开关是启动参数 `random.trust_cpu`（现代内核默认 `true`，源码 `static bool trust_cpu __initdata = true;`）。它只影响一件事：初始化阶段是否将 `RDSEED`/`RDRAND` 提供的比特**计入**熵计数（`_credit_init_bits(arch_bits)`），从而允许 CRNG 更早就绪。无论开关如何，输出路径都经过 ChaCha20，内核从不把 CPU 指令的裸输出交给用户。

现行实现是 `drivers/char/random.c`（Jason A. Donenfeld 于 5.17/5.18 重写），文件头注释自述分六段：初始化与就绪等待；fast key erasure RNG（“crng”）；熵累积与提取；熵收集；用户态读写接口；sysctl 接口。

## 2.2 熵收集：多源汇入 BLAKE2s 池

输入池是一个 BLAKE2s 哈希状态，各路来源经 `mix_pool_bytes()` 持续搅入：

| 熵源 | 函数 |
|---|---|
| 中断时序 | `add_interrupt_randomness()` |
| 键盘鼠标 | `add_input_randomness()` |
| 磁盘 I/O 时延 | `add_disk_randomness()` |
| CPU 硬件 RNG | `arch_get_random_seed_longs()` |
| 定时器抖动（启动期兜底） | `try_to_generate_entropy()` |

从池中取种子的函数是 `extract_entropy()`：对池做 BLAKE2s finalize / derive-key，并在同一函数里主动向 CPU 索取：

```c
for (i = 0; i < ARRAY_SIZE(block.rdseed);) {
    longs = arch_get_random_seed_longs(&block.rdseed[i], ARRAY_SIZE(block.rdseed) - i);
    if (longs) { i += longs; continue; }
    longs = arch_get_random_longs(&block.rdseed[i], ARRAY_SIZE(block.rdseed) - i);
    ...
}
```

优先 `RDSEED`，取不到才退用 `RDRAND`——内核要的是未经确定性扩展的熵。`try_to_generate_entropy()` 是启动期的兜底：在多个 CPU 上互设定时器，把触发时刻相对预期的偏差当熵搅入，供无外设、无磁盘的环境完成初始化。

## 2.3 输出路径：crng 的结构

内核维护一个全局 `base_crng`（32 字节 key + generation 计数）和每 CPU 一份 per-CPU crng。所有出数都经过 `crng_fast_key_erasure()`，其核心（源码注释：生成一个 ChaCha 块，立刻用块的前半覆盖 key）：

```c
chacha20_block(chacha_state, first_block); // 出 64 字节
memcpy(key, first_block, CHACHA_KEY_SIZE); // 前 32 字节覆盖 key
memcpy(random_data, first_block + CHACHA_KEY_SIZE, random_data_len); // 后 32 字节交给调用方
memzero_explicit(first_block, sizeof(first_block));
```

这就是 Bernstein 的 **fast key erasure** 结构（2017）：交付出去的字节与留下的新 key 是同一 keystream 块**不相交的两半**，且旧 key 当场被覆盖。取数流程 `crng_make_state()`：

1. 在当前 CPU 上，若 crng 的 generation 落后于 `base_crng.generation`，先以 `base_crng.key` 做一次 fast key erasure，派生出新的 per-CPU key；
2. 再以 per-CPU key 做一次 fast key erasure：直接得到至多 32 字节输出，同时返回一个 ChaCha state——需要更长输出时调用方在它上面继续出块，用毕清零（源码注释明确要求，因为该 state 内含旧 key）。

**再播种节奏**：`crng_reseed()` 由输出路径惰性触发。启动头 2 分钟内间隔约为 uptime/2（下限 1 s），此后固定 `CRNG_RESEED_INTERVAL = 60 s`。每次 reseed 使 `base_crng.generation` 加一，并把 vDSO 侧的 generation 同步为其加一（两侧的“无效值”哨兵不同：前者 `ULONG_MAX`，后者 0，故差一）。这个 generation 计数就是第 3 层失效通知的来源。

## 2.4 `getrandom(2)` 的语义

```c
ssize_t getrandom(void *buf, size_t buflen, unsigned int flags);
```

`flags = 0`：阻塞直到 CRNG 完成初始化，此后永不阻塞——要么给合格的随机数，要么等，绝不给半成品。其余 flags：

* `GRND_NONBLOCK`：CRNG 未就绪时立刻返回 `EAGAIN`。Rust `std` 给 `HashMap` 取 SipHash key 用的就是它——哈希种子不值得为之阻塞启动；
* `GRND_INSECURE`（5.6+）：不等初始化，尽力而为地返回——仅限非密码学用途；
* `GRND_RANDOM`：历史遗留，现代内核上无实质作用。

## 2.5 三个接口的对比

| 接口 | 现代 Linux 上的行为 |
|---|---|
| `getrandom(buf, n, 0)` | 推荐。初始化前阻塞，之后永不阻塞 |
| `/dev/random` | 5.6 起语义等同 `getrandom(flags=0)`：只在初始化前阻塞，不再按熵计数阻塞 |
| `/dev/urandom` | 从不阻塞，启动早期可能返回未初始化的输出 |

三者背后是同一个 ChaCha20 CRNG。`getrandom(2)` 的优势不在随机性质量，而在：正确处理了启动早期竞态；不占文件描述符，不受 fd 耗尽、chroot、seccomp 拦 `open` 影响。

## 2.6 “熵池会不会抽干” 是个提错了的问题

流传甚广的心智模型是“熵池像水池，输出会消耗熵，抽干了要等蓄水”。这个模型在两个层面上都立不住。

**第一，输出不消耗熵。** “消耗” 这个提法，混淆了信息论熵与计算安全性：对一个 PRF 而言，只要 key 对攻击者未知，出多少数都不会让后续输出更可预测——预测输出等价于攻破 ChaCha20（完整论证见 §5.2）。这正是 Linux 5.17 删除输出侧熵计数的理论依据；`/proc/sys/kernel/random/entropy_avail` 在初始化完成后恒为 256，仅余观赏价值。

**第二，“抽干与否”不可观测。** 信息熵度量的是攻击者对内部状态的不确定性——熵越低，攻击者对状态知道得越多。而内核的熵记账从来是保守低估：各路来源实际混入的比特远多于计入的额度，计数器还封顶在 256。所以见顶不代表熵恰好是 256，账面归零也不代表熵真是零——实际上没人能测出精确的熵值。于是有意义的讨论只剩两个：攻击者多大程度上知道了状态？此后是否引入足够多的“未知”来稀释攻击者的“已知”？

由此才能正确解释 §2.2、§2.3 那套持续收集 + 60 s 重播种的机制。这些机制根本不是在“防抽干”，而是在做“状态万一泄露后的自愈”。若攻击者经由内存读取、冷启动攻击、VM 快照恢复等途径获知了某时刻的状态，只要熵源继续注入、下一次 reseed 混入了足够的未知熵，发生器就重新回到安全状态。分工因此是清晰的：

* 如果 “状态从未泄露”，那么一次 256 bit 播种，足以支撑 ChaCha20 输出无限长的安全随机数。
* 万一 “状态泄露了”，那么未来的安全靠持续补熵与 reseed 恢复，过去的输出靠 fast key erasure（§2.3）保护。

操作系统维护熵池的哲学就是：默认状态随时可能泄露。

旧模型有过实际危害：催生了“`/dev/random` 比 `/dev/urandom` 更安全”的错误建议，和在服务器上跑 `rngd` “补熵”的迷信运维。

---

# 第 3 层：glibc 与 vDSO

## 3.1 动机

系统调用不便宜——Meltdown/Spectre 缓解（KPTI 等）之后，一次用户态/内核态往返可达数百纳秒。传统解法是用户态自建 PRNG 缓存（`ThreadRng` 即是），但用户态缓存有两个经典失效场景：**fork 后父子状态相同**，与 **VM 快照回滚后状态重放**——两者都会导致输出逐字节重复。

Linux 6.11 引入的 vDSO `getrandom`（x86_64 首发，glibc 2.40 起接入）就是让内核参与管理用户态缓存：性能上常态不进内核，而 “缓存是否仍有效” 的判定权交给内核——因为内核是唯一知道 “世界变了”（reseed、fork、快照回滚）的一方。它与内核如何打交道、两个失效场景各自如何闭环，是 §3.2 的主题。

## 3.2 vDSO 是什么：在调用栈的哪里，上下游是谁

**vDSO（virtual dynamic shared object）是内核编译、随内核一起发布的一个小共享库。** 进程启动时，内核把它映射进每个进程的地址空间（`/proc/<pid>/maps` 里的 `[vdso]` 段），并经辅助向量 `AT_SYSINFO_EHDR` 把基址告诉动态链接器。它是一个普通的 ELF 共享库，可以从内存 dump 出来查符号（方法见附录 A）：

```
0000000000001340 T __vdso_getrandom@@LINUX_2.6
0000000000001340 W getrandom@@LINUX_2.6
```

关键定位：**vDSO 代码是用户态代码，它出现在调用栈里**——由发起调用的线程、在该线程自己的栈上、以非特权级执行，与普通库函数无异。特殊之处只有一点：作者是内核，因此内核可以与它约定共享数据结构和失效协议。以本仓库修复后的取数为例，完整调用栈：

```
Scalar::new_rand()        应用（svarog-secp256k1）
→ getrandom::fill()       getrandom crate
→ getrandom(3)            glibc 封装（crate 经 dlsym 拿到的正是它）
→ __vdso_getrandom        vDSO：仍是本线程、用户态、同一个栈
    比对 state->generation 与内核当前 generation：
    ├─ 一致（常态）→ 就地跑 ChaCha20 填满 buf，逐层 ret 返回 —— 全程零 syscall
    └─ 不一致 → 内嵌的 syscall 指令陷入内核，取 32 B 新 key，返回后续跑
```

可观测性与此一致：gdb / perf 抓栈能看到 `[vdso]` 栈帧；strace 看不到它——strace 只观测 syscall 边界，这正是 §3.3 里 “5 次调用只见 1 次 syscall” 的原因。

下游是 libc 的 `getrandom(3)` 封装（glibc 2.40 起接入；是否接入随 libc 而异，见 §4.1）。

上游分两种：常态下没有上游——vDSO 只读写两块内存就返回；失效时上游是真正的 `getrandom(2)`，由 vDSO 代码内嵌的 `syscall` 指令发起（§3.3 的反汇编）。

**内核与 vDSO 怎么打交道。** 全部交道只有四条（实现在内核源码 `lib/vdso/getrandom.c` 的 `__cvdso_getrandom_data()`，注释自述 “This implements a ‘fast key erasure’ RNG using ChaCha20, in the same way that the kernel's getrandom() syscall does”）：

* **代码下发**：vDSO 映像本身由内核编译、内核映射——内核把自己写的代码放进每个用户进程。

* **数据下行（常态的唯一通道）**：内核只读导出一页共享数据，内含当前 generation 计数，每次 `crng_reseed()` 将其递增（§2.3）。vDSO 每次被调都读它一次、与本线程 state 里的副本比对。所谓 “失效通知由内核掌握”，机制上没有任何通知——内核单方面发布计数，用户侧调用时自取自比。

* **调用上行（仅失效时）**：副本与当前值不一致时，vDSO 用内嵌的 `syscall` 指令调真 `getrandom(2)` 取 32 B 新 key，并把 generation 副本同步到当前值。

* **作废权**：每线程 state 页（ChaCha20 key、已出批次、generation 副本）由 glibc 按 vDSO 告知的尺寸以 `mmap(…, MAP_DROPPABLE | MAP_ANONYMOUS, …)` 分配。`MAP_DROPPABLE`（6.11 为此新增）把这块页的生死交给内核：永不写入 swap；内存压力下可直接丢弃、其后读到零页；同时被标记 `VM_WIPEONFORK | VM_DONTDUMP`——fork 时子进程页清零、不进 core dump。**内核对这块用户态缓存握有单方面作废权**，这是 `ThreadRng` 之类普通用户态缓存不具备的。

state 页被清零后 generation 副本为 0——0 是保留的无效值，与内核发布的当前值必然不匹配。于是所有作废路径（fork 抹零、内存压力丢页、内核 reseed）都汇入同一条重建逻辑。

**§3.1 的两个失效场景由此闭环：**

* **fork**：`VM_WIPEONFORK` 使子进程的 state 页为零页 → 副本 0 ≠ 当前 generation → 首次调用即 syscall 重建，旧 key 不跨 fork 存活。实验验证见 §3.4。

* **VM 快照回滚**：恢复后 guest 内所有进程的 state 页与快照时刻逐字节相同（含旧 key），用户态自身无从察觉——这一场景必须由内核侧闭环。hypervisor 经 ACPI 的 Virtual Machine Generation ID 虚拟设备（Microsoft 规范；QEMU/KVM、Hyper-V、VMware 均支持）告知内核 “世界变了”；内核 `vmgenid` 驱动检测到 ID 变化即调 `add_vmfork_randomness()`，立即重播种 crng 并递增 generation——此后任何线程首次取数都会比对失败、作废旧缓存。注意前提：hypervisor 须提供该设备，否则回滚对内核同样不可见。

出数本身与内核同款 fast key erasure：`__arch_chacha20_blocks_nostack()` 纯用户态出块；批内已消费的字节复制即清零（`memcpy_and_zero_src`）；换批时用当前 key 生成新批、并同时覆盖 key。

## 3.3 反汇编与实测

对本机 vDSO 的 `__vdso_getrandom` 反汇编，换 key 路径：

```asm
15f0:  b8 3e 01 00 00        mov    $0x13e,%eax      ; __NR_getrandom = 318
15f5:  48 8d 7b 60           lea    0x60(%rbx),%rdi  ; → state->key
15f9:  be 20 00 00 00        mov    $0x20,%esi       ; len = 32
15fe:  31 d2                 xor    %edx,%edx        ; flags = 0
1600:  0f 05                 syscall
```

另一处 `15bb…15c3` 的 `syscall` 是整体回退路径（state 不可用、flags 超出支持范围等）。这两条指令就是随机性穿越用户态/内核态边界的全部位置；`len = 32` 也解释了 strace 中 `getrandom` 调用长度清一色是 32 字节。

实测：一个连调 5 次 `getrandom(buf, 32, 0)` 的 C 程序，strace 只见 1 次系统调用——

```
mmap(NULL, 4096, …, MAP_DROPPABLE|MAP_ANONYMOUS, -1, 0) = 0x…
getrandom("\xf5\x3a…", 32, 0) = 32          ← 仅此一次
```

其余 4 次由 vDSO 在用户态服务。稳态下系统调用频率的上限由内核 reseed 周期决定：每线程至多约一分钟一次（§2.3）。

## 3.4 fork 安全性

由 §3.2 的 `MAP_DROPPABLE` 语义，fork 后子进程的 state 页是零页，generation = 0 与内核当前值不匹配，首次调用即走 syscall 重建。实测（C，直接调 `getrandom()`）：

```
parent pre-fork : 612f323e7b4c77d9
child  post-fork: 2631f2717d34a9d5
parent post-fork: 51106bebdee999c4
```

父子分叉。**直接使用 `getrandom()` 的代码无须为 fork 做任何事**——这一结论到第 4 层会成为关键对照。

---

# 第 4 层：Rust

## 4.1 `getrandom` crate：后端选择

`getrandom` 是 Rust 生态取系统随机数的标准底座，按目标三元组在编译期选后端（`src/backends.rs` 的 `cfg_if` 链）。在 `x86_64-unknown-linux-gnu` 上：

1. 显式的 `getrandom_backend = "custom" / "linux_raw" / "rdrand" / …` 均未设置，跳过；
2. `all(target_os = "linux", target_env = "")` 不匹配（本机是 `gnu`）——`linux_raw` 后端（自发裸 syscall）只服务无 libc 的目标；
3. 命中 `linux_android_with_fallback`。

该后端（`backends/linux_android_with_fallback.rs`）：

* 以 `dlsym(RTLD_DEFAULT, "getrandom")` **动态解析 libc 符号**再调用——因此享受 glibc 的 vDSO 加速；musl 目标则静态链接 `libc::getrandom` 符号（源码注释：*Use static linking to `libc::getrandom` on MUSL targets and `dlsym` everywhere else*）；
* 首次使用时以 `getrandom_fn(dangling, 0, 0)` 探测：返回 `ENOSYS`（内核过老）或 `EPERM`（被 seccomp 拦截）则标记不可用；
* 仅在不可用时回退到 `open("/dev/urandom", O_RDONLY | O_CLOEXEC)` + `read()`，短读与 `EINTR` 循环重试。

注意：随机数的实际路径随 libc 与目标配置而变（glibc 走 vDSO；是否有 vDSO 加速取决于 libc 是否接入 `__vdso_getrandom`）。做性能测量前先用 strace 确认路径（附录 A）。

## 4.2 `rand_core`：`OsRng` / `SysRng`

`rand_core` 在 `getrandom` 之上包一层 trait。0.9 → 0.10 有更名，是跨版本代码的主要坑：

| | rand 0.9 | rand 0.10 |
|---|---|---|
| 类型 | `rand::rngs::OsRng` | `rand::rngs::SysRng` |
| trait | `TryRngCore` | `TryRng` |
| 填字节 | `try_fill_bytes` | `try_fill_bytes` |
| 包成 infallible | `rand_core::UnwrapErr(OsRng)` | 同 |

实现是单行转发（rand_core 0.9.5 `src/os.rs:97`）：

```rust
fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), Self::Error> {
    getrandom::fill(dest).map_err(OsError)
}
```

**这一层无任何缓存**，每次调用都到达 libc。

## 4.3 `rand`：`ThreadRng`

`rand::rng()` 返回的 `ThreadRng` 是每线程一份的 ChaCha12 缓存：

* rand 0.10.1（`src/rngs/thread.rs:39,41`）：`type Core = chacha20::ChaChaCore<chacha20::R12, …>`，`RESEED_BLOCK_THRESHOLD = 1024` 块 × 64 B = 64 KiB；
* rand 0.9.3（`src/rngs/thread.rs:39`，`std.rs:14`）：`rand_chacha::ChaCha12Core`，阈值 `1024 * 64` 字节，同为 64 KiB。

即：线程首次使用时向 `SysRng`/`OsRng` 要 32 字节 key，此后纯内存出数，每输出 64 KiB 换一次 key。选 12 轮而非 20 轮是速度与余量的折中：已知最优密码分析到 7—7.5 轮，12 轮保有余量而吞吐约为 20 轮的 5/3；`rand` 文档自述其定位为 “fast, reasonably secure generator”。

失败语义正确：初始播种或再播种失败直接 `panic!`（`thread.rs:69,162`），不存在退回时间戳、PID 之类弱种子的路径。

## 4.4 `ThreadRng` 的 fork 陷阱

`ThreadRng` 文档明言：

> `ThreadRng` is not automatically reseeded on fork.

后果是父进程与 fork 出的子进程产生**逐字节相同**的随机数。实测（Rust，完整代码见附录 A）：

```
parent pre-fork : 76dad39c59edd813
parent post-fork: 82d7a112cbe76d4e
child  post-fork: 82d7a112cbe76d4e     ← 与父进程相同
```

对照 §3.4：vDSO 层 fork 安全，问题完全出在 `rand` 的用户态缓存。两个结论并不矛盾，恰恰划出了保护的边界——内核的作废权（§3.2）只覆盖内核托管的那块 state 页；`ThreadRng` 的 ChaCha12 状态是普通 thread-local 堆内存，fork 的语义就是逐字节复制，内核既不知道、也无权抹除。时序上更糟：`ThreadRng` 每 64 KiB 才向下触碰一次 `getrandom`，fork 后直到下次换 key 前的整个窗口，下层的失效机制根本没有执行机会。**fork 安全不沿调用栈向上传递：谁自建缓存，谁自己负责。**

对签名类应用这是致命的——ECDSA nonce 跨签名复用即泄私钥，而 fork 在部署中并不罕见（prefork 服务器、daemonize、容器 supervisor）。

两条修法：

* **补救式**：fork 后在子进程立刻调 `rand::rng().reseed()`（0.9 与 0.10 均提供）。缺点是依赖调用方记得做；且依赖树中若同时存在 rand 0.9 与 0.10 两条栈（各自独立的 thread-local），须逐一 reseed，漏一条即前功尽弃；
* **根治式**：秘密材料绕开 `ThreadRng`，直接用 `SysRng`/`OsRng`。每次调用走 `getrandom`，路径上不再存在内核作废权之外的任何缓存；且 §3.3 已证明该路径常态不进内核，开销远小于直觉。

本项目采用后者，见 [RNG-PROVENANCE.md](RNG-PROVENANCE.md) §4。

## 4.5 选型

| 场景 | 选择 |
|---|---|
| 密钥、签名 nonce、一切秘密 | `SysRng` / `OsRng` |
| 进程可能 fork | 同上（或严格管理 reseed） |
| 大批量非秘密随机（洗牌、采样、蒙特卡洛） | `ThreadRng` |
| 需要可复现（测试、基准） | `StdRng` / `ChaCha12Rng` 显式播种 |

---

# 第 5 层：全链安全性

## 5.1 一次完整调用

Rust 代码执行 `SysRng.try_fill_bytes(&mut buf)`，`buf` 为 32 字节：

1. `SysRng` → `getrandom::fill()` → 经 `dlsym` 缓存的函数指针进入 glibc `getrandom(3)`；
2. glibc 跳入 vDSO `__vdso_getrandom`，比对本线程 state 的 generation：
   * **常态**：一致——用 state 内的 key 跑 ChaCha20 填满 32 字节返回，全程零系统调用；
   * generation 落后：执行 `mov $0x13e, %eax; syscall` 进内核取 32 字节新 key，再出数；
3. 内核侧 `crng_make_state()`：per-CPU key 若落后于 `base_crng` 先派生，再以 fast key erasure 出数；
4. 若距上次 reseed 已超过间隔（稳态 60 s），`crng_reseed()` 调 `extract_entropy()`——BLAKE2s 搅拌熵池并执行 `rdseed`；
5. `RDSEED` 读取的是片上 AES-256 CBC-MAC 调理器的输出，其上游是 16 条环形振荡器链的抖动采样。

注意第 2、4 步的两个“常态不会走到”的分支：绝大多数调用止步于第 2 步的用户态 ChaCha20。这解释了实测数字——一个消耗上万个随机标量的门限 ECDSA 测试套件，10 个线程各只发生 1 次 `getrandom` 系统调用，从内核共取走 288 字节。

## 5.2 两次调用的输出会不会相关

要区分两个层面。

**信息论层面：必然相关。** 从 32 字节种子拉出的任意长输出，联合 min-entropy 不超过 256 bit——存在一个极短描述（key + 计数器）能重构全部输出。这种相关性客观存在，但提取它需要先恢复 key。

**计算层面：不可检测。** 各级的安全定义都是与均匀分布**计算不可区分**（在 “ChaCha / AES 是 PRF” 的假设下）。任何“检验两次输出是否相关”的多项式时间程序，本身就是一个区分器，其优势被 PRF 优势上界压住。具体到实现：

* **内核与 vDSO**：由 §2.3，交付出去的字节与留作新 key 的字节是同一 keystream 块不相交的两半，调用方从未见过任何 key 材料；旧 key 出块后即被覆盖，因此还有**前向安全**——此刻攻破内存也无法回溯已交付的输出。
* **`ThreadRng`**：同一 key 下按计数器连续出块。计算上同样不可区分，但**没有前向安全**：转储状态（key + 计数器）可重算当前 64 KiB 周期内已输出的全部字节；跨周期则不可，因为新周期的 key 来自操作系统而非旧 key。

**计算上可检测的相关只有一种来源：key 与计数器同时复用**——此时两份输出不是“相关”，而是逐字节相同。现实中的触发方式恰是 §3.1 列的两个：fork 与 VM 快照回滚。vDSO 以 `MAP_DROPPABLE` 清零 + generation 校验设防（§3.2/§3.4）；`ThreadRng` 未设防（§4.4）。换言之，这条链上“输出相关”不会自发产生，只会由状态复制事故产生。

## 5.3 生日界与各层换 key 的真实动机

**生日界**：从 $N$ 个值中独立均匀取 $q$ 个，出现重复的概率约 $q^2 / (2N)$——$q \approx \sqrt{N}$ 时重复即大概率发生（365 天取 23 人即过半，因 $\sqrt{365} \approx 19$）。

它与 DRBG 的关联在 **PRP 与 PRF 的差距**。AES 在固定 key 下是 128-bit 上的置换（PRP）：CTR 模式下输入块互不相同，输出块**永不碰撞**。而真随机序列在 $q$ 个块后以约 $q^2 / 2^{129}$ 的概率出现碰撞。于是“收集输出、查找重复块”就是一个区分器：无重复指向 AES-CTR，有重复指向真随机。其优势即 PRP/PRF switching lemma 的上界 $q^2 / 2^{n+1}$；代入 $q = 2^{64}$（即 $2^{68}$ 字节）时优势达 $1/2$。这就是 AES-CTR 类构造的生日上限。

ChaCha 没有这一项：其块函数末尾把初始状态按字加回轮变换结果（feed-forward，类似 Davies–Meyer），构造出的不是置换而直接是 PRF，输出块该碰撞就碰撞，与真随机一致。（ChaCha 的输出上限来自计数器宽度，与生日界无关：IETF 版 32-bit 计数器限单 (key, nonce) 出 256 GiB；DJB 原版计数器为 64 bit。）

据此可以校准各层换 key 阈值的真实动机：

| 层 | 实际阈值 | 动机 |
|---|---|---|
| 硬件 AES CTR_DRBG | 约 500 个块（§1.4） | 预测抵抗：压缩状态泄露的影响窗口 |
| SP 800-90A 的规定上限 | $2^{48}$ 次请求 | 标准天花板，内含生日界余量 |
| 内核 / vDSO ChaCha20 | 每次出数换 key；种子 60 s 一换 | 前向安全 + fork/快照失效 |
| `ThreadRng` ChaCha12 | 64 KiB | 限制状态泄露的回溯窗口 |

**没有任何一层的实际阈值是被生日界卡住的**——实际值都比生日界要求严格若干个数量级，动机全在状态泄露与前向安全一侧。

---

# 附录 A：自行验证

本文结论均可在自己的机器上复核。

**CPU 支持**：

```sh
grep -m1 ^flags /proc/cpuinfo | tr ' ' '\n' | grep -E '^(rdrand|rdseed)$'
```

**内核与 glibc 支持**：

```sh
grep VDSO_GETRANDOM /boot/config-$(uname -r)      # CONFIG_VDSO_GETRANDOM=y
ldd --version | head -1                            # glibc ≥ 2.40
```

**数系统调用**（`-f` 必加，随机数常发生在工作线程）：

```sh
strace -f -e trace=getrandom,mmap,openat ./your-binary
```

三个看点：`getrandom` 的次数与长度；有无 `MAP_DROPPABLE` 的 mmap（有则走了 vDSO）；有无 `/dev/urandom` 的 `openat`（有则 vDSO/syscall 路径不可用，触发了回退）。

**dump vDSO 并反汇编**：

```python
with open('/proc/self/maps') as f:
    for line in f:
        if '[vdso]' in line:
            start, end = [int(x, 16) for x in line.split()[0].split('-')]
            break
with open('/proc/self/mem', 'rb', buffering=0) as m:
    m.seek(start)
    open('vdso.so', 'wb').write(m.read(end - start))
```

```sh
nm -D vdso.so | grep getrandom
objdump -d --start-address=0x1340 --stop-address=0x1700 vdso.so | grep -B4 syscall
```

**fork 实验**。C 版验证 vDSO 层（预期父子不同）：

```c
#include <sys/random.h>
#include <unistd.h>
#include <stdio.h>
int main(void) {
    unsigned char b[8];
    getrandom(b, 8, 0);                       /* 先在父进程建立 vDSO state */
    fork();
    getrandom(b, 8, 0);
    for (int i = 0; i < 8; i++) printf("%02x", b[i]);
    puts("");
}
```

Rust 版验证 `ThreadRng` 层（未修复时预期父子相同）：

```rust
use rand::Rng;
fn main() {
    let mut b = [0u8; 8];
    rand::rng().fill_bytes(&mut b);           // 先在父进程初始化 ThreadRng
    unsafe { libc::fork() };
    rand::rng().fill_bytes(&mut b);
    println!("{}", b.iter().map(|x| format!("{x:02x}")).collect::<String>());
}
```

**内核 reseed 参数**：`drivers/char/random.c` 中 `CRNG_RESEED_START_INTERVAL`（HZ，即 1 s）与 `CRNG_RESEED_INTERVAL`（60 × HZ）。

---

# 附录 B：参考文献

**硬件**

* AMD，*AMD Random Number Generator*，2017-06-27。章节 Noise Source / Entropy Conditioner / Entropy Health Checks / DRBG / Software Visibility。
  <https://www.amd.com/content/dam/amd/en/documents/processor-tech-docs/white-papers/amd-random-number-generator.pdf>
* Intel，*Intel Digital Random Number Generator (DRNG) Software Implementation Guide*，Rev 2.2，2025-09。§3.2.1 Entropy Source，§3.2.2 DRBG，§3.3.1 RDRAND，§3.3.2 RDSEED，§4.0 Standards Compliance。
  <https://cdrdv2-public.intel.com/864722/drng-software-implementation-guide.pdf>
* M. Hamburg, P. Kocher, M. E. Marson，*Analysis of Intel's Ivy Bridge Digital Random Number Generator*，Cryptography Research Inc.，2012-03-12。RS-NOR 锁存器亚稳态与热噪声的电路级描述。
  <https://www.rambus.com/wp-content/uploads/2015/08/Intel_TRNG_Report_20120312.pdf>
* T. Shrimpton, R. S. Terashima，*A Provable-Security Analysis of Intel's Secure Key RNG*，IACR ePrint 2014/504。
  <https://eprint.iacr.org/2014/504.pdf>

**标准**

* NIST SP 800-90A Rev.1。§10.2.1 CTR_DRBG；reseed_interval 上限 $2^{48}$。
* NIST SP 800-90B（2018 最终版）。§6.4 vetted conditioning（CBC-MAC）；§4.4 连续健康测试。AMD 白皮书引用的 §6.5.1.2 为 2012 草案编号。
* NIST SP 800-90C。RBG3(XOR)。
* FIPS-197（AES）；NIST SP 800-38A（CBC-MAC）。

**内核**

* `drivers/char/random.c`——`crng_fast_key_erasure()`、`crng_make_state()`、`extract_entropy()`、`crng_reseed()`、`try_to_generate_entropy()`。
* `lib/vdso/getrandom.c`——`__cvdso_getrandom_data()`，Linux 6.11 起。
* `drivers/virt/vmgenid.c`——VM 快照回滚的内核侧感知（ACPI Virtual Machine Generation ID → `add_vmfork_randomness()`），Linux 5.18 起。
* `arch/x86/include/asm/archrandom.h`——`rdrand_long()` / `rdseed_long()`。
* J. A. Donenfeld，*mm: add MAP_DROPPABLE for designating always lazily freeable mappings*（Linux 6.11 合入；fork 清零、不入 swap、不入 core dump 的语义出处）。
  <https://lore.kernel.org/linux-mm/20240712014009.281406-2-Jason@zx2c4.com/>
* LWN，*Implement getrandom() in vDSO*。<https://lwn.net/Articles/980272/>
* `getrandom(2)` man page。<https://man7.org/linux/man-pages/man2/getrandom.2.html>
* D. J. Bernstein，*Fast-key-erasure random-number generators*，2017-07-23。<https://blog.cr.yp.to/20170723-random.html>

**Rust**

* `rand` 0.10.1：`src/rngs/thread.rs`；`rand` 0.9.3：`src/rngs/thread.rs`、`src/rngs/std.rs`。
* `rand_core` 0.9.5：`src/os.rs`。
* `getrandom` 0.4.2 / 0.3.4：`src/backends.rs`、`src/backends/linux_android_with_fallback.rs`、`src/utils/sys_fill_exact.rs`。
* The Rust Rand Book。<https://rust-random.github.io/book/guide-rngs.html>
