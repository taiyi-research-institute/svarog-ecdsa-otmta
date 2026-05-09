# Birkhoff 插值

## 1. 先回顾 Lagrange 插值（rank = 0 的特例）

给定 t-1 次多项式 f(x)，如果 t 个参与方分别持有**函数值**：

```
party_i 持有 f(x_i)      （即第 0 阶导数）
```

Lagrange 插值可以恢复 f(0) = 秘密：

```
f(0) = Σ λ_i · f(x_i),  其中 λ_i = Π_{j≠i} x_j / (x_j - x_i)
```

代码中对应（`dkg.rs:1007`、`utils.rs:133`）：

```rust
// Lagrange 系数
coeff *= x_j / (x_j - x_i);
```

## 2. Birkhoff 插值的推广：每方可以持有不同阶导数

在 Birkhoff 方案中，每个参与方有一个 **rank** `r_i`（非负整数），表示该方持有多项式的**第 `r_i` 阶导数**在 `x_i` 处的求值：

```
party_i 持有 f^{(r_i)}(x_i)
```

其中 `f^{(r)}(x)` 是 f 的第 r 阶导数。

- `rank = 0` → 持有 `f(x_i)` （普通函数值，即 Lagrange 情形）
- `rank = 1` → 持有 `f'(x_i)` （一阶导数值）
- `rank = 2` → 持有 `f''(x_i)` （二阶导数值）

## 3. 代码中的映射

**Keygen 阶段**（`dkg.rs`）:

```rust
// 每方生成随机多项式 u_i(x)，t-1 次
let polynomial = Polynomial::random(rng, t - 1);

// 给自己算：f 在 (rank_i, x_i) 处的导数值
let d_i = polynomial.derivative_at(rank as usize, &x_i);
//                   ^^^^^^^^^^^^^^ 第 rank 阶导数在 x_i 处求值

// 所有人交换后，聚合为最终份额
s_i = Σ_j d_j_i   // 其中 d_j_i = u_j^{(rank_i)}(x_i)
```

所以 `s_i = F^{(rank_i)}(x_i)`，其中 `F = Σ u_j` 是联合多项式，`sk = F(0)` 是全局私钥。

**签名阶段**（`dsg.rs`）恢复时需要系数 `coeff_i` 使得：

```
sk = F(0) = Σ coeff_i · s_i = Σ coeff_i · F^{(rank_i)}(x_i)
```

- 当所有 rank = 0 时，`coeff_i` 就是标准 Lagrange 系数
- 当 rank 不全为 0 时，需要 Birkhoff 系数（由 `birkhoff_coeffs()` 计算）

代码路径（`dsg.rs:302-314`）:

```rust
let coeff = if rank_list.iter().all(|&r| r == 0) {
    get_lagrange_coeff(...)     // 快速路径：标准 Lagrange
} else {
    // get_birkhoff_coefficients(...)
    unimplemented!()            // dkls23-ll 尚未实现！
};

// 用系数乘以本方份额
sk_i = coeff * s_i + additive_offset + zeta_i;
```

**验证阶段**（`utils.rs:155-194`）验公钥时两条路径都实现了：

```rust
if rank_list.iter().all(|&r| r == 0) {
    // Lagrange: PK = Σ λ_i · S_i
} else {
    // Birkhoff: PK = Σ β_i · S_i，β_i 由 birkhoff_coeffs() 计算
    let betta_vector = birkhoff_coeffs(&params);
}
```

## 4. Birkhoff 系数的数学含义

对于参与方集合 `{(x_i, r_i)}`，Birkhoff 系数 `β_i` 满足：

```
对任意 t-1 次多项式 f：f(0) = Σ β_i · f^{(r_i)}(x_i)
```

这等价于求解一个线性方程组（Birkhoff 矩阵的逆）。当所有 `r_i = 0` 时，退化为 Vandermonde 矩阵 → Lagrange。

## 5. 为什么需要 Birkhoff？

**灵活的阈值结构**。普通 Shamir 要求所有方地位相同。Birkhoff 允许：

- 不同方持有不同"级别"的秘密信息（导数阶不同）
- 支持分层访问控制（例如：高权限方持有 f(x)，低权限方只持有 f'(x)）
- 同一个 x 坐标上可以放多个不同 rank 的份额，不会冲突

## 6. 当前实现状态

|                           | dkls23-ll                      | dkls23（生产版） |
|---------------------------|--------------------------------|------------------|
| Keygen 中 `derivative_at` | ✅ 已实现                      | ✅ 已实现        |
| 验证公钥时 Birkhoff 系数  | ✅ 调用 `birkhoff_coeffs`      | ✅               |
| 签名时 Birkhoff 系数      | ❌ `unimplemented!()`          | ✅ 已实现        |
| 实际使用                  | `assert!(ranks.all(0))` 强制全 0 | 支持非零 rank    |

`dkls23-ll` 在 keygen 入口处 `assert!(ranks.iter().all(|&r| r == 0))`，签名处 `unimplemented!()`，所以实际只支持 Lagrange。生产版 `dkls23` 完整实现了 Birkhoff。