//! 有限域 $\mathbb{GF}(2^{128})$ 元素的乘法.
//!
//! 多项式 $p(x) = x^{128} + x^7 + x^2 + x + 1$ (GCM polynomial).
//! 字节序: LSB-first, 即字节 `i` 的 bit `k` 对应 $x^{8i + k}$.
//!
//! [`mult_gf2pow128`] 运行时分派:
//! * x86_64 (Windows/Linux/macOS Intel) + `pclmulqdq` → PCLMUL 路径.
//! * aarch64 (macOS M 系列 / iOS / 现代 Android arm64) + `aes` → PMULL 路径.
//! * 其他 (WASM, 32-bit ARM, 没有相应指令集的旧 x86, ...) → 软件实现.

pub(crate) fn mult_gf2pow128(a: &[u8; 16], b: &[u8; 16]) -> [u8; 16] {
    #[cfg(target_arch = "x86_64")]
    {
        if std::arch::is_x86_feature_detected!("pclmulqdq") {
            return unsafe { mult_pclmul(a, b) };
        }
    }
    #[cfg(target_arch = "aarch64")]
    {
        if std::arch::is_aarch64_feature_detected!("aes") {
            return unsafe { mult_pmull(a, b) };
        }
    }
    mult_software(a, b)
}

/// x86_64 PCLMUL 实现.
///
/// 用 4 次 `pclmulqdq` 算 $a \cdot b$ 的 256-bit carry-less 积, 然后走
/// 软件约简. 单次乘法约 ~10 cycle, 比纯软件版本 (~400+ cycle) 快约 40x.
///
/// # Safety
/// 调用方必须确保 `pclmulqdq` (隐含 `sse2`) 已可用.
#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "pclmulqdq,sse2")]
unsafe fn mult_pclmul(a: &[u8; 16], b: &[u8; 16]) -> [u8; 16] {
    use std::arch::x86_64::*;

    unsafe {
        let av = _mm_loadu_si128(a.as_ptr() as *const __m128i);
        let bv = _mm_loadu_si128(b.as_ptr() as *const __m128i);

        // 4 个 64x64 -> 128 carry-less 子积.
        // imm8[0]=0 取低 64, =1 取高 64; imm8[4] 同样作用于 b.
        let t0 = _mm_clmulepi64_si128(av, bv, 0x00); // a_lo * b_lo
        let t1 = _mm_clmulepi64_si128(av, bv, 0x01); // a_hi * b_lo
        let t2 = _mm_clmulepi64_si128(av, bv, 0x10); // a_lo * b_hi
        let t3 = _mm_clmulepi64_si128(av, bv, 0x11); // a_hi * b_hi

        // 拼成 256-bit 积:
        // P = t0 ^ (mid << 64) ^ (t3 << 128), 其中 mid = t1 ^ t2.
        let mid = _mm_xor_si128(t1, t2);
        let mid_up = _mm_slli_si128(mid, 8); // mid 低 64-bit 移到位置 64-127
        let mid_dn = _mm_srli_si128(mid, 8); // mid 高 64-bit 移到位置 0-63

        let lo = _mm_xor_si128(t0, mid_up);
        let hi = _mm_xor_si128(t3, mid_dn);

        let mut c = [0u8; 32];
        _mm_storeu_si128(c.as_mut_ptr() as *mut __m128i, lo);
        _mm_storeu_si128(c.as_mut_ptr().add(16) as *mut __m128i, hi);
        reduce_256_to_128(&mut c)
    }
}

/// aarch64 PMULL 实现.
///
/// 用 4 次 `pmull` (`vmull_p64`) 算 256-bit carry-less 积, 然后走软件约简.
///
/// # Safety
/// 调用方必须确保 `aes` (含 `pmull`, 隐含 `neon`) 已可用.
#[cfg(target_arch = "aarch64")]
#[target_feature(enable = "neon,aes")]
unsafe fn mult_pmull(a: &[u8; 16], b: &[u8; 16]) -> [u8; 16] {
    use std::arch::aarch64::*;

    unsafe {
        let av = vld1q_u8(a.as_ptr());
        let bv = vld1q_u8(b.as_ptr());

        let au = vreinterpretq_u64_u8(av);
        let bu = vreinterpretq_u64_u8(bv);

        let a_lo = vgetq_lane_u64(au, 0);
        let a_hi = vgetq_lane_u64(au, 1);
        let b_lo = vgetq_lane_u64(bu, 0);
        let b_hi = vgetq_lane_u64(bu, 1);

        let t0 = vreinterpretq_u8_p128(vmull_p64(a_lo, b_lo));
        let t1 = vreinterpretq_u8_p128(vmull_p64(a_hi, b_lo));
        let t2 = vreinterpretq_u8_p128(vmull_p64(a_lo, b_hi));
        let t3 = vreinterpretq_u8_p128(vmull_p64(a_hi, b_hi));

        let mid = veorq_u8(t1, t2);
        let zero = vdupq_n_u8(0);
        // vextq_u8(a, b, n): 输出取 (a||b) 的 [n..n+16) 字节.
        // vextq_u8(zero, mid, 8) = zero[8..16] || mid[0..8]: mid 低 8 字节移到高 8 字节位.
        let mid_up = vextq_u8(zero, mid, 8);
        // vextq_u8(mid, zero, 8) = mid[8..16] || zero[0..8]: mid 高 8 字节移到低 8 字节位.
        let mid_dn = vextq_u8(mid, zero, 8);

        let lo = veorq_u8(t0, mid_up);
        let hi = veorq_u8(t3, mid_dn);

        let mut c = [0u8; 32];
        vst1q_u8(c.as_mut_ptr(), lo);
        vst1q_u8(c.as_mut_ptr().add(16), hi);
        reduce_256_to_128(&mut c)
    }
}

/// 软件实现, 始终可用. 平台无关; 作为没有相应硬件指令时的回退.
fn mult_software(a: &[u8; 16], b_data: &[u8; 16]) -> [u8; 16] {
    const W: usize = 8;
    const T: usize = 16;

    let mut c = [0u8; T * 2];
    let mut b = [0u8; T + 1];
    b[..16].copy_from_slice(b_data);

    for k in 0..W {
        for j in 0..T {
            let mask = -(((a[j] >> k) & 0x01) as i8) as u8;
            for i in 0..T + 1 {
                c[j + i] ^= b[i] & mask;
            }
        }
        for i in (1..=T).rev() {
            b[i] = (b[i] << 1) | (b[i - 1] >> 7);
        }
        b[0] <<= 1;
    }
    reduce_256_to_128(&mut c)
}

/// 把 256-bit 无约简积折回 128-bit, 模 $p(x) = x^{128} + x^7 + x^2 + x + 1$.
/// 硬件路径用 clmul / pmull 算出 256-bit 积后, 复用同一段约简.
#[inline]
fn reduce_256_to_128(c: &mut [u8; 32]) -> [u8; 16] {
    for i in (16..=31).rev() {
        // $x^{128} \equiv x^7 + x^2 + x + 1 \pmod{p(x)}$,
        // 因此第 $i$ 字节 (位置 $8i\ldots 8i+7$, $i\ge 16$) 折回到 $(i-16, i-15)$
        // 两个字节, 错位 $\{0, 1, 2, 7\}$.
        c[i - 16] ^= c[i];
        c[i - 16] ^= c[i] << 1;
        c[i - 15] ^= c[i] >> 7;
        c[i - 16] ^= c[i] << 2;
        c[i - 15] ^= c[i] >> 6;
        c[i - 16] ^= c[i] << 7;
        c[i - 15] ^= c[i] >> 1;
    }
    let mut out = [0u8; 16];
    out.copy_from_slice(&c[..16]);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Fermat: 对 $r \in \mathrm{GF}(2^{128})^*$, $r^{2^{128}} = r$.
    /// 抓代数级错误.
    #[test]
    fn gf2_128_fermat_squaring() {
        for _ in 0..3 {
            let r: [u8; 16] = rand::random();
            let mut t = r;
            for _ in 0..128 {
                t = mult_gf2pow128(&t, &t);
            }
            assert_eq!(t, r);
        }
    }

    /// 跑分派后实际选中的实现 vs 纯软件实现, 应字节级一致.
    /// 在硬件路径生效的平台上, 这就在断言 HW == SW.
    #[test]
    fn gf2_128_hardware_matches_software() {
        for _ in 0..256 {
            let a: [u8; 16] = rand::random();
            let b: [u8; 16] = rand::random();
            assert_eq!(
                mult_gf2pow128(&a, &b),
                mult_software(&a, &b),
                "a={:?} b={:?}",
                a,
                b
            );
        }
        // 边界: 全 0, 全 1, 单比特.
        let zero = [0u8; 16];
        let ones = [0xFFu8; 16];
        assert_eq!(mult_gf2pow128(&zero, &ones), mult_software(&zero, &ones));
        assert_eq!(mult_gf2pow128(&ones, &ones), mult_software(&ones, &ones));
        for bit in 0..128 {
            let mut x = [0u8; 16];
            x[bit / 8] = 1 << (bit % 8);
            assert_eq!(mult_gf2pow128(&x, &ones), mult_software(&x, &ones));
        }
    }
}
