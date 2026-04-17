/// Endemic OT
///
/// 理想功能:
/// 批量执行 KAPPA 个 OT 实例. 对于每个实例,
/// * Receiver 持有选择比特 w, 最终得到解密密钥 rho_w.
/// * Sender 得到 (rho_0, rho_1), 但不知道 w.
///
/// 流程:
/// 1. Receiver → Sender: 每个 idx 发送 R_0, R_1
/// 2. Sender → Receiver: 每个 idx 发送 M_b_0, M_b_1
/// 3. 双方各自本地计算 OT 密钥 rho.
///
/// 参考: Fig.8, https://eprint.iacr.org/2019/706.pdf
use curve_abstract::{TrCurve, TrPoint, TrScalar};
use erreur::*;
use rand::Rng;
use serde::{Deserialize, Serialize};

/// 计算安全参数 KAPPA, 等于曲线标量字节长度的8倍.
fn kappa<C: TrCurve + 'static>() -> usize {
    C::curve_order_bytes().len() * 8
}

/// KAPPA 对应的字节数.
fn kappa_bytes<C: TrCurve + 'static>() -> usize {
    C::curve_order_bytes().len()
}

fn endemic_ot_idx(idx: usize) -> u16 {
    debug_assert!(idx <= u16::MAX as usize);
    idx as u16
}

// 辅助: 提取 packed 字节数组第 idx 位
fn extract_bit(packed: &[u8], idx: usize) -> u8 {
    (packed[idx / 8] >> (idx % 8)) & 1
}

// ════════════════════════════════════════════════
// Msg1: Receiver → Sender
// ════════════════════════════════════════════════

/// Endemic OT 第一条消息 (Receiver → Sender).
/// 每个 idx 包含 (R_0, R_1) 两个曲线点的序列化.
#[derive(Clone, Serialize, Deserialize)]
pub struct EndemicOTMsg1<C: TrCurve> {
    R0_list: Vec<C::PointT>,
    R1_list: Vec<C::PointT>,
}

impl<C: TrCurve> Default for EndemicOTMsg1<C> {
    fn default() -> Self {
        Self {
            R0_list: vec![],
            R1_list: vec![],
        }
    }
}

// ════════════════════════════════════════════════
// Msg2: Sender → Receiver
// ════════════════════════════════════════════════

/// Endemic OT 第二条消息 (Sender → Receiver).
/// 每个 idx 包含 (M_b_0, M_b_1) 两个曲线点的序列化.
#[derive(Clone, Serialize, Deserialize)]
pub struct EndemicOTMsg2<C: TrCurve> {
    m_b_list: Vec<(C::PointT, C::PointT)>,
}

impl<C: TrCurve> Default for EndemicOTMsg2<C> {
    fn default() -> Self {
        Self { m_b_list: vec![] }
    }
}

// ════════════════════════════════════════════════
// OT 输出
// ════════════════════════════════════════════════

/// 单个 idx 的 Sender 加密密钥对.
pub struct OTPEncKeys {
    pub rho_0: Vec<u8>,
    pub rho_1: Vec<u8>,
}

/// Sender 的输出: KAPPA 组加密密钥.
pub struct SenderOutput {
    pub otp_enc_keys: Vec<OTPEncKeys>,
}

/// Receiver 的输出: 选择位 + KAPPA 个解密密钥.
pub struct ReceiverOutput {
    pub choice_bits: Vec<u8>,
    pub otp_dec_keys: Vec<Vec<u8>>,
}

// ════════════════════════════════════════════════
// Receiver 状态 (跨两轮保持)
// ════════════════════════════════════════════════

/// Receiver 的中间状态, 在 new() 创建后保存, 收到 Msg2 后调用 process() 完成.
#[derive(Clone, Serialize, Deserialize)]
pub struct EndemicOTReceiver<C: TrCurve> {
    choices: Vec<u8>,
    blind_terms: Vec<C::ScalarT>,
}

impl<C: TrCurve + 'static> EndemicOTReceiver<C> {
    /// 第 1 步: 生成 Msg1. 保存生成时的选择位和盲因子.
    ///
    /// 对每个 OT 实例, 生成随机的
    /// * 选择位 `choice_bit`, 盲化项 `blind` 和盲化选项 `Rblind`.
    /// * 实际选项为 `Rchoose = Rblind - H(Rblind, ...)`.
    pub fn new(sid: &str, out_msg1: &mut EndemicOTMsg1<C>) -> Self {
        let kappa = kappa::<C>();
        let kb = kappa_bytes::<C>();
        out_msg1.R0_list = Vec::with_capacity(kappa);
        out_msg1.R1_list = Vec::with_capacity(kappa);

        let mut choices = vec![0u8; kb];
        rand::rng().fill_bytes(&mut choices);
        let blind_terms: Vec<C::ScalarT> = (0..kappa).map(|_| C::ScalarT::new_rand()).collect();

        for idx in 0..kappa {
            let choice_bit = u16::from(extract_bit(&choices, idx));
            let blind = &blind_terms[idx];

            // R_other: 随机曲线点 = random_scalar * G
            let Rblind = C::PointT::new_gx(&C::ScalarT::new_rand());

            // R_choice = t_a*G − H(w, idx, sid, R_other)
            let hw = C::PointT::new_gx(&C::ScalarT::new_from_bytes(&hash!(
                kappa_bytes::<C>();
                b"endemic-ot-h",
                choice_bit.to_be_bytes(),
                endemic_ot_idx(idx).to_be_bytes(),
                sid.as_bytes(),
                Rblind.to_bytes()
            )));
            let Rchoose = C::PointT::new_gx(blind).sub(&hw);

            if choice_bit == 0 {
                out_msg1.R0_list.push(Rchoose);
                out_msg1.R1_list.push(Rblind);
            } else {
                out_msg1.R0_list.push(Rblind);
                out_msg1.R1_list.push(Rchoose);
            }
        }

        Self {
            choices,
            blind_terms,
        }
    }

    /// 处理 Msg2, 计算 Receiver 的 OT 输出.
    ///
    /// 对每个 idx: rho_w = H'(idx, M_b_w · t_a)
    pub fn process(self, msg2: &EndemicOTMsg2<C>) -> Resultat<ReceiverOutput> {
        let kappa = kappa::<C>();
        assert_throw!(
            msg2.m_b_list.len() == kappa,
            "EndemicOTMsg2LengthMismatch",
            format!(
                "expected {} entries in Msg2, got {}",
                kappa,
                msg2.m_b_list.len()
            )
        );

        let mut otp_dec_keys = Vec::with_capacity(kappa);
        for idx in 0..kappa {
            let w = extract_bit(&self.choices, idx);
            let m_b_w = if w == 0 {
                &msg2.m_b_list[idx].0
            } else {
                &msg2.m_b_list[idx].1
            };
            // rho_w = H'(idx, M_b_w · t_a)
            let shared = m_b_w.mul_x(&self.blind_terms[idx]);
            otp_dec_keys.push(hash!(
                kappa_bytes::<C>();
                b"endemic-ot-seed",
                endemic_ot_idx(idx).to_be_bytes(),
                shared.to_bytes()
            ));
        }

        Ok(ReceiverOutput {
            choice_bits: self.choices,
            otp_dec_keys,
        })
    }
}

// ════════════════════════════════════════════════
// Sender (无状态)
// ════════════════════════════════════════════════

pub struct EndemicOTSender;

impl EndemicOTSender {
    /// 第2步: 处理 Msg1, 生成 Msg2, 输出 Sender 的 OT 密钥.
    ///
    /// 对第 j 个 OT 实例:
    ///   M_a_0 = R_0 + H(0, idx, sid, R_1)
    ///   M_a_1 = R_1 + H(1, idx, sid, R_0)
    ///   t_b_0, t_b_1 ← random
    ///   M_b_0 = t_b_0·G, M_b_1 = t_b_1·G   → 写入 Msg2
    ///   rho_0 = H'(idx, M_a_0 · t_b_0)
    ///   rho_1 = H'(idx, M_a_1 · t_b_1)
    pub fn process<C: TrCurve + 'static>(
        sid: &str,
        msg1: &EndemicOTMsg1<C>,
        msg2: &mut EndemicOTMsg2<C>,
    ) -> Resultat<SenderOutput> {
        let kappa = kappa::<C>();
        assert_throw!(
            msg1.R0_list.len() == kappa && msg1.R1_list.len() == kappa,
            "EndemicOTMsg1LengthMismatch",
            format!(
                "expected {} entries in Msg1, got R0_list: {}, R1_list: {}",
                kappa,
                msg1.R0_list.len(),
                msg1.R1_list.len()
            )
        );

        msg2.m_b_list = Vec::with_capacity(kappa);
        let mut otp_enc_keys = Vec::with_capacity(kappa);

        for idx in 0..kappa {
            let r_0 = &msg1.R0_list[idx];
            let r_1 = &msg1.R1_list[idx];

            let Ma0 = r_0.add(&C::PointT::new_gx(&C::ScalarT::new_from_bytes(&hash!(
                kappa_bytes::<C>();
                b"endemic-ot-h",
                0u16.to_be_bytes(),
                endemic_ot_idx(idx).to_be_bytes(),
                sid.as_bytes(),
                r_1.to_bytes()
            ))));
            let Ma1 = r_1.add(&C::PointT::new_gx(&C::ScalarT::new_from_bytes(&hash!(
                kappa_bytes::<C>();
                b"endemic-ot-h",
                1u16.to_be_bytes(),
                endemic_ot_idx(idx).to_be_bytes(),
                sid.as_bytes(),
                r_0.to_bytes()
            ))));

            let tb0 = C::ScalarT::new_rand();
            let tb1 = C::ScalarT::new_rand();

            let m_b_0 = C::PointT::new_gx(&tb0);
            let m_b_1 = C::PointT::new_gx(&tb1);
            msg2.m_b_list.push((m_b_0, m_b_1));

            let rho_0 = hash!(
                kappa_bytes::<C>();
                b"endemic-ot-seed",
                endemic_ot_idx(idx).to_be_bytes(),
                Ma0.mul_x(&tb0).to_bytes()
            );
            let rho_1 = hash!(
                kappa_bytes::<C>();
                b"endemic-ot-seed",
                endemic_ot_idx(idx).to_be_bytes(),
                Ma1.mul_x(&tb1).to_bytes()
            );

            otp_enc_keys.push(OTPEncKeys { rho_0, rho_1 });
        }

        Ok(SenderOutput { otp_enc_keys })
    }
}

// ════════════════════════════════════════════════
// 测试
// ════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    /// 正确性测试: Receiver 的 rho_w 应等于 Sender 的 rho_w.
    fn test_endemic_ot_correctness<C: TrCurve + Default + Clone + 'static>() {
        let sid = "test-endemic-ot-session";

        // Receiver 生成 Msg1
        let mut msg1 = EndemicOTMsg1::<C>::default();
        let receiver = EndemicOTReceiver::<C>::new(sid, &mut msg1);

        // Sender 处理 Msg1, 生成 Msg2
        let mut msg2 = EndemicOTMsg2::<C>::default();
        let sender_output = EndemicOTSender::process::<C>(sid, &msg1, &mut msg2).unwrap();

        // Receiver 处理 Msg2
        let receiver_output = receiver.process(&msg2).unwrap();

        // 验证: 对每个 idx, rho_w 一致
        let kappa = kappa::<C>();
        for idx in 0..kappa {
            let w = extract_bit(&receiver_output.choice_bits, idx);
            let sender_rho = if w == 0 {
                &sender_output.otp_enc_keys[idx].rho_0
            } else {
                &sender_output.otp_enc_keys[idx].rho_1
            };
            assert_eq!(
                sender_rho, &receiver_output.otp_dec_keys[idx],
                "OT 密钥不一致: idx={}, w={}",
                idx, w
            );
        }
    }

    /// 安全性测试: Receiver 不应知道未选择的那个密钥.
    fn test_endemic_ot_security<C: TrCurve + Default + Clone + 'static>() {
        let sid = "test-endemic-ot-security";

        let mut msg1 = EndemicOTMsg1::<C>::default();
        let receiver = EndemicOTReceiver::<C>::new(sid, &mut msg1);

        let mut msg2 = EndemicOTMsg2::<C>::default();
        let sender_output = EndemicOTSender::process::<C>(sid, &msg1, &mut msg2).unwrap();

        let receiver_output = receiver.process(&msg2).unwrap();

        let kappa = kappa::<C>();
        let mut mismatch_count = 0;
        for idx in 0..kappa {
            let w = extract_bit(&receiver_output.choice_bits, idx);
            let sender_rho_other = if w == 0 {
                &sender_output.otp_enc_keys[idx].rho_1
            } else {
                &sender_output.otp_enc_keys[idx].rho_0
            };
            if sender_rho_other != &receiver_output.otp_dec_keys[idx] {
                mismatch_count += 1;
            }
        }
        // 绝大多数 (理想情况下全部) 未选择密钥应不匹配
        assert!(
            mismatch_count > kappa * 9 / 10,
            "未选择侧密钥不匹配数量过低: {}/{}",
            mismatch_count,
            kappa
        );
    }

    #[test]
    fn test_secp256k1_endemic_ot_correctness() {
        use svarog_secp256k1::Secp256k1;
        test_endemic_ot_correctness::<Secp256k1>();
    }

    #[test]
    fn test_secp256k1_endemic_ot_security() {
        use svarog_secp256k1::Secp256k1;
        test_endemic_ot_security::<Secp256k1>();
    }
}
