use tfhe::prelude::*;
use tfhe::{ConfigBuilder, FheUint8, FheUint16, FheUint32, generate_keys, set_server_key};

#[test]
fn encrypted_application_workloads_match_plaintext_references() {
    let profile = std::env::var("FHE_CORRECTNESS_PROFILE").unwrap_or_else(|_| "full".to_string());
    assert!(
        profile == "full" || profile == "smoke",
        "FHE_CORRECTNESS_PROFILE must be full or smoke"
    );
    println!("FHE_CORRECTNESS_PROFILE={profile}");

    let config = ConfigBuilder::default().build();
    let (client_key, server_key) = generate_keys(config);
    set_server_key(server_key);

    assert_quantized_linear_classifier_matches_plaintext(&client_key);
    assert_qoe_mos_degradation_alarm_matches_plaintext(&client_key);
    assert_qoe_decision_tree_matches_plaintext(&client_key);
    assert_webrtc_poor_call_classifier_matches_plaintext(&client_key);
    assert_webrtc_gaze_attention_monitor_matches_plaintext(&client_key);
    if profile == "full" {
        assert_mean_matches_plaintext(&client_key);
        assert_stav360_mos_panel_matches_plaintext(&client_key);
        assert_regulatory_compliance_monitor_matches_plaintext(&client_key);
        assert_webrtc_acr_panel_matches_plaintext(&client_key);
    }
}

fn encrypt(value: u8, client_key: &tfhe::ClientKey) -> FheUint8 {
    FheUint8::try_encrypt(value, client_key).expect("u8 encryption should succeed")
}

fn decrypt(value: &FheUint8, client_key: &tfhe::ClientKey) -> u8 {
    value.decrypt(client_key)
}

fn encrypt32(value: u32, client_key: &tfhe::ClientKey) -> FheUint32 {
    FheUint32::try_encrypt(value, client_key).expect("u32 encryption should succeed")
}

fn decrypt32(value: &FheUint32, client_key: &tfhe::ClientKey) -> u32 {
    value.decrypt(client_key)
}

fn decrypt_bool(value: &tfhe::FheBool, client_key: &tfhe::ClientKey) -> bool {
    value.decrypt(client_key)
}

fn assert_quantized_linear_classifier_matches_plaintext(client_key: &tfhe::ClientKey) {
    let x0 = 12u8;
    let x1 = 7u8;
    let w0 = 5u8;
    let w1 = 3u8;
    let bias = 10u8;
    let scale_shift = 1u8;
    let threshold = 40u8;

    let expected_p0 = x0 * w0;
    let expected_p1 = x1 * w1;
    let expected_sum = expected_p0 + expected_p1;
    let expected_biased = expected_sum + bias;
    let expected_score = expected_biased >> scale_shift;
    let expected_class = expected_score > threshold;

    let enc_x0 = encrypt(x0, client_key);
    let enc_x1 = encrypt(x1, client_key);

    let enc_p0 = &enc_x0 * w0;
    let enc_p1 = &enc_x1 * w1;
    let enc_sum = &enc_p0 + &enc_p1;
    let enc_biased = &enc_sum + bias;
    let enc_score = &enc_biased >> scale_shift;
    let enc_class = enc_score.gt(threshold);

    assert_eq!(decrypt(&enc_p0, client_key), expected_p0, "encrypted x0*w0");
    assert_eq!(decrypt(&enc_p1, client_key), expected_p1, "encrypted x1*w1");
    assert_eq!(
        decrypt(&enc_sum, client_key),
        expected_sum,
        "encrypted linear sum"
    );
    assert_eq!(
        decrypt(&enc_biased, client_key),
        expected_biased,
        "encrypted biased score"
    );
    assert_eq!(
        decrypt(&enc_score, client_key),
        expected_score,
        "encrypted fixed-point shift"
    );
    assert_eq!(
        decrypt_bool(&enc_class, client_key),
        expected_class,
        "encrypted threshold predicate"
    );
}

fn assert_mean_matches_plaintext(client_key: &tfhe::ClientKey) {
    let values = [1u8, 2, 3, 4];
    let divisor = values.len() as u8;
    let mean_threshold = 1u8;

    let expected_sum: u8 = values.iter().sum();
    let expected_mean = expected_sum / divisor;
    let expected_mean_ok = expected_mean > mean_threshold;

    let encrypted_values = values.map(|v| encrypt(v, client_key));
    let enc_sum01 = &encrypted_values[0] + &encrypted_values[1];
    let enc_sum23 = &encrypted_values[2] + &encrypted_values[3];
    let enc_sum = &enc_sum01 + &enc_sum23;
    let enc_mean = &enc_sum / divisor;
    let enc_mean_ok = enc_mean.gt(mean_threshold);

    assert_eq!(expected_mean, 2, "plaintext fixture sanity check");
    assert_eq!(decrypt(&enc_sum, client_key), expected_sum, "encrypted sum");
    assert_eq!(
        decrypt(&enc_mean, client_key),
        expected_mean,
        "encrypted mean"
    );
    assert_eq!(
        decrypt_bool(&enc_mean_ok, client_key),
        expected_mean_ok,
        "encrypted mean threshold"
    );
}

fn assert_stav360_mos_panel_matches_plaintext(client_key: &tfhe::ClientKey) {
    // FeedTheDucks / Pattern2_Uniform_Mid panel from STAV360 Users_Ratings.csv
    let values = [3u8, 4, 4, 4];
    let divisor = values.len() as u8;
    let mean_threshold = 2u8;
    let variance_threshold = 0u8;

    let expected_sum: u8 = values.iter().sum();
    let expected_mean = expected_sum / divisor;
    let expected_squares: Vec<u8> = values.iter().map(|v| v * v).collect();
    let expected_ss: u8 = expected_squares.iter().sum();
    let expected_ex2 = expected_ss / divisor;
    let expected_mean_sq = expected_mean * expected_mean;
    let expected_variance = expected_ex2 - expected_mean_sq;
    let expected_mean_ok = expected_mean > mean_threshold;
    let expected_variance_ok = expected_variance > variance_threshold;

    let encrypted_values = values.map(|v| encrypt(v, client_key));
    let enc_sum01 = &encrypted_values[0] + &encrypted_values[1];
    let enc_sum23 = &encrypted_values[2] + &encrypted_values[3];
    let enc_sum = &enc_sum01 + &enc_sum23;
    let enc_mean = &enc_sum / divisor;

    let enc_squares: Vec<FheUint8> = encrypted_values.iter().map(|v| v * v).collect();
    let enc_ss01 = &enc_squares[0] + &enc_squares[1];
    let enc_ss23 = &enc_squares[2] + &enc_squares[3];
    let enc_ss = &enc_ss01 + &enc_ss23;
    let enc_ex2 = &enc_ss / divisor;
    let enc_mean_sq = &enc_mean * &enc_mean;
    let enc_variance = &enc_ex2 - &enc_mean_sq;
    let enc_mean_ok = enc_mean.gt(mean_threshold);
    let enc_variance_ok = enc_variance.gt(variance_threshold);

    assert_eq!(expected_mean, 3, "STAV360 panel mean");
    assert_eq!(expected_variance, 5, "STAV360 panel variance");
    assert_eq!(
        decrypt(&enc_mean, client_key),
        expected_mean,
        "encrypted STAV360 mean"
    );
    assert_eq!(
        decrypt(&enc_variance, client_key),
        expected_variance,
        "encrypted STAV360 variance"
    );
    assert_eq!(
        decrypt_bool(&enc_mean_ok, client_key),
        expected_mean_ok,
        "encrypted STAV360 mean threshold"
    );
    assert_eq!(
        decrypt_bool(&enc_variance_ok, client_key),
        expected_variance_ok,
        "encrypted STAV360 variance threshold"
    );
}

fn assert_regulatory_compliance_monitor_matches_plaintext(client_key: &tfhe::ClientKey) {
    // bs1_3000kbps_compliance_16 panel from MOS_BS_1_Driver_PRB_10.csv
    // (deterministic 16-row stride sample; milli-MOS at 3000 kbps).
    // All quantities fit u16 (max milli-MOS 4834; scaled counts <= 16000), so
    // the encrypted pipeline uses FheUint16 to keep the radix width minimal.
    let values_milli = [
        4834u16, 1000, 4834, 1000, 3241, 4834, 3241, 4834, 4834, 4834, 1000, 4834, 4834, 1000,
        3241, 4834,
    ];
    let poor_threshold_milli = 2000u16;
    let target_permille = 950u16;
    let n = values_milli.len() as u16;

    let expected_good_count = values_milli
        .iter()
        .filter(|m| **m > poor_threshold_milli)
        .count() as u16;
    let expected_violation = expected_good_count * 1000 < n * target_permille;

    // Encrypted pipeline: per-session good indicator, indicator sum, scaled
    // comparison against the regulatory target.
    let enc_indicators: Vec<FheUint16> = values_milli
        .iter()
        .map(|m| {
            let enc = FheUint16::try_encrypt(*m, client_key).expect("u16 encryption should succeed");
            let good = enc.gt(poor_threshold_milli);
            FheUint16::cast_from(good)
        })
        .collect();
    let mut enc_good_count = enc_indicators[0].clone();
    for indicator in &enc_indicators[1..] {
        enc_good_count = &enc_good_count + indicator;
    }
    let enc_scaled_good = &enc_good_count * 1000u16;
    let enc_violation = enc_scaled_good.lt(n * target_permille);

    assert_eq!(expected_good_count, 12, "panel fixture sanity check");
    assert!(expected_violation, "panel fixture reports a violation");
    let decrypted_good_count: u16 = enc_good_count.decrypt(client_key);
    assert_eq!(
        decrypted_good_count, expected_good_count,
        "encrypted good-session count"
    );
    assert_eq!(
        decrypt_bool(&enc_violation, client_key),
        expected_violation,
        "encrypted compliance violation flag"
    );
}

fn assert_qoe_decision_tree_matches_plaintext(client_key: &tfhe::ClientKey) {
    // bs_crossstation_poor_tree fixture: depth-2 tree fitted on
    // MOS_BS_1_Driver_PRB_10.csv, held-out sample from
    // MOS_BS_4_Driver_PRB_10.csv (row 1, 4000 kbps).
    // Oblivious evaluation: both branch predicates are computed and masked by
    // the root split, mirroring the straight-line micro-trace lowering.
    let throughput_kbps = 2792u32;
    let bitrate_kbps = 4000u32;
    let root_bitrate_threshold_kbps = 3000u32;
    let low_tput_threshold_kbps = 1928u32;
    let high_tput_threshold_kbps = 4736u32;

    let expected_hi = bitrate_kbps > root_bitrate_threshold_kbps;
    let expected_poor_low = throughput_kbps < low_tput_threshold_kbps;
    let expected_poor_high = throughput_kbps < high_tput_threshold_kbps;
    let expected_predicted_poor =
        (!expected_hi & expected_poor_low) | (expected_hi & expected_poor_high);

    let enc_throughput = encrypt32(throughput_kbps, client_key);
    let enc_bitrate = encrypt32(bitrate_kbps, client_key);

    let enc_hi = enc_bitrate.gt(root_bitrate_threshold_kbps);
    let enc_lo = !&enc_hi;
    let enc_poor_low = enc_throughput.lt(low_tput_threshold_kbps);
    let enc_poor_high = enc_throughput.lt(high_tput_threshold_kbps);
    let enc_contrib_low = &enc_lo & &enc_poor_low;
    let enc_contrib_high = &enc_hi & &enc_poor_high;
    let enc_predicted_poor = &enc_contrib_low | &enc_contrib_high;

    assert!(expected_hi, "fixture exercises the high-demand branch");
    assert!(expected_predicted_poor, "fixture is a true positive");
    assert_eq!(
        decrypt_bool(&enc_hi, client_key),
        expected_hi,
        "encrypted tree root split"
    );
    assert_eq!(
        decrypt_bool(&enc_poor_high, client_key),
        expected_poor_high,
        "encrypted high-branch predicate"
    );
    assert_eq!(
        decrypt_bool(&enc_predicted_poor, client_key),
        expected_predicted_poor,
        "encrypted tree prediction bit"
    );
}

fn assert_qoe_mos_degradation_alarm_matches_plaintext(client_key: &tfhe::ClientKey) {
    // MOS_BS_1_Driver_PRB_10.csv, row 3, 3000 kbps poor-QoE alarm fixture.
    let throughput_kbps = 1928u32;
    let bitrate_kbps = 3000u32;
    let headroom_percent = 72u32;

    let expected_capacity_score = throughput_kbps * 100;
    let expected_required_score = bitrate_kbps * headroom_percent;
    let expected_predicted_poor = expected_capacity_score < expected_required_score;

    let enc_throughput = encrypt32(throughput_kbps, client_key);
    let enc_capacity_score = &enc_throughput * 100u32;
    let enc_predicted_poor = enc_capacity_score.lt(expected_required_score);

    assert_eq!(
        decrypt32(&enc_capacity_score, client_key),
        expected_capacity_score,
        "encrypted QoE throughput headroom score"
    );
    assert_eq!(
        expected_required_score, 216000,
        "QoE required score fixture sanity check"
    );
    assert_eq!(
        decrypt_bool(&enc_predicted_poor, client_key),
        expected_predicted_poor,
        "encrypted QoE degradation predicate"
    );
}

/// WebRTC-QoE, worst test condition (TC15: 1000 ms delay, 500 ms jitter,
/// 30% packet loss): integer mean/variance and the poor-call count over the
/// 20 encrypted ACR scores of the panel. Every operation runs on ciphertexts;
/// only the aggregates and the SLA bit are decrypted.
fn assert_webrtc_acr_panel_matches_plaintext(client_key: &tfhe::ClientKey) {
    let values = [
        1u8, 3, 1, 1, 3, 2, 2, 1, 1, 1, 1, 3, 1, 1, 1, 1, 1, 3, 3, 1,
    ];
    let divisor = values.len() as u8;
    let poor_threshold = 2u8;
    let sla_threshold = 10u8;

    let expected_sum: u8 = values.iter().sum();
    let expected_mean = expected_sum / divisor;
    let expected_ss: u8 = values.iter().map(|v| v * v).sum();
    let expected_ex2 = expected_ss / divisor;
    let expected_variance = expected_ex2 - expected_mean * expected_mean;
    let expected_poor_count = values.iter().filter(|v| **v <= poor_threshold).count() as u8;
    let expected_breach = expected_poor_count > sla_threshold;

    assert_eq!(expected_sum, 32, "WebRTC-QoE worst-condition panel sum");
    assert_eq!(expected_mean, 1, "WebRTC-QoE worst-condition mean");
    assert_eq!(expected_variance, 2, "WebRTC-QoE worst-condition variance");
    assert_eq!(expected_poor_count, 15, "WebRTC-QoE poor-call count");

    let encrypted: Vec<FheUint8> = values.iter().map(|v| encrypt(*v, client_key)).collect();

    let mut enc_sum = encrypted[0].clone();
    for value in &encrypted[1..] {
        enc_sum = &enc_sum + value;
    }
    let enc_mean = &enc_sum / divisor;

    let mut enc_ss = &encrypted[0] * &encrypted[0];
    for value in &encrypted[1..] {
        enc_ss = &enc_ss + &(value * value);
    }
    let enc_ex2 = &enc_ss / divisor;
    let enc_variance = &enc_ex2 - &(&enc_mean * &enc_mean);

    let mut enc_poor_count = FheUint8::cast_from(encrypted[0].le(poor_threshold));
    for value in &encrypted[1..] {
        enc_poor_count = &enc_poor_count + &FheUint8::cast_from(value.le(poor_threshold));
    }
    let enc_breach = enc_poor_count.gt(sla_threshold);

    assert_eq!(decrypt(&enc_mean, client_key), expected_mean, "encrypted WebRTC mean");
    assert_eq!(
        decrypt(&enc_variance, client_key),
        expected_variance,
        "encrypted WebRTC variance"
    );
    assert_eq!(
        decrypt(&enc_poor_count, client_key),
        expected_poor_count,
        "encrypted WebRTC poor-call count"
    );
    assert_eq!(
        decrypt_bool(&enc_breach, client_key),
        expected_breach,
        "encrypted WebRTC SLA breach bit"
    );
}

/// WebRTC-QoE poor-call classifier: a quantized logistic model fitted
/// off-chain on the 300 human ACR labels. Weights and bias are public; the
/// session feature vector (delay, jitter, packet loss) is encrypted. Signed
/// weights are handled by comparing the positive and the negative
/// accumulation, so no signed ciphertext arithmetic is required.
fn assert_webrtc_poor_call_classifier_matches_plaintext(client_key: &tfhe::ClientKey) {
    let features = [1000u32, 500, 30];
    let weights = [5u32, 14, 947];
    let negative_total = 22575u32;
    let expected_class = true;

    let expected_positive: u32 = features
        .iter()
        .zip(weights.iter())
        .map(|(x, w)| x * w)
        .sum();
    let expected_predicted = expected_positive > negative_total;
    assert_eq!(expected_positive, 40410, "classifier positive accumulation");
    assert_eq!(expected_predicted, expected_class, "classifier decision");

    let encrypted: Vec<FheUint32> = features.iter().map(|x| encrypt32(*x, client_key)).collect();
    let mut enc_positive = &encrypted[0] * weights[0];
    for (value, weight) in encrypted[1..].iter().zip(weights[1..].iter()) {
        enc_positive = &enc_positive + &(value * *weight);
    }
    let enc_predicted = enc_positive.gt(negative_total);

    assert_eq!(
        decrypt32(&enc_positive, client_key),
        expected_positive,
        "encrypted classifier score"
    );
    assert_eq!(
        decrypt_bool(&enc_predicted, client_key),
        expected_predicted,
        "encrypted classifier decision bit"
    );
}

/// WebRTC-QoE gaze attention monitor: per-frame gaze deviation magnitudes
/// (milliradians, encoded owner-side) are compared against a public
/// threshold, counted homomorphically, and reduced to one alarm bit. No frame
/// value is decrypted; only the alarm is opened.
fn assert_webrtc_gaze_attention_monitor_matches_plaintext(client_key: &tfhe::ClientKey) {
    let deviations_milli = [
        321u16, 354, 277, 278, 277, 321, 373, 355, 358, 511, 481, 341, 404, 446, 360, 377,
    ];
    let off_center_threshold = 350u16;
    let attention_target_permille = 500u16;
    let frames = deviations_milli.len() as u16;

    let expected_off_count = deviations_milli
        .iter()
        .filter(|d| **d > off_center_threshold)
        .count() as u16;
    let expected_alarm = expected_off_count * 1000 > frames * attention_target_permille;
    assert_eq!(expected_off_count, 10, "off-centre frame count");
    assert!(expected_alarm, "gaze window raises the attention alarm");

    let enc_off_bits: Vec<FheUint16> = deviations_milli
        .iter()
        .map(|d| {
            let enc = FheUint16::try_encrypt(*d, client_key).expect("u16 encryption should succeed");
            FheUint16::cast_from(enc.gt(off_center_threshold))
        })
        .collect();
    let mut enc_off_count = enc_off_bits[0].clone();
    for bit in &enc_off_bits[1..] {
        enc_off_count = &enc_off_count + bit;
    }
    let enc_scaled_off = &enc_off_count * 1000u16;
    let enc_alarm = enc_scaled_off.gt(frames * attention_target_permille);

    let decrypted_off_count: u16 = enc_off_count.decrypt(client_key);
    assert_eq!(
        decrypted_off_count, expected_off_count,
        "encrypted off-centre frame count"
    );
    assert_eq!(
        decrypt_bool(&enc_alarm, client_key),
        expected_alarm,
        "encrypted gaze attention alarm bit"
    );
}
