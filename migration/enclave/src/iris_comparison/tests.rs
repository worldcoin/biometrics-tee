// Expected scores are exactly representable binary fractions.
#![allow(clippy::float_cmp)]

use super::*;

fn eye(code: &[u8], mask: &[u8]) -> EyeResult {
    EyeResult {
        iris_code: STANDARD.encode(code),
        mask_code: STANDARD.encode(mask),
        ..EyeResult::default()
    }
}

#[test]
fn counts_only_mutually_valid_differences() {
    let old = eye(&[0; TEMPLATE_BYTES], &[0xf0; TEMPLATE_BYTES]);
    let new = eye(&[0x90; TEMPLATE_BYTES], &[0xa0; TEMPLATE_BYTES]);
    let comparison = compare_eye(Some((&old.iris_code, &old.mask_code)), Some(&new), "v2.1");
    let zero = comparison.zero_shift.unwrap();
    assert_eq!(comparison.old_valid_bits, Some(6400));
    assert_eq!(comparison.new_valid_bits, Some(3200));
    assert_eq!(zero.common_valid_bits, 3200);
    assert_eq!(zero.differing_bits, 1600);
    assert_eq!(zero.hamming_distance, 0.5);
    assert_eq!(comparison.rotation_adjusted.unwrap().rotation_columns, 0);
}

#[test]
fn identical_and_opposite_codes_have_expected_distances() {
    let mask = vec![255; TEMPLATE_BYTES];
    let old = eye(&[0; TEMPLATE_BYTES], &mask);
    for (fill, distance) in [(0, 0.0), (255, 1.0)] {
        let new = eye(&[fill; TEMPLATE_BYTES], &mask);
        let result = compare_templates(Some((&old.iris_code, &old.mask_code)), Some(&new), "v2.1")
            .unwrap_or_else(|_| panic!("valid input"));
        for score in [
            result.zero_shift.unwrap(),
            result.rotation_adjusted.unwrap(),
        ] {
            assert_eq!(score.hamming_distance, distance);
            assert_eq!(score.rotation_columns, 0);
            assert_eq!(score.common_valid_bits, 12800);
        }
    }
}

fn set_bit(bytes: &mut [u8], index: usize) {
    bytes[index / 8] |= 1 << (7 - index % 8);
}

#[test]
fn rotation_rolls_columns_with_masks_and_wraps_each_row() {
    let mut source_code = vec![0; TEMPLATE_BYTES];
    let mut source_mask = vec![0; TEMPLATE_BYTES];
    let mut new_code = vec![0; TEMPLATE_BYTES];
    let mut new_mask = vec![0; TEMPLATE_BYTES];
    // The regenerated template is shifted right by one column, including a row-edge wrap.
    for row in 0..ROWS {
        let column = if row % 2 == 0 { COLUMNS - 1 } else { 7 };
        for phase in 0..BITS_PER_COLUMN {
            let old = (row * COLUMNS + column) * BITS_PER_COLUMN + phase;
            let new = (row * COLUMNS + (column + 1) % COLUMNS) * BITS_PER_COLUMN + phase;
            set_bit(&mut source_mask, old);
            set_bit(&mut new_mask, new);
            if phase % 2 == 0 {
                set_bit(&mut source_code, old);
                set_bit(&mut new_code, new);
            }
        }
    }
    let old = eye(&source_code, &source_mask);
    let new = eye(&new_code, &new_mask);
    let result = compare_eye(Some((&old.iris_code, &old.mask_code)), Some(&new), "v2.1");
    assert!(result.zero_shift.is_none());
    let best = result.rotation_adjusted.unwrap();
    assert_eq!(best.rotation_columns, -1);
    assert_eq!(best.common_valid_bits, 64);
    assert_eq!(best.hamming_distance, 0.0);
}

#[test]
fn unavailable_comparisons_are_explicit_and_finite() {
    let old = eye(&[0; TEMPLATE_BYTES], &[0; TEMPLATE_BYTES]);
    let valid = eye(&[255; TEMPLATE_BYTES], &[255; TEMPLATE_BYTES]);
    let bad = EyeResult {
        iris_code: "!".repeat(TEMPLATE_BYTES.div_ceil(3) * 4),
        ..valid.clone()
    };
    let short = EyeResult {
        mask_code: STANDARD.encode([0; TEMPLATE_BYTES - 1]),
        ..valid.clone()
    };
    for (source, worker, version, status) in [
        (None, Some(&valid), "v2.1", "missing_source"),
        (
            Some((&old.iris_code, &old.mask_code)),
            None,
            "v2.1",
            "missing_worker",
        ),
        (
            Some((&old.iris_code, &old.mask_code)),
            Some(&valid),
            "v3",
            "unsupported_version",
        ),
        (
            Some((&old.iris_code, &old.mask_code)),
            Some(&bad),
            "v2.1",
            "invalid_encoding",
        ),
        (
            Some((&old.iris_code, &old.mask_code)),
            Some(&short),
            "v2.1",
            "invalid_length",
        ),
        (
            Some((&old.iris_code, &old.mask_code)),
            Some(&valid),
            "v2.1",
            "no_valid_overlap",
        ),
    ] {
        let comparison = compare_eye(
            source.map(|(c, m)| (c.as_str(), m.as_str())),
            worker,
            version,
        );
        let json = serde_json::to_value(comparison).unwrap();
        assert_eq!(json["status"], status);
        assert!(json["zero_shift"].is_null());
        assert!(json["rotation_adjusted"].is_null());
    }
}

#[test]
fn compares_eyes_independently_and_preserves_version_provenance() {
    let valid = eye(&[0; TEMPLATE_BYTES], &[255; TEMPLATE_BYTES]);
    let source = IrisCodes {
        iris_version: Some("2.10.0".into()),
        left_iris_code: Some(valid.iris_code.clone()),
        left_mask_code: Some(valid.mask_code.clone()),
        right_iris_code: None,
        right_mask_code: None,
    };
    let worker = MigrationResult {
        iris_code_version: "v2.1".into(),
        left_iris: Some(valid.clone()),
        right_iris: Some(valid),
        ..MigrationResult::default()
    };
    let json = serde_json::to_value(Comparison::new(Some(&source), &worker)).unwrap();
    assert_eq!(json["source_iris_version"], "2.10.0");
    assert_eq!(json["worker_iris_code_version"], "v2.1");
    assert_eq!(json["left"]["zero_shift"]["hamming_distance"], 0.0);
    assert_eq!(json["right"]["status"], "missing_source");
}

#[test]
fn searches_both_directions_including_the_rotation_limit() {
    let mask = vec![255; TEMPLATE_BYTES];
    let mut source_code = vec![0; TEMPLATE_BYTES];
    set_bit(&mut source_code, 0);
    let source = eye(&source_code, &mask);
    for displacement in [-16_i32, -15, -7, 1, 15, 16] {
        let mut code = vec![0; TEMPLATE_BYTES];
        set_bit(
            &mut code,
            usize::try_from(displacement.rem_euclid(200)).unwrap() * BITS_PER_COLUMN,
        );
        let worker = eye(&code, &mask);
        let result = compare_eye(
            Some((&source.iris_code, &source.mask_code)),
            Some(&worker),
            "v2.1",
        );
        assert!(result.zero_shift.unwrap().hamming_distance > 0.0);
        let best = result.rotation_adjusted.unwrap();
        if displacement.abs() <= ROTATION_SHIFT {
            assert_eq!(best.rotation_columns, -displacement);
            assert_eq!(best.hamming_distance, 0.0);
        } else {
            assert!(best.hamming_distance > 0.0);
        }
    }
}
