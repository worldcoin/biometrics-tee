//! Masked Hamming distances between source and regenerated iris templates.

use base64::{Engine as _, engine::general_purpose::STANDARD};
use di_worker_protocol::migration::{EyeResult, MigrationResult};
use orb_pcp_defs::v1::IrisCodes;
use serde::Serialize;
use zeroize::Zeroizing;

// Packed v2.1 templates use (rows, columns, filters, real/imaginary), MSB first.
const ROWS: usize = 16;
const COLUMNS: usize = 200;
const BITS_PER_COLUMN: usize = 4;
const TEMPLATE_BYTES: usize = ROWS * COLUMNS * BITS_PER_COLUMN / 8;
const ROTATION_SHIFT: i32 = 15;

#[derive(Serialize)]
pub struct Comparison {
    source_iris_version: Option<String>,
    worker_iris_code_version: String,
    rotation_limit_columns: i32,
    left: EyeComparison,
    right: EyeComparison,
}

#[derive(Serialize)]
struct EyeComparison {
    status: Status,
    old_valid_bits: Option<u32>,
    new_valid_bits: Option<u32>,
    zero_shift: Option<MatchResult>,
    rotation_adjusted: Option<MatchResult>,
}

#[derive(Clone, Copy, Serialize)]
#[serde(rename_all = "snake_case")]
enum Status {
    Compared,
    MissingSource,
    MissingWorker,
    UnsupportedVersion,
    InvalidEncoding,
    InvalidLength,
    NoValidOverlap,
}

#[derive(Clone, Copy, Debug, Serialize)]
struct MatchResult {
    hamming_distance: f64,
    rotation_columns: i32,
    differing_bits: u32,
    common_valid_bits: u32,
}

impl Comparison {
    pub(crate) fn new(source: Option<&IrisCodes>, worker: &MigrationResult) -> Self {
        Self {
            // Source IRIS_version identifies its pipeline, not the worker's code format.
            source_iris_version: source.and_then(|codes| codes.iris_version.clone()),
            worker_iris_code_version: worker.iris_code_version.clone(),
            rotation_limit_columns: ROTATION_SHIFT,
            left: compare_eye(
                source.and_then(|s| s.left_iris_code.as_deref().zip(s.left_mask_code.as_deref())),
                worker.left_iris.as_ref(),
                &worker.iris_code_version,
            ),
            right: compare_eye(
                source.and_then(|s| {
                    s.right_iris_code
                        .as_deref()
                        .zip(s.right_mask_code.as_deref())
                }),
                worker.right_iris.as_ref(),
                &worker.iris_code_version,
            ),
        }
    }
}

fn compare_eye(
    source: Option<(&str, &str)>,
    worker: Option<&EyeResult>,
    version: &str,
) -> EyeComparison {
    compare_templates(source, worker, version).unwrap_or_else(|status| EyeComparison {
        status,
        old_valid_bits: None,
        new_valid_bits: None,
        zero_shift: None,
        rotation_adjusted: None,
    })
}

fn decode(encoded: &str) -> Result<Zeroizing<Vec<u8>>, Status> {
    // Bound allocation before decoding untrusted worker/source strings.
    if encoded.len() != TEMPLATE_BYTES.div_ceil(3) * 4 {
        return Err(Status::InvalidLength);
    }
    let mut bytes = Zeroizing::new(vec![0; TEMPLATE_BYTES]);
    let length = STANDARD
        .decode_slice(encoded, &mut bytes)
        .map_err(|_| Status::InvalidEncoding)?;
    if length != TEMPLATE_BYTES {
        return Err(Status::InvalidLength);
    }
    Ok(bytes)
}

fn compare_templates(
    source: Option<(&str, &str)>,
    worker: Option<&EyeResult>,
    version: &str,
) -> Result<EyeComparison, Status> {
    let (source_code, source_mask) = source.ok_or(Status::MissingSource)?;
    let worker = worker.ok_or(Status::MissingWorker)?;
    if version != "v2.1" {
        return Err(Status::UnsupportedVersion);
    }
    let source_code = decode(source_code)?;
    let source_mask = decode(source_mask)?;
    let worker_code = decode(&worker.iris_code)?;
    let worker_mask = decode(&worker.mask_code)?;
    let at_shift = |shift| {
        masked_distance(
            &worker_code,
            &worker_mask,
            &source_code,
            &source_mask,
            shift,
        )
    };
    let zero = at_shift(0);
    let mut best = zero;
    // Match the engine's search order and strict improvement rule: 0, -1, +1, ... .
    for shift in (1..=ROTATION_SHIFT).flat_map(|shift| [-shift, shift]) {
        if let Some(candidate) = at_shift(shift)
            && best.is_none_or(|best| candidate.hamming_distance < best.hamming_distance)
        {
            best = Some(candidate);
        }
    }
    Ok(EyeComparison {
        status: if best.is_some() {
            Status::Compared
        } else {
            Status::NoValidOverlap
        },
        old_valid_bits: Some(source_mask.iter().map(|byte| byte.count_ones()).sum()),
        new_valid_bits: Some(worker_mask.iter().map(|byte| byte.count_ones()).sum()),
        zero_shift: zero,
        rotation_adjusted: best,
    })
}

const fn bit(bytes: &[u8], index: usize) -> bool {
    bytes[index / 8] & (1 << (7 - index % 8)) != 0
}

fn masked_distance(
    probe_code: &[u8],
    probe_mask: &[u8],
    gallery_code: &[u8],
    gallery_mask: &[u8],
    shift: i32,
) -> Option<MatchResult> {
    let mut differing_bits = 0;
    let mut common_valid_bits = 0;
    // Roll the regenerated probe and its mask along columns within each row.
    // The engine sums mismatches and common valid bits across both filters and phases.
    let offset = usize::try_from(shift.rem_euclid(200)).expect("column offset is nonnegative");
    for row in 0..ROWS {
        for column in 0..COLUMNS {
            let probe_column = (column + COLUMNS - offset) % COLUMNS;
            for phase in 0..BITS_PER_COLUMN {
                let probe = (row * COLUMNS + probe_column) * BITS_PER_COLUMN + phase;
                let gallery = (row * COLUMNS + column) * BITS_PER_COLUMN + phase;
                let mask = bit(probe_mask, probe) & bit(gallery_mask, gallery);
                if mask {
                    common_valid_bits += 1;
                    differing_bits +=
                        u32::from(bit(probe_code, probe) != bit(gallery_code, gallery));
                }
            }
        }
    }
    // A distance is undefined without common valid bits; never emit NaN or a sentinel score.
    (common_valid_bits != 0).then(|| MatchResult {
        hamming_distance: f64::from(differing_bits) / f64::from(common_valid_bits),
        rotation_columns: shift,
        differing_bits,
        common_valid_bits,
    })
}

#[cfg(test)]
mod tests;
