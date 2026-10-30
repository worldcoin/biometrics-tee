//! Enclave-owned migration diagnostics.
//!
//! Worker JSON is borrowed from zeroizing storage and
//! remains opaque below its face/iris wrappers; diagnostics are only returned after encryption.

use std::{collections::BTreeMap, io, sync::LazyLock, time::SystemTime};

use di_migration_enclave_primitives::{Error, MAX_MIGRATION_DIAGNOSTIC_BYTES};
use di_migration_pcp::{SignupId, SourcePcp};
use di_worker_protocol::migration::{Failure, ImageRole, invalid_request_reason};
use pontifex::AttestationDoc;
use serde::{
    Deserialize, Serialize,
    de::{Error as _, MapAccess, Visitor},
};
use serde_json::value::RawValue;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::state::EnclaveState;

/// Exact published schema bytes whose SHA-256 identifies the report contract.
pub const SCHEMA: &str = include_str!("debug_report/schema.json");
static VERSION: LazyLock<String> = LazyLock::new(|| hex::encode(Sha256::digest(SCHEMA.as_bytes())));

/// Observations fixed for this enclave boot. Unavailable observations are omitted.
#[derive(Default)]
pub struct RuntimeMetadata {
    worker_sha384: Option<String>,
    hardware: Option<Hardware>,
    attestation: Option<Measurements>,
}

impl RuntimeMetadata {
    /// Collects the verified executable identity, enclave-visible resources and NSM measurements.
    ///
    /// Collection failures are logged without substituting host resources or expected PCRs.
    #[must_use]
    pub fn collect(worker_sha384: String, document: &AttestationDoc) -> Self {
        std::panic::catch_unwind(|| Self::observe(worker_sha384, document)).unwrap_or_else(|_| {
            tracing::warn!("debug report metadata collection panicked; omitting optional metadata");
            Self::default()
        })
    }

    fn observe(worker_sha384: String, document: &AttestationDoc) -> Self {
        let usable_logical_cpus = std::thread::available_parallelism()
            .map(std::num::NonZeroUsize::get)
            .inspect_err(|error| tracing::warn!(%error, "could not observe enclave CPU allocation"))
            .ok();
        let visible_memory_bytes = std::fs::read_to_string("/proc/meminfo")
            .ok()
            .and_then(|text| memory_bytes(&text));
        if visible_memory_bytes.is_none() {
            tracing::warn!("could not observe enclave total memory");
        }
        let pcrs: BTreeMap<_, _> = (0..=2)
            .filter_map(|index| {
                let pcr = document.pcrs.get(&index).filter(|value| value.len() == 48);
                if pcr.is_none() {
                    tracing::warn!(index, "boot measurement unavailable for debug reports");
                }
                pcr.map(|value| (index.to_string(), hex::encode(value)))
            })
            .collect();
        Self {
            worker_sha384: Some(worker_sha384),
            hardware: Some(Hardware {
                architecture: std::env::consts::ARCH,
                usable_logical_cpus,
                visible_memory_bytes,
            }),
            attestation: (!pcrs.is_empty()).then(|| Measurements {
                measurements_zeroed: crate::attestation::has_zeroed_measurements(document),
                pcrs,
            }),
        }
    }
}

fn memory_bytes(text: &str) -> Option<u64> {
    let mut fields = text
        .lines()
        .find(|line| line.starts_with("MemTotal:"))?
        .split_whitespace();
    fields.next()?;
    let value = fields.next()?.parse::<u64>().ok()?;
    (fields.next()? == "kB" && fields.next().is_none())
        .then_some(value)?
        .checked_mul(1024)
        .filter(|value| *value > 0)
}

#[derive(Serialize)]
struct Hardware {
    architecture: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    usable_logical_cpus: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    visible_memory_bytes: Option<u64>,
}

#[derive(Serialize)]
struct Measurements {
    measurements_zeroed: bool,
    pcrs: BTreeMap<String, String>,
}

#[derive(Clone, Copy, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Stage {
    DecodePayload,
    VerifyCredential,
    OpenPcp,
    Biometrics,
    PrepareBiometrics,
    BuildPcp,
    GenerateRecipients,
    SignManifest,
    SealPcp,
}

pub(crate) struct Report {
    start_timestamp: Option<f64>,
    pub signup_id: Option<SignupId>,
    src_signup_id: Option<SignupId>,
    source_pcp_version: Option<&'static str>,
    pub stage: Stage,
    worker_json: Option<Zeroizing<String>>,
    worker_failure: Option<WorkerFailure>,
}

impl Report {
    pub fn new(started: SystemTime) -> Self {
        Self {
            start_timestamp: timestamp(started),
            signup_id: None,
            src_signup_id: None,
            source_pcp_version: None,
            stage: Stage::DecodePayload,
            worker_json: None,
            worker_failure: None,
        }
    }

    pub fn source(&mut self, source: &SourcePcp) {
        self.source_pcp_version = Some(source.version().as_str());
        self.src_signup_id = source.info().signup_id.as_deref().and_then(|value| {
            value
                .parse()
                .inspect_err(|_| {
                    tracing::warn!("source signup ID cannot be represented in debug report");
                })
                .ok()
        });
    }

    pub fn worker_report(&mut self, report: Option<Zeroizing<String>>) {
        self.worker_json = report.filter(|report| {
            let valid = !report.is_empty() && report.len() <= MAX_MIGRATION_DIAGNOSTIC_BYTES;
            if !valid {
                tracing::warn!("worker debug report has an invalid size");
            }
            valid
        });
    }

    pub fn worker_failure(&mut self, failure: &Failure) {
        self.worker_failure = Some(WorkerFailure {
            image: match ImageRole::try_from(failure.image) {
                Ok(ImageRole::Face) => Some("Face"),
                Ok(ImageRole::LeftIris) => Some("LeftIris"),
                Ok(ImageRole::RightIris) => Some("RightIris"),
                Ok(ImageRole::IrisPair) => Some("IrisPair"),
                Ok(ImageRole::Unspecified) | Err(_) => None,
            },
            invalid_request_reason: failure
                .invalid_request_reason
                .as_ref()
                .and_then(|reason| reason.reason.as_ref())
                .map(|reason| match reason {
                    invalid_request_reason::Reason::MissingImage(_) => {
                        InvalidRequest::MissingImage {}
                    }
                    invalid_request_reason::Reason::ImageTooLarge(limit) => {
                        InvalidRequest::ImageTooLarge {
                            limit_bytes: limit.limit_bytes,
                        }
                    }
                }),
        });
    }

    pub fn serialize(
        &self,
        state: &EnclaveState,
        error: Option<Error>,
    ) -> Option<Zeroizing<String>> {
        let end_timestamp = timestamp(SystemTime::now());
        let worker = self
            .worker_json
            .as_deref()
            .and_then(|text| {
                serde_json::from_str::<WorkerReport<'_>>(text)
                    .inspect_err(|_| {
                        tracing::warn!("worker debug report has an invalid structure");
                    })
                    .ok()
                    .filter(|worker| {
                        let valid = worker.face.as_ref().is_none_or(|face| {
                            face.request_type.get().starts_with('{')
                                && face
                                    .outputs
                                    .iter()
                                    .all(|output| output.get().starts_with('{'))
                        });
                        if !valid {
                            tracing::warn!("worker face report has an invalid structure");
                        }
                        valid
                    })
            })
            .unwrap_or_default();
        let runtime = state.report_metadata();
        let (signup_status, signup_reason) = match error {
            None => ("Success", "Normal"),
            Some(Error::BiometricSpoofDetected) => ("Fraud", "Fraud"),
            Some(_) => ("Failure", "Failure"),
        };
        let versions = worker.versions();
        let report = Envelope {
            signup_id: self.signup_id.as_ref(),
            src_signup_id: self.src_signup_id.as_ref(),
            version: &VERSION,
            metadata: Metadata {
                start_timestamp: self.start_timestamp,
                end_timestamp,
                signup_status,
                signup_reason,
                source_pcp_version: self.source_pcp_version,
                software_version: SoftwareVersion {
                    main_program_version: env!("CARGO_PKG_VERSION"),
                    worker_sha384: runtime.worker_sha384.as_deref(),
                    worker_version: versions.worker,
                    face_engine_version: versions.face,
                    iris_engine_version: versions.iris,
                },
                environment: Environment {
                    r#type: "tee",
                    boot_id: hex::encode(state.channel().public_key_commitment()),
                    tee: Tee {
                        technology: "aws_nitro_enclaves",
                        attestation: runtime.attestation.as_ref(),
                    },
                },
                hardware: runtime.hardware.as_ref(),
            },
            face: worker.face.as_ref(),
            iris: worker.iris,
            pipeline_errors: PipelineErrors {
                migration_error: error.map(|code| MigrationError {
                    stage: self.stage,
                    code,
                    image: self
                        .worker_failure
                        .as_ref()
                        .and_then(|failure| failure.image),
                    invalid_request_reason: self
                        .worker_failure
                        .as_ref()
                        .and_then(|failure| failure.invalid_request_reason.as_ref()),
                }),
            },
        };
        serialize_report(&report)
    }
}

fn serialize_report(report: &impl Serialize) -> Option<Zeroizing<String>> {
    let mut writer = ReportWriter(Zeroizing::new(Vec::new()));
    serde_json::to_writer(&mut writer, report)
        .inspect_err(|_| tracing::warn!("debug report serialization failed or exceeded its limit"))
        .ok()?;
    match String::from_utf8(std::mem::take(&mut *writer.0)) {
        Ok(text) => Some(Zeroizing::new(text)),
        Err(error) => {
            drop(Zeroizing::new(error.into_bytes()));
            tracing::warn!("debug report serialization produced invalid UTF-8");
            None
        }
    }
}

struct ReportWriter(Zeroizing<Vec<u8>>);

impl io::Write for ReportWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.len() > MAX_MIGRATION_DIAGNOSTIC_BYTES - self.0.len() {
            return Err(io::Error::other("debug report size limit exceeded"));
        }
        self.0.try_reserve(bytes.len()).map_err(io::Error::other)?;
        self.0.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn timestamp(time: SystemTime) -> Option<f64> {
    time.duration_since(SystemTime::UNIX_EPOCH)
        .inspect_err(|_| {
            tracing::warn!("migration debug report clock is before the Unix epoch");
        })
        .ok()
        .map(|duration| duration.as_secs_f64())
}

struct WorkerFailure {
    image: Option<&'static str>,
    invalid_request_reason: Option<InvalidRequest>,
}

#[derive(Serialize)]
#[serde(rename_all = "snake_case")]
enum InvalidRequest {
    MissingImage {},
    ImageTooLarge { limit_bytes: u64 },
}

#[derive(Serialize)]
struct Envelope<'a> {
    signup_id: Option<&'a SignupId>,
    src_signup_id: Option<&'a SignupId>,
    version: &'a str,
    metadata: Metadata<'a>,
    face: Option<&'a FaceReport<'a>>,
    iris: Option<&'a RawValue>,
    pipeline_errors: PipelineErrors<'a>,
}

#[derive(Serialize)]
struct Metadata<'a> {
    start_timestamp: Option<f64>,
    end_timestamp: Option<f64>,
    signup_status: &'static str,
    signup_reason: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    source_pcp_version: Option<&'static str>,
    software_version: SoftwareVersion<'a>,
    environment: Environment<'a>,
    #[serde(skip_serializing_if = "Option::is_none")]
    hardware: Option<&'a Hardware>,
}

#[derive(Serialize)]
struct SoftwareVersion<'a> {
    main_program_version: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    worker_version: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    worker_sha384: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    face_engine_version: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    iris_engine_version: Option<&'a str>,
}

#[derive(Serialize)]
struct Environment<'a> {
    r#type: &'static str,
    boot_id: String,
    tee: Tee<'a>,
}

#[derive(Serialize)]
struct Tee<'a> {
    technology: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    attestation: Option<&'a Measurements>,
}

#[derive(Serialize)]
struct PipelineErrors<'a> {
    migration_error: Option<MigrationError<'a>>,
}

#[derive(Serialize)]
struct MigrationError<'a> {
    stage: Stage,
    code: Error,
    image: Option<&'static str>,
    invalid_request_reason: Option<&'a InvalidRequest>,
}

#[derive(Default, Deserialize)]
struct WorkerReport<'a> {
    #[serde(borrow)]
    worker_version: Option<&'a str>,
    #[serde(borrow)]
    iris_engine_version: Option<&'a str>,
    #[serde(borrow)]
    face: Option<FaceReport<'a>>,
    #[serde(borrow, deserialize_with = "object_or_null", default)]
    iris: Option<&'a RawValue>,
}

fn object_or_null<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<&'de RawValue>, D::Error> {
    let value = Option::<&RawValue>::deserialize(deserializer)?;
    if value.is_some_and(|value| !value.get().starts_with('{')) {
        return Err(serde::de::Error::custom("expected a diagnostic object"));
    }
    Ok(value)
}

#[derive(Serialize)]
struct FaceReport<'a> {
    #[serde(skip_serializing)]
    worker_version: Option<&'a str>,
    request_type: &'a RawValue,
    outputs: Vec<&'a RawValue>,
    #[serde(flatten)]
    extra: BTreeMap<String, &'a RawValue>,
}

impl<'de: 'a, 'a> Deserialize<'de> for FaceReport<'a> {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct FaceVisitor;

        impl<'de> Visitor<'de> for FaceVisitor {
            type Value = FaceReport<'de>;

            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("a face diagnostic object")
            }

            fn visit_map<M: MapAccess<'de>>(self, mut map: M) -> Result<Self::Value, M::Error> {
                let mut worker_version = None;
                let mut request_type = None;
                let mut outputs = None;
                let mut extra = BTreeMap::new();

                // Read values directly from JSON so extensions borrow their exact raw text.
                while let Some(key) = map.next_key::<String>()? {
                    match key.as_str() {
                        "worker_version" => {
                            if worker_version.is_some() {
                                return Err(M::Error::duplicate_field("worker_version"));
                            }
                            worker_version = Some(map.next_value()?);
                        }
                        "request_type" => {
                            if request_type.is_some() {
                                return Err(M::Error::duplicate_field("request_type"));
                            }
                            request_type = Some(map.next_value()?);
                        }
                        "outputs" => {
                            if outputs.is_some() {
                                return Err(M::Error::duplicate_field("outputs"));
                            }
                            outputs = Some(map.next_value()?);
                        }
                        _ => {
                            if extra.insert(key, map.next_value()?).is_some() {
                                return Err(M::Error::custom("duplicate face diagnostic field"));
                            }
                        }
                    }
                }

                Ok(FaceReport {
                    worker_version: worker_version.flatten(),
                    request_type: request_type
                        .ok_or_else(|| M::Error::missing_field("request_type"))?,
                    outputs: outputs.ok_or_else(|| M::Error::missing_field("outputs"))?,
                    extra,
                })
            }
        }

        deserializer.deserialize_map(FaceVisitor)
    }
}

struct Versions<'a> {
    worker: Option<&'a str>,
    face: Option<&'a str>,
    iris: Option<&'a str>,
}

impl<'a> WorkerReport<'a> {
    fn versions(&self) -> Versions<'a> {
        let face: Vec<_> = self
            .face
            .iter()
            .flat_map(|face| &face.outputs)
            .filter_map(|output| {
                serde_json::from_str::<FaceVersions<'a>>(output.get())
                    .inspect_err(|_| {
                        tracing::warn!("face engine version metadata is malformed");
                    })
                    .ok()
            })
            .collect();
        let iris = self
            .iris
            .and_then(|iris| {
                serde_json::from_str::<IrisVersions<'a>>(iris.get())
                    .inspect_err(|_| {
                        tracing::warn!("iris engine version metadata is malformed");
                    })
                    .ok()
            })
            .unwrap_or_default();
        Versions {
            worker: agreed_version(
                "worker",
                [
                    self.worker_version,
                    self.face.as_ref().and_then(|face| face.worker_version),
                ]
                .into_iter()
                .flatten(),
            ),
            face: agreed_version(
                "face",
                face.iter()
                    .flat_map(|face| {
                        [
                            face.captured_image_analyzer.as_ref(),
                            face.template_generator.as_ref(),
                        ]
                    })
                    .flatten()
                    .filter_map(|value| value.version),
            ),
            iris: agreed_version(
                "iris",
                self.iris_engine_version.into_iter().chain(
                    [iris.left, iris.right]
                        .into_iter()
                        .flatten()
                        .filter_map(|eye| eye.outputs)
                        .filter_map(|output| output.capture_qa)
                        .filter_map(|qa| qa.metadata)
                        .flat_map(|metadata| [metadata.irnet_version, metadata.library_version])
                        .flatten(),
                ),
            ),
        }
    }
}

fn agreed_version<'a>(
    engine: &'static str,
    versions: impl Iterator<Item = &'a str>,
) -> Option<&'a str> {
    let mut version = None;
    for candidate in versions {
        if candidate.is_empty()
            || candidate.len() > 256
            || version.is_some_and(|value| value != candidate)
        {
            tracing::warn!(engine, "debug report versions are invalid or inconsistent");
            return None;
        }
        version = Some(candidate);
    }
    version
}

#[derive(Deserialize)]
struct FaceVersions<'a> {
    #[serde(borrow)]
    captured_image_analyzer: Option<EngineVersion<'a>>,
    #[serde(borrow)]
    template_generator: Option<EngineVersion<'a>>,
}
#[derive(Deserialize)]
struct EngineVersion<'a> {
    #[serde(borrow)]
    version: Option<&'a str>,
}
#[derive(Default, Deserialize)]
struct IrisVersions<'a> {
    #[serde(borrow)]
    left: Option<EyeVersion<'a>>,
    #[serde(borrow)]
    right: Option<EyeVersion<'a>>,
}
#[derive(Deserialize)]
struct EyeVersion<'a> {
    #[serde(borrow)]
    outputs: Option<EyeOutputs<'a>>,
}
#[derive(Deserialize)]
struct EyeOutputs<'a> {
    #[serde(borrow)]
    capture_qa: Option<CaptureQa<'a>>,
}
#[derive(Deserialize)]
struct CaptureQa<'a> {
    #[serde(borrow)]
    metadata: Option<IrisMetadata<'a>>,
}
#[derive(Deserialize)]
struct IrisMetadata<'a> {
    #[serde(borrow)]
    irnet_version: Option<&'a str>,
    #[serde(borrow)]
    library_version: Option<&'a str>,
}

#[cfg(test)]
mod tests;
