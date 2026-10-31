//! Summarize explicit terminal errors in the worker-reported failing branch.
//! Full engine outputs remain borrowed and are serialized without modification.

use super::{Deserialize, Error, ImageRole, RawValue, WorkerReport};

#[derive(Default)]
pub(super) struct Details<'a> {
    pub component: Option<&'static str>,
    pub code: Option<&'a str>,
    pub message: Option<&'a RawValue>,
}

impl<'a> WorkerReport<'a> {
    pub(super) fn pipeline_error(&self, image: Option<ImageRole>, error: Error) -> Details<'a> {
        let component = match image {
            Some(ImageRole::Face) => "face",
            Some(ImageRole::LeftIris) => "iris.left",
            Some(ImageRole::RightIris) => "iris.right",
            Some(ImageRole::IrisPair) => "iris.pair",
            _ => return Details::default(),
        };
        match self.terminal_error(image, error) {
            Ok(Some(details)) => details,
            result => {
                if result.is_err() {
                    tracing::warn!(
                        component,
                        "pipeline error details are malformed or ambiguous"
                    );
                }
                Details {
                    component: Some(component),
                    ..Details::default()
                }
            }
        }
    }

    fn terminal_error(
        &self,
        image: Option<ImageRole>,
        error: Error,
    ) -> Result<Option<Details<'a>>, ()> {
        if !(matches!(
            error,
            Error::BiometricQualityRejected | Error::BiometricSpoofDetected
        ) || image == Some(ImageRole::IrisPair) && error == Error::BiometricPipelineFailed)
        {
            return Ok(None);
        }
        if image == Some(ImageRole::Face) {
            let Some(face) = &self.face else {
                return Ok(None);
            };
            let request: FaceRequest<'_> = parse(face.request_type)?;
            if request.kind != "Embedding" || request.source != "Orb" || face.outputs.len() != 1 {
                return Err(());
            }
            let stages: FaceStages<'a> = parse(face.outputs[0])?;
            return terminal(&[
                (
                    "face.captured_image_analyzer",
                    stages.captured_image_analyzer,
                    false,
                ),
                ("face.challenge_response", stages.challenge_response, false),
                ("face.template_generator", stages.template_generator, false),
            ]);
        }
        let Some(raw) = self.iris else {
            return Ok(None);
        };
        let iris: Iris<'a> = parse(raw)?;
        if image == Some(ImageRole::IrisPair) {
            let Some(raw) = iris.pair.and_then(|pair| pair.output) else {
                return Ok(None);
            };
            let Some(raw) = parse::<Output<'a>>(raw)?.error else {
                return Ok(None);
            };
            let pair: PairError<'a> = parse(raw)?;
            if !matches!(
                (error, pair.kind),
                (Error::BiometricSpoofDetected, "Rejected")
                    | (Error::BiometricPipelineFailed, "Internal")
            ) {
                return Err(());
            }
            return Ok(Some(Details {
                component: Some("iris.pair"),
                code: Some(valid_code(pair.check)?),
                message: None,
            }));
        }
        let (eye, components) = if image == Some(ImageRole::LeftIris) {
            (
                iris.left,
                [
                    "iris.left.capture_qa",
                    "iris.left.pipeline",
                    "iris.left.pad",
                ],
            )
        } else {
            (
                iris.right,
                [
                    "iris.right.capture_qa",
                    "iris.right.pipeline",
                    "iris.right.pad",
                ],
            )
        };
        let Some(stages) = eye.and_then(|eye| eye.outputs) else {
            return Ok(None);
        };
        terminal(&[
            (components[0], stages.capture_qa, true),
            (components[1], stages.pipeline, true),
            (components[2], stages.pad, false),
        ])
    }
}

// The worker records each output before returning its error and does not run later stages.
// Only stage-level errors are candidates; nested per-check diagnostics are not searched.
fn terminal<'a>(
    stages: &[(&'static str, Option<&'a RawValue>, bool)],
) -> Result<Option<Details<'a>>, ()> {
    let mut result = None;
    for &(component, output, wrapped) in stages {
        let Some(output) = output else { continue };
        if result.is_some() {
            return Err(());
        }
        let Some(error) = parse::<Output<'a>>(output)?.error else {
            continue;
        };
        let (error, message) = if wrapped {
            let info: ErrorInfo<'a> = parse(error)?;
            (info.error, info.message)
        } else {
            (error, None)
        };
        let code: EngineCode<'a> = parse(error)?;
        if message
            .is_some_and(|message| !message.get().starts_with('"') || message.get().len() > 4096)
        {
            return Err(());
        }
        result = Some(Details {
            component: Some(component),
            code: Some(valid_code(code.0)?),
            message,
        });
    }
    Ok(result)
}

fn parse<'a, T: Deserialize<'a>>(raw: &'a RawValue) -> Result<T, ()> {
    serde_json::from_str(raw.get()).map_err(|_| ())
}

fn valid_code(code: &str) -> Result<&str, ()> {
    if code.is_empty()
        || code.len() > 128
        || !code.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'_')
    {
        Err(())
    } else {
        Ok(code)
    }
}

// Engine validation enums serialize as a name or one named variant with parameters.
// Borrow the name and leave parameters in the original diagnostic JSON.
struct EngineCode<'a>(&'a str);
impl<'de> Deserialize<'de> for EngineCode<'de> {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct Visitor;
        impl<'de> serde::de::Visitor<'de> for Visitor {
            type Value = EngineCode<'de>;
            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("engine error variant")
            }
            fn visit_borrowed_str<E: serde::de::Error>(
                self,
                value: &'de str,
            ) -> Result<Self::Value, E> {
                Ok(EngineCode(value))
            }
            fn visit_map<M: serde::de::MapAccess<'de>>(
                self,
                mut map: M,
            ) -> Result<Self::Value, M::Error> {
                let (name, _): (&str, serde::de::IgnoredAny) = map
                    .next_entry()?
                    .ok_or_else(|| serde::de::Error::custom("missing error variant"))?;
                if map
                    .next_entry::<serde::de::IgnoredAny, serde::de::IgnoredAny>()?
                    .is_some()
                {
                    return Err(serde::de::Error::custom("multiple error variants"));
                }
                Ok(EngineCode(name))
            }
        }
        deserializer.deserialize_any(Visitor)
    }
}

#[derive(Deserialize)]
struct Iris<'a> {
    #[serde(borrow)]
    left: Option<Eye<'a>>,
    #[serde(borrow)]
    right: Option<Eye<'a>>,
    #[serde(borrow)]
    pair: Option<Pair<'a>>,
}
#[derive(Deserialize)]
struct Eye<'a> {
    #[serde(borrow)]
    outputs: Option<EyeStages<'a>>,
}
#[derive(Deserialize)]
struct Pair<'a> {
    #[serde(borrow)]
    output: Option<&'a RawValue>,
}
#[derive(Deserialize)]
struct EyeStages<'a> {
    #[serde(borrow)]
    capture_qa: Option<&'a RawValue>,
    #[serde(borrow)]
    pipeline: Option<&'a RawValue>,
    #[serde(borrow)]
    pad: Option<&'a RawValue>,
}
#[derive(Deserialize)]
struct FaceRequest<'a> {
    #[serde(rename = "type")]
    kind: &'a str,
    source: &'a str,
}
#[derive(Deserialize)]
struct FaceStages<'a> {
    #[serde(borrow)]
    captured_image_analyzer: Option<&'a RawValue>,
    #[serde(borrow)]
    challenge_response: Option<&'a RawValue>,
    #[serde(borrow)]
    template_generator: Option<&'a RawValue>,
}
#[derive(Deserialize)]
struct Output<'a> {
    #[serde(borrow)]
    error: Option<&'a RawValue>,
}
#[derive(Deserialize)]
struct ErrorInfo<'a> {
    #[serde(borrow)]
    error: &'a RawValue,
    #[serde(borrow)]
    message: Option<&'a RawValue>,
}
#[derive(Deserialize)]
struct PairError<'a> {
    check: &'a str,
    kind: &'a str,
}
