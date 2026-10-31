//! Extract one explicit error from the worker-reported failing branch.
//! The original raw diagnostics are serialized separately, without modification.

use super::{Error, ImageRole, WorkerReport};
use serde_json::Value;

#[derive(Default)]
pub(super) struct Details {
    pub component: Option<String>,
    pub code: Option<String>,
    pub message: Option<String>,
}

impl WorkerReport<'_> {
    pub(super) fn pipeline_error(&self, image: Option<ImageRole>, error: Error) -> Details {
        let (component, raw, pointer) = match image {
            Some(ImageRole::LeftIris) => ("iris.left", self.iris, "/left/outputs"),
            Some(ImageRole::RightIris) => ("iris.right", self.iris, "/right/outputs"),
            Some(ImageRole::IrisPair) => ("iris.pair", self.iris, "/pair/output"),
            Some(ImageRole::Face) => (
                "face",
                self.face
                    .as_ref()
                    .filter(|face| face.outputs.len() == 1)
                    .map(|face| face.outputs[0]),
                "",
            ),
            _ => return Details::default(),
        };
        let mut details = Details {
            component: Some(component.into()),
            ..Details::default()
        };
        if matches!(
            error,
            Error::BiometricQualityRejected
                | Error::BiometricSpoofDetected
                | Error::BiometricPipelineFailed
        ) {
            let parsed = raw.and_then(|raw| {
                serde_json::from_str::<Value>(raw.get())
                    .inspect_err(|_| {
                        tracing::warn!(component, "cannot parse pipeline error details");
                    })
                    .ok()
            });
            if let Some(branch) = parsed.as_ref().and_then(|value| value.pointer(pointer)) {
                copy_error(branch, component, &mut details);
            }
        }
        details
    }
}

fn copy_error(branch: &Value, component: &str, details: &mut Details) {
    // Pair checks put their error directly on the output; image branches contain stages.
    let direct = branch
        .get("error")
        .filter(|error| !error.is_null())
        .map(|error| ("", error));
    let mut errors = direct
        .into_iter()
        .chain(branch.as_object().into_iter().flat_map(|object| {
            object
                .iter()
                .filter(|(stage, _)| stage.as_str() != "error")
                .filter_map(|(stage, output)| {
                    output
                        .get("error")
                        .filter(|error| !error.is_null())
                        .map(|error| (stage.as_str(), error))
                })
        }));
    let Some((stage, error)) = errors.next() else {
        return;
    };
    if errors.next().is_some() {
        tracing::warn!(
            component,
            "multiple pipeline errors; omitting summary details"
        );
        return;
    }
    let value = error
        .get("error")
        .or_else(|| error.get("check"))
        .unwrap_or(error);
    let code = value.as_str().or_else(|| {
        value
            .as_object()
            .filter(|object| object.len() == 1)
            .and_then(|object| object.keys().next().map(String::as_str))
    });
    let message = error.get("message").filter(|value| !value.is_null());
    let Some(code) = code.filter(|code| identifier(code, 128)) else {
        tracing::warn!(component, "invalid pipeline error code");
        return;
    };
    if (!stage.is_empty() && !identifier(stage, 64))
        || message.is_some_and(|value| value.as_str().is_none_or(|text| text.len() > 4096))
    {
        tracing::warn!(component, "invalid pipeline error stage or message");
        return;
    }
    details.component = Some(if stage.is_empty() {
        component.into()
    } else {
        format!("{component}.{stage}")
    });
    details.code = Some(code.into());
    details.message = message.and_then(Value::as_str).map(str::to_owned);
}

fn identifier(value: &str, max: usize) -> bool {
    !value.is_empty()
        && value.len() <= max
        && value
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || c == b'_')
}
