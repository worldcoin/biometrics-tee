# Biometric engines protocol

Public protobuf messages, codec logic and stream framing for use with biometric engines processing.
The primary use case is communication with a biometric engines instance running in a jailbox process for the TEE model.

> [!IMPORTANT]
> Building requires `protoc` to be available.

## Public API

Envelope types are defined at the crate root, with domain-specific messages defined under their respective module.
The envelope messages for the common `Request` and `Response` structures are defined in [biometric_engines.proto](proto/biometric_engines.proto).

Exemplary usage:

```rust
use biometric_engines_protocol::{
    Request, request::Operation, protobuf,
    face::{
        FaceImage, GrayBadgeRequest, LightGuard, LightGuardMatchingFrame, face_image,
    },
};

let request = Request::new(42, Operation::GrayBadge(GrayBadgeRequest {
    live: Some(FaceImage {
        source: Some(face_image::Source::LightGuard(LightGuard {
            illuminated: illuminated_jpeg,
            unilluminated: unilluminated_jpeg,
            matching_frame: LightGuardMatchingFrame::Illuminated as i32,
        })),
    }),
    challenge: Some(FaceImage {
        source: Some(face_image::Source::Rtms(rtms_jpeg)),
    }),
}));
let bytes = protobuf::encode_request(&request);
```

A `Request` specifies the protocol version it uses, a request ID that will be carried over into the response, and which operation it is requesting to be executed.
Clients must use non-zero request IDs: responses with request ID `0` are reserved for requests that could not be decoded at all.
`Operation` here defines the actual processing flow that is to be selected, such as `DeepFace`.

The `Response` to a request will repeat the protocol version and same request ID it is responding to.
Its `outcome` will be either the specific result type of the requested operation, or a `Failure` message in case of an error.

## Framing

Implementation of message frames uses a four-byte unsigned big-endian header indicating the *length* of a frame, followed by the specified number of bytes for the actual message.

> [!IMPORTANT]
> A limit of maximum 64 MiB is currently applied to serialized messages (excluding header).

The implementations for reading and writing frames over any `Read` or `Write` stream are defined in [framing.rs](src/framing.rs).

## Face domain

Processing operations specific to the face domain are defined in [face.proto](proto/face.proto).
The currently supported requests for face-domain processing are:

|Operation  |Input                      |Successful outcome         |
|:----------|:--------------------------|:--------------------------|
|`DeepFace` |Credential, live, challenge|3 similarity scores        |
|`GrayBadge`|Live, challenge            |Similarity score           |
|`Embedding`|Single face image          |Embedding vector + metadata|

*Live selfie* differentiates between two variants: `Vanilla` and `LightGuard` captures.
LightGuard requires two images, explicitly marked as illuminated and unilluminated, as well as which of the two is to be used for the embedding generation.

Limits used for face domain messages, any violation leads to a failure response:

- Maximum 16 MiB per individual image, where each LightGuard frame counts as an image.
  Violations are reported as `ImageTooLarge` at the offending image role.
- Maximum 60 MiB in total for all images in a single request (e.g. for 3 DeepFace images).
  Violations are reported as `TotalImagesTooLarge` without location.
- Maximum 4 KiB for a returned encoded face embedding vector, excluding metadata.

Image limits are enforced by `protobuf::decode_request` on the decoded request, without re-encoding.
Clients can run the same check with `face::check_image_limits` before encoding a request.

## DeepIdentifier migration

The migration operation is defined in [migration.proto](proto/migration.proto).

|Operation  |Input                                        |Successful outcome                                                  |
|:----------|:--------------------------------------------|:-------------------------------------------------------------------|
|`Migration`|Orb RGB face image, left and right IR captures|Face embedding; per eye: iris and mask code, DeepIdentifier embedding|

`Migration` re-processes the archived images of an Orb signup for the DeepIdentifier migration.
The face image runs the Orb credential face pipeline, including its spoof checks.
Each iris capture runs capture QA, the full iris pipeline with its validators, and presentation attack detection.
Any failure fails the request.

The result carries:

- The face embedding, in the same shape as the PCP's `face_embeddings.json` entries.
- Per eye, iris and mask code as base64 of the packed v2.1 template, byte-identical to the Orb's `iris_codes.json` entries.
- Per eye, the int4-quantized DeepIdentifier embedding and its mirror, one value in `[-8, 7]` per byte, plus their f32 values before quantization.

`protobuf::decode_response` rejects results missing any part, face embeddings that are empty or over 4 KiB, codes that are not 2,136 base64 characters, and iris embeddings that are not 512 values in range.
Shares are not part of the result; the consumer derives them.

Limits: maximum 16 MiB per image, reported as `ImageTooLarge` at the offending image.

## Failures

The `Failure.kind` field differentiates general protocol failures from domain-specific ones.

*Protocol failures* are caused by malformed messages, broken contracts or exceeded message size limits.

### Face failures

Face domain failures contain a `FailureCode` indicating the general source of the failure.
The `location` field on a failure indicates which image role or comparison role the failure occurred for.

- Image roles: Credential, live, challenge, embedding input.
- Comparison roles: Credential/live, credential/challenge, live/challenge.
- No location for anything that is operation-wide or cannot be attributed to a single source.

Helpers to construct `Failure` structures are defined in [face.rs](src/face.rs).

### Migration failures

Migration failures carry the outcome class only, never scores or thresholds: invalid request, invalid image, quality rejected, spoof detected, or internal.
Every failure except `INTERNAL` names the image it occurred for: face, left iris or right iris.
Helpers are defined in [migration.rs](src/migration.rs).
