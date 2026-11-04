//! Emits synthetic enrollment wire data for signup-service interoperability tests.
//! The attestation and ownership proof are deliberately not valid credentials.
use std::io::Write;
use std::path::PathBuf;

use base64::{Engine, engine::general_purpose::STANDARD};
use crypto_box::SecretKey;
use rand::{SeedableRng, rngs::StdRng};
use selfie_enrollment_identity::{
    AttestationFailed, Capture, CaptureAttestor, Inputs, Subject, assemble, binding_digest,
    user_data,
};
use selfie_enrollment_sealed_types::FaceEmbedding;
use uuid::Uuid;

struct SyntheticAttestor;
impl CaptureAttestor for SyntheticAttestor {
    fn attest(&self, _: &[u8; 32], _: &[u8; 49]) -> Result<Vec<u8>, AttestationFailed> {
        Ok(b"synthetic-interop-document-not-AWS".to_vec())
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let output = PathBuf::from(
        std::env::args_os()
            .nth(1)
            .ok_or("output directory required")?,
    );
    std::fs::create_dir(&output)?;
    let mut rng = StdRng::seed_from_u64(7);
    let keys: [SecretKey; 3] = std::array::from_fn(|_| SecretKey::generate(&mut rng));
    let recipients = keys.each_ref().map(SecretKey::public_key);
    let mut vector = 512_u64.to_le_bytes().to_vec();
    for index in 0..512_u16 {
        vector.extend_from_slice(&(f32::from(index % 15) * 0.02 - 0.14).to_le_bytes());
    }
    let embedding = FaceEmbedding {
        embedding: STANDARD.encode(vector),
        embedding_type: "ghostfacenet_flipped_mean".into(),
        embedding_version: "2.0.0".into(),
        embedding_inference_backend: "face-engine".into(),
    };
    // Exercise realistic proof size and bytes unsafe to interpret as UTF-8/text.
    let proof: Vec<u8> = (0..570_464).map(|i| (i % 256) as u8).collect();
    let worker = [0x5a; 48];
    let enrollment = assemble(
        &Inputs {
            capture: Capture {
                capture_id: Uuid::from_u128(0x6f96_19ff_8b86_4d01_b42d_00cf_4fc9_64ff),
                captured_at: 1_700_000_000,
                image_png: b"\x89PNG\r\n\x1a\nsynthetic-test-image",
                embedding: &embedding,
            },
            subject: Subject {
                sub: "0x1f",
                challenge_id: Uuid::from_u128(0x1234),
                ownership_proof: &proof,
            },
            id_commitment: "0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            pcp_version: "1",
            recipient_keys: &recipients,
            worker_sha384: &worker,
        },
        &SyntheticAttestor,
        &mut rng,
    )?;
    // The producer currently returns Form::parts, not an HTTP request. This test
    // adapter serializes those exact bytes, including a binary proof file part.
    let boundary = "nitro-rust-go-interop-v1";
    let mut body = Vec::new();
    for (name, value) in enrollment.form.parts() {
        write!(
            body,
            "--{boundary}\r\nContent-Disposition: form-data; name=\"{name}\""
        )?;
        if name == "world_id_ownership_proof" {
            write!(
                body,
                "; filename=\"proof.cbor\"\r\nContent-Type: application/cbor"
            )?;
        }
        write!(body, "\r\n\r\n")?;
        body.extend_from_slice(value);
        write!(body, "\r\n")?;
    }
    write!(body, "--{boundary}--\r\n")?;
    let mut request = std::fs::File::create_new(output.join("request.http"))?;
    write!(
        request,
        "PUT /api/v1/identity?idComm={} HTTP/1.1\r\nHost: interop.invalid\r\nContent-Type: multipart/form-data; boundary={boundary}\r\nX-Nitro-Attestation: {}\r\nContent-Length: {}\r\n\r\n",
        enrollment.id_commitment,
        enrollment.attestation_header(),
        body.len()
    )?;
    request.write_all(&body)?;
    let expected = serde_json::json!({
        "nonce_hex": hex::encode(binding_digest(&enrollment.id_commitment, &enrollment.form)),
        "user_data_hex": hex::encode(user_data(&worker)),
        "proof_bytes": proof.len(),
    });
    let mut metadata = std::fs::File::create_new(output.join("expected.json"))?;
    serde_json::to_writer_pretty(&mut metadata, &expected)?;
    Ok(())
}
