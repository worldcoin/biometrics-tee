//! PoseGuard challenge verification against an in-process enclave whose Nitro-format documents
//! chain to a test root that only this test's verifier trusts.
use super::*;
use coset::{CborSerializable, CoseSign1Builder, HeaderBuilder, iana::Algorithm};
use p384::ecdsa::{Signature, SigningKey, signature::Signer};
use pontifex::{AttestationDoc, ChannelEnclave, nsm::Digest};
use selfie_enrollment_sealed_types::{Failure, Request};
use serde_bytes::ByteBuf;
use std::{
    cell::{Cell, RefCell},
    rc::Rc,
    time::{SystemTime, UNIX_EPOCH},
};

#[derive(Clone, Copy, Debug, PartialEq)]
enum Tamper {
    None,
    Attestation,
    Targets,
    RequestNonce,
    EnclaveBoot,
}

/// Only a challenge the attested enclave signed for this request and boot reaches capture;
/// every rejected challenge leaves capture uncalled and sends no images.
#[tokio::test]
async fn only_an_authenticated_challenge_reaches_capture_and_submission() {
    for tamper in [
        Tamper::None,
        Tamper::Attestation,
        Tamper::Targets,
        Tamper::RequestNonce,
        Tamper::EnclaveBoot,
    ] {
        let enclave = Rc::new(FakeEnclave::new(tamper));
        let session = EnrollmentSession {
            socket: FakeSocket {
                enclave: enclave.clone(),
                response: None,
            },
            assignment: enclave.assignment(),
        };
        let captures = Cell::new(0);
        let result = session
            .enroll_with_poseguard("0x1f".into(), [7; 32], async |prompt| {
                captures.set(captures.get() + 1);
                assert_eq!(prompt.targets, TARGETS);
                Ok(images())
            })
            .await;
        if tamper == Tamper::None {
            assert!(matches!(
                result,
                Ok(EnrollmentResult::Failed {
                    reason: Failure::QualityRejected
                })
            ));
            assert_eq!(captures.get(), 1);
            let submitted = enclave.submitted.borrow();
            let submission = submitted.as_ref().expect("the images reach the enclave");
            assert_eq!(submission.challenge_token, TOKEN);
            assert_eq!(submission.central_png, images().central_png);
            for (capture, image) in submission.captures.iter().zip(&images().captures) {
                assert_eq!(&capture.image, image);
            }
        } else {
            let error = result.err().expect("a tampered challenge is rejected");
            let expected = if tamper == Tamper::Attestation {
                "Attestation"
            } else {
                "Authentication"
            };
            assert_eq!(format!("{error:?}"), expected, "{tamper:?}");
            assert_eq!(captures.get(), 0, "{tamper:?} must not reach capture");
            assert_eq!(enclave.requests.get(), 1, "{tamper:?} must not send images");
        }
    }
}

/// A test-only P-384 CA and enclave leaf, valid 2026–2126.
const ROOT_CERTIFICATE: &str = concat!(
    "MIIB8DCCAXagAwIBAgIUPLRd482e6E5XYxILGdfIm9DwgmowCgYIKoZIzj0EAwMwJjEkMCIGA1UE",
    "Awwbc2VsZmllLWVucm9sbG1lbnQgdGVzdCByb290MCAXDTI2MDEwMTAwMDAwMFoYDzIxMjYwMTAx",
    "MDAwMDAwWjAmMSQwIgYDVQQDDBtzZWxmaWUtZW5yb2xsbWVudCB0ZXN0IHJvb3QwdjAQBgcqhkjO",
    "PQIBBgUrgQQAIgNiAAThbCXcOR3RKutfijRe3ZRu+c/ikxjtbrgyBLsBHkwqXDXzDN4aDdC1LowO",
    "hbz/zkmxOCY0c1I0s34f+X5zxUuLBcAtxYTkTVd4UgPmqy9yeKZx0JLGzK+ZRJq1btXUnZOjYzBh",
    "MB0GA1UdDgQWBBSdc0jEtvAZ28PTpyuUKr1Ly2edJjAfBgNVHSMEGDAWgBSdc0jEtvAZ28PTpyuU",
    "Kr1Ly2edJjAPBgNVHRMBAf8EBTADAQH/MA4GA1UdDwEB/wQEAwICBDAKBggqhkjOPQQDAwNoADBl",
    "AjATuZ4HsDNQrcAMUa1BdXOXl/fX01bpO6vgUuQhV50+o59taLOxh1bgmRDh9LQXdI8CMQD7d6IH",
    "nKZn2E1hOIj0s04nOH66KfbMp1amabPrzT1VvMNlxRNFdqyXedaCSbD4IDI=",
);
const ENCLAVE_CERTIFICATE: &str = concat!(
    "MIIB3jCCAWOgAwIBAgIBAjAKBggqhkjOPQQDAzAmMSQwIgYDVQQDDBtzZWxmaWUtZW5yb2xsbWVu",
    "dCB0ZXN0IHJvb3QwIBcNMjYwMTAxMDAwMDAwWhgPMjEyNjAxMDEwMDAwMDBaMCkxJzAlBgNVBAMM",
    "HnNlbGZpZS1lbnJvbGxtZW50IHRlc3QgZW5jbGF2ZTB2MBAGByqGSM49AgEGBSuBBAAiA2IABCXa",
    "mOiWAHDrQ+Ix5NnxOtuPPTyb5dEe0i3XX406q0Cb01h8SPLP8QMMJjfNb2upPYrF6t8glpoOYclB",
    "IODy7sYSAYTJZ7uEtyea2kjscN9u/mX+bm/ktVlxMH1XNzfXjKNgMF4wDAYDVR0TAQH/BAIwADAO",
    "BgNVHQ8BAf8EBAMCB4AwHQYDVR0OBBYEFPnaYUe8DFzLSN+rGeO8wg0T3uxlMB8GA1UdIwQYMBaA",
    "FJ1zSMS28Bnbw9OnK5QqvUvLZ50mMAoGCCqGSM49BAMDA2kAMGYCMQCfDRx0HwgA81WG0hfP/5UW",
    "x4rj1pZkeBSZvytj+HCT9Et5ndZxfqYmpdUI81v9bNoCMQCweK+LgEd/qgQVDhW6WdEuKTCFs+GV",
    "otHqM8AEU6Dv4kRGTecLgUmSDFpJ1G+JdwA=",
);
const ENCLAVE_SIGNING_KEY: &str = "e0f32e0ed474903b2c10a21b289cf638b9b99436856da0760c4ca187728fd1e4867a321ca6794f1d9835c61dd2c4bda6";
const PCRS: [[u8; 48]; 3] = [[1; 48], [2; 48], [3; 48]];
const TOKEN: [u8; 32] = [5; 32];
const TARGETS: [PoseGuardTarget; 3] = [
    PoseGuardTarget {
        target_pitch: 0.0,
        target_yaw: -30.0,
    },
    PoseGuardTarget {
        target_pitch: 0.0,
        target_yaw: 30.0,
    },
    PoseGuardTarget {
        target_pitch: 15.0,
        target_yaw: 0.0,
    },
];

fn images() -> PoseGuardImages {
    PoseGuardImages {
        central_png: b"\x89PNG\r\n\x1a\ncentral".to_vec(),
        captures: [vec![1], vec![2], vec![3]],
    }
}

/// Answers sealed requests like the enclave does, applying one tamper to the challenge.
struct FakeEnclave {
    channel: ChannelEnclave,
    signing_key: SigningKey,
    tamper: Tamper,
    requests: Cell<usize>,
    submitted: RefCell<Option<PoseGuardEnrollmentRequest>>,
}

impl FakeEnclave {
    fn new(tamper: Tamper) -> Self {
        Self {
            channel: ChannelEnclave::generate(ChannelDomain::new(CHANNEL_DOMAIN)).unwrap(),
            signing_key: SigningKey::from_slice(&hex::decode(ENCLAVE_SIGNING_KEY).unwrap())
                .unwrap(),
            tamper,
            requests: Cell::new(0),
            submitted: RefCell::new(None),
        }
    }

    fn assignment(&self) -> VerifiedAssignment {
        let verifier = Verifier::new(
            vec![
                PcrConfig::new(PCRS[0])
                    .with_pcr(1, PCRS[1].to_vec())
                    .with_pcr(2, PCRS[2].to_vec()),
            ],
            Duration::from_secs(3600),
        )
        .with_root_certificate(STANDARD.decode(ROOT_CERTIFICATE).unwrap());
        let commitment = self.channel.public_key_commitment();
        VerifiedAssignment::verify_with(
            verifier,
            &Assignment {
                attestation: STANDARD.encode(self.document(Some(commitment), None)),
                public_key: STANDARD.encode(self.channel.public_key()),
            },
        )
        .unwrap()
    }

    fn answer(&self, sealed: &[u8]) -> Vec<u8> {
        self.requests.set(self.requests.get() + 1);
        let (plaintext, sealer) = self.channel.open(sealed).unwrap();
        let response = match Request::decode(&plaintext).unwrap() {
            Request::GeneratePoseGuardTargets(request) => self.challenge(&request).encode(),
            Request::PoseGuardEnrollment(request) => {
                *self.submitted.borrow_mut() = Some(request);
                EnrollmentResult::Failed {
                    reason: Failure::QualityRejected,
                }
                .encode()
            }
            _ => panic!("the client sends only PoseGuard requests"),
        };
        sealer.seal(&response.unwrap()).unwrap()
    }

    fn challenge(&self, request: &GeneratePoseGuardTargetsRequest) -> PoseGuardTargetsResult {
        let mut challenge = PoseGuardChallenge {
            challenge_token: TOKEN,
            targets: TARGETS,
            expires_at: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs()
                + POSEGUARD_CHALLENGE_TTL_SECS,
        };
        let mut signed = GeneratePoseGuardTargetsRequest {
            version: request.version,
            operation: EnrollmentOperation::GeneratePoseGuardTargets,
            nonce: request.nonce,
        };
        let mut commitment = self.channel.public_key_commitment();
        match self.tamper {
            Tamper::RequestNonce => signed.nonce[0] ^= 1,
            Tamper::EnclaveBoot => {
                commitment = ChannelEnclave::generate(ChannelDomain::new(CHANNEL_DOMAIN))
                    .unwrap()
                    .public_key_commitment();
            }
            _ => {}
        }
        let nonce = challenge.attestation_nonce(&signed, &commitment).unwrap();
        let mut attestation = self.document(None, Some(nonce));
        match self.tamper {
            Tamper::Attestation => *attestation.last_mut().unwrap() ^= 1,
            Tamper::Targets => challenge.targets[0].target_yaw += 1.0,
            _ => {}
        }
        PoseGuardTargetsResult {
            challenge,
            attestation,
        }
    }

    fn document(&self, public_key: Option<[u8; 32]>, nonce: Option<[u8; 32]>) -> Vec<u8> {
        let document = AttestationDoc {
            module_id: "i-test-enc".into(),
            digest: Digest::SHA384,
            timestamp: u64::try_from(
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_millis(),
            )
            .unwrap(),
            pcrs: PCRS
                .iter()
                .enumerate()
                .map(|(index, pcr)| (index, ByteBuf::from(pcr.to_vec())))
                .collect(),
            certificate: ByteBuf::from(STANDARD.decode(ENCLAVE_CERTIFICATE).unwrap()),
            cabundle: vec![ByteBuf::from(STANDARD.decode(ROOT_CERTIFICATE).unwrap())],
            public_key: public_key.map(|key| ByteBuf::from(key.to_vec())),
            user_data: None,
            nonce: nonce.map(|nonce| ByteBuf::from(nonce.to_vec())),
        };
        let mut payload = Vec::new();
        ciborium::into_writer(&document, &mut payload).unwrap();
        CoseSign1Builder::new()
            .protected(HeaderBuilder::new().algorithm(Algorithm::ES384).build())
            .payload(payload)
            .create_signature(&[], |data| {
                let signature: Signature = self.signing_key.sign(data);
                signature.to_bytes().to_vec()
            })
            .build()
            .to_vec()
            .unwrap()
    }
}

struct FakeSocket {
    enclave: Rc<FakeEnclave>,
    response: Option<Vec<u8>>,
}

impl Transport for FakeSocket {
    async fn send(&mut self, frame: Frame, _: Duration) -> Result<(), Error> {
        let Frame::Binary(sealed) = frame else {
            panic!("only sealed requests follow the assignment");
        };
        self.response = Some(self.enclave.answer(&sealed));
        Ok(())
    }
    async fn receive(&mut self, _: Duration) -> Result<Frame, Error> {
        match self.response.take() {
            Some(response) => Ok(Frame::Binary(response)),
            None => std::future::pending().await,
        }
    }
    async fn close(&mut self) {}
}
