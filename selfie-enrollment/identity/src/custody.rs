//! Serializes and encrypts a Face PCP with Nitro evidence inside the enclave.
//! Only ciphertext leaves this API.
//!
//! The authenticated enrollment channel must supply the user's custody public key.
//! This helper checks its cryptographic suitability, not ownership or provenance.

use std::io::{self, Cursor, Write};

use base64::{Engine as _, engine::general_purpose::STANDARD};
use crypto_box::PublicKey;
use flate2::Crc;
use rand::{CryptoRng, Rng};
use serde::Serialize;
use tar::{Builder, Header};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::{
    IdentityEnrollment, MAX_ATTESTATION_DOCUMENT_BYTES, MAX_OWNERSHIP_PROOF_BYTES, poseidon,
};
use selfie_enrollment_api_types::MAX_IMAGE_BYTES;

/// Includes image, base64 ownership proof, bounded metadata, archive and encryption overhead.
pub const MAX_PACKAGE_BYTES: usize = MAX_IMAGE_BYTES + MAX_OWNERSHIP_PROOF_BYTES * 2 + 256 * 1024;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("invalid custody recipient")]
    InvalidRecipient,
    #[error("custody data does not match enrollment")]
    InconsistentEnrollment,
    #[error("custody package exceeds its limit")]
    TooLarge,
    #[error("custody package serialization failed")]
    Serialization,
    #[error("custody package encryption failed")]
    Encryption,
}

#[derive(Serialize)]
struct Info<'a> {
    id_commitment: &'a str,
    capture_id: &'a str,
    captured_at: u64,
}

#[derive(Serialize)]
struct Manifest<'a> {
    pcp_version: &'a str,
    associated_data_hash: &'a str,
}

#[derive(Serialize, Zeroize, ZeroizeOnDrop)]
struct Part<'a> {
    #[zeroize(skip)]
    name: &'a str,
    value_base64: String,
}

#[derive(Serialize)]
struct Enrollment<'a> {
    id_commitment: &'a str,
    parts: Vec<Part<'a>>,
}

/// Creates a libsodium-compatible sealed box containing a tar archive in gzip stored blocks.
/// Reuses the exact data and plaintext shares produced by `assemble`; never generates shares.
/// No credential or legacy Gateway signature is fabricated. Credential import happens later.
/// Owned plaintext serialization buffers are erased on drop.
///
/// # Errors
/// Rejects unsuitable keys, mismatched/oversized data, serialization or encryption failures.
pub fn encrypt<R: Rng + CryptoRng>(
    enrollment: &IdentityEnrollment,
    custody_key: &PublicKey,
    rng: &mut R,
) -> Result<Vec<u8>, Error> {
    embedding_shares::validate_recipients(std::slice::from_ref(custody_key))
        .map_err(|_| Error::InvalidRecipient)?;
    let data = &enrollment.associated_data;
    if data.image_png.len() > MAX_IMAGE_BYTES
        || enrollment.form.world_id_ownership_proof.len() > MAX_OWNERSHIP_PROOF_BYTES
        || enrollment.tee_attestation_document.len() > MAX_ATTESTATION_DOCUMENT_BYTES
        || enrollment
            .form
            .parts()
            .iter()
            .any(|(name, value)| *name != "world_id_ownership_proof" && value.len() > 8192)
        || data.embedding.embedding.len() > 4096
        || data
            .shares
            .iter()
            .any(|share| share.version.len() > 128 || share.share_data.len() > 2048)
    {
        return Err(Error::TooLarge);
    }
    if data.id_commitment.len() > 128
        || data.id_commitment != enrollment.id_commitment
        || data.embedding.embedding_type != enrollment.form.face_embedding_type
        || data.embedding.embedding_version != enrollment.form.face_embedding_version
        || data.embedding.embedding_inference_backend
            != enrollment.form.face_embedding_inference_backend
        || data.capture_id != enrollment.form.capture_id
        || data.captured_at.to_string() != enrollment.form.timestamp
        || data.pcp_version != enrollment.form.pcp_version
        || poseidon::associated_data(data)
            .map(|hash| hash.to_string())
            .as_deref()
            != Some(enrollment.form.associated_data_hash.as_str())
    {
        return Err(Error::InconsistentEnrollment);
    }

    let mut entries = vec![
        (
            "manifest.json",
            json(&Manifest {
                pcp_version: &data.pcp_version,
                associated_data_hash: &enrollment.form.associated_data_hash,
            })?,
        ),
        (
            "associated_data/info.json",
            json(&Info {
                id_commitment: &data.id_commitment,
                capture_id: &data.capture_id,
                captured_at: data.captured_at,
            })?,
        ),
        (
            "associated_data/face_embeddings.json",
            json(&[&data.embedding])?,
        ),
        (
            "associated_data/face_ampc_share_0.json",
            json(&data.shares[0])?,
        ),
        (
            "associated_data/face_ampc_share_1.json",
            json(&data.shares[1])?,
        ),
        (
            "associated_data/face_ampc_share_2.json",
            json(&data.shares[2])?,
        ),
        (
            "enrollment.json",
            json(&Enrollment {
                id_commitment: &enrollment.id_commitment,
                parts: enrollment
                    .form
                    .parts()
                    .into_iter()
                    .map(|(name, value)| Part {
                        name,
                        value_base64: STANDARD.encode(value),
                    })
                    .collect(),
            })?,
        ),
    ];
    // Each fixed, short entry name needs one tar header and 512-byte data padding.
    // The archive ends with two zero blocks.
    let tar_bytes = entries
        .iter()
        .map(|(_, bytes)| bytes.len())
        .chain([
            data.image_png.len(),
            enrollment.tee_attestation_document.len(),
        ])
        .map(|length| 512 + length.div_ceil(512) * 512)
        .sum::<usize>()
        + 1024;
    let capacity = StoredGzip::encoded_len(tar_bytes);
    if capacity + crypto_box::SEALBYTES > MAX_PACKAGE_BYTES {
        return Err(Error::TooLarge);
    }
    // Fixed backing storage prevents a growing Vec from leaving abandoned plaintext copies.
    let mut plaintext = Zeroizing::new(vec![0; capacity]);
    let length = {
        let encoder =
            StoredGzip::new(plaintext.as_mut_slice()).map_err(|_| Error::Serialization)?;
        let mut archive = Builder::new(encoder);
        for (name, bytes) in &mut entries {
            append(&mut archive, name, bytes)?;
        }
        append(
            &mut archive,
            "associated_data/face_image.png",
            &data.image_png,
        )?;
        append(
            &mut archive,
            "attestation/nitro.cose",
            &enrollment.tee_attestation_document,
        )?;
        archive
            .into_inner()
            .map_err(|_| Error::Serialization)?
            .finish()
            .map_err(|_| Error::Serialization)?
    };
    custody_key
        .seal(rng, &plaintext[..length])
        .map_err(|_| Error::Encryption)
}

// RFC 1951 stored blocks keep gzip compatibility without a compressor's unwiped
// history/work buffers. Payload bytes go directly into the caller's fixed buffer.
struct StoredGzip<'a> {
    output: Cursor<&'a mut [u8]>,
    crc: Crc,
    block_start: usize,
    block_len: u16,
}

impl<'a> StoredGzip<'a> {
    const BLOCK_BYTES: usize = u16::MAX as usize;

    fn encoded_len(input_len: usize) -> usize {
        10 + input_len + input_len.div_ceil(Self::BLOCK_BYTES).max(1) * 5 + 8
    }

    fn new(buffer: &'a mut [u8]) -> io::Result<Self> {
        let mut output = Cursor::new(buffer);
        // Gzip: DEFLATE, no optional fields, zero timestamp, unspecified OS.
        output.write_all(&[0x1f, 0x8b, 8, 0, 0, 0, 0, 0, 0, 255])?;
        output.write_all(&[0; 5])?;
        Ok(Self {
            output,
            crc: Crc::new(),
            block_start: 10,
            block_len: 0,
        })
    }

    fn finish_block(&mut self, last: bool) {
        let header = &mut self.output.get_mut()[self.block_start..self.block_start + 5];
        header[0] = u8::from(last); // BFINAL and BTYPE=00, padded to a byte.
        header[1..3].copy_from_slice(&self.block_len.to_le_bytes());
        header[3..5].copy_from_slice(&(!self.block_len).to_le_bytes());
    }

    fn finish(mut self) -> io::Result<usize> {
        self.finish_block(true);
        self.output.write_all(&self.crc.sum().to_le_bytes())?;
        self.output.write_all(&self.crc.amount().to_le_bytes())?;
        Ok(self.output.position() as usize)
    }
}

impl Write for StoredGzip<'_> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.is_empty() {
            return Ok(0);
        }
        if self.block_len == u16::MAX {
            self.finish_block(false);
            let next = self.output.position() as usize;
            self.output.write_all(&[0; 5])?;
            self.block_start = next;
            self.block_len = 0;
        }
        let count = bytes
            .len()
            .min(Self::BLOCK_BYTES - usize::from(self.block_len));
        let written = self.output.write(&bytes[..count])?;
        self.crc.update(&bytes[..written]);
        self.block_len += written as u16;
        Ok(written)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.output.flush()
    }
}

fn append<W: Write>(archive: &mut Builder<W>, name: &str, bytes: &[u8]) -> Result<(), Error> {
    let mut header = Header::new_gnu();
    header.set_size(bytes.len() as u64);
    header.set_mode(0o600);
    header.set_uid(0);
    header.set_gid(0);
    header.set_mtime(0);
    header.set_cksum();
    archive
        .append_data(&mut header, name, bytes)
        .map_err(|_| Error::Serialization)
}

fn json(value: &impl Serialize) -> Result<Zeroizing<Vec<u8>>, Error> {
    struct Size(usize);
    impl Write for Size {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            self.0 = self
                .0
                .checked_add(bytes.len())
                .filter(|&size| size <= MAX_PACKAGE_BYTES)
                .ok_or_else(|| io::Error::other("package limit"))?;
            Ok(bytes.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    let mut size = Size(0);
    serde_json::to_writer(&mut size, value).map_err(|_| Error::Serialization)?;
    let mut bytes = Zeroizing::new(vec![0; size.0]);
    serde_json::to_writer(bytes.as_mut_slice(), value).map_err(|_| Error::Serialization)?;
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;

    #[test]
    fn stored_gzip_roundtrips_empty_and_block_boundaries_with_chunked_writes() {
        for length in [0, 1, 65_534, 65_535, 65_536, 131_070, 131_071] {
            let input: Vec<u8> = (0..length).map(|index| (index % 251) as u8).collect();
            for chunk_size in [1, 511, 65_535, 131_071] {
                let mut output = Zeroizing::new(vec![0; StoredGzip::encoded_len(length)]);
                let mut encoder = StoredGzip::new(&mut output).unwrap();
                encoder.write_all(&[]).unwrap();
                for chunk in input.chunks(chunk_size) {
                    encoder.write_all(chunk).unwrap();
                }
                encoder.flush().unwrap();
                let written = encoder.finish().unwrap();
                assert_eq!(written, output.len());
                let mut decoded = Vec::new();
                flate2::read::GzDecoder::new(output.as_slice())
                    .read_to_end(&mut decoded)
                    .unwrap();
                assert_eq!(decoded, input);
            }
        }
    }

    #[test]
    fn stored_gzip_reports_insufficient_capacity_at_each_stage() {
        let input = vec![0x5a; 65_536];
        // Header, payload, next block header, and trailer failures all propagate.
        for capacity in [
            0,
            9,
            14,
            15,
            65_550,
            65_554,
            StoredGzip::encoded_len(input.len()) - 1,
        ] {
            let mut output = Zeroizing::new(vec![0; capacity]);
            let result = (|| {
                let mut encoder = StoredGzip::new(&mut output)?;
                encoder.write_all(&input)?;
                encoder.finish()
            })();
            assert_eq!(result.unwrap_err().kind(), io::ErrorKind::WriteZero);
        }
    }

    #[test]
    fn stored_gzip_trailer_detects_corrupt_payload_and_length() {
        let input = b"custody archive contents";
        let mut output = Zeroizing::new(vec![0; StoredGzip::encoded_len(input.len())]);
        let mut encoder = StoredGzip::new(&mut output).unwrap();
        encoder.write_all(input).unwrap();
        encoder.finish().unwrap();
        for index in [15, output.len() - 8, output.len() - 4] {
            output[index] ^= 1;
            assert!(
                flate2::read::GzDecoder::new(output.as_slice())
                    .read_to_end(&mut Vec::new())
                    .is_err()
            );
            output[index] ^= 1;
        }
    }
}
