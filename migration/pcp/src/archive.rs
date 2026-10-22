//! Bounded extraction of an already-opened source PCP archive.

use std::io::Read;

use flate2::read::GzDecoder;
use tar::Archive;

use crate::{Error, Files};

const MAX_FILES: usize = 512;
const MAX_TOTAL_BYTES: usize = 128 * 1024 * 1024;

/// Extracts regular files in a gzip-compressed source archive into logical paths.
///
/// The archive must already have had its outer PCP tier encryption removed.
/// Encrypted inner archives remain as members for [`crate::SourcePcp::parse`] to open.
/// This function rejects duplicate or unsafe paths and enforces the same artifact-count and
/// aggregate-size bounds as [`crate::SourcePcp::parse`].
pub fn files_from_tar_gz(pcp: &[u8]) -> Result<Files, Error> {
    files_from_reader(GzDecoder::new(pcp))
}

/// Extracts regular files from an uncompressed inner PCP archive.
pub(crate) fn files_from_tar(pcp: &[u8]) -> Result<Files, Error> {
    files_from_reader(pcp)
}

fn files_from_reader(reader: impl Read) -> Result<Files, Error> {
    let mut files = Files::new();
    let mut total_bytes = 0usize;
    let mut archive = Archive::new(reader);
    let entries = archive.entries().map_err(|_| Error::InvalidArchive)?;

    for entry in entries {
        let entry = entry.map_err(|_| Error::InvalidArchive)?;
        if !entry.header().entry_type().is_file() {
            return Err(Error::InvalidArchive);
        }
        let path = entry
            .path()
            .map_err(|_| Error::InvalidArchive)?
            .to_str()
            .ok_or(Error::UnsafePath)?
            .to_owned();
        validate_path(&path)?;
        if files.len() == MAX_FILES || files.contains_key(&path) {
            return Err(if files.len() == MAX_FILES {
                Error::SizeLimit
            } else {
                Error::InvalidArchive
            });
        }

        let remaining = MAX_TOTAL_BYTES
            .checked_sub(total_bytes)
            .ok_or(Error::SizeLimit)?;
        let mut bytes = Vec::new();
        entry
            .take(u64::try_from(remaining).expect("usize fits in u64") + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| Error::InvalidArchive)?;
        if bytes.len() > remaining {
            return Err(Error::SizeLimit);
        }
        total_bytes += bytes.len();
        files.insert(path, bytes);
    }
    Ok(files)
}

fn validate_path(path: &str) -> Result<(), Error> {
    if path.len() > 256
        || path.contains(['\\', '\0'])
        || !path.is_ascii()
        || path
            .split('/')
            .any(|part| part.is_empty() || part == "." || part == "..")
    {
        return Err(Error::UnsafePath);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::io::Write;

    use flate2::write::GzEncoder;

    use super::files_from_tar_gz;
    use crate::Error;

    fn archive(entries: &[(&str, &[u8])]) -> Vec<u8> {
        let mut tar = tar::Builder::new(Vec::new());
        for (path, contents) in entries {
            let mut header = tar::Header::new_gnu();
            header.set_path(path).unwrap();
            header.set_size(contents.len() as u64);
            header.set_mode(0o600);
            header.set_cksum();
            tar.append(&header, *contents).unwrap();
        }
        let bytes = tar.into_inner().unwrap();
        let mut gzip = GzEncoder::new(Vec::new(), flate2::Compression::default());
        gzip.write_all(&bytes).unwrap();
        gzip.finish().unwrap()
    }

    #[test]
    fn extracts_regular_files_to_logical_paths() {
        let files = files_from_tar_gz(&archive(&[
            ("iris/left_ir.png", b"left"),
            ("face/thumbnail.png", b"thumbnail"),
        ]))
        .unwrap();

        assert_eq!(files["iris/left_ir.png"], b"left");
        assert_eq!(files["face/thumbnail.png"], b"thumbnail");
    }

    #[test]
    fn rejects_duplicate_paths() {
        assert_eq!(
            files_from_tar_gz(&archive(&[
                ("hashes.json", b"one"),
                ("hashes.json", b"two")
            ])),
            Err(Error::InvalidArchive)
        );
    }
}
