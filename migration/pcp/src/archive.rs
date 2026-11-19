//! Bounded extraction of an already-opened source PCP archive.

use std::io::Read;

use flate2::read::GzDecoder;
use tar::Archive;

use crate::{Error, Files};

const MAX_FILES: usize = 512;
const MAX_TOTAL_BYTES: usize = 128 * 1024 * 1024;
// Allow headers, extended metadata and padding without reducing the file-content budget.
const MAX_ARCHIVE_BYTES: u64 = (MAX_TOTAL_BYTES + 2 * 1024 * 1024) as u64;

/// Extracts regular files in a gzip-compressed source archive into logical paths.
///
/// The archive must already have had its outer PCP tier encryption removed.
/// Encrypted inner archives remain as members for [`crate::SourcePcp::parse`] to open.
/// This function rejects duplicate or unsafe paths and enforces the same artifact-count and
/// aggregate-size bounds as [`crate::SourcePcp::parse`].
/// The entire decompressed tar stream is limited to 130 MiB, including metadata and padding.
pub fn files_from_tar_gz(pcp: &[u8]) -> Result<Files, Error> {
    files_from_reader(GzDecoder::new(pcp), MAX_ARCHIVE_BYTES)
}

/// Extracts regular files from an uncompressed inner PCP archive.
pub(crate) fn files_from_tar(pcp: &[u8]) -> Result<Files, Error> {
    files_from_reader(pcp, MAX_ARCHIVE_BYTES)
}

fn files_from_reader(reader: impl Read, max_archive_bytes: u64) -> Result<Files, Error> {
    let mut reader = reader.take(max_archive_bytes + 1);
    let result = files_from_archive(&mut reader);
    // Exhausting Take must be an error even if tar treats the artificial EOF as its end.
    if reader.limit() == 0 {
        return Err(Error::SizeLimit);
    }
    result
}

fn files_from_archive(reader: impl Read) -> Result<Files, Error> {
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
        if entry.size() > remaining as u64 {
            return Err(Error::SizeLimit);
        }
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
    use std::io::{self, Read, Write};

    use flate2::{read::GzDecoder, write::GzEncoder};

    use super::{
        MAX_ARCHIVE_BYTES, MAX_FILES, MAX_TOTAL_BYTES, files_from_reader, files_from_tar_gz,
    };
    use crate::Error;

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

    #[test]
    fn bounds_expansion_before_a_manifest_or_when_it_is_missing() {
        for include_manifest in [false, true] {
            let contents = vec![0; 4096];
            let mut entries = vec![("prefix", contents.as_slice())];
            if include_manifest {
                entries.push(("hashes.json", b"{}"));
            }
            let pcp = archive(&entries);
            let mut reader = CountingReader {
                inner: GzDecoder::new(pcp.as_slice()),
                bytes_read: 0,
            };

            assert_eq!(files_from_reader(&mut reader, 1024), Err(Error::SizeLimit));
            assert_eq!(reader.bytes_read, 1025);
        }
    }

    #[test]
    fn counts_extended_metadata_and_padding_in_the_stream_budget() {
        for entry_type in [tar::EntryType::GNULongName, tar::EntryType::XHeader] {
            let mut tar = tar::Builder::new(Vec::new());
            let mut header = tar::Header::new_gnu();
            header.set_entry_type(entry_type);
            header.set_path("metadata").unwrap();
            header.set_size(4096);
            header.set_cksum();
            tar.append(&header, &[b'a'; 4096][..]).unwrap();
            let pcp = gzip(&tar.into_inner().unwrap());
            let mut reader = CountingReader {
                inner: GzDecoder::new(pcp.as_slice()),
                bytes_read: 0,
            };
            assert_eq!(files_from_reader(&mut reader, 1024), Err(Error::SizeLimit));
            assert_eq!(reader.bytes_read, 1025);
        }

        let pcp = archive(&[("prefix", b"x"), ("hashes.json", b"{}")]);
        assert_eq!(
            files_from_reader(GzDecoder::new(pcp.as_slice()), 1024),
            Err(Error::SizeLimit)
        );
    }

    #[test]
    fn rejects_budget_exhaustion_at_a_header_boundary() {
        let pcp = archive(&[("hashes.json", b"{}"), ("trailing", b"payload")]);
        assert_eq!(
            files_from_reader(GzDecoder::new(pcp.as_slice()), 1023),
            Err(Error::SizeLimit)
        );
    }

    #[test]
    fn rejects_oversized_members_without_expanding_their_contents() {
        let mut header = tar::Header::new_gnu();
        header.set_path("prefix").unwrap();
        header.set_size(MAX_TOTAL_BYTES as u64 + 1);
        header.set_cksum();
        let mut reader = io::Cursor::new(header.as_bytes());

        assert_eq!(
            files_from_reader(&mut reader, MAX_ARCHIVE_BYTES),
            Err(Error::SizeLimit)
        );
        assert_eq!(reader.position(), 512);
    }

    #[test]
    fn accepts_the_file_count_boundary_and_rejects_an_extra_member() {
        let names: Vec<_> = (0..MAX_FILES).map(|index| format!("file{index}")).collect();
        let mut entries: Vec<_> = names.iter().map(|name| (name.as_str(), &b""[..])).collect();
        assert_eq!(
            files_from_tar_gz(&archive(&entries)).unwrap().len(),
            MAX_FILES
        );

        entries.push(("hashes.json", b"{}"));
        assert_eq!(files_from_tar_gz(&archive(&entries)), Err(Error::SizeLimit));
    }

    #[test]
    fn preserves_long_paths_and_manifest_bytes_at_the_stream_boundary() {
        let long_path = format!("iris/{}", "a".repeat(150));
        let hashes_json = b"{ \"version\": \"2.7\" }\n";
        let pcp = archive(&[(long_path.as_str(), b"image"), ("hashes.json", hashes_json)]);
        let mut reader = CountingReader {
            inner: GzDecoder::new(pcp.as_slice()),
            bytes_read: 0,
        };
        let files = files_from_reader(&mut reader, MAX_ARCHIVE_BYTES).unwrap();
        assert_eq!(files[&long_path], b"image");
        assert_eq!(files["hashes.json"], hashes_json);
        assert_eq!(
            files_from_reader(GzDecoder::new(pcp.as_slice()), reader.bytes_read),
            Ok(files)
        );
    }

    fn archive(entries: &[(&str, &[u8])]) -> Vec<u8> {
        let mut tar = tar::Builder::new(Vec::new());
        for (path, contents) in entries {
            let mut header = tar::Header::new_gnu();
            header.set_size(contents.len() as u64);
            header.set_mode(0o600);
            tar.append_data(&mut header, path, *contents).unwrap();
        }
        gzip(&tar.into_inner().unwrap())
    }

    fn gzip(bytes: &[u8]) -> Vec<u8> {
        let mut gzip = GzEncoder::new(Vec::new(), flate2::Compression::default());
        gzip.write_all(bytes).unwrap();
        gzip.finish().unwrap()
    }

    struct CountingReader<R> {
        inner: R,
        bytes_read: u64,
    }

    impl<R: Read> Read for CountingReader<R> {
        fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
            let count = self.inner.read(buffer)?;
            self.bytes_read += count as u64;
            Ok(count)
        }
    }
}
