//! Four-byte unsigned big-endian length, followed by exactly that many bytes.
//! EOF between frames is graceful; EOF within a frame is an error.
use std::io::{self, Read, Write};

/// Maximum serialized message size: 64 MiB, excluding the header.
pub const MAX_FRAME_BYTES: usize = 64 * 1024 * 1024;

/// Reads one length-prefixed frame, returning `None` for EOF before its header.
///
/// # Errors
/// Returns an error for invalid lengths, failed allocation, truncated frames, or I/O failure.
pub fn read_frame(reader: &mut impl Read) -> io::Result<Option<Vec<u8>>> {
    let mut header = [0; 4];

    // Read the first byte of the header, handling EOF and interrupt signals.
    loop {
        match reader.read(&mut header[..1]) {
            Ok(0) => return Ok(None), // EOF before first byte -> no frame
            Ok(_) => break,           // First header byte read
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {} // retry
            Err(error) => return Err(error), // I/O failure
        }
    }

    // Read remaining three header bytes and interpret as frame length.
    reader.read_exact(&mut header[1..])?;
    let length = u32::from_be_bytes(header) as usize;
    if length == 0 || length > MAX_FRAME_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid IPC frame length",
        ));
    }

    // Read the remaining frame as the actual message.
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(length)
        .map_err(|_| io::Error::other("IPC frame allocation failed"))?;
    bytes.resize(length, 0);
    reader.read_exact(&mut bytes)?;
    Ok(Some(bytes))
}

/// Writes a length-prefixed frame and flushes the writer.
///
/// # Errors
/// Returns an error for an empty or oversized payload, or any write/flush failure.
pub fn write_frame(writer: &mut impl Write, bytes: &[u8]) -> io::Result<()> {
    if bytes.is_empty() || bytes.len() > MAX_FRAME_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid IPC frame length",
        ));
    }
    let length = u32::try_from(bytes.len())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "IPC frame length exceeds u32"))?;
    writer.write_all(&length.to_be_bytes())?;
    writer.write_all(bytes)?;
    writer.flush()
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn multiple_frames_and_eof() {
        let mut bytes = Vec::new();
        write_frame(&mut bytes, &[1, 2]).unwrap();
        write_frame(&mut bytes, &[3]).unwrap();
        let mut reader = bytes.as_slice();
        assert_eq!(read_frame(&mut reader).unwrap(), Some(vec![1, 2]));
        assert_eq!(read_frame(&mut reader).unwrap(), Some(vec![3]));
        assert_eq!(read_frame(&mut reader).unwrap(), None);
    }
    #[test]
    fn truncation_is_not_clean_eof() {
        for bytes in [&[0][..], &[0, 0, 0, 2, 1][..]] {
            assert_eq!(
                read_frame(&mut &*bytes).unwrap_err().kind(),
                io::ErrorKind::UnexpectedEof
            );
        }
    }
    #[test]
    fn invalid_lengths_rejected_before_payload_allocation() {
        for length in [0, u32::try_from(MAX_FRAME_BYTES).unwrap() + 1, u32::MAX] {
            assert_eq!(
                read_frame(&mut length.to_be_bytes().as_slice())
                    .unwrap_err()
                    .kind(),
                io::ErrorKind::InvalidData
            );
        }
    }
}
