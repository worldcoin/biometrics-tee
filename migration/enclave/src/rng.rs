//! Nitro hardware RNG verification.

use std::{fs, io, path::Path};

const RNG_CURRENT_PATHS: [&str; 2] = [
    "/sys/class/misc/hw_random/rng_current",
    "/sys/devices/virtual/misc/hw_random/rng_current",
];

/// Verifies that the enclave kernel draws its entropy from the Nitro Secure Module, so the boot
/// keys come from hardware randomness.
///
/// # Errors
///
/// Returns an error when the kernel RNG source cannot be read or is not `nsm-hwrng`.
pub fn verify_nsm_hwrng_current() -> io::Result<()> {
    let mut last_error = None;

    for path in RNG_CURRENT_PATHS {
        if !Path::new(path).exists() {
            continue;
        }

        match fs::read_to_string(path) {
            Ok(contents) if contents.trim() == "nsm-hwrng" => return Ok(()),
            Ok(contents) => {
                return Err(io::Error::other(format!(
                    "rng_current is '{}', expected 'nsm-hwrng'",
                    contents.trim()
                )));
            }
            Err(error) => last_error = Some(error),
        }
    }

    Err(last_error.unwrap_or_else(|| {
        io::Error::new(
            io::ErrorKind::NotFound,
            "rng_current sysfs path was not found",
        )
    }))
}
