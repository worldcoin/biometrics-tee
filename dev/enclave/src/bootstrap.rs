//! Single-threaded worker bundle reception before the async runtime starts.

use std::{
    fs::File,
    io::{self, Write},
    os::{
        fd::AsRawFd,
        unix::fs::{MetadataExt, PermissionsExt},
    },
    path::Path,
    time::Duration,
};

use anyhow::{Context, bail};
use di_sandbox::{BOOTSTRAP_PORT, BootstrapConfig, VerifiedRuntime};

/// Nitro uses CID 3 for the parent EC2 instance.
const NITRO_PARENT_CID: u32 = 3;

/// Staging on the executable root filesystem; Nitro mounts `/tmp` noexec.
const RUNTIME_PARENT: &str = "/worker-runtime";

/// Owns the verified runtime and the unacknowledged bundle transfer.
pub struct BootWorker {
    /// Executable checked against its deployment-supplied digest; must outlive the worker.
    pub runtime: VerifiedRuntime,
    /// Measured worker address-space budget.
    pub address_space_bytes: u64,
    /// Measured worker thread budget.
    pub max_threads: u32,
    /// The provisioner waits for this acknowledgement once the enclave serves.
    provisioner: vsock::VsockStream,
}

impl BootWorker {
    /// Acknowledges a ready worker and closes bootstrap for this boot.
    ///
    /// # Errors
    ///
    /// Returns an error on a write timeout, write failure or shutdown failure.
    pub fn acknowledge(&mut self) -> anyhow::Result<()> {
        self.provisioner
            .write_all(&[0])
            .context("failed to acknowledge worker startup")?;
        self.provisioner.shutdown(std::net::Shutdown::Both)?;
        Ok(())
    }
}

/// Accepts one size-bounded bundle from the parent, then closes the bootstrap listener.
///
/// Socket timeouts bound each read and write after accept. The provisioner bounds total
/// startup, including accept, and tears down the enclave on failure.
///
/// # Errors
///
/// Returns an error for invalid measured limits, unusable staging, a non-parent peer,
/// transport failure, or a bundle that fails verification.
pub fn receive() -> anyhow::Result<BootWorker> {
    let config = BootstrapConfig::default();
    config.validate()?;

    let runtime_parent = Path::new(RUNTIME_PARENT);
    let metadata = std::fs::symlink_metadata(runtime_parent)?;
    if !metadata.is_dir() || metadata.uid() != 0 {
        bail!("worker staging must be a real root-owned directory");
    }
    check_executable_mount(runtime_parent)?;
    // Nix normalizes directory modes; restore private write access before receiving bytes.
    std::fs::set_permissions(runtime_parent, std::fs::Permissions::from_mode(0o700))?;

    let listener = vsock::VsockListener::bind_with_cid_port(libc::VMADDR_CID_ANY, BOOTSTRAP_PORT)?;
    let (mut provisioner, peer) = loop {
        match listener.accept() {
            Ok(connection) => break connection,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(error.into()),
        }
    };
    drop(listener);
    if peer.cid() != NITRO_PARENT_CID {
        bail!("worker provisioner must be the parent host");
    }

    let timeout = Some(Duration::from_secs(config.provisioning_io_timeout_seconds));
    provisioner.set_read_timeout(timeout)?;
    provisioner.set_write_timeout(timeout)?;
    let runtime = di_sandbox::receive(&mut provisioner, config.max_bundle_bytes, runtime_parent)
        .context("worker bundle verification failed")?;
    tracing::info!(release_id = %runtime.release_id, worker_sha384 = %runtime.sha384, "worker executable provisioned");

    Ok(BootWorker {
        runtime,
        address_space_bytes: config.address_space_bytes,
        max_threads: config.max_threads,
        provisioner,
    })
}

/// Execution of the staged worker needs a writable mount without `noexec`.
fn check_executable_mount(directory: &Path) -> anyhow::Result<()> {
    let directory = File::open(directory)?;
    // SAFETY: fstatvfs writes only this initialized buffer for a live directory descriptor.
    let mut filesystem: libc::statvfs = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstatvfs(directory.as_raw_fd(), &raw mut filesystem) } != 0 {
        return Err(io::Error::last_os_error()).context("failed to inspect worker staging mount");
    }
    if filesystem.f_flag & (libc::ST_NOEXEC | libc::ST_RDONLY) != 0 {
        bail!("worker staging requires an executable, writable root filesystem");
    }
    Ok(())
}
