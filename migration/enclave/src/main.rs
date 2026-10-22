#[cfg(target_os = "linux")]
mod runtime;

/// Starts the Linux enclave runtime.
#[cfg(target_os = "linux")]
fn main() -> anyhow::Result<()> {
    runtime::run()
}

/// Refuses an unsandboxed fallback on unsupported platforms.
#[cfg(not(target_os = "linux"))]
fn main() -> anyhow::Result<()> {
    anyhow::bail!("di-migration-enclave requires x86_64 Linux with Minijail and vsock")
}
