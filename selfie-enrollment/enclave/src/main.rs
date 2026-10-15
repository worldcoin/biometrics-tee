fn main() -> anyhow::Result<()> {
    #[cfg(target_os = "linux")]
    {
        selfie_enrollment_enclave::runtime::run()
    }
    #[cfg(not(target_os = "linux"))]
    {
        anyhow::bail!("the enrollment enclave requires Linux/Nitro")
    }
}
