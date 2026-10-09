/// Media type for the compressed PCP sent in, and the migrated PCP that comes back.
pub const MIGRATION_CONTENT_TYPE: &str = "application/octet-stream";

/// The largest PCP the host accepts, compressed or decompressed. Not measured; pick a real one.
pub const MAX_PCP_BYTES: usize = 32 * 1024 * 1024;
