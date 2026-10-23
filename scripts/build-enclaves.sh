#!/bin/bash
set -euo pipefail

# Build a workload's enclave EIF and emit its PCR measurements.
#
# Nix constructs a reproducible OCI image and converts its root filesystem directly into
# an EIF with aws-nitro-util and AWS's EIF builder.
#
# Needs x86_64-linux. Nitro hardware is only needed to run.
#
# Usage: STAGING_PCP_KMS_KEY_ARN=<arn> STAGING_PCP_KMS_SIGNING_KEY_ARN=<arn> \\
#        scripts/build-enclaves.sh [--workload <name>] [--pcp-kms-key-arn <arn>]
#        [--pcp-kms-signing-key-arn <arn>] [output-dir]
#        (workload defaults to dev, output-dir to target/eif)
#
# Outputs in <output-dir>:
#   di-<workload>-enclave.eif   the enclave image
#   di-<workload>-pcr.json      PCR measurements extracted from the EIF

# A new workload is an entry here plus `di-<name>-oci` and `di-<name>-eif` outputs in
# nix/enclave-images.nix.
WORKLOADS=("migration" "dev" "selfie-enrollment")

usage() {
  printf '%s\n' \
    "Usage: scripts/build-enclaves.sh [--workload <name>] [--pcp-kms-key-arn <arn>]" \
    "                                 [--pcp-kms-signing-key-arn <arn>] [output-dir]" \
    "" \
    "Build a workload's enclave EIF and emit its PCR measurements." \
    "" \
    "Options:" \
    "  --workload <name>  Which enclave to build: ${WORKLOADS[*]} (default dev)." \
    "  --pcp-kms-key-arn <arn>  Bake a full wrapping key/alias ARN into the migration EIF (overrides STAGING_PCP_KMS_KEY_ARN)." \
    "  --pcp-kms-signing-key-arn <arn>  Bake a full manifest-signing key/alias ARN into the migration EIF (overrides STAGING_PCP_KMS_SIGNING_KEY_ARN)." \
    "  -h, --help         Show this help."
}

# dev is the default because it is the workload that actually gets deployed; migration is
# still a skeleton.
workload="dev"
out_dir="target/eif"
output_dir_provided=false
# Deployment automation supplies these as protected environment variables. Keep command-line
# flags as explicit overrides for local builds, but never require ARNs in repository config.
pcp_kms_key_arn="${STAGING_PCP_KMS_KEY_ARN:-}"
pcp_kms_signing_key_arn="${STAGING_PCP_KMS_SIGNING_KEY_ARN:-}"

while (( $# > 0 )); do
  case "$1" in
    --pcp-kms-key-arn)
      if (( $# < 2 )) || [[ -z "$2" ]]; then
        echo "[ERROR] --pcp-kms-key-arn needs a full key/alias ARN." >&2
        exit 2
      fi
      pcp_kms_key_arn="$2"
      shift
      ;;
    --pcp-kms-signing-key-arn)
      if (( $# < 2 )) || [[ -z "$2" ]]; then
        echo "[ERROR] --pcp-kms-signing-key-arn needs a full key/alias ARN." >&2
        exit 2
      fi
      pcp_kms_signing_key_arn="$2"
      shift
      ;;
    --workload)
      if (( $# < 2 )); then
        echo "[ERROR] --workload needs a value." >&2
        exit 2
      fi
      workload="$2"
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    -*)
      echo "[ERROR] Unknown option: $1" >&2
      exit 2
      ;;
    *)
      if [[ "$output_dir_provided" == "true" ]]; then
        echo "[ERROR] Only one output directory may be provided." >&2
        exit 2
      fi
      out_dir="$1"
      output_dir_provided=true
      ;;
  esac
  shift
done

if [[ ! " ${WORKLOADS[*]} " == *" $workload "* ]]; then
  echo "[ERROR] Unknown workload: $workload (expected one of: ${WORKLOADS[*]})" >&2
  exit 2
fi

if [[ ( -n "$pcp_kms_key_arn" || -n "$pcp_kms_signing_key_arn" ) && "$workload" != "migration" && "$workload" != "dev" ]]; then
  echo "[ERROR] PCP KMS key options require --workload migration or dev." >&2
  exit 2
fi

command -v nix >/dev/null || {
  echo "[ERROR] nix not found. The OCI image and EIF are built by flake.nix." >&2
  exit 1
}

repo_root="$(git rev-parse --show-toplevel)"
cd "$repo_root"

build_output() {
  local format="$1"
  if [[ -n "$pcp_kms_key_arn" || -n "$pcp_kms_signing_key_arn" ]]; then
    # Terraform validates the ARNs. Pass them as data, never interpolated Nix source;
    # the image embeds their identities in the measured environment.
    PCP_BUILD_ROOT="$repo_root" PCP_BUILD_KEY_ARN="$pcp_kms_key_arn" PCP_BUILD_SIGNING_KEY_ARN="$pcp_kms_signing_key_arn" PCP_BUILD_FORMAT="$format" \
      nix build --impure --no-update-lock-file --no-link --print-out-paths --expr '
        let
          # GitHub Actions checks out a shallow repository. This tells Nix that the local
          # git+file source is intentionally shallow, so it does not require revCount.
          flake = builtins.getFlake ("git+file://" + builtins.getEnv "PCP_BUILD_ROOT" + "?shallow=1");
          optionalArn = name:
            let value = builtins.getEnv name;
            in if value == "" then null else value;
          images = flake.lib.migrationImages {
            pcpKmsKeyArn = optionalArn "PCP_BUILD_KEY_ARN";
            pcpKmsSigningKeyArn = optionalArn "PCP_BUILD_SIGNING_KEY_ARN";
          };
        in builtins.getAttr ("di-migration-" + builtins.getEnv "PCP_BUILD_FORMAT") images
      '
  else
    nix build ".#$output_prefix-$format" --no-update-lock-file --no-link --print-out-paths
  fi
}

mkdir -p "$out_dir"
out_dir="$(cd "$out_dir" && pwd)"

output_prefix="di-$workload"
if [[ "$workload" == "selfie-enrollment" ]]; then
  output_prefix="$workload"
fi
eif_name="$output_prefix-enclave.eif"
pcr_name="$output_prefix-pcr.json"

# --no-update-lock-file on the flake calls below: an input added to flake.nix without a
# matching `nix flake update` would otherwise be resolved to whatever upstream serves right
# now, and the lock silently rewritten. The PCRs must follow the committed lock or nothing.
echo "Building reproducible $workload OCI image..."
if ! oci_store=$(build_output oci); then
  echo >&2
  echo "[ERROR] OCI image build failed; the error above says why. A 'platform" >&2
  echo "        mismatch' for x86_64-linux means this host needs a remote builder." >&2
  exit 1
fi

echo "Building $workload EIF..."
if ! eif_store=$(build_output eif); then
  echo >&2
  echo "[ERROR] EIF build failed; the error above says why." >&2
  exit 1
fi

install -m 0644 "$eif_store/image.eif" "$out_dir/$eif_name"
install -m 0644 "$eif_store/pcr.json" "$out_dir/$pcr_name"

echo "Validating measurements..."
# Registering a missing or malformed PCR with a client would weaken verification.
for pcr in PCR0 PCR1 PCR2; do
  value="$(jq -r --arg k "$pcr" '.[$k] // ""' "$out_dir/$pcr_name")"
  if [[ ! "$value" =~ ^[0-9a-f]{96}$ ]]; then
    echo "[ERROR] $pcr_name holds no usable $pcr (got '$value')." >&2
    echo "        eif_build's output format may have changed; do not register these." >&2
    exit 1
  fi
done

echo
echo "OCI image:    $oci_store"
echo "EIF:          $out_dir/$eif_name"
echo "Measurements: $out_dir/$pcr_name"
jq . "$out_dir/$pcr_name"
