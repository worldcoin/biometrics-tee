#!/bin/bash
set -euo pipefail

# Build a workload's enclave EIF and emit its PCR measurements.
#
# Nix constructs a reproducible OCI image and converts its root filesystem directly into
# an EIF with aws-nitro-util and AWS's EIF builder.
#
# Needs x86_64-linux. Nitro hardware is only needed to run.
#
# Usage: scripts/build-enclaves.sh [--workload <name>]
#        [--face-ampc-public-keys-file <file>] [output-dir]
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
    "Usage: scripts/build-enclaves.sh [--workload <name>]" \
    "                                 [--face-ampc-public-keys-file <file>] [output-dir]" \
    "" \
    "Build a workload's enclave EIF and emit its PCR measurements." \
    "" \
    "Options:" \
    "  --workload <name>  Which enclave to build: ${WORKLOADS[*]} (default dev)." \
    "  --face-ampc-public-keys-file <file>  Bake a JSON array of three base64 public keys in party order into the selfie-enrollment EIF." \
    "  -h, --help         Show this help."
}

workload="dev"
out_dir="target/eif"
output_dir_provided=false
face_ampc_public_keys_file=""

while (( $# > 0 )); do
  case "$1" in
    --face-ampc-public-keys-file)
      if (( $# < 2 )) || [[ -z "$2" ]]; then
        echo "[ERROR] --face-ampc-public-keys-file needs a JSON file." >&2
        exit 2
      fi
      face_ampc_public_keys_file="$2"
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

if [[ -n "$face_ampc_public_keys_file" ]]; then
  if [[ "$workload" != "selfie-enrollment" ]]; then
    echo "[ERROR] --face-ampc-public-keys-file requires --workload selfie-enrollment." >&2
    exit 2
  fi
  if [[ ! -f "$face_ampc_public_keys_file" || ! -r "$face_ampc_public_keys_file" ]]; then
    echo "[ERROR] Face-AMPC public key file must be a readable regular file." >&2
    exit 2
  fi
  # Snapshot the input once so the OCI image and EIF use identical key bytes.
  face_ampc_public_keys="$(cat "$face_ampc_public_keys_file")"
fi

command -v nix >/dev/null || {
  echo "[ERROR] nix not found. The OCI image and EIF are built by flake.nix." >&2
  exit 1
}

repo_root="$(git rev-parse --show-toplevel)"
cd "$repo_root"

build_output() {
  local format="$1"
  if [[ "$workload" == "selfie-enrollment" && -n "$face_ampc_public_keys_file" ]]; then
    FACE_AMPC_BUILD_ROOT="$repo_root" FACE_AMPC_BUILD_PUBLIC_KEYS="$face_ampc_public_keys" FACE_AMPC_BUILD_FORMAT="$format" \
      nix build --impure --no-update-lock-file --no-link --print-out-paths --expr '
        let
          flake = builtins.getFlake ("git+file://" + builtins.getEnv "FACE_AMPC_BUILD_ROOT" + "?shallow=1");
          images = flake.lib.selfieEnrollmentImages {
            faceAmpcPublicKeys = builtins.fromJSON (builtins.getEnv "FACE_AMPC_BUILD_PUBLIC_KEYS");
          };
        in builtins.getAttr ("selfie-enrollment-" + builtins.getEnv "FACE_AMPC_BUILD_FORMAT") images
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
