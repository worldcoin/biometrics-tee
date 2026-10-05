{
  root,
  pkgs,
  crane,
}:
let
  # The same rust-toolchain.toml cargo already uses, so a channel bump moves the enclaves
  # and the hosts together instead of drifting. rust-overlay carries the component hashes,
  # so there is no hash to paste in here and none to go stale.
  rustToolchain = pkgs.rust-bin.fromRustupToolchainFile (root + "/rust-toolchain.toml");
  craneLib = (crane.mkLib pkgs).overrideToolchain rustToolchain;

  version = (builtins.fromTOML (builtins.readFile (root + "/Cargo.toml"))).workspace.package.version;

  buildEnclaveBin =
    { pname }:
    craneLib.buildPackage {
      inherit pname version;
      src = root;
      strictDeps = true;
      cargoExtraArgs = "--locked --bin ${pname}";

      # Crane prepares dependencies for the whole workspace, including di-sandbox's Linux-only
      # Minijail and the PCP builder's protoc and libsodium. Give it Nix's Minijail: the Cargo
      # fallback expects the full upstream repository around the vendored crate and fails with
      # no makefile.
      nativeBuildInputs = [
        pkgs.clang
        pkgs.pkg-config
        pkgs.protobuf
      ];
      buildInputs = [
        pkgs.minijail
        pkgs.libcap
        pkgs.libsodium
      ];
      LIBCLANG_PATH = "${pkgs.llvmPackages.libclang.lib}/lib";

      # LLVM's LICM scalar promotion orders work by pointer value, so rustc (1.97 and 1.98
      # both) emits different code for the same input under different address-space layouts —
      # the same commit measured different PCRs on different machines. Nix disables ASLR in
      # builds, which hides it locally: each machine is self-consistent and machines disagree.
      # Disabling the promotion makes codegen address-independent, verified by building the
      # enclave under ASLR and varied stack rlimits and getting identical bytes. The cost is
      # one loop optimization. Do not drop this without re-running that experiment.
      RUSTFLAGS = "-C llvm-args=-disable-licm-promotion";
    };
in
{
  di-migration-enclave = buildEnclaveBin { pname = "di-migration-enclave"; };
  di-dev-enclave = buildEnclaveBin { pname = "di-dev-enclave"; };
}
