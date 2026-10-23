{
  description = "di-migration-tee — reproducible Nitro enclave images";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-26.05";
    crane.url = "github:ipetkov/crane";
    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    nitro-util = {
      url = "github:monzo/aws-nitro-util";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs =
    {
      nixpkgs,
      crane,
      rust-overlay,
      nitro-util,
      ...
    }:
    let
      root = ./.;
      # EIFs are linux/amd64 only, so there is nothing to gain from other systems here.
      system = "x86_64-linux";
      pkgs = import nixpkgs {
        inherit system;
        overlays = [ rust-overlay.overlays.default ];
      };
      enclaveBins = import ./nix/enclave-binaries.nix {
        inherit root pkgs crane;
      };
      enclaveImages = import ./nix/enclave-images.nix {
        inherit system pkgs nitro-util enclaveBins;
      };
    in
    {
      packages.${system} = enclaveBins // enclaveImages;

      # Key identity is part of the measured filesystem, supplied by deployment
      # configuration. Account-specific values are not stored in this repository.
      lib.migrationImages =
        { pcpKmsKeyArn, pcpKmsSigningKeyArn ? null }:
        import ./nix/enclave-images.nix {
          inherit system pkgs nitro-util enclaveBins pcpKmsKeyArn pcpKmsSigningKeyArn;
        };

      devShells = import ./nix/dev-shells.nix {
        inherit root nixpkgs rust-overlay;
      };
    };
}
