{
  system,
  pkgs,
  nitro-util,
  enclaveBins,
  pcpKmsKeyArn ? null,
}:
let
  nitroLib = nitro-util.lib.${system};
  nitroBlobs = nitroLib.blobs.x86_64;
  # aws-nitro-util still pins v1.2.3; v1.5.0 fixes init's mount-root setup, which the
  # worker's Minijail bind mounts need (same pin as flamingo).
  sandboxInit = pkgs.runCommand "nitro-init-1.5.0" { } ''
    install -m755 ${
      pkgs.fetchurl {
        name = "nitro-init-1.5.0";
        url = "https://raw.githubusercontent.com/aws/aws-nitro-enclaves-cli/2950b3699d81ad304df2458915688a552734833d/blobs/x86_64/init";
        hash = "sha256-dV5lC3Mnd7eYy57CQ+5AK+9IJveJzwGh5FO7ckIHwAU=";
      }
    } "$out"
  '';

  buildEnclaveImage =
    {
      pname,
      sandboxed ? false,
      environment ? [ ],
    }:
    let
      version = enclaveBins.${pname}.version;

      root = pkgs.buildEnv {
        name = "${pname}-root";
        paths = [
          enclaveBins.${pname}
          pkgs.cacert
        ];
        pathsToLink = [
          "/bin"
          "/etc"
        ];
        # Nitro mounts /tmp noexec. Stage the worker on the executable root filesystem, not a
        # Nix store symlink; bootstrap restores its private mode after Nix normalization.
        postBuild = pkgs.lib.optionalString sandboxed ''
          mkdir -p "$out/worker-runtime"
        '';
      };

      dockerArchive = pkgs.dockerTools.buildLayeredImage {
        name = pname;
        tag = version;
        created = "1970-01-01T00:00:01Z";
        contents = [ root ];
        config = {
          Entrypoint = [ "/bin/${pname}" ];
          Env = [
            "RUST_LOG=info"
            "SSL_CERT_FILE=/etc/ssl/certs/ca-bundle.crt"
          ] ++ environment;
        };
      };

      ociImage =
        pkgs.runCommand "${pname}-oci-${version}"
          {
            nativeBuildInputs = [ pkgs.skopeo ];
          }
          ''
            mkdir -p "$out"
            skopeo --tmpdir "$TMPDIR" --insecure-policy copy \
              "docker-archive:${dockerArchive}" \
              "oci:$out:${version}"
          '';

      eif = nitroLib.buildEif {
        name = pname;
        inherit version;
        arch = "x86_64";
        kernel = nitroBlobs.kernel;
        kernelConfig = nitroBlobs.kernelConfig;
        nsmKo = nitroBlobs.nsmKo;
        init = if sandboxed then sandboxInit else nitroBlobs.init;
        copyToRoot = root;
        copyToRootWithClosure = true;
        entrypoint = "/bin/${pname}";
        env = ''
          RUST_LOG=info
          SSL_CERT_FILE=/etc/ssl/certs/ca-bundle.crt
        '' + pkgs.lib.optionalString (environment != [ ]) (builtins.concatStringsSep "\n" environment + "\n");
      };
    in
    {
      oci = ociImage;
      inherit eif;
    };

  migration = buildEnclaveImage {
    pname = "di-migration-enclave";
    environment = pkgs.lib.optional (pcpKmsKeyArn != null) "PCP_KMS_KEY_ARN=${pcpKmsKeyArn}";
  };
  dev = buildEnclaveImage {
    pname = "di-dev-enclave";
    sandboxed = true;
  };
in
assert pcpKmsKeyArn == null || builtins.match "arn:aws(-us-gov|-cn)?:kms:[a-z0-9-]+:[0-9]{12}:(alias|key)/[a-zA-Z0-9_/-]+" pcpKmsKeyArn != null;
{
  di-migration-oci = migration.oci;
  di-migration-eif = migration.eif;
  di-dev-oci = dev.oci;
  di-dev-eif = dev.eif;
}
