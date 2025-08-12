# https://github.com/loophp/rust-shell/blob/main/flake.nix
{
  description = "Rust shells";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
    rust-overlay.url = "github:oxalica/rust-overlay";

    flake-parts = {
      url = "github:hercules-ci/flake-parts";
      inputs.nixpkgs-lib.follows = "nixpkgs";
    };

    devshell = {
      url = "github:numtide/devshell";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs = inputs @ {
    flake-parts,
    devshell,
    ...
  }:
    flake-parts.lib.mkFlake {inherit inputs;} {
      systems = [
        "x86_64-linux"
        "aarch64-linux"
        "aarch64-darwin"
      ];

      imports = [
        devshell.flakeModule
      ];

      perSystem = {
        config,
        pkgs,
        system,
        ...
      }: let
        pkgs = import inputs.nixpkgs {
          inherit system;
          overlays = [(import inputs.rust-overlay)];
        };

        makeRustInfo = {
          version,
          profile,
        }: let
          rust = pkgs.rust-bin.${version}.latest.${profile}.override {extensions = ["rust-src"];};
        in {
          name = "rust-" + version + "-" + profile;

          # From https://discourse.nixos.org/t/rust-src-not-found-and-other-misadventures-of-developing-rust-on-nixos/11570/11
          path = "${rust}/lib/rustlib/src/rust/library";

          drvs = [
            pkgs.just
            pkgs.openssl
            pkgs.pkg-config
            pkgs.rust-analyzer
            rust
            pkgs.gcc
            pkgs.dbus.dev
            pkgs.gdb
            pkgs.protobuf
            pkgs.lldb
            (
              pkgs.python3.withPackages (
                ps: [
                  ps.pycryptodome
                ]
              )
            )

            (
              let
                binwalk = pkgs.python3Packages.callPackage ./pkgs/binwalk-old.nix {};
              in
                with pkgs.python3Packages; toPythonApplication binwalk
              # pkgs.binwalk.overrideAttrs (oldAttrs: {
              #   src = pkgs.fetchFromGitHub {
              #     owner = "ReFirmLabs";
              #     repo = "binwalk";
              #     rev = "4b09fca2af088e38ed1a16889c2df4ca7e59fe6e";
              #     hash = "sha256-xzrkpZ534HbI7bXQCiEONB6v7S9wD2qdlLuP9ZEeEes=";
              #   };
              #   cargoHash = "";
              #   cargoSha256 = "";
              # })
            )
          ];

          PKG_CONFIG_PATH = "";
        };

        makeRustEnv = {
          version,
          profile,
        }: let
          rustInfo = makeRustInfo {
            inherit version profile;
          };
        in
          pkgs.buildEnv {
            name = rustInfo.name;
            paths = rustInfo.drvs;
          };

        versions = {
          stable-default = {
            version = "stable";
            profile = "default";
          };

          stable-minimal = {
            version = "stable";
            profile = "minimal";
          };

          beta-default = {
            version = "beta";
            profile = "default";
          };

          beta-minimal = {
            version = "beta";
            profile = "minimal";
          };

          nightly-default = {
            version = "nightly";
            profile = "default";
          };

          nightly-minimal = {
            version = "nightly";
            profile = "minimal";
          };
        };
      in {
        devshells.default = let
          version = versions.stable-default.version;
          profile = versions.stable-default.profile;

          rustInfo = makeRustInfo {
            inherit version profile;
          };
        in {
          name = rustInfo.name;

          env = [
            {
              # rust-analyzer may use this to quicker find the rust source
              name = "RUST_SRC_PATH";
              value = "${rustInfo.path}";
            }

            {
              name = "PKG_CONFIG_PATH";
              prefix = "$DEVSHELL_DIR/lib/pkgconfig";
            }
          ];

          packages = rustInfo.drvs;
        };
      };
    };
}
