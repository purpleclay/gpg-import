{
  description = "Easily import a GPG key within any CI workflow";

  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs?ref=nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs = {
        nixpkgs.follows = "nixpkgs";
      };
    };
  };

  outputs = {
    self,
    nixpkgs,
    flake-utils,
    rust-overlay,
  }:
    flake-utils.lib.eachDefaultSystem (
      system: let
        overlays = [(import rust-overlay)];
        pkgs = import nixpkgs {
          inherit system overlays;
        };

        inherit (nixpkgs) lib;

        rustToolchain = pkgs.rust-bin.stable."1.87.0".default.override {
          extensions = ["rust-src" "cargo" "rustc" "clippy" "rustfmt"];
          targets = [
            "x86_64-unknown-linux-musl"
            "aarch64-unknown-linux-musl"
            "x86_64-apple-darwin"
            "aarch64-apple-darwin"
          ];
        };

        rustPlatform = pkgs.makeRustPlatform {
          cargo = rustToolchain;
          rustc = rustToolchain;
        };

        buildInputs = with pkgs; [
          alejandra
          cargo-zigbuild
          libfaketime
          nil
          nodePackages.prettier
          openssl
          shellcheck
          shfmt
          typos
          zig
          zlib
          zlib.dev
          zlib.static
        ];

        nativeBuildInputs = with pkgs;
          [
            rustToolchain
            pkg-config
          ]
          ++ lib.optionals stdenv.isDarwin [darwin.apple_sdk.frameworks.Security];
      in
        with pkgs; {
          devShells.default = mkShell {
            inherit buildInputs nativeBuildInputs;

            # Environment variables for cargo-zigbuild cross-compilation
            CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_LINKER = "${pkgs.zig}/bin/zig";
            CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_LINKER = "${pkgs.zig}/bin/zig";
            CARGO_TARGET_X86_64_APPLE_DARWIN_LINKER = "${pkgs.zig}/bin/zig";
            CARGO_TARGET_AARCH64_APPLE_DARWIN_LINKER = "${pkgs.zig}/bin/zig";

            # Provide include paths for cross-compilation
            C_INCLUDE_PATH = "${pkgs.zlib.dev}/include";
            CPATH = "${pkgs.zlib.dev}/include";

            # Target-specific RUSTFLAGS for static linking (only for musl targets)
            CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_RUSTFLAGS = "-C target-feature=+crt-static";
            CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_RUSTFLAGS = "-C target-feature=+crt-static";
          };

          packages.default = pkgs.callPackage ./default.nix {
            inherit rustPlatform;
          };
        }
    );
}
