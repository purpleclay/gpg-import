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
        };

        rustPlatform = pkgs.makeRustPlatform {
          cargo = rustToolchain;
          rustc = rustToolchain;
        };
        buildInputs = with pkgs; [
          alejandra
          libfaketime
          nil
          nodePackages.prettier
          openssl
          shellcheck
          shfmt
          typos
          zlib
        ];

        nativeBuildInputs = with pkgs;
          [
            rustToolchain
            pkg-config
          ]
          ++ lib.optionals stdenv.isDarwin [
            darwin.apple_sdk.frameworks.Security
          ];
      in
        with pkgs; {
          devShells.default = mkShell {
            inherit buildInputs nativeBuildInputs;
          };

          packages.default = pkgs.callPackage ./default.nix {
            inherit rustPlatform;
          };
        }
    );
}
