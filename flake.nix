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

  outputs = { self, nixpkgs, flake-utils, rust-overlay }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        overlays = [ (import rust-overlay) ];
        pkgs = import nixpkgs {
          inherit system overlays;
        };

        inherit (nixpkgs) lib;

        buildInputs = with pkgs; [
          openssl
          zlib
          libfaketime
        ];

        nativeBuildInputs = with pkgs; [
          (rust-bin.stable.latest.default.override{
            extensions = ["rust-src" "cargo" "rustc"];
          })
          pkg-config
        ]
        ++ lib.optionals stdenv.isDarwin [ darwin.apple_sdk.frameworks.Security ];
      in
      with pkgs;
      {
        devShells.default = mkShell {
          inherit buildInputs nativeBuildInputs;
        };
      }
    );
}
