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

    git-hooks = {
      url = "github:cachix/git-hooks.nix";
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
    git-hooks,
  }:
    flake-utils.lib.eachDefaultSystem (
      system: let
        overlays = [(import rust-overlay)];
        pkgs = import nixpkgs {
          inherit system overlays;
        };

        inherit (nixpkgs) lib;

        rustToolchain = pkgs.rust-bin.stable."1.97.1".default.override {
          extensions = ["rust-src" "cargo" "rustc" "clippy" "rustfmt" "rust-analyzer"];
        };

        rustPlatform = pkgs.makeRustPlatform {
          cargo = rustToolchain;
          rustc = rustToolchain;
        };

        # Lint tools for CI jobs that don't need the Rust toolchain
        ciTools = with pkgs; [
          alejandra
          typos
        ];

        buildInputs = with pkgs;
          ciTools
          ++ [
            cargo-deny
            cargo-insta
            cargo-nextest
            gnupg
            libfaketime
            nil
            prettier
            zizmor
          ];

        nativeBuildInputs = [
          rustToolchain
        ];

        pre-commit-check = git-hooks.lib.${system}.run {
          src = ./.;
          package = pkgs.prek;
          hooks = {
            alejandra = {
              enable = true;
              settings = {
                check = true;
              };
            };

            typos = {
              enable = true;
              entry = "${pkgs.typos}/bin/typos --force-exclude";
            };
          };
        };
      in
        with pkgs; {
          checks = {
            inherit pre-commit-check;
          };

          devShells.default = mkShell {
            inherit nativeBuildInputs;
            inherit (pre-commit-check) shellHook;
            buildInputs = buildInputs ++ pre-commit-check.enabledPackages;
          };

          devShells.ci = mkShell {
            packages = ciTools;
          };

          # cargo-fuzz needs nightly for its sanitizers, so it gets its own shell
          # rather than moving the default one off the pinned stable toolchain
          devShells.fuzz = mkShell {
            packages = [
              (pkgs.rust-bin.selectLatestNightlyWith (toolchain: toolchain.minimal))
              cargo-fuzz
            ];
          };

          packages.default = pkgs.callPackage ./default.nix {
            inherit rustPlatform;
            rev = self.rev or self.dirtyRev or null;
            lastModified = self.lastModified or null;
          };
        }
    );
}
