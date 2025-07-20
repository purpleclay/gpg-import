{
  darwin,
  fetchFromGitHub,
  lib,
  openssl,
  pkg-config,
  rustPlatform,
  stdenv,
  zlib,
}: let
  version = "0.5.0";
in
  rustPlatform.buildRustPackage {
    pname = "gpg-import";
    inherit version;

    src = fetchFromGitHub {
      owner = "purpleclay";
      repo = "gpg-import";
      rev = "${version}";
      hash = "sha256-HF9hbDL8wRFOwpxgXcCL1m8Qo79Rx2nCE7JgVuhmQpY=";
    };

    cargoHash = "sha256-5jLvjBVkcN6E8KPaqN8UpbOD2b1X8GDszQc37muHDd4=";

    nativeBuildInputs =
      [
        pkg-config
      ]
      ++ lib.optionals stdenv.isDarwin [
        darwin.apple_sdk.frameworks.Security
      ];

    buildInputs = [
      openssl
      zlib
    ];

    meta = with lib; {
      homepage = "https://github.com/purpleclay/gpg-import";
      changelog = "https://github.com/purpleclay/gpg-import/releases/tag/${version}";
      description = "Easily import a GPG key within any CI workflow";
      license = licenses.mit;
      maintainers = with maintainers; [purpleclay];
    };

    doCheck = false;
  }
