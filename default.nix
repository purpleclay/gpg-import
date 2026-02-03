{
  lib,
  openssl,
  pkg-config,
  rustPlatform,
  zlib,
}:
rustPlatform.buildRustPackage {
  pname = "gpg-import";
  version = (builtins.fromTOML (builtins.readFile ./Cargo.toml)).package.version;
  src = ./.;

  cargoLock = {
    lockFile = ./Cargo.lock;
  };

  nativeBuildInputs = [
    pkg-config
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
