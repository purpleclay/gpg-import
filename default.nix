{
  lib,
  rustPlatform,
  rev ? null,
  lastModified ? null,
}:
rustPlatform.buildRustPackage {
  pname = "gpg-import";
  version = (builtins.fromTOML (builtins.readFile ./Cargo.toml)).package.version;
  src = ./.;

  cargoLock = {
    lockFile = ./Cargo.lock;
  };

  # The Nix sandbox has no .git, so build.rs reads the commit from these instead
  GPG_IMPORT_GIT_SHA = rev;
  SOURCE_DATE_EPOCH = lastModified;

  meta = with lib; {
    homepage = "https://github.com/purpleclay/gpg-import";
    changelog = "https://github.com/purpleclay/gpg-import/releases/tag/${version}";
    description = "Easily import a GPG key within any CI workflow";
    license = licenses.mit;
    maintainers = with maintainers; [purpleclay];
  };

  doCheck = false;
}
