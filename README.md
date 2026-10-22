# GPG Import

![Nix](https://img.shields.io/badge/Nix-5277C3?logo=nixos&logoColor=white)
![Rust](https://img.shields.io/badge/Rust-CE412B?logo=rust&logoColor=white)
[![MIT](https://img.shields.io/badge/MIT-gray?logo=github&logoColor=white)](LICENSE)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/purpleclay/gpg-import/badge)](https://scorecard.dev/viewer/?uri=github.com/purpleclay/gpg-import)

Import and configure GPG signing for git. Runs on Linux and macOS.

> [!TIP]
> Requires GnuPG (`gpg` and `gpg-connect-agent`) on your `$PATH`, and `git` for configuring signing. `git` isn't needed with `--skip-git`.

## Features

- Import GPG keys in ASCII armored format (_optionally base64 encoded for CI environments_) from an environment variable, stdin or a file.
- Read the passphrase from an environment variable, stdin or a file, keeping it off the command line.
- Preset the passphrase in the GPG agent for the primary key and every subkey, for non-interactive signing.
- Configure local or global git signing for commits, tags and pushes.
- Select a specific key or subkey for signing by fingerprint. GPG then signs with exactly that key, not the newest signing subkey.
- Set key trust level.
- Refuse an expired primary key or selected subkey, and flag unused expired subkeys in the output.
- Create `gpg.conf` and `gpg-agent.conf` with defaults for non-interactive signing, without overwriting existing ones.
- Override committer identity independently from the GPG key.
- Dry-run mode to preview changes without applying them.

## Install

To install the latest version using a bash script:

```sh
sh -c "$(curl https://raw.githubusercontent.com/purpleclay/gpg-import/main/scripts/install.sh)"
```

To install a specific version, into another directory or without `sudo`, see the installer's options:

```sh
sh -c "$(curl https://raw.githubusercontent.com/purpleclay/gpg-import/main/scripts/install.sh)" \
  -- --help
```

## Run with Nix

If you have nix installed, you can run the binary directly from the GitHub repository:

```sh
nix run github:purpleclay/gpg-import -- --help
```

## Preparing your GPG key

[Generate](https://docs.github.com/en/authentication/managing-commit-signature-verification/generating-a-new-gpg-key) a GPG key and export it as an ASCII armored private key:

```sh
gpg --armor --export-secret-key batman@dc.com
```

For CI environments that don't handle multiline secrets well, you can base64 encode the key:

```sh
gpg --armor --export-secret-key batman@dc.com | base64
```

`base64` wraps its output at 76 columns by default. Wrapped input is accepted, so there is no need for `-w 0`.

## Quick Start

Set the `GPG_PRIVATE_KEY` environment variable (and optionally `GPG_PASSPHRASE`), then run:

```sh
$ gpg-import

> Detected GnuPG:
version: 2.4.5 (libgcrypt: 1.10.3)
homedir: /root/.gnupg

> Imported GPG key:
user:           batman <batman@dc.com>
fingerprint:    85E1AA4D4F9FE316A8F452DDEF48BE1DFBFA8BA5
keygrip:        99A0B6DD933CC25D0DC8D36299B4F51A9E3DD8C9
key_id:         EF48BE1DFBFA8BA5
created_on:     Wed, 11 Jun 2025 04:36:06 +0000
expires_on:     Thu, 11 Jun 2026 04:36:06 +0000 (in 364 days)
sub_keygrip:    A6780D53C3236724F960FD8AC07848F38C66CF48
sub_key_id:     008183F9F50359D1
sub_created_on: Wed, 11 Jun 2025 04:36:06 +0000
sub_expires_on: Fri, 11 Jul 2025 04:36:59 +0000 (in 29 days)

> GPG config:
gpg.conf:       written
gpg-agent.conf: written

> Setting Passphrase:
keygrip: 99A0B6DD933CC25D0DC8D36299B4F51A9E3DD8C9 [EF48BE1DFBFA8BA5]
keygrip: A6780D53C3236724F960FD8AC07848F38C66CF48 [008183F9F50359D1]

> Setting Trust Level:
trust_level: 5 [EF48BE1DFBFA8BA5]

> Git config set (local):
user.name:       batman
user.email:      batman@dc.com
user.signingKey: EF48BE1DFBFA8BA5
commit.gpgsign:  true
tag.gpgsign:     true
push.gpgsign:    if-asked
```

> [!TIP]
> On a workstation, your existing `gpg.conf` and `gpg-agent.conf` are left alone. To preset a passphrase, your `gpg-agent.conf` must contain `allow-preset-passphrase`.
