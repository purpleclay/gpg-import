# GPG Import

![Nix](https://img.shields.io/badge/Nix-5277C3?logo=nixos&logoColor=white)
![Rust](https://img.shields.io/badge/Rust-CE412B?logo=rust&logoColor=white)
[![MIT](https://img.shields.io/badge/MIT-gray?logo=github&logoColor=white)](LICENSE)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/purpleclay/gpg-import/badge)](https://scorecard.dev/viewer/?uri=github.com/purpleclay/gpg-import)
[![SLSA 3](https://slsa.dev/images/gh-badge-level3.svg)](https://slsa.dev)

Import and configure GPG signing for git. Runs on Linux and macOS.

> [!IMPORTANT]
> Requires GnuPG (`gpg` and `gpg-connect-agent`) on your `$PATH`. `git` is optional, and only needed to configure signing.

## Features

- Import GPG keys in ASCII armored format (_optionally base64 encoded for CI environments_).
- Read the key and passphrase from an environment variable, stdin or a file, keeping them off the command line.
- Preset the passphrase in the GPG agent for the primary key and every subkey, for non-interactive signing.
- Configure local or global git signing for commits, tags and pushes, or only the ones you choose with `--sign`. Settings for the rest are left alone.
- Select a specific key or subkey for signing by fingerprint. GPG then signs with exactly that key, not the newest signing subkey.
- Set key trust level.
- Refuse an expired primary key or selected subkey, and flag unused expired subkeys in the output.
- Create `gpg.conf` and `gpg-agent.conf` with defaults for non-interactive signing, without overwriting existing ones.
- Override committer identity independently from the GPG key.
- Dry-run mode to preview changes without applying them.

## Install

```sh
curl -fsSL https://get.purpleclay.io | sh -s -- gpg-import
gpg-import --help
```

> [!TIP]
> By default, `gpg-import` installs to `~/.local/bin`. If that isn't on your `$PATH`, add it, or install to `/usr/local/bin` by running the installer with `sudo`:
>
> ```sh
> curl -fsSL https://get.purpleclay.io | sudo sh -s -- gpg-import
> ```

Or, with Nix, run it straight from the repository without installing:

```sh
nix run github:purpleclay/gpg-import -- --help
```

## Preparing your GPG key

[Generate](https://docs.github.com/en/authentication/managing-commit-signature-verification/generating-a-new-gpg-key) a GPG key and export it as an ASCII armored private key:

```sh
gpg --armor --export-secret-key batman@dc.com

# For CI systems that don't handle multiline secrets, base64 encode it.
# Wrapped output is accepted, so there's no need for -w 0
gpg --armor --export-secret-key batman@dc.com | base64
```

Export one key per run. If the input holds more than one key, public or secret, `gpg-import` fails and lists their fingerprints. gpg will already have imported them into the keyring by then.

The key's first uid supplies the git identity (`user.name` and `user.email`). Use `--git-committer-name` and `--git-committer-email` to override it.

## Quick start

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

> Verified signing:
signing_key: 85E1AA4D4F9FE316A8F452DDEF48BE1DFBFA8BA5
signed_with: 85E1AA4D4F9FE316A8F452DDEF48BE1DFBFA8BA5

> Git config set (local):
user.name:       batman
user.email:      batman@dc.com
user.signingKey: 85E1AA4D4F9FE316A8F452DDEF48BE1DFBFA8BA5
commit.gpgsign:  true
tag.gpgsign:     true
push.gpgsign:    if-asked
```

> [!NOTE]
> On a workstation, your existing `gpg.conf` and `gpg-agent.conf` are left alone. To preset a passphrase, your `gpg-agent.conf` must contain `allow-preset-passphrase`.
