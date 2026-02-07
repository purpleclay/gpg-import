# GPG Import

Import and configure GPG signing for git. Runs on Linux and MacOS.

## Features

- Import GPG keys in ASCII armored format (_optionally base64 encoded for CI environments_).
- Configure local or global git signing settings.
- Preset GPG agent passphrase for non-interactive signing.
- Set key trust level.
- Select a specific key or subkey for signing via fingerprint.
- Override committer identity independently from the GPG key.
- Dry-run mode to preview changes without applying them.

## Install

To install the latest version using a bash script:

```sh
sh -c "$(curl https://raw.githubusercontent.com/purpleclay/gpg-import/main/scripts/install)"
```

Download a specific version using the `-v` flag. The script uses `sudo` by default but can be disabled through the `--no-sudo` flag. You can also provide a different installation directory from the default `/usr/local/bin` by using the `-d` flag:

```sh
sh -c "$(curl https://raw.githubusercontent.com/purpleclay/gpg-import/main/scripts/install)" \
  -- -v 0.3.0 --no-sudo -d ./bin
```

## Run with Nix

If you have nix installed, you can run the binary directly from the GitHub repository:

```sh
nix run github:purpleclay/gpg-import -- --help
```

## Prerequisites

[Generate](https://docs.github.com/en/authentication/managing-commit-signature-verification/generating-a-new-gpg-key) a GPG key and export it as an ASCII armored private key:

```sh
gpg --armor --export-secret-key batman@dc.com
```

For CI environments that don't handle multiline secrets well, you can base64 encode the key:

```sh
gpg --armor --export-secret-key batman@dc.com | base64
```

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

> Setting Passphrase:
keygrip: 99A0B6DD933CC25D0DC8D36299B4F51A9E3DD8C9 [EF48BE1DFBFA8BA5]
keygrip: A6780D53C3236724F960FD8AC07848F38C66CF48 [008183F9F50359D1]

> Setting Trust Level:
trust_level: 5 [EF48BE1DFBFA8BA5]

> Git config set (local):
user.name:       batman
user.email:      batman@dc.com
user.signingKey: AE799E2DEB4AFE11
commit.gpgsign:  true
tag.gpgsign:     true
push.gpgsign:    if-asked
```

## Configuration

All options can be set via CLI flags or environment variables:

| Flag                    | Environment Variable      | Description                                                |
| ----------------------- | ------------------------- | ---------------------------------------------------------- |
| `-k, --key`             | `GPG_PRIVATE_KEY`         | GPG private key (ASCII armored, optionally base64 encoded) |
| `-p, --passphrase`      | `GPG_PASSPHRASE`          | Passphrase for the GPG key                                 |
| `-f, --fingerprint`     | `GPG_FINGERPRINT`         | Fingerprint of a specific key or subkey to use for signing |
| `-t, --trust-level`     | `GPG_TRUST_LEVEL`         | Trust level for the key (1-5)                              |
| `-s, --skip-git`        | `GPG_SKIP_GIT`            | Skip git configuration                                     |
| `--git-global-config`   | `GPG_GIT_GLOBAL_CONFIG`   | Apply git config globally instead of locally               |
| `--git-committer-name`  | `GPG_GIT_COMMITTER_NAME`  | Override committer name                                    |
| `--git-committer-email` | `GPG_GIT_COMMITTER_EMAIL` | Override committer email                                   |
| `--dry-run`             | `GPG_DRY_RUN`             | Preview changes without applying them                      |

### Trust Levels

| Level | Description               |
| ----- | ------------------------- |
| 1     | I don't know or won't say |
| 2     | I do NOT trust            |
| 3     | I trust marginally        |
| 4     | I trust fully             |
| 5     | I trust ultimately        |

## Examples

### Basic import with passphrase

```sh
gpg-import --key "$GPG_PRIVATE_KEY" --passphrase "$GPG_PASSPHRASE"
```

### Global git configuration

Apply signing configuration to your global git config instead of the local repository:

```sh
gpg-import --key "$GPG_PRIVATE_KEY" --git-global-config
```

### Using a specific subkey

Select a specific subkey for signing by its fingerprint:

```sh
gpg-import --key "$GPG_PRIVATE_KEY" --fingerprint "A6780D53C3236724F960FD8AC07848F38C66CF48"
```

### Override committer identity

Use a different committer identity than the one in the GPG key:

```sh
gpg-import --key "$GPG_PRIVATE_KEY" \
  --git-committer-name "Bruce Wayne" \
  --git-committer-email "bruce@wayne.enterprises"
```

### Dry run

Preview what would happen without making any changes:

```sh
gpg-import --key "$GPG_PRIVATE_KEY" --dry-run
```
