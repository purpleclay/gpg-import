# GPG Import

Easily import a GPG key within any CI workflow. Runs on any Linux, MacOs or Windows build agent.

## Features

- Configures local git config (`.git/config`) within a detected repository, syncing committer details and enabling GPG signing of commits, tags, and pushes. You can skip this step by setting the `GPG_SKIP_GIT=true` environment variable.
- Seed the GPG Agent with your key's passphrase to remove the need for manual passphrase entry by simply setting the `GPG_PASSPHRASE` environment variable. For best security practice, mask the variable in your chosen CI tool.
- Set the owner trust level of a private GPG key by defining the `GPG_TRUST_LEVEL` environment variable. Trust levels range between 1 (`undefined`) and 5 (`ultimate`), details of each can be found [here](https://gpgtools.tenderapp.com/kb/faq/what-is-ownertrust-trust-levels-explained).

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

## Prerequisites

[Generate](https://docs.github.com/en/authentication/managing-commit-signature-verification/generating-a-new-gpg-key) a GPG key and export it to your clipboard as a base64 encoded ASCII armored private key:

```sh
# macos
gpg --armor --export-secret-key batman@dc.com | base64 -w 0 | pbcopy

# linux
gpg --armor --export-secret-key batman@dc.com | base64 -w 0  | xclip
```

## Quick Start

For seamless integration into your CI platform, set the `GPG_PRIVATE_KEY` and any optional environment variables (`GPG_PASSPHRASE` and `GPG_TRUST_LEVEL`), then let `gpg-import` import do the rest.

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

> Git config set:
user.name:       batman
user.email:      batman@dc.com
user.signingKey: AE799E2DEB4AFE11
commit.gpgsign:  true
tag.gpgsign:     true
push.gpgsign:    if-asked
```
