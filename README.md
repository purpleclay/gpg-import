# GPG Import

Easily import a GPG key within any CI workflow. Runs on any Linux, MacOs or Windows build agent.

## Features

- Configures local git config (`.git/config`) within a detected repository, syncing committer details and enabling GPG signing of commits, tags, and pushes. You can skip this step by setting the `GPG_SKIP_GIT=true` environment variable.
- Seed the GPG Agent with your key's passphrase to remove the need for manual passphrase entry by simply setting the `GPG_PASSPHRASE` environment variable. For best security practice, mask the variable in your chosen CI tool.
- Set the owner trust level of a private GPG key by defining the `GPG_TRUST_LEVEL` environment variable. Trust levels range between 1 (`undefined`) and 5 (`ultimate`), details of each can be found [here](https://gpgtools.tenderapp.com/kb/faq/what-is-ownertrust-trust-levels-explained).

## Install

To install the latest version using a bash script:

```sh
curl https://raw.githubusercontent.com/purpleclay/gpg-import/main/scripts/install \
  | bash
```

Download a specific version using the `-v` flag. The script uses `sudo` by default but can be disabled through the `--no-sudo` flag.

```sh
curl https://raw.githubusercontent.com/purpleclay/gpg-import/main/scripts/install \
  | bash -s -- -v 0.3.0 --no-sudo
```

## Prerequisites

[Generate](https://docs.github.com/en/authentication/managing-commit-signature-verification/generating-a-new-gpg-key) a GPG key and export it to your clipboard as a base64 encoded ASCII armored private key:

```sh
# macos
gpg --armor --export-secret-key batman@dc.com | base64 | pbcopy

# linux
gpg --armor --export-secret-key batman@dc.com | base64 | xclip
```

## Quick Start

For seamless integration into your CI platform, set the `GPG_PRIVATE_KEY` and any optional environment variables (`GPG_PASSPHRASE` and `GPG_TRUST_LEVEL`), then let `gpg-import` import do the rest.

```sh
$ gpg-import

> Detected GnuPG:
version: 2.4.1 (libgcrypt: 1.10.2)
homedir: /root/.gnupg

> Imported GPG key:
fingerprint: 241315DDAB6865162C0389BFE5389A1079D5A52F
keygrip:     147098685499F4C183A39CA1A51CDE6316DDD479
key_id:      E5389A1079D5A52F
user:        batman <batman@dc.com>
created_on:  Tue, 09 May 2023 19:39:26 +0000
sub_keygrip: A213D84D786B8DBED68195C178B650CD24B88B2D
sub_key_id:  2D219DD41933A2D5

> Setting Passphrase:
keygrip: 147098685499F4C183A39CA1A51CDE6316DDD479 [E5389A1079D5A52F]
keygrip: A213D84D786B8DBED68195C178B650CD24B88B2D [2D219DD41933A2D5]

> Setting Trust Level:
trust_level: 5 [E5389A1079D5A52F]

> Git config set:
user.name:       batman
user.email:      batman@dc.com
user.signingKey: E5389A1079D5A52F
commit.gpgsign:  true
tag.gpgsign:     true
push.gpgsign:    if-asked
```
