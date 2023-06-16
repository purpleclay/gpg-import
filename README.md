# GPG Import

Easily import a GPG key within any CI workflow.

## Features

- Configures local git config (`.git/config`) within a detected repository, syncing committer details and enabling GPG signing of commits, tags, and pushes.

## Prerequisites

[Generate](https://docs.github.com/en/authentication/managing-commit-signature-verification/generating-a-new-gpg-key) a GPG key and export it to your clipboard as a base64 encoded ASCII armored private key:

```sh
# macos
gpg --armor --export-secret-key batman@dc.com | base64 | pbcopy

# linux
gpg --armor --export-secret-key batman@dc.com | base64 | xclip
```

## Quick Start

For seamless integration into your CI platform, set the `GPG_PRIVATE_KEY` environment variable and let `gpg-import` import do the rest.

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

> Git config set:
user.name:       batman
user.email:      batman@dc.com
user.signingKey: E5389A1079D5A52F
commit.gpgsign:  true
tag.gpgsign:     true
push.gpgsign:    if-asked
```
