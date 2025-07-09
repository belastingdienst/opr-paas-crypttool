---
title: Overview
summary: A short introduction.
authors:
  - hikarukin
date: 2025-03-10
---

# Introduction to the Crypttool

The goal is to provide a tool that can be used by operators to encrypt and decrypt secrets
in their PAAS files using public keys provided by the operator.

The tool can also be used to decrypt secrets in PAAS files using the old public
keys provided by the operator and then re-encrypt them with a new key.

This can be used by operators who have a new key and are ready to replace the old keys,
for example as part of a migration process or as part of a regular key rotation process.

This documentation site is arranged into a generic section called overview and a
developer section.

If you have any questions or feel that certain parts of the documentation can be
improved or expanded, feel free to create a [PR](https://github.com/belastingdienst/opr-paas-crypttool/pulls)
(Pull Request).

For full contribution guidelines, see the `CONTRIBUTING.md` file in the root of
the repository, the [About >> Contributing](/about/contributing/) section and/or the
[Development Guide](/development-guide/).

# Basic usage

## Re-encrypting secrets with a new key

The most common use case is to re-encrypt secrets in PAAS files using a new key:

`crypttool reencrypt --privateKeyFiles "/tmp/priv" --publicKeyFile "/tmp/pub" [file or dir] ([file or dir]...)`

## Creating a new key pair

You can create a new key pair with the `keygen` command. This will generate a new
key pair and save it to a file.

`crypttool generate --publicKeyFile "/tmp/pub" --privateKeyFile "/tmp/priv"`

## Encrypting secrets in PAAS files

The `encrypt` command can be used to encrypt secrets in PAAS files. This will
create a new encrypted version of the file, using the key pair specified with the
`--publicKeyFile` flag.

`crypttool encrypt --publicKeyFile "/tmp/pub" --dataFile "/tmp/decrypted" --paas my-paas`

## Decrypting secrets in PAAS files

The `decrypt` command can be used to decrypt secrets in PAAS files. This will
create a new decrypted version of the file, using the key pair specified with the
`--publicKeyFile` flag.

`crypttool decrypt --privateKeyFiles "/tmp/priv" --paas my-paas`