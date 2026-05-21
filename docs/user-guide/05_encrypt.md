---
title: Encryption
summary: How encryption works
authors:
  - Devotional Phoenix
date: 2026-05-21
---

## Encrypting secrets in PAAS files

The `encrypt` command can be used to encrypt secrets in PAAS files. This will
create a new encrypted version of the file, using the key pair specified with the
`--publicKeyFile` flag.

`kubectl-paas encrypt --publicKeyFile "/tmp/pub" --dataFile "/tmp/decrypted" --paas my-paas`
