---
title: Decrypting secrets
summary: A description on how to decrypt secrets without relying on the operator to do it (e.a. for debugging purposes).
authors:
  - Devotional Phoenix
date: 2026-05-21
---

## Decrypting secrets in PAAS files

The `decrypt` command can be used to decrypt secrets in PAAS files. This will
create a new decrypted version of the file, using the key pair specified with the
`--publicKeyFile` flag.

`kubectl-paas decrypt --privateKeyFiles "/tmp/priv" --paas my-paas`
