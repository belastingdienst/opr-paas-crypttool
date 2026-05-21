---
title: Reencryption
summary: A description of the reencrypt subcommand
authors:
  - Devotional Phoenix
date: 2026-05-21
---

## Re-encrypting secrets with a new key

The most common use case is to re-encrypt secrets in PAAS files using a new key:

`kubectl-paas reencrypt --privateKeyFiles "/tmp/priv" --publicKeyFile "/tmp/pub" [file or dir] ([file or dir]...)`

!!! note
    Rencryption without the --preserve option will always convert to the latest api version (currently v1alpha2).
    The --preserved option has no extra validation on version and works for all currently known versions.
    This may change in the future.
