---
title: Migration
summary: Migrating between olders versions of a Paas and the latest version
authors:
  - Devotional Phoenix
date: 2026-05-21
---

# Migrating a PAAS from older versions to the latest (currently v1alpha2)

The `migrate` command can be used to convert yaml/json files with PAAS versions from olders versions to the latest.
This will read the file, migrate it to the latest version and write the new version back.
We do not preserve any formatting, ordering, comments, etc.

Example for migrating all files in the current folder:

`crypttool migrate *`

!!! note
    crypttool will be renamed to kubectl-paas and will cover more than just the encryption of secrets
