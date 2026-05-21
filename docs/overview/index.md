---
title: Overview
summary: A short introduction.
authors:
  - hikarukin
date: 2025-03-10
---

# Introduction to kubectl-paas

The goal is to provide a tool that can be used by operators to encrypt and decrypt secrets
in their PAAS files using public keys provided by the operator.

The tool can also be used to decrypt secrets in PAAS files using the old public
keys provided by the operator and then re-encrypt them with a new key.

This can be used by operators who have a new key and are ready to replace the old keys,
for example as part of a migration process or as part of a regular key rotation process.

This documentation site is arranged into a generic section called overview and a
developer section.

If you have any questions or feel that certain parts of the documentation can be
improved or expanded, feel free to create a [PR](https://github.com/belastingdienst/opr-paas-cli/pulls)
(Pull Request).

For User docs, see the [user guide](./user-guide/), for admin commands (elevated permissions), see [teh admin guide](./administrators-guide).
And for full contribution guidelines, see the `CONTRIBUTING.md` file in the root of
the repository, the [About >> Contributing](/about/contributing/) section and/or the
[Development Guide](/development-guide/).
