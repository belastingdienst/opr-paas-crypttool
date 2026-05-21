---
title: Overview
summary: A short introduction.
authors:
  - Devotional Phoenix
date: 2026-05-21
---

# Introduction to kubectl-paas

The `kubectl-paas` is meant to manage Paas resources with an interface which is more usable than `kubectl` itself.
The `kubectl-paas` is meant to be used as a kubectl plugin, which means that if you download the latest version
name it `kubectl-paas` and place it in your path, it will extend kubectl (e.a. you can use it as `kubectl paas [...]`).
`kubectl-paas` tries to align with commandline arguments of kubectl as closely as possible.

`kubectl-paas` will use a kubernetes connection for any info it requires and is not passed as argument.
For example: When running `kubectl-paas` reencrypt, it will look for private keys in kubernetes, by getting
and parsing paas config and fetching the secret as set in PaasConfig. Alternatively you can pass the keys by
passing a path to a folder either by environment variables or arguments.
Docs on the specific sub commands have more descriptions on the exact workings, arguments and environment variables.

`kubectl-paas` supports all current versions of opr-paas resources (e.a. v1alpha2 as of this writing).
Additionally, `kubectl-paas` supports upgrading the latest removed version (e.a. v1alpha1 as of this writing) to the latest version.

For more info, please refer to the docs for specific subcommands.

## Types of docs

kubectl-paas was meant to be used by Administrators managing the Paas operator,
and by Users managing their Paas and PaasNs resources.
This docs describes all options specific to Users (and/or Administrators).
For docs on these and other commands with elevated permissions, we need to refer you to [the user docs instead](../administrators-guide/)

For Developer, please see our full contribution guidelines in the `CONTRIBUTING.md` file in the root of
the repository, the [About >> Contributing](/about/contributing/) section and/or the
[Development Guide](/development-guide/).

## Questions and commments
If you have any questions or feel that certain parts of the documentation can be
improved or expanded, feel free to create a [PR](https://github.com/belastingdienst/opr-paas-cli/pulls)
(Pull Request).

