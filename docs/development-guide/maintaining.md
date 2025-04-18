---
title: Maintenance
summary: How to maintain the crypttool.
authors:
  - devotional-phoenix-97
  - hikarukin
date: 2025-03-10
---

Introduction
============

This file documents the methods and standards that should be applied by the maintainers
of this project. For example: how to create a new release.

Standards used
--------------

### Commits

We adhere to the [Conventional Commits v1.0](https://www.conventionalcommits.org/en/v1.0.0/)
standard.

### Versioning

For versioning purposes, we adhere to the [SemVer v2.0.0](https://semver.org/spec/v2.0.0.html)
standard with a side note that we always prefix the semantic version number with
the character 'v'. This stands for "version".

As a quick summary, this means we use version numbers in the style of vX.Y.Z.
With:

- X being major, including breaking, changes;
- Y being minor, possibly including patch but never breaking, changes;
- Z being patch, but never breaking, changes;

Methods used
------------

### Creating a release

We release from `main`. All changes to `main` are made through PRs. Merging a PR
will trigger the release drafter action to create a draft release.

The process to create a release is mostly automated, to start it:

- Merge one or more PRs to `main`;
- Ensure completeness;
- Edit the draft release and publish it;
