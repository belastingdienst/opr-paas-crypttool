# opr-paas-crypttool

## Goal

The goal is to provide a tool that can be used by operators to encrypt and decrypt secrets
in their PAAS files using public keys provided by the operator.

The tool can also be used to decrypt secrets in PAAS files using the old public
keys provided by the operator and then re-encrypt them with a new key.

This can be used by operators who have a new key and are ready to replace the old keys,
for example as part of a migration process or as part of a regular key rotation process.

## Quickstart

The most common use case is to re-encrypt secrets in PAAS files using a new key:

`crypttool reencrypt --privateKeyFiles "/tmp/priv" --publicKeyFile "/tmp/pub" [file or dir] ([file or dir]...)`

## Contributing

Please refer to our documentation in the [CONTRIBUTING.md](./CONTRIBUTING.md) file
and the Developer Guide section of the documentation site if you want to help us
improve the Paas Operator.

## License

Copyright 2025, Tax Administration of The Netherlands.
Licensed under the EUPL 1.2.

See [LICENSE.md](./LICENSE.md) for details.
