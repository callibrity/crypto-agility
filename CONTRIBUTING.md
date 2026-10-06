# Contributing

Thanks for taking a look. This repository is a teaching demo: its job is to make
crypto agility easy to see and easy to try. Changes that serve that are welcome.

## What fits

- **Fixes**, to the code or to the docs. If an experiment in
  [docs/exploring.md](docs/exploring.md) doesn't do what it says, that's a bug.
- **Clearer explanations.** If something confused you, it will confuse the next
  person too.
- **New algorithms.** A new `KeyWrapper` (or `DataCipher`) that describes itself
  through `facts()`, plus one register line in `LocalKms`. Experiment 5 in the
  exploring guide walks through what that takes.
- **Adapters for real key management services.** A `KeyManagementService` for
  AWS KMS, Google Cloud KMS, Azure Key Vault or HashiCorp Vault would show the
  seam working against the real thing.

## What doesn't

Turning this into a production library. The envelope format is homegrown and
`LocalKms` keeps its keys in plain files on purpose, so you can look at them.
Hardening those would hide the ideas the repo is here to show. For production,
use a real KMS with a reviewed library such as Tink or the AWS Encryption SDK.

## Reporting a problem

Open an issue with what you ran, what you expected and what happened. The output
of `java -version` helps, since the algorithms on offer depend on the JDK.

## Sending a change

1. Fork the repository and create a branch.
2. Make the change, with tests. Tests read as sentences: `snake_case` method
   names under `@Nested` classes, with `@DisplayNameGeneration(ReplaceUnderscores)`.
3. Run the build: `./mvnw verify`.
4. Tidy formatting and license headers: `./mvnw spotless:apply license:format`.
   CI checks both (google-java-format, and the Apache header on every source
   file); local builds don't, so you can experiment freely until you're ready.
5. Open a pull request saying what changed and why.

A few conventions the code follows:

- No suppressed warnings; fix the cause instead.
- No star imports.
- Singular package names (`wrapper`, not `wrappers`).

## Code of conduct

Everyone taking part is expected to follow the [code of conduct](CODE_OF_CONDUCT.md).

## License

By contributing, you agree that your contributions will be licensed under the
[Apache License 2.0](LICENSE).
