# Release Policy

ZitPit releases are signed and verifiable.

## Release Process

1. bump the version in `Cargo.toml`
2. create a signed Git tag for the release
3. build release artifacts in CI
4. publish release hashes and provenance
5. attach attestations where supported

## Release Rule

A release is not complete until its exact artifact identity and provenance are published.

If a hash or provenance check fails, treat the release as compromised.

