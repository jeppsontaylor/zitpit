# Dependency Policy

ZitPit treats dependency and license policy as part of the public repo contract.

The canonical configuration lives in [`deny.toml`](../deny.toml) and is enforced by CI with `cargo deny check all`.

## Launch Posture

- denied licenses fail CI
- known RustSec advisories fail CI
- yanked crates fail CI
- unknown registries fail CI
- Git-based dependencies require explicit review before they can land

## Default License Allowlist

The launch allowlist is intentionally narrow:

- `MIT`
- `Apache-2.0`
- `BSD-2-Clause`
- `BSD-3-Clause`
- `ISC`
- `MPL-2.0`
- `Unicode-3.0`
- `Zlib`

If a new transitive dependency brings in a different license, either replace the dependency or add a deliberate, reviewed policy change to `deny.toml`.

## Updating The Policy

When a dependency exception is genuinely needed:

1. confirm the crate is still necessary
2. review the new license, advisory, or source risk
3. update [`deny.toml`](../deny.toml) in the smallest possible way
4. explain the exception in the PR summary
5. rerun `cargo deny check all`

Do not silently widen the policy just to make CI green.

The current launch config includes only narrowly reviewed exceptions:

- `CDLA-Permissive-2.0` because it is required by `webpki-roots`
- `RUSTSEC-2024-0436` because `paste` is a transitive dependency of the current `ratatui` stack and does not yet have a safe upstream replacement in this workspace
