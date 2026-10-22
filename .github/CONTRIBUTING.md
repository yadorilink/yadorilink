# Contributing to YadoriLink

Thanks for taking the time to improve YadoriLink. The project is pre-1.0, so
interfaces and workflows can still change quickly, but small, focused issues
and pull requests are welcome.

## Before Opening an Issue

- Search existing issues first.
- Do not include credentials, tokens, private keys, recovery codes, account
  IDs, device IDs, or private file contents.
- Report security vulnerabilities by email as described in
  [SECURITY.md](SECURITY.md), not in a public issue.
- For diagnostics, prefer the built-in report export flow and review the
  exported JSON before sharing it.

## Development Setup

Install a stable Rust toolchain and Protocol Buffers compiler, then run:

```bash
cargo build --workspace
cargo test --workspace
```

## Checks Before a Pull Request

Run the checks that match the area you changed:

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo audit
```

For the Windows shell extension:

```bash
cd crates/yadorilink-shell-ext-windows
cargo fmt --all -- --check
cargo clippy --all-targets -- -D warnings
cargo build --release
```

## Pull Request Guidelines

- Keep PRs focused on one behavior or documentation change.
- Include tests when changing sync, transport, persistence, IPC, or security
  relevant behavior.
- Document user-visible CLI or packaging changes.
- Explain any intentionally skipped platform check in the PR description.
- Do not add new network submission, telemetry, credential handling, or
  key-handling behavior without calling it out explicitly.

## Licensing

The open engine is licensed under AGPL-3.0-only (see `LICENSE` and
[LICENSING.md](../LICENSING.md)).

Contributions are accepted under the [Contributor License Agreement](CLA.md)
(current text: [v1.0](legal/CLA-v1.0.md)). You keep the copyright in your
contribution. You grant the maintainer a broad copyright and patent licence,
including the right to sublicense it under AGPL-3.0-only or other licence
terms, commercial ones included. This is why the CLA is required alongside the
AGPL: the copyright holder needs additional licensing rights, for example to
use contributed code in the proprietary official applications.

You must explicitly agree before a pull request can be merged: the contributor
licence check comments on your first pull request with the sentence to reply
with (`I have read and agree to the YadoriLink CLA v1.0`). The agreement is
recorded once per GitHub account and version. Maintainers and automation
accounts are exempt.
