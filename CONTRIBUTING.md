# Contributing

Operations Engine is at an early stage. Protocol and security decisions should
be made explicitly before adding mutating server operations.

## Local checks

Run all checks before opening a pull request:

```console
cargo fmt --all --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-features
```

The CI workflow runs the same checks on Linux and verifies that the project
still compiles with the minimum supported Rust version declared in
`Cargo.toml`.

## Design rules

- Keep stdout reserved for protocol output after CLI arguments are accepted.
- Send diagnostic information to stderr.
- Do not expose secrets, credentials, private keys, or raw environment dumps.
- Use stable, documented operation names and error codes.
- Keep protocol compatibility independent from the crate version.
- Start subprocesses with an executable and explicit arguments. Avoid `sh -c`.
- Validate all identifiers and paths again at the server execution boundary.
- Add integration tests for every command's public JSON shape.
- Do not advertise an operation through `capabilities` before it is implemented.

## Adding a command

1. Define its CLI shape in `src/cli.rs`.
2. Implement it in a dedicated module under `src/commands`.
3. Return a protocol `Response`; do not print from the command module.
4. Register the operation in `capabilities` only when it is usable.
5. Add integration tests under `tests/`.
6. Document security boundaries, failure states, and recovery behavior for any
   mutation.

Mutating commands additionally require an idempotency strategy, locking rules,
an audit event shape, interruption tests, and an explicit recovery procedure.

