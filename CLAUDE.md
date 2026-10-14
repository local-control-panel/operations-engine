# Project Instructions

## Git Commits

Never add a `Co-Authored-By:` trailer to commit messages in this repository.

## Checks before a PR

`cargo fmt --all`, `cargo clippy --all-targets --all-features -- -D warnings`,
`cargo test --all-features`. CI also checks the minimum supported Rust version.

## Rules that always apply

- This engine is the only component that mutates a customer server; every
  mutation is a typed operation with a validated request, a bounded subprocess
  and a recorded transaction. See `CONTRIBUTING.md` and `docs/protocol.md`.
- Do not advertise an operation or feature before it works.
- Secrets never appear in argv, state, audit or error text.

## Project skills

`.claude/skills/adding-engine-operations` is the procedure for new operations,
extended requests, capability features and the panel pin bump.
