# Evaluations

1. Query: "Let wordpress.clone also disable comments on the copy." Expected: new value in the closed `stagingDefaults` set, parse test for it, argv-order test, `docs/protocol.md` line, no new advertised operation, panel only sends it when the feature flag is true and fails closed otherwise.
2. Query: "Add an operation that clears a Joomla cache." Expected: new module + OPERATIONS entry only when usable, fixed argv through the bounded runner, tests/cli.rs list updated, panel `require_operation`.
3. Query: "The mu-plugin write follows wp-content into another directory." Expected: `symlink_metadata` checks refuse it, test with a symlinked wp-content.
