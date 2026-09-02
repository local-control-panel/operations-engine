# Subprocess execution

All external programs used by Operations Engine must run through the bounded
runner in `src/process.rs`.

## Required inputs

Every call defines:

- one explicit executable;
- an explicit argument list;
- a timeout;
- maximum retained stdout and stderr byte counts;
- a cancellation token.

The runner does not invoke a shell. Operation code must not concatenate an
executable and untrusted input into a command string.

## Output bounds

stdout and stderr are drained concurrently to prevent a child from blocking on
a full pipe. Only the configured prefix of each stream is retained. The
`truncated` field records whether additional bytes were discarded.

Draining is bounded in memory, but not in the total number of bytes a child may
attempt to write before the timeout. Callers must therefore choose a short,
operation-specific timeout and must never return captured output without
redaction and an explicit protocol contract.

## Termination

The runner distinguishes normal exit, timeout, and accepted cancellation. On
timeout or cancellation it terminates the direct child and waits for it before
returning.

The current runner does not establish or terminate an entire Unix process
group. Commands used through it must not detach descendants or hand inherited
stdout/stderr pipes to background processes. Process-group termination must be
implemented and tested before workflows that can spawn descendants are
accepted.

The polling interval is an implementation detail and is not a protocol timing
guarantee.

## Error mapping

Starting a missing executable maps to dependency or subprocess availability at
the operation boundary. Other runner failures map to an internal failure unless
an operation documents a safer and more specific interpretation.

Timeout and cancellation map to the stable `TIMEOUT` and `CANCELLED` protocol
codes when they terminate a requested operation. A non-successful child exit
maps to `SUBPROCESS_FAILED`; raw child output is not automatically included in
the response.

## Tests

The runner is tested for output truncation, timeout, and cancellation. Commands
that use it must additionally test their own exit-code mapping, redaction, and
operation-specific limits.
