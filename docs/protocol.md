# Protocol

Operations Engine protocol version 1 uses one JSON object per completed
operation. Long-running operations may later add JSON Lines progress events,
but that feature is not implemented yet.

## Response envelope

```json
{
  "protocolVersion": 1,
  "operation": "version",
  "ok": true,
  "result": {},
  "warnings": [],
  "error": null
}
```

| Field | Meaning |
| --- | --- |
| `protocolVersion` | Version of the response contract, independent of the binary version. |
| `operation` | Stable operation identifier. |
| `ok` | Whether the operation completed successfully. |
| `result` | Operation-specific result, or `null` after a failure. |
| `warnings` | Non-fatal machine-readable warnings. |
| `error` | Stable error code, safe message, and optional structured details. |

## Output rules

- Field names use `camelCase`.
- stdout contains protocol output only.
- stderr contains human-oriented diagnostic logs.
- Secret values and raw environment dumps are forbidden in both streams.
- Clients must ignore unknown result fields within a compatible protocol
  version.
- Clients must reject unsupported protocol versions rather than attempting to
  interpret them.
- Operation and warning codes are stable API values, not display text.

## Version negotiation

Clients should call `version` and `capabilities` before using operations whose
availability depends on the installed engine version. The engine semantic
version describes a release; `protocolVersion` describes the wire contract.
Neither value substitutes for the other.

Protocol-breaking changes require a new protocol version. Adding an optional
result field or a new capability does not necessarily require one.

## Exit status

An envelope with `ok: true` exits with status 0. An envelope with `ok: false`
exits with a non-zero status. CLI parsing errors occur before an operation is
selected and are currently emitted by the argument parser on stderr.

