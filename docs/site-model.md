# Site identity and filesystem model

Status: Phase 2 contract  
Last updated: 2026-09-02

## Stable identity

Every managed site receives an opaque, canonical UUID called `siteId`.

```text
550e8400-e29b-41d4-a716-446655440000
```

The domain is not the site identity. Domains, filenames, runtime pools, and
document roots can change while `siteId` remains stable. New requests must use
`siteId`; a domain may be included only as display or expected-state metadata.

The control plane allocates and stores `siteId` once. Operations Engine accepts
only the lowercase hyphenated UUID form and uses it as the key for manifests,
locks, transactions, releases, and audit records.

## Configuration source

Requests do not contain an arbitrary absolute site root. Operations Engine
resolves `siteId` through a root-owned manifest:

```text
/etc/operations-engine/sites/<siteId>.json
```

The proposed manifest contains only execution policy and non-secret identity:

```json
{
  "schemaVersion": 1,
  "siteId": "550e8400-e29b-41d4-a716-446655440000",
  "domain": "example.com",
  "contentRoot": "sites/550e8400-e29b-41d4-a716-446655440000",
  "siteUser": "site-example",
  "repository": {
    "url": "git@github.com:example/site.git",
    "allowedBranches": ["main"],
    "credentialId": "550e8400-e29b-41d4-a716-446655440000"
  }
}
```

`contentRoot` is relative to a configured trusted root. Repository and branch
values supplied by a mutation request must match registered policy; they do not
replace it.

Manifest creation/update is a separate privileged operation with its own
validation and atomic-write contract. Deploy and rollback never rewrite the
manifest.

## Trusted roots

The initial configuration has an explicit allowlist, for example:

```json
{
  "schemaVersion": 1,
  "contentRoots": ["/var/www"],
  "stateRoot": "/var/lib/operations-engine",
  "credentialRoot": "/var/lib/operations-engine/credentials"
}
```

Rules:

- roots are absolute, normalized, and cannot be `/`;
- request payloads select no root and contain no absolute filesystem path;
- site-relative paths contain only normal components—no empty value, `.`,
  `..`, absolute prefix, or NUL byte;
- existing paths are canonicalized and must remain beneath the canonical root;
- symlinks that resolve outside the trusted root are rejected;
- creating a new path requires directory-relative operations that prevent
  symlink replacement races; lexical `join` plus a containment check is not
  sufficient for mutations.

The current validation types implement lexical validation and safe resolution
of existing paths. Creation/mutation primitives remain pending; no deploy code
may use `TrustedRoot::join` alone as an authorization check.

## Filesystem layout

Proposed layout:

```text
/etc/operations-engine/
  config.json                         root:root 0644
  sites/<siteId>.json                 root:root 0644

/var/lib/operations-engine/
  credentials/<credentialId>          ops-engine:ops-engine 0600
  sites/<siteId>/
    active                            symlink managed atomically
    releases/<releaseId>/             owned by the site's service user
    transactions/<requestId>.json     ops-engine:ops-engine 0600
    locks/mutation.lock               ops-engine:ops-engine 0600
    audit/events.jsonl                ops-engine:ops-engine 0600
```

The final active-release switch mechanism is decided in Phase 2 after checking
how Caddy and runtime configs currently reference document roots. Until then,
`active` is a proposed representation, not an implemented contract.

## Ownership and privilege direction

- `/usr/local/bin/ops-engine` is owned by root and not writable by its invoking
  user.
- Root-owned configuration defines all trusted filesystem boundaries.
- A non-login `ops-engine` service identity owns engine transaction state and
  installed credentials.
- Site release contents are owned by the existing per-site Unix user where one
  exists.
- Privilege escalation is limited to named entry points needed for manifest
  installation, ownership changes, and atomic activation.
- The structured API never accepts arbitrary executables, shell commands,
  users, ownership IDs, or sudo arguments.

The exact invoking user and sudoers entries remain open until the existing
server bootstrap and per-site user lifecycle are mapped in detail.

## Git revision validation

The engine accepts a resolved full object ID, not a short SHA. Validation
currently allows 40-character SHA-1 and 64-character SHA-256 hexadecimal object
IDs and normalizes ASCII hex to lowercase.

A syntactically valid object ID is not sufficient authorization. Deploy must
resolve it from an allowed remote ref; rollback must find a retained release
with that object ID in engine-owned state.

## Security invariants

- Changing a domain does not change `siteId` or orphan engine state.
- A request cannot direct an operation outside configured roots.
- A manifest cannot select `/` as a trusted content root.
- Existing symlink traversal outside a trusted root is rejected.
- Rollback never trusts client-side history as its authorization source.
- A full commit SHA does not become eligible until repository policy or retained
  release state authorizes it.
