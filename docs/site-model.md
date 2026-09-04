# Site identity and filesystem model

Status: Phase 2 contract  
Last updated: 2026-09-04

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
  "contentRoot": "sites/550e8400-e29b-41d4-a716-446655440000/current",
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
  "schemaVersion": 2,
  "contentRoots": ["/var/www"],
  "stateRoot": "/var/lib/operations-engine",
  "credentialRoot": "/var/lib/operations-engine-credentials",
  "ingressRoot": "/var/lib/operations-engine-ingress"
}
```

Every field above is required. `schemaVersion` must equal the engine's
`CONFIG_SCHEMA_VERSION` exactly — an older or newer value is rejected outright
rather than partially honored, so a config written for a different engine
version can never be silently misread. `ingressRoot` arrived with schema
version 2, for `ingress.activateConfig`; it is the one root outside a site's
own content root that a mutation may write into, and it must not overlap any
content root, the state root, or the credential root.

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

One documented exception to the second rule exists today: `ingress
activate-config --content-file <path>` names a host path the engine reads the
submitted route file from. It is read-only, never a write destination, and the
read is bounded — the engine opens the path, refuses anything that is not a
regular file (so a FIFO cannot block this root process and a directory or
device node cannot be submitted), and reads at most `MAX_CONTENT_BYTES + 1`
bytes so an oversized file is rejected during the read rather than after it is
already in memory. The path is still not resolved through a trusted root, which
is weaker than every other path this engine handles; requiring it to live under
a root-owned staging root is a recorded follow-up (it needs a new configured
root, so a schema bump, and coordinated client staging).

The validation types implement lexical validation and safe resolution of
existing paths. Capability-relative directory creation and reads are available;
atomic file/symlink replacement belongs to the transaction layer. No deploy
code may use `TrustedRoot::join` alone as an authorization check.

Race-safe relative access is implemented through `ManagedRoot`, backed by
[`cap-std`](https://docs.rs/cap-std/latest/cap_std/fs/struct.Dir.html). Ambient
authority is used only once to open a validated configured root; subsequent
operations are relative to that directory capability. Pre-existing symlinks
that escape the capability root are rejected.

## Filesystem layout

Proposed layout:

```text
/etc/operations-engine/
  config.json                         root:root 0644
  sites/<siteId>.json                 root:root 0644

/var/lib/operations-engine/
  credentials/<credentialId>          ops-engine:ops-engine 0600
  sites/<siteId>/
    current                           relative symlink managed atomically
    releases/<releaseId>/             owned by the site's service user
    shared/                            persistent site-owned content
    transactions/<requestId>.json     ops-engine:ops-engine 0600
    locks/mutation.lock               ops-engine:ops-engine 0600
    audit/events.jsonl                ops-engine:ops-engine 0600
```

### Activation decision

The stable document root is `<content-root>/sites/<siteId>/current`. `current`
is a relative symlink to `releases/<releaseId>`. A new relative symlink is
created under a unique temporary name in the same directory and then renamed
over `current`; same-directory rename is the commit point.

Caddy and the per-site FrankenPHP child currently embed an absolute document
root, and the site's `.user.ini` currently restricts `open_basedir` to that
exact root. Adopting the release layout therefore requires a one-time,
transactional integration migration:

1. import the existing content as the initial release;
2. create `current` without changing live routing;
3. regenerate runtime identity and Caddy configuration to point to `current`;
4. set `open_basedir` to the stable site base so both `current` and declared
   `shared` paths remain usable;
5. reload and probe the runtime;
6. retain the old configuration and content until the probe succeeds.

Operations that need persistent writable content must declare allowlisted
relative shared paths in a future manifest revision. Deploy creates only
relative links from a release into the site's `shared` directory. No default
shared-path guess is made for arbitrary applications.

## Ownership and privilege direction

- `/usr/local/bin/ops-engine` is owned by root and not writable by its invoking
  user.
- Root-owned configuration defines all trusted filesystem boundaries.
- The daemonless MVP is invoked by a dedicated non-login SSH automation user.
  Its sudo policy permits only the root-owned `ops-engine` executable, not a
  shell, Git, filesystem utilities, or user-selected binaries.
- Mutation commands start with elevated authority, load root-owned policy, and
  expose only the compiled operation allowlist. There is no arbitrary command
  or absolute-path parameter.
- Git and build subprocesses drop to the manifest's existing per-site UID/GID;
  they do not run as root.
- Each installed credential directory is owned by its per-site user with mode
  `0700`; the private key is mode `0600`. Requests select only a validated
  credential ID already registered in the manifest.
- Site release contents are owned by the existing per-site Unix user where one
  exists.
- Engine state that controls activation, locks, transactions, and audit records
  remains root-owned and is not writable by the site user.
- The structured API never accepts arbitrary executables, shell commands,
  users, ownership IDs, or sudo arguments.

This is the MVP boundary. A later daemon/socket design requires a separate
threat model and is not implied by these sudo rules.

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
- The site user cannot rewrite `current`, transaction state, locks, or manifests.
- The automation user cannot invoke a general privileged shell through the
  Operations Engine sudo entry.
