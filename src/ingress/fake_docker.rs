//! The fake `docker` fixture the `ingress` unit tests drive
//! `caddy validate`/`caddy reload` outcomes with. Shared between
//! `activate`'s tests (which exercise the sequence itself) and
//! `execute`'s (which exercise the mutation wiring around it), so both
//! reach the container steps through the same real `process::run` path
//! rather than a second, differently-behaved stand-in.

use std::fs;

use crate::compose;

/// A fake `docker` (written through `compose::write_fake_docker`, the
/// same fixture Task 2's own tests use) that records every
/// `caddy validate`/`caddy reload` it is asked for and can be told to
/// fail either of them — the first N times, or always. That is enough
/// to drive every branch of the activation sequence deterministically
/// without a Compose stack, a container, or a real Caddy.
pub(crate) struct FakeDocker {
    pub(crate) dir: tempfile::TempDir,
}

impl FakeDocker {
    pub(crate) fn new() -> Self {
        let dir = tempfile::tempdir().expect("fake docker directory should be created");
        fs::create_dir(dir.path().join("bin")).expect("bin directory should be created");
        fs::create_dir(dir.path().join("control")).expect("control directory should exist");
        let control = dir.path().join("control");
        compose::write_fake_docker(
            &dir.path().join("bin"),
            // Shell builtins only, deliberately: `docker_path`
            // replaces `PATH` outright for this child (see
            // `compose::Access`), so a fixture that reached for
            // `wc`/`cat`/`tr` would silently find none of them and
            // exit 0 no matter what it was told to do.
            &format!(
                r#"mode=unknown
for arg in "$@"; do
  case "$arg" in
validate) mode=validate ;;
reload) mode=reload ;;
  esac
done
control='{control}'
printf '%s\n' "$*" >> "$control/$mode.calls"
count=0
while read -r _line; do count=$((count+1)); done < "$control/$mode.calls"
if [ -f "$control/fail-$mode" ]; then
  read -r limit < "$control/fail-$mode"
  if [ "$limit" = all ] || [ "$count" -le "$limit" ]; then
printf 'simulated %s failure\n' "$mode" >&2
exit 1
  fi
fi
exit 0"#,
                control = control.display()
            ),
        );
        Self { dir }
    }

    /// Fails the next `times` calls of `mode` (`"all"` for every call).
    pub(crate) fn failing(self, mode: &str, times: &str) -> Self {
        // Trailing newline so the fixture's builtin `read` sees a
        // complete line.
        fs::write(
            self.dir.path().join(format!("control/fail-{mode}")),
            format!("{times}\n"),
        )
        .expect("control file should be written");
        self
    }

    pub(crate) fn access(&self) -> compose::Access {
        compose::Access::default()
            // Any existing directory works: the fake `docker` never
            // reads a Compose file. The real resolution of
            // `COMPOSE_BASE_DIR` is `compose.rs`'s own tested concern.
            .stack_dir(self.dir.path())
            .docker_path(self.dir.path().join("bin"))
    }

    pub(crate) fn calls(&self, mode: &str) -> Vec<String> {
        match fs::read_to_string(self.dir.path().join(format!("control/{mode}.calls"))) {
            Ok(log) => log.lines().map(str::to_owned).collect(),
            Err(_) => Vec::new(),
        }
    }
}
