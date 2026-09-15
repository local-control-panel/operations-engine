#!/usr/bin/env bash
set -euo pipefail

if [[ "$(uname -s)" != "Linux" ]]; then
  echo "Meilisearch container tests require Linux or a Linux DinD runner." >&2
  exit 1
fi

docker info >/dev/null
cargo test --test meilisearch_docker -- --ignored --test-threads=1
