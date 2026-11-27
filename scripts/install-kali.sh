#!/usr/bin/env bash
set -euo pipefail
if [[ "$(uname -s)" != "Linux" ]]; then
  echo "This installer targets Kali Linux." >&2
  exit 1
fi
command -v go >/dev/null || { echo "Install Go 1.26+ first." >&2; exit 1; }
root="$(cd "$(dirname "$0")/.." && pwd)"
(cd "$root" && go install ./cmd/tunnelcheck)
bin="$(go env GOPATH)/bin"
case ":$PATH:" in
  *":$bin:"*) ;;
  *) echo "Add $bin to PATH, then run: tunnelcheck -h" ;;
esac
