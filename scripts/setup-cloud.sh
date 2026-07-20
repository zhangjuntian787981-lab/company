#!/bin/sh
set -eu

PROJECT_ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
GO_VERSION=1.26.5
CLAUDE_CODE_VERSION=2.1.215
PINNED_GO="$PROJECT_ROOT/.tools/go/bin/go"
PINNED_GOFMT="$PROJECT_ROOT/.tools/go/bin/gofmt"

if [ -x "$PINNED_GO" ] && [ -x "$PINNED_GOFMT" ]; then
    GO_BINARY=$PINNED_GO
else
    GO_BINARY=$(command -v go || true)
fi

if [ -z "$GO_BINARY" ] || ! "$GO_BINARY" version 2>/dev/null | grep -q "go${GO_VERSION}"; then
    mise install "go@${GO_VERSION}"
    mise use --global "go@${GO_VERSION}"
    GO_BINARY=$(mise which go --tool="go@${GO_VERSION}")
fi

GOFMT_BINARY="$(dirname -- "$GO_BINARY")/gofmt"
if [ ! -x "$GOFMT_BINARY" ]; then
    echo "matching gofmt is unavailable: $GOFMT_BINARY" >&2
    exit 1
fi

mkdir -p "$(dirname -- "$PINNED_GO")"
if [ "$GO_BINARY" != "$PINNED_GO" ]; then
    ln -sf "$GO_BINARY" "$PINNED_GO"
fi
if [ "$GOFMT_BINARY" != "$PINNED_GOFMT" ]; then
    ln -sf "$GOFMT_BINARY" "$PINNED_GOFMT"
fi

if ! claude --version 2>/dev/null | grep -q "${CLAUDE_CODE_VERSION}"; then
    npm install -g "@anthropic-ai/claude-code@${CLAUDE_CODE_VERSION}" --no-audit --no-fund
fi

cd "$PROJECT_ROOT"
python3 scripts/bootstrap-cloud.py
