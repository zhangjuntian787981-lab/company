#!/bin/sh
set -eu

PROJECT_ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
GO_VERSION=1.26.5
CLAUDE_CODE_VERSION=2.1.215

if ! go version 2>/dev/null | grep -q "go${GO_VERSION}"; then
    mise install "go@${GO_VERSION}"
    mise use --global "go@${GO_VERSION}"
fi

if ! claude --version 2>/dev/null | grep -q "${CLAUDE_CODE_VERSION}"; then
    npm install -g "@anthropic-ai/claude-code@${CLAUDE_CODE_VERSION}" --no-audit --no-fund
fi

cd "$PROJECT_ROOT"
python3 scripts/bootstrap-cloud.py
