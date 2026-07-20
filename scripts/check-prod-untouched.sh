#!/bin/sh
set -eu

REPO_ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
export PYTHONPATH="$REPO_ROOT"
exec python3 -m harness.prod_guard "$@"
