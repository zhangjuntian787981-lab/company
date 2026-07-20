#!/usr/bin/env python3
"""Resolve local or cloud executables without machine-specific assumptions."""

import os
import shutil
from pathlib import Path
from typing import Optional


def resolve_executable(
    environment_variable: str,
    preferred: Optional[Path],
    command: str,
) -> Path:
    override = os.environ.get(environment_variable, "").strip()
    if override:
        return Path(override).expanduser()
    if preferred is not None and preferred.is_file():
        return preferred
    discovered = shutil.which(command)
    if discovered:
        return Path(discovered)
    return preferred if preferred is not None else Path(command)
