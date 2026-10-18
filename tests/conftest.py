"""Shared fixtures: repo paths and a temporary data directory."""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))


@pytest.fixture(scope="session")
def data_dir() -> Path:
    return ROOT / "data"


@pytest.fixture(scope="session")
def eml_dir(data_dir: Path) -> Path:
    return data_dir / "samples" / "eml"
