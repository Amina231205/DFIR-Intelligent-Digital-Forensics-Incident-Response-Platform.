"""Shared pytest fixtures."""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from helpers import SAMPLE_DIR


@pytest.fixture
def case(tmp_path: Path) -> Path:
    """A fresh, disposable copy of the sample case (the original is never touched)."""
    destination = tmp_path / "INC-001"
    shutil.copytree(SAMPLE_DIR, destination)
    return destination
