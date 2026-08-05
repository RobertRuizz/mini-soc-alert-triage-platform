from pathlib import Path
from typing import Any

import pytest

from app.detector import load_events
from app.rule_loader import load_all_rules


PROJECT_ROOT = Path(__file__).resolve().parent.parent


@pytest.fixture
def sample_events() -> list[dict[str, Any]]:
    """Load a fresh copy of the synthetic events for each test."""
    events_path = (
        PROJECT_ROOT
        / "data"
        / "sample_events.json"
    )

    return load_events(events_path)


@pytest.fixture
def detection_rules() -> dict[str, dict[str, Any]]:
    """Load all enabled YAML detection rules."""
    return load_all_rules()