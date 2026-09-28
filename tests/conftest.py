from datetime import UTC, datetime, timedelta

import pytest

from sysscan.models import Category, InventoryItem, TimeConfidence

T0 = datetime(2026, 9, 19, 12, 0, tzinfo=UTC)
T1 = T0 + timedelta(days=7)


def item(key, name, version, *, source="registry", cat=Category.DESKTOP_APP, t=None,
         conf=TimeConfidence.FILE, publisher=None):
    return InventoryItem(key=key, category=cat, source=source, name=name, version=version, publisher=publisher,
                         install_time=t, time_confidence=conf if t else TimeConfidence.UNKNOWN)


@pytest.fixture
def home(tmp_path, monkeypatch):
    monkeypatch.setenv("SYSSCAN_HOME", str(tmp_path / "home"))
    return tmp_path / "home"
