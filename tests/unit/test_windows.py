from datetime import datetime, timedelta

from cypher.features.windows import SlidingWindowCounter


def test_counts_within_window():
    c = SlidingWindowCounter()
    now = datetime(2026, 1, 1, 12, 0, 0)
    for i in range(5):
        c.add("1.2.3.4", now + timedelta(seconds=i))
    assert c.count("1.2.3.4", window_seconds=60, now=now + timedelta(seconds=4)) == 5


def test_prunes_entries_outside_window():
    c = SlidingWindowCounter()
    now = datetime(2026, 1, 1, 12, 0, 0)
    c.add("1.2.3.4", now)
    c.add("1.2.3.4", now + timedelta(seconds=120))
    assert c.count("1.2.3.4", window_seconds=60, now=now + timedelta(seconds=120)) == 1


def test_separate_keys_do_not_interfere():
    c = SlidingWindowCounter()
    now = datetime(2026, 1, 1, 12, 0, 0)
    c.add("1.1.1.1", now)
    c.add("2.2.2.2", now)
    c.add("2.2.2.2", now)
    assert c.count("1.1.1.1", 60, now=now) == 1
    assert c.count("2.2.2.2", 60, now=now) == 2
