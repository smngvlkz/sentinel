"""Unit tests for analysis_service.seen_twice.SeenTwiceTable."""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from analysis_service.seen_twice import SeenTwiceTable


def table(cap=8, evicted=None):
    return SeenTwiceTable(cap, on_evict=(lambda k, v: evicted.append(k)) if evicted is not None else None)


def test_one_offs_only_push_out_each_other():
    t = table(cap=8)                      # probation 2, protected 6
    t.touch("keep", dict)
    t.touch("keep", dict)                 # second sighting: protected
    for i in range(100):
        t.touch(f"spoof{i}", dict)
    assert "keep" in t and len(t) == 3    # keep + the two newest one-offs
    assert t.evicted == 98


def test_dropped_key_returns_straight_to_protected():
    t = table(cap=8)
    t.touch("scanner", dict)
    for i in range(5):
        t.touch(f"spoof{i}", dict)        # pushes the scanner out of probation
    assert "scanner" not in t
    t.touch("scanner", dict)              # remembered as recently dropped
    for i in range(5, 100):
        t.touch(f"spoof{i}", dict)
    assert "scanner" in t


def test_forgotten_after_the_dropped_list_cycles():
    t = table(cap=8)                      # dropped list holds 16 keys
    t.touch("scanner", dict)
    for i in range(100):
        t.touch(f"spoof{i}", dict)
    t.touch("scanner", dict)              # back too late: a one-off again
    for i in range(100, 200):
        t.touch(f"spoof{i}", dict)
    assert "scanner" not in t


def test_protected_has_its_own_limit():
    evicted = []
    t = table(cap=8, evicted=evicted)     # protected 6
    for i in range(10):
        t.touch(i, dict)
        t.touch(i, dict)
    assert len(t) == 6 and evicted == [0, 1, 2, 3]


def test_values_survive_promotion():
    t = table()
    first = t.touch("k", lambda: {"n": 1})
    first["n"] += 1
    assert t.touch("k", dict) is first and t["k"] == {"n": 2}


def test_expire_takes_stale_entries_from_both_areas():
    removed = []
    t = table(cap=8)
    t.touch("old-protected", lambda: [1.0])
    t.touch("old-protected", dict)
    t.touch("old-probation", lambda: [2.0])
    t.touch("new", lambda: [50.0])
    n = t.expire(lambda v: v[0] < 10, on_remove=lambda k, v: removed.append(k))
    assert n == 2 and sorted(removed) == ["old-probation", "old-protected"]
    assert list(t) == ["new"] and t.evicted == 0      # expiry isn't eviction


def test_reads_dont_count_as_activity():
    t = table(cap=8)
    t.touch("k", dict)
    assert t.get("k") == {} and t["k"] == {} and "k" in t
    for i in range(2):
        t.touch(f"spoof{i}", dict)
    assert "k" not in t                   # get() didn't promote it


def test_behaves_like_a_mapping():
    t = table()
    assert t == {}
    t.touch("a", lambda: 1)
    assert t == {"a": 1} and dict(t.items()) == {"a": 1} and list(t.values()) == [1]
