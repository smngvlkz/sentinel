"""
A capped table that a flood of one-off entries can't empty.

A plain "drop whatever was quiet longest" table has a weakness: a flood of
packets from made-up addresses creates a new entry per packet and pushes
everything else out, including a slow port scan running underneath it, which
then never accumulates enough evidence to be caught. Made-up addresses are
each used once, though, and a real scanner reuses its address for every
probe. So entries start in a small probation area and move to a protected
one when seen a second time; one-off entries only ever push each other out.

Entries pushed out of probation are remembered by key alone (no data) in a
list of recently dropped keys, twice the table's size. A key that comes back
while still on that list goes straight to protected: that catches a scanner
whose first probe was pushed out before its second arrived.

Limits: an attacker who sends from each made-up address twice fills the
protected area too, and a flood fast enough to cycle through the dropped
list before a scanner's next probe still hides it. Either way the table
drops entries, which raises the RESOURCE_PRESSURE alert.

Both areas are kept in order of last activity, so expiry still pops stale
entries from the quiet end of each, exactly as before.
"""

from __future__ import annotations

from collections import OrderedDict
from collections.abc import Callable, Hashable, Iterator, Mapping
from typing import Generic, TypeVar

K = TypeVar("K", bound=Hashable)
V = TypeVar("V")

PROBATION_SHARE = 0.25
DROPPED_KEYS_FACTOR = 2

_MISSING = object()


class SeenTwiceTable(Mapping[K, V], Generic[K, V]):

    def __init__(self, cap: int, on_evict: Callable[[K, V], None] | None = None) -> None:
        self.cap = max(2, int(cap))
        self.probation_cap = max(1, int(self.cap * PROBATION_SHARE))
        self.protected_cap = self.cap - self.probation_cap
        self.dropped_cap = self.cap * DROPPED_KEYS_FACTOR
        self._probation: OrderedDict[K, V] = OrderedDict()
        self._protected: OrderedDict[K, V] = OrderedDict()
        self._dropped: OrderedDict[K, None] = OrderedDict()
        self.on_evict = on_evict
        self.evicted = 0

    # Read access, without counting as activity.
    def __getitem__(self, key: K) -> V:
        value = self._protected.get(key, _MISSING)
        if value is _MISSING:
            return self._probation[key]
        return value  # type: ignore[return-value]

    def get(self, key: K, default: V | None = None) -> V | None:  # type: ignore[override]
        value = self._protected.get(key, _MISSING)
        if value is _MISSING:
            return self._probation.get(key, default)
        return value  # type: ignore[return-value]

    def __contains__(self, key: object) -> bool:
        return key in self._protected or key in self._probation

    def __iter__(self) -> Iterator[K]:
        yield from self._probation
        yield from self._protected

    def __len__(self) -> int:
        return len(self._probation) + len(self._protected)

    def items(self):  # type: ignore[override]
        yield from self._probation.items()
        yield from self._protected.items()

    def values(self):  # type: ignore[override]
        yield from self._probation.values()
        yield from self._protected.values()

    def touch(self, key: K, make: Callable[[], V]) -> V:
        """The entry for `key`, created with `make()` if new, marked as active now."""
        value = self._protected.get(key, _MISSING)
        if value is not _MISSING:
            self._protected.move_to_end(key)
            return value  # type: ignore[return-value]
        value = self._probation.pop(key, _MISSING)
        if value is not _MISSING:
            self._protect(key, value)  # type: ignore[arg-type]
            return value  # type: ignore[return-value]
        value = make()
        if self._dropped.pop(key, _MISSING) is not _MISSING:
            self._protect(key, value)
        else:
            self._probation[key] = value
            while len(self._probation) > self.probation_cap:
                self._drop(self._probation)
        return value

    def _protect(self, key: K, value: V) -> None:
        self._protected[key] = value
        while len(self._protected) > self.protected_cap:
            self._drop(self._protected)

    def _drop(self, area: OrderedDict[K, V]) -> None:
        key, value = area.popitem(last=False)
        self._dropped[key] = None
        while len(self._dropped) > self.dropped_cap:
            self._dropped.popitem(last=False)
        self.evicted += 1
        if self.on_evict is not None:
            self.on_evict(key, value)

    def expire(self, is_stale: Callable[[V], bool], on_remove: Callable[[K, V], None] | None = None) -> int:
        """Remove stale entries from the quiet end of each area; returns how many."""
        removed = 0
        for area in (self._probation, self._protected):
            while area:
                key, value = next(iter(area.items()))
                if not is_stale(value):
                    break
                del area[key]
                removed += 1
                if on_remove is not None:
                    on_remove(key, value)
        return removed
