"""
What counts as a hostname. Shared by capture, which learns names from
packets, and the analyzer, which checks them again as they come off the
stream, so both sides always apply the same rule.
"""

from __future__ import annotations

import re

# A DNS name is at most 253 characters.
MAX_NAME_LEN = 253
# Labels of letters, digits, hyphens and underscores (underscores aren't
# valid in strict hostnames but appear in real DNS). Punycode (xn--...) is
# plain ASCII, so internationalised names pass.
_HOSTNAME = re.compile(r"[a-z0-9_-]{1,63}(?:\.[a-z0-9_-]{1,63})*")


def valid_hostname(name: str) -> str | None:
    """
    `name` as a lowercase hostname, or None if it isn't one. Names are
    dropped, never cleaned: stripping characters can turn a hostile name into
    a different, real-looking domain (pay<b>pal.com → paybpal.com), and
    showing a name that was never sent is worse than none.
    """
    name = name.lower()
    if name.endswith("."):
        name = name[:-1]
    if len(name) <= MAX_NAME_LEN and _HOSTNAME.fullmatch(name):
        return name
    return None
