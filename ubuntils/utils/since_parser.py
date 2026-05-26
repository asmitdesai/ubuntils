from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone

from dateutil import parser as dateutil_parser

_RELATIVE_RE = re.compile(r'^(\d+)(m|h|d|w)$')
_UNITS = {'m': 'minutes', 'h': 'hours', 'd': 'days', 'w': 'weeks'}


def parse_since(value: str) -> datetime:
    m = _RELATIVE_RE.match(value.strip())
    if m:
        amount = int(m.group(1))
        unit = _UNITS[m.group(2)]
        return datetime.now(tz=timezone.utc) - timedelta(**{unit: amount})
    try:
        dt = dateutil_parser.parse(value)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except Exception:
        raise ValueError(
            f"Invalid --since value: {value!r}. "
            "Use relative (e.g. '24h', '7d') or absolute (e.g. '2026-05-20', '2026-05-20 14:00')."
        )
