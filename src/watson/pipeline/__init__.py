"""Watson Pre-Synthesis Pipeline.

Universal target canonicalization + multilingual relevance filtering.
Works for any target type (person, org, domain, email, wallet, phone, IP, username)
and any language/script (Latin, Cyrillic, CJK, Arabic, Devanagari, etc.).

Conservative by design: only drops findings with ZERO relevance (no token overlap
AND no verified source URL). Never penalizes borderline cases.
"""

from .pre_synthesis import (
    TargetProfile,
    canonicalize_target,
    relevance_score,
    relevance_filter,
)
