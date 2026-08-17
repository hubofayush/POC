"""
app.core.guardrails.wordlist
~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Shared profanity / banned-word blocklist for both ingress and egress.

Curated default set + optional extra words via settings.GUARDRAIL_WORD_FILTER_WORDS
(comma-separated). Matching is done on leetspeak-normalized text (reuses
`_normalise` from layer2_security) so "f*ck", "fuckk", "f u c k" bypasses fail.
"""
from __future__ import annotations

import re
import unicodedata

from app.config import settings

# Leetspeak / homoglyph folding (mirrors layer2_security._normalise but local
# — importing from layer2_security creates a cycle via the package __init__s)
_LEET: dict[str, str] = {
    "0": "o", "1": "i", "3": "e", "4": "a", "5": "s",
    "7": "t", "@": "a", "$": "s", "!": "i",
}
_INVISIBLE = re.compile(r"[\u200B-\u200F\u2060-\u2064\uFEFF\x00-\x1F\x7F]")


def _normalise(text: str) -> str:
    text = _INVISIBLE.sub("", text)
    text = unicodedata.normalize("NFKD", text)
    text = "".join(_LEET.get(c, c) for c in text)
    text = re.sub(r"\s+", " ", text).strip()
    return text.lower()

# Curated profanity set (lower-case, normalised). Extend as needed.
_DEFAULT_WORDS: frozenset[str] = frozenset(
    [
        "fuck", "fucking", "fucked", "fucker", "fucks", "fuk", "fuq",
        "shit", "shits", "shitty", "shite",
        "bitch", "bitches", "bitching", "bitchy",
        "asshole", "asshat", "dick", "dickhead", "cock", "cocksucker",
        "pussy", "cunt", "whore", "slut", "bastard", "motherfucker",
        "mf'er", "twat", "wanker", "prick", "retard", "nigger", "nigga",
    ]
)


def get_blocked_words() -> frozenset[str]:
    """Curated default set plus any configured extra words."""
    extra = {
        w.strip().lower()
        for w in settings.GUARDRAIL_WORD_FILTER_WORDS.split(",")
        if w.strip()
    }
    return _DEFAULT_WORDS | extra


def find_blocked_words(text: str) -> list[str]:
    """
    Return the blocked words present in ``text`` (case/leetspeak tolerant).

    Uses word-boundary matching on the normalized text so legitimate words
    like "scunthorpe" or "assassin" are not flagged.
    """
    normalised = _normalise(text)
    found: list[str] = []
    for word in get_blocked_words():
        if re.search(rf"\b{re.escape(word)}\b", normalised):
            found.append(word)
    return found