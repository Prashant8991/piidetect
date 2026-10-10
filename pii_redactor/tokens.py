"""Stable replacement tokens: the same value always maps to the same token across the whole document."""
import re


class TokenMap:
    def __init__(self):
        self._ids = {}
        self._count = {}

    def token(self, entity_type, value):
        key = (entity_type, re.sub(r"\W+", "", value.lower()))
        if key not in self._ids:
            self._count[entity_type] = self._count.get(entity_type, 0) + 1
            self._ids[key] = self._count[entity_type]
        return f"[{entity_type}_{self._ids[key]}]"
