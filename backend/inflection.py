"""
Minimal inflection helpers required by Django REST Framework's OpenAPI generator.

This project only needs ``pluralize`` for operationId generation.
"""


def pluralize(word: str) -> str:
    text = str(word or "")
    if not text:
        return text

    lower = text.lower()
    if lower.endswith(("s", "x", "z", "ch", "sh")):
        return f"{text}es"
    if lower.endswith("y") and len(text) > 1 and lower[-2] not in "aeiou":
        return f"{text[:-1]}ies"
    return f"{text}s"
