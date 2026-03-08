from __future__ import annotations

import re

PRIMARY_VERIFICATION_CLASSES = (
    "analysis",
    "test",
    "proof",
    "inspection",
    "operational drill",
)

def split_verification_phrase(phrase: str) -> tuple[str, ...]:
    normalized = phrase.replace("，", ",").replace("、", ",")
    normalized = re.sub(r"\s+(?:と|および|または|又は)\s+", ",", normalized)
    labels = tuple(part.strip() for part in normalized.split(",") if part.strip())
    return labels


def normalize_verification_label(label: str) -> tuple[str, ...]:
    lowered = " ".join(label.casefold().split())
    if lowered in PRIMARY_VERIFICATION_CLASSES:
        return (lowered,)
    if lowered == "proof":
        return ("proof",)
    if lowered == "operational drill" or lowered.startswith("operational ") or ("operational" in lowered and "drill" in lowered):
        return ("operational drill",)
    if lowered == "proof artifact review":
        return ("proof",)
    if lowered == "fault injection" or "fault injection" in lowered:
        return ("test",)
    if lowered == "fuzzing" or lowered == "fuzz campaign evidence":
        return ("test",)
    if lowered.endswith(" test") or " test " in lowered:
        return ("test",)
    if lowered.endswith(" campaign") or " campaign " in lowered:
        return ("test",)
    if lowered.endswith(" analysis") or " analysis " in lowered:
        return ("analysis",)
    if lowered.endswith(" inspection") or " inspection " in lowered:
        return ("inspection",)
    if lowered.endswith(" review board"):
        return ("inspection",)
    if lowered.endswith(" review") or " review " in lowered:
        return ("inspection",)
    if lowered.endswith(" audit") or " audit " in lowered:
        return ("inspection",)
    raise ValueError(f"cannot normalize verification label: {label!r}")


def normalize_verification_phrase(phrase: str) -> tuple[tuple[str, ...], tuple[str, ...]]:
    labels = split_verification_phrase(phrase)
    ordered: list[str] = []
    seen: set[str] = set()
    for label in labels:
        for normalized_label in normalize_verification_label(label):
            if normalized_label not in seen:
                seen.add(normalized_label)
                ordered.append(normalized_label)
    return labels, tuple(ordered)
