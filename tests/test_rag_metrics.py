
import pytest


def hit_at_k(
    retrieved_items: list[dict],
    expected_guideline: str,
    k: int,
) -> int:
    """Return 1 if the expected guideline appears in the top k results."""
    if k <= 0:
        raise ValueError("k must be greater than zero.")

    for item in retrieved_items[:k]:
        if expected_guideline in item["text"]:
            return 1

    return 0


def reciprocal_rank(
    retrieved_items: list[dict],
    expected_guideline: str,
) -> float:
    """Return reciprocal rank of the first matching result."""
    for rank, item in enumerate(retrieved_items, start=1):
        if expected_guideline in item["text"]:
            return 1.0 / rank

    return 0.0


def test_hit_at_1_when_guideline_is_first():
    results = [
        {"text": "Guideline 3: Treat HTTPS carefully."},
        {"text": "Guideline 1: Inspect the hostname."},
    ]

    assert hit_at_k(results, "Guideline 3", 1) == 1


def test_hit_at_1_when_guideline_is_not_first():
    results = [
        {"text": "Guideline 1: Inspect the hostname."},
        {"text": "Guideline 3: Treat HTTPS carefully."},
    ]

    assert hit_at_k(results, "Guideline 3", 1) == 0


def test_hit_at_3_when_guideline_is_third():
    results = [
        {"text": "Guideline 1: Inspect the hostname."},
        {"text": "Guideline 2: Check URL structure."},
        {"text": "Guideline 3: Treat HTTPS carefully."},
    ]

    assert hit_at_k(results, "Guideline 3", 3) == 1


def test_reciprocal_rank_for_first_result():
    results = [
        {"text": "Guideline 4: Avoid suspicious links."}
    ]

    assert reciprocal_rank(results, "Guideline 4") == 1.0


def test_reciprocal_rank_for_third_result():
    results = [
        {"text": "Guideline 1"},
        {"text": "Guideline 2"},
        {
            "text": (
                "Guideline 5: Use independent security evidence."
            )
        },
    ]

    assert reciprocal_rank(results, "Guideline 5") == pytest.approx(
        1 / 3
    )


def test_reciprocal_rank_when_guideline_is_missing():
    results = [
        {"text": "Guideline 1"},
        {"text": "Guideline 2"},
    ]

    assert reciprocal_rank(results, "Guideline 6") == 0.0


def test_hit_at_k_rejects_invalid_k():
    with pytest.raises(ValueError, match="greater than zero"):
        hit_at_k([], "Guideline 1", 0)
