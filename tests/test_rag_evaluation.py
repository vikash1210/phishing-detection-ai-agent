
import pytest

from phishing_detection.rag.retriever import SemanticRetriever


EVALUATION_CASES = [
    {
        "query": "Does HTTPS prove that a website is legitimate?",
        "expected_guideline": "Guideline 3: Treat HTTPS carefully.",
    },
    {
        "query": "Should I enter my password on a suspicious link?",
        "expected_guideline": (
            "Guideline 4: Avoid interacting with suspicious links."
        ),
    },
    {
        "query": "How can I identify a misleading hostname or domain?",
        "expected_guideline": "Guideline 1: Inspect the hostname.",
    },
    {
        "query": (
            "What should I do when there is not enough reliable evidence?"
        ),
        "expected_guideline": "Guideline 6: Report uncertainty.",
    },
    {
        "query": "Why should I check independent threat intelligence?",
        "expected_guideline": (
            "Guideline 5: Use independent security evidence."
        ),
    },
]


def hit_at_k(
    retrieved_items: list[dict],
    expected_guideline: str,
    k: int,
) -> int:
    """Return 1 if the expected guideline occurs in the top k results."""
    if k <= 0:
        raise ValueError("k must be greater than zero.")

    return int(
        any(
            expected_guideline in item["text"]
            for item in retrieved_items[:k]
        )
    )


def reciprocal_rank(
    retrieved_items: list[dict],
    expected_guideline: str,
) -> float:
    """Return reciprocal rank of the first matching result."""
    for rank, item in enumerate(retrieved_items, start=1):
        if expected_guideline in item["text"]:
            return 1.0 / rank

    return 0.0


@pytest.fixture(scope="module")
def retriever():
    """Load the real knowledge base and pretrained embedding model once."""
    return SemanticRetriever(
        knowledge_base_dir="data/knowledge_base",
    )


def test_expected_guideline_is_retrieved(retriever):
    """Verify all five expected guidelines appear in the top three."""
    for case in EVALUATION_CASES:
        results = retriever.retrieve(case["query"], top_k=3)

        assert results, (
            f"No results returned for query: {case['query']}"
        )

        retrieved_text = "\n".join(
            item["text"] for item in results
        )

        assert case["expected_guideline"] in retrieved_text, (
            f"Expected guideline was not retrieved.\n"
            f"Query: {case['query']}\n"
            f"Expected: {case['expected_guideline']}\n"
            f"Retrieved text:\n{retrieved_text}"
        )


def test_real_retrieval_metrics_report(retriever):
    """Calculate Hit@1, Hit@3 and MRR on real retrieval results."""
    hit1_scores = []
    hit3_scores = []
    reciprocal_ranks = []

    print("\n\n===== RAG RETRIEVAL EVALUATION =====")

    for case in EVALUATION_CASES:
        results = retriever.retrieve(case["query"], top_k=3)
        expected = case["expected_guideline"]

        hit1 = hit_at_k(results, expected, 1)
        hit3 = hit_at_k(results, expected, 3)
        rr = reciprocal_rank(results, expected)

        hit1_scores.append(hit1)
        hit3_scores.append(hit3)
        reciprocal_ranks.append(rr)

        matching_rank = next(
            (
                rank
                for rank, item in enumerate(results, start=1)
                if expected in item["text"]
            ),
            None,
        )

        print(f"\nQuery: {case['query']}")
        print(f"Expected guideline: {expected}")
        print(f"Matching rank: {matching_rank or 'Not found'}")
        print(f"Hit@1: {hit1}")
        print(f"Hit@3: {hit3}")
        print(f"Reciprocal Rank: {rr:.4f}")

        if "password" in case["query"].lower():
            print("\n--- Password query retrieval diagnostics ---")

            for rank, item in enumerate(results, start=1):
                print(f"\nRank: {rank}")
                print(f"Source: {item['source']}")
                print(f"Chunk ID: {item['chunk_id']}")
                print(f"Similarity: {item['similarity']:.4f}")
                print(f"Text: {item['text']}")

    count = len(EVALUATION_CASES)
    mean_hit1 = sum(hit1_scores) / count
    mean_hit3 = sum(hit3_scores) / count
    mrr = sum(reciprocal_ranks) / count

    print("\n===== OVERALL METRICS =====")
    print(f"Queries evaluated: {count}")
    print(f"Hit@1: {mean_hit1:.2%}")
    print(f"Hit@3: {mean_hit3:.2%}")
    print(f"MRR: {mrr:.4f}")

    assert count > 0
    assert 0.0 <= mean_hit1 <= 1.0
    assert 0.0 <= mean_hit3 <= 1.0
    assert 0.0 <= mrr <= 1.0
