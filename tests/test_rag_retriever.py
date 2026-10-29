
import pytest

from phishing_detection.rag.retriever import SemanticRetriever


class FakeEmbeddingService:
    """Provide predictable vectors for retriever tests."""

    def embed_texts(self, texts: list[str]) -> list[list[float]]:
        vectors = []

        for text in texts:
            normalized_text = text.lower()

            if "https" in normalized_text:
                vectors.append([1.0, 0.0, 0.0])
            elif "password" in normalized_text:
                vectors.append([0.0, 1.0, 0.0])
            else:
                vectors.append([0.0, 0.0, 1.0])

        return vectors

    def embed_query(self, query: str) -> list[float]:
        normalized_query = query.lower()

        if "https" in normalized_query:
            return [1.0, 0.0, 0.0]
        if "password" in normalized_query:
            return [0.0, 1.0, 0.0]

        return [0.0, 0.0, 1.0]


@pytest.fixture
def retriever(tmp_path):
    knowledge_dir = tmp_path / "knowledge_base"
    knowledge_dir.mkdir()

    (knowledge_dir / "https.txt").write_text(
        "HTTPS encrypts the connection but does not guarantee trust.",
        encoding="utf-8",
    )
    (knowledge_dir / "passwords.txt").write_text(
        "Never enter passwords on suspicious websites.",
        encoding="utf-8",
    )
    (knowledge_dir / "hostname.txt").write_text(
        "Inspect the hostname for misspellings and misleading subdomains.",
        encoding="utf-8",
    )

    return SemanticRetriever(
        knowledge_base_dir=knowledge_dir,
        embedding_service=FakeEmbeddingService(),
        chunk_size=500,
        overlap=50,
    )


def test_retrieve_returns_most_relevant_chunk_first(retriever):
    results = retriever.retrieve(
        "Does HTTPS guarantee trust?",
        top_k=3,
    )

    assert len(results) == 3
    assert results[0]["source"] == "https.txt"
    assert results[0]["similarity"] == pytest.approx(1.0)


def test_password_query_prioritizes_password_guidance(retriever):
    results = retriever.retrieve(
        "Should I enter my password?",
        top_k=3,
    )

    assert results[0]["source"] == "passwords.txt"
    assert results[0]["similarity"] == pytest.approx(1.0)


def test_retrieve_returns_required_metadata(retriever):
    results = retriever.retrieve("HTTPS security", top_k=1)

    assert set(results[0]) == {
        "text",
        "source",
        "chunk_id",
        "similarity",
    }
    assert isinstance(results[0]["text"], str)
    assert isinstance(results[0]["similarity"], float)


def test_retrieve_respects_top_k(retriever):
    results = retriever.retrieve("HTTPS security", top_k=1)

    assert len(results) == 1


def test_retrieve_rejects_empty_query(retriever):
    with pytest.raises(ValueError, match="non-empty string"):
        retriever.retrieve("   ")


def test_retrieve_rejects_invalid_top_k(retriever):
    with pytest.raises(ValueError, match="greater than zero"):
        retriever.retrieve("HTTPS security", top_k=0)


def test_retrieve_rejects_embedding_dimension_mismatch(tmp_path):
    knowledge_dir = tmp_path / "knowledge_base"
    knowledge_dir.mkdir()

    (knowledge_dir / "security.txt").write_text(
        "HTTPS does not guarantee trust.",
        encoding="utf-8",
    )

    class MismatchedEmbeddingService:
        def embed_texts(self, texts):
            return [[1.0, 0.0] for _ in texts]

        def embed_query(self, query):
            return [1.0, 0.0, 0.0]

    retriever = SemanticRetriever(
        knowledge_base_dir=knowledge_dir,
        embedding_service=MismatchedEmbeddingService(),
    )

    with pytest.raises(ValueError, match="dimensions do not match"):
        retriever.retrieve("HTTPS security")
