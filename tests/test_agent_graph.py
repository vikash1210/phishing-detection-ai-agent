
from phishing_detection.agent.graph import (
    EVIDENCE_NOTE,
    build_phishing_graph,
)


class FakeClassifier:
    def __init__(self):
        self.calls = []

    def predict(self, url):
        self.calls.append(url)
        return {
            "url": url,
            "label": 1,
            "prediction": "phishing",
            "phishing_score": 0.98,
        }


class FakeRetriever:
    def __init__(self):
        self.calls = []

    def retrieve(self, query, top_k=3):
        self.calls.append((query, top_k))
        return [
            {
                "text": "Inspect the hostname carefully.",
                "source": "phishing_url_security.txt",
                "chunk_id": "1",
                "similarity": 0.82,
            }
        ]


def test_valid_url_runs_classification_and_retrieval():
    classifier = FakeClassifier()
    retriever = FakeRetriever()
    graph = build_phishing_graph(classifier, retriever)

    result = graph.invoke(
        {"url": "https://example.com"}
    )

    assert result["normalized_url"] == "https://example.com"
    assert result["prediction"]["prediction"] == "phishing"
    assert result["prediction"]["phishing_score"] == 0.98
    assert len(result["evidence"]) == 1
    assert result["evidence_note"] == EVIDENCE_NOTE

    assert classifier.calls == ["https://example.com"]
    assert len(retriever.calls) == 1
    assert retriever.calls[0][1] == 3


def test_invalid_url_does_not_run_classifier_or_retriever():
    classifier = FakeClassifier()
    retriever = FakeRetriever()
    graph = build_phishing_graph(classifier, retriever)

    result = graph.invoke({"url": "ftp://example.com"})

    assert result["error"] == (
        "URL must be a valid HTTP or HTTPS URL."
    )
    assert classifier.calls == []
    assert retriever.calls == []
    assert "prediction" not in result
    assert "evidence" not in result


def test_empty_url_returns_validation_error():
    classifier = FakeClassifier()
    retriever = FakeRetriever()
    graph = build_phishing_graph(classifier, retriever)

    result = graph.invoke({"url": "   "})

    assert result["error"] == "URL must be a non-empty string."
    assert classifier.calls == []
    assert retriever.calls == []


def test_url_is_trimmed_before_processing():
    classifier = FakeClassifier()
    retriever = FakeRetriever()
    graph = build_phishing_graph(classifier, retriever)

    result = graph.invoke({"url": "  https://example.com  "})

    assert result["normalized_url"] == "https://example.com"
    assert classifier.calls == ["https://example.com"]
