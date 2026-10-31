
import pytest

import phishing_detection.agent.graph as graph_module
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


@pytest.fixture
def safe_browsing_mock(monkeypatch):
    """Prevent real Google API calls during graph tests."""

    calls = []

    def fake_check(url):
        calls.append(url)
        return {
            "status": "no_match",
            "is_threat": False,
            "matches": [],
            "message": "Mock Safe Browsing response.",
        }

    monkeypatch.setattr(
        graph_module,
        "check_google_safe_browsing",
        fake_check,
    )

    return calls


def test_valid_url_runs_classification_and_retrieval(
    safe_browsing_mock,
):
    classifier = FakeClassifier()
    retriever = FakeRetriever()
    graph = build_phishing_graph(classifier, retriever)

    result = graph.invoke({"url": "https://example.com"})

    assert result["normalized_url"] == "https://example.com"
    assert result["prediction"]["prediction"] == "phishing"
    assert result["prediction"]["phishing_score"] == 0.98
    assert len(result["evidence"]) == 1
    assert result["evidence_note"] == EVIDENCE_NOTE

    assert classifier.calls == ["https://example.com"]
    assert retriever.calls[0][1] == 3
    assert safe_browsing_mock == ["https://example.com"]


@pytest.mark.parametrize(
    "url",
    [
        "ftp://example.com",
        "https://",
        "https:///example.com",
        "https://example.com:abc",
        "https://example.com:99999",
        "https://user:password@example.com",
        "https://-bad.example",
        "https://bad-.example",
        "https://example..com",
        "https://bad_host.example",
        "https://exa%mple.com",
        "http://[invalid-ipv6]",
        "https://exa mple.com",
        "https://exa\nmple.com",
        r"https://example.com\@evil.com",
    ],
)
def test_invalid_urls_do_not_reach_processing_nodes(
    url,
    safe_browsing_mock,
):
    classifier = FakeClassifier()
    retriever = FakeRetriever()
    graph = build_phishing_graph(classifier, retriever)

    result = graph.invoke({"url": url})

    assert result["error"] == (
        "URL must be a valid HTTP or HTTPS URL."
    )
    assert classifier.calls == []
    assert retriever.calls == []
    assert safe_browsing_mock == []
    assert "prediction" not in result
    assert "evidence" not in result


@pytest.mark.parametrize(
    "url",
    [
        "http://127.0.0.1",
        "http://192.168.1.1",
        "http://localhost",
        "http://[::1]",
        "https://example.com",
    ],
)
def test_valid_hosts_are_accepted(
    url,
    safe_browsing_mock,
):
    classifier = FakeClassifier()
    retriever = FakeRetriever()
    graph = build_phishing_graph(classifier, retriever)

    result = graph.invoke({"url": url})

    assert result["normalized_url"] == url
    assert classifier.calls == [url]
    assert safe_browsing_mock == [url]


def test_empty_url_returns_validation_error(
    safe_browsing_mock,
):
    classifier = FakeClassifier()
    retriever = FakeRetriever()
    graph = build_phishing_graph(classifier, retriever)

    result = graph.invoke({"url": "   "})

    assert result["error"] == "URL must be a non-empty string."
    assert classifier.calls == []
    assert retriever.calls == []
    assert safe_browsing_mock == []


def test_non_string_url_returns_validation_error(
    safe_browsing_mock,
):
    classifier = FakeClassifier()
    retriever = FakeRetriever()
    graph = build_phishing_graph(classifier, retriever)

    result = graph.invoke({"url": 123})

    assert result["error"] == "URL must be a non-empty string."
    assert classifier.calls == []
    assert retriever.calls == []
    assert safe_browsing_mock == []


def test_url_is_trimmed_before_processing(
    safe_browsing_mock,
):
    classifier = FakeClassifier()
    retriever = FakeRetriever()
    graph = build_phishing_graph(classifier, retriever)

    result = graph.invoke({"url": "  https://example.com  "})

    assert result["normalized_url"] == "https://example.com"
    assert classifier.calls == ["https://example.com"]
    assert safe_browsing_mock == ["https://example.com"]
