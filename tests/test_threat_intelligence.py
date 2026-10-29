
import httpx

from phishing_detection.agent.graph import (
    build_phishing_graph,
    check_google_safe_browsing,
)


class FakeResponse:
    def __init__(self, payload):
        self.payload = payload

    def raise_for_status(self):
        pass

    def json(self):
        return self.payload


def test_google_safe_browsing_reports_threat(monkeypatch):
    def fake_post(*args, **kwargs):
        assert "key" in kwargs["params"]
        assert kwargs["json"]["threatInfo"]["threatEntries"] == [
            {"url": "https://example.com"}
        ]
        return FakeResponse(
            {
                "matches": [
                    {
                        "threatType": "SOCIAL_ENGINEERING",
                        "platformType": "ANY_PLATFORM",
                        "threatEntryType": "URL",
                    }
                ]
            }
        )

    monkeypatch.setenv("GOOGLE_SAFE_BROWSING_API_KEY", "test-key")
    monkeypatch.setattr(
        "phishing_detection.agent.graph.httpx.post",
        fake_post,
    )

    result = check_google_safe_browsing("https://example.com")

    assert result["status"] == "threat_found"
    assert result["is_threat"] is True
    assert result["matches"][0]["threat_type"] == "SOCIAL_ENGINEERING"


def test_google_safe_browsing_no_match(monkeypatch):
    monkeypatch.setenv("GOOGLE_SAFE_BROWSING_API_KEY", "test-key")
    monkeypatch.setattr(
        "phishing_detection.agent.graph.httpx.post",
        lambda *args, **kwargs: FakeResponse({}),
    )

    result = check_google_safe_browsing("https://example.com")

    assert result["status"] == "no_match"
    assert result["is_threat"] is False
    assert result["matches"] == []
    assert "does not guarantee" in result["message"]


def test_google_safe_browsing_timeout_is_unavailable(monkeypatch):
    def fake_post(*args, **kwargs):
        raise httpx.TimeoutException("simulated timeout")

    monkeypatch.setenv("GOOGLE_SAFE_BROWSING_API_KEY", "test-key")
    monkeypatch.setattr(
        "phishing_detection.agent.graph.httpx.post",
        fake_post,
    )

    result = check_google_safe_browsing("https://example.com")

    assert result["status"] == "unavailable"
    assert result["is_threat"] is None


def test_google_safe_browsing_http_error_is_unavailable(monkeypatch):
    def fake_post(*args, **kwargs):
        raise httpx.ConnectError("simulated connection error")

    monkeypatch.setenv("GOOGLE_SAFE_BROWSING_API_KEY", "test-key")
    monkeypatch.setattr(
        "phishing_detection.agent.graph.httpx.post",
        fake_post,
    )

    result = check_google_safe_browsing("https://example.com")

    assert result["status"] == "unavailable"
    assert result["is_threat"] is None


def test_graph_includes_threat_intelligence(monkeypatch):
    monkeypatch.setattr(
        "phishing_detection.agent.graph.check_google_safe_browsing",
        lambda url: {
            "status": "threat_found",
            "is_threat": True,
            "matches": [{"threat_type": "SOCIAL_ENGINEERING"}],
            "message": "Threat match found.",
        },
    )

    class FakeClassifier:
        def predict(self, url):
            return {
                "url": url,
                "label": 0,
                "prediction": "legitimate",
                "phishing_score": 0.1,
            }

    class FakeRetriever:
        def retrieve(self, query, top_k=3):
            return []

    graph = build_phishing_graph(FakeClassifier(), FakeRetriever())
    result = graph.invoke({"url": "https://example.com"})

    assert result["prediction"]["prediction"] == "legitimate"
    assert result["threat_intelligence"]["status"] == "threat_found"
    assert result["threat_intelligence"]["is_threat"] is True


def test_invalid_url_skips_threat_intelligence(monkeypatch):
    def unexpected_lookup(url):
        raise AssertionError("Lookup must not run for an invalid URL.")

    monkeypatch.setattr(
        "phishing_detection.agent.graph.check_google_safe_browsing",
        unexpected_lookup,
    )

    class FakeClassifier:
        def predict(self, url):
            raise AssertionError("Classifier must not run.")

    class FakeRetriever:
        def retrieve(self, query, top_k=3):
            raise AssertionError("Retriever must not run.")

    graph = build_phishing_graph(FakeClassifier(), FakeRetriever())
    result = graph.invoke({"url": "ftp://example.com"})

    assert result["error"] == "URL must be a valid HTTP or HTTPS URL."
    assert "threat_intelligence" not in result
