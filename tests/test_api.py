
import pytest
from fastapi.testclient import TestClient

import phishing_detection.agent.graph as graph_module
import phishing_detection.api as api_module


class FakeClassifier:
    """Return a controlled prediction without loading the real ML model."""

    def __init__(self, prediction="legitimate", score=0.10):
        self.prediction = prediction
        self.score = score

    def predict(self, url):
        label = 1 if self.prediction == "phishing" else 0

        return {
            "url": url,
            "label": label,
            "prediction": self.prediction,
            "phishing_score": self.score,
        }


class FakeRetriever:
    """Return empty evidence for deterministic API tests."""

    def retrieve(self, query, top_k=3):
        return []


def setup_test_environment(
    monkeypatch,
    prediction="legitimate",
    score=0.10,
    threat_status="no_match",
):
    """Replace external dependencies with controlled test doubles."""

    monkeypatch.setattr(
        api_module,
        "PhishingURLClassifier",
        lambda: FakeClassifier(prediction, score),
    )

    monkeypatch.setattr(
        api_module,
        "SemanticRetriever",
        FakeRetriever,
    )

    if threat_status == "threat_found":
        threat_result = {
            "status": "threat_found",
            "is_threat": True,
            "matches": [
                {
                    "threat_type": "SOCIAL_ENGINEERING",
                    "platform_type": "ANY_PLATFORM",
                    "threat_entry_type": "URL",
                }
            ],
            "message": "Threat match found.",
        }
    elif threat_status == "unavailable":
        threat_result = {
            "status": "unavailable",
            "is_threat": None,
            "matches": [],
            "message": "Lookup unavailable.",
        }
    else:
        threat_result = {
            "status": "no_match",
            "is_threat": False,
            "matches": [],
            "message": "No matching threat returned.",
        }

    monkeypatch.setattr(
        graph_module,
        "check_google_safe_browsing",
        lambda url: threat_result,
    )


def test_health_endpoint():
    with TestClient(api_module.app) as client:
        response = client.get("/health")

    assert response.status_code == 200
    assert response.json()["status"] == "healthy"


@pytest.mark.parametrize(
    ("prediction", "score", "expected_risk"),
    [
        ("phishing", 0.95, "SUSPICIOUS"),
        ("legitimate", 0.05, "UNVERIFIED"),
    ],
)
def test_predict_risk_levels_for_no_match(
    monkeypatch,
    prediction,
    score,
    expected_risk,
):
    setup_test_environment(
        monkeypatch,
        prediction=prediction,
        score=score,
        threat_status="no_match",
    )

    with TestClient(api_module.app) as client:
        response = client.post(
            "/predict",
            json={"url": "https://example.com"},
        )

    assert response.status_code == 200

    data = response.json()

    assert data["prediction"] == prediction
    assert data["phishing_score"] == score
    assert data["threat_intelligence"]["status"] == "no_match"

    risk = data["risk_assessment"]

    assert risk["risk_level"] == expected_risk
    assert len(risk["reasons"]) > 0
    assert risk["verification_status"] == (
        "not_confirmed_by_external_feed"
    )


def test_predict_returns_high_risk_for_confirmed_threat(monkeypatch):
    setup_test_environment(
        monkeypatch,
        prediction="legitimate",
        score=0.05,
        threat_status="threat_found",
    )

    with TestClient(api_module.app) as client:
        response = client.post(
            "/predict",
            json={"url": "https://example.com"},
        )

    assert response.status_code == 200

    data = response.json()

    assert data["threat_intelligence"]["status"] == "threat_found"

    risk = data["risk_assessment"]

    assert risk["risk_level"] == "HIGH RISK"
    assert risk["verification_status"] == (
        "threat_confirmed_by_external_feed"
    )
    assert len(risk["reasons"]) > 0


def test_predict_returns_unverified_when_lookup_unavailable(
    monkeypatch,
):
    setup_test_environment(
        monkeypatch,
        prediction="legitimate",
        score=0.05,
        threat_status="unavailable",
    )

    with TestClient(api_module.app) as client:
        response = client.post(
            "/predict",
            json={"url": "https://example.com"},
        )

    assert response.status_code == 200

    risk = response.json()["risk_assessment"]

    assert risk["risk_level"] == "UNVERIFIED"
    assert risk["verification_status"] == (
        "external_check_unavailable"
    )


def test_predict_rejects_invalid_url(monkeypatch):
    setup_test_environment(monkeypatch)

    with TestClient(api_module.app) as client:
        response = client.post(
            "/predict",
            json={"url": "ftp://example.com"},
        )

    assert response.status_code == 422


def test_predict_rate_limit_returns_429(monkeypatch):
    setup_test_environment(monkeypatch)

    with TestClient(api_module.app) as client:
        responses = [
            client.post(
                "/predict",
                json={"url": "https://example.com"},
            )
            for _ in range(11)
        ]

    assert all(
        response.status_code == 200
        for response in responses[:10]
    )

    assert responses[10].status_code == 429

    assert responses[10].json()["detail"] == (
        "Rate limit exceeded. Please try again after one minute."
    )

    assert responses[10].headers["retry-after"] == "60"


def test_health_endpoint_is_not_rate_limited(monkeypatch):
    setup_test_environment(monkeypatch)

    with TestClient(api_module.app) as client:
        responses = [
            client.get("/health")
            for _ in range(15)
        ]

    assert all(response.status_code == 200 for response in responses)
