
from fastapi.testclient import TestClient

import phishing_detection.agent.graph as graph_module
from phishing_detection.api import app


def test_health_endpoint():
    response = TestClient(app).get("/health")

    assert response.status_code == 200
    assert response.json()["status"] == "healthy"


def test_predict_endpoint(monkeypatch):
    monkeypatch.setattr(
        graph_module,
        "check_google_safe_browsing",
        lambda url: {
            "status": "no_match",
            "is_threat": False,
            "matches": [],
            "message": "No matching threat returned.",
        },
    )

    with TestClient(app) as client:
        response = client.post(
            "/predict",
            json={"url": "https://www.google.com"},
        )

    assert response.status_code == 200

    data = response.json()
    assert data["url"] == "https://www.google.com"
    assert data["prediction"] in {"legitimate", "phishing"}
    assert 0.0 <= data["phishing_score"] <= 1.0
    assert data["threat_intelligence"]["status"] == "no_match"
    assert data["threat_intelligence"]["is_threat"] is False


def test_predict_returns_threat_found(monkeypatch):
    monkeypatch.setattr(
        graph_module,
        "check_google_safe_browsing",
        lambda url: {
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
        },
    )

    with TestClient(app) as client:
        response = client.post(
            "/predict",
            json={"url": "https://example.com"},
        )

    assert response.status_code == 200
    data = response.json()
    assert data["threat_intelligence"]["status"] == "threat_found"
    assert data["threat_intelligence"]["is_threat"] is True
    assert (
        data["threat_intelligence"]["matches"][0]["threat_type"]
        == "SOCIAL_ENGINEERING"
    )


def test_predict_rejects_invalid_url(monkeypatch):
    def unexpected_lookup(url):
        raise AssertionError("Lookup must not run for an invalid URL.")

    monkeypatch.setattr(
        graph_module,
        "check_google_safe_browsing",
        unexpected_lookup,
    )

    with TestClient(app) as client:
        response = client.post(
            "/predict",
            json={"url": "ftp://example.com"},
        )

    assert response.status_code == 422
