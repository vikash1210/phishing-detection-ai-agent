import pytest

from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool
from datetime import datetime, timedelta, timezone

from phishing_detection.db_models import ScanResult, ScannedURL
import phishing_detection.agent.graph as graph_module
import phishing_detection.api as api_module
from phishing_detection.database import Base


@pytest.fixture(autouse=True)
def configure_test_api_key(monkeypatch):
    """Configure API authentication for tests."""
    monkeypatch.setenv("GMAIL_ADDON_API_KEY", "test-api-key")


@pytest.fixture(autouse=True)
def isolate_database(monkeypatch):
    """Give every test an isolated in-memory SQLite database."""

    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )

    Base.metadata.create_all(bind=engine)

    TestSessionLocal = sessionmaker(
        bind=engine,
        autoflush=False,
        autocommit=False,
    )

    monkeypatch.setattr(
        api_module,
        "SessionLocal",
        TestSessionLocal,
    )

    yield

    Base.metadata.drop_all(bind=engine)
    engine.dispose()


def auth_headers():
    return {"X-API-Key": "test-api-key"}


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
            headers=auth_headers(),
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
            headers=auth_headers(),
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
            headers=auth_headers(),
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
            headers=auth_headers(),
        )

    assert response.status_code == 422


def test_predict_rate_limit_returns_429(monkeypatch):
    setup_test_environment(monkeypatch)

    with TestClient(api_module.app) as client:
        responses = [
            client.post(
                "/predict",
                json={"url": "https://example.com"},
                headers=auth_headers(),
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

    assert all(
        response.status_code == 200
        for response in responses
    )


def create_test_scan(db, url, scanned_at):
    """Insert a URL and its associated scan result."""

    scanned_url = ScannedURL(
        original_url=url,
        normalized_url=url,
        domain=url.split("//")[-1],
    )

    db.add(scanned_url)
    db.flush()

    scan_result = ScanResult(
        scanned_url_id=scanned_url.id,
        model_label=0,
        prediction="legitimate",
        phishing_score=0.10,
        scanned_at=scanned_at,
    )

    db.add(scan_result)
    db.commit()

    return scan_result


def test_scan_history_requires_api_key():
    with TestClient(api_module.app) as client:
        response = client.get("/scans")

    assert response.status_code == 401
    assert response.json()["detail"] == "Invalid or missing API key."


def test_scan_history_rejects_invalid_api_key():
    with TestClient(api_module.app) as client:
        response = client.get(
            "/scans",
            headers={"X-API-Key": "wrong-api-key"},
        )

    assert response.status_code == 401
    assert response.json()["detail"] == "Invalid or missing API key."


def test_scan_history_returns_empty_list():
    with TestClient(api_module.app) as client:
        response = client.get(
            "/scans",
            headers=auth_headers(),
        )

    assert response.status_code == 200

    data = response.json()

    assert data["total"] == 0
    assert data["items_returned"] == 0
    assert data["scans"] == []


def test_scan_history_returns_saved_records(monkeypatch):
    setup_test_environment(monkeypatch)

    db = api_module.SessionLocal()

    try:
        create_test_scan(
            db,
            "https://example.com",
            datetime(2026, 10, 30, tzinfo=timezone.utc),
        )
    finally:
        db.close()

    with TestClient(api_module.app) as client:
        response = client.get(
            "/scans",
            headers=auth_headers(),
        )

    assert response.status_code == 200

    data = response.json()

    assert data["total"] == 1
    assert data["items_returned"] == 1
    assert data["scans"][0]["original_url"] == "https://example.com"
    assert data["scans"][0]["prediction"] == "legitimate"
    assert data["scans"][0]["scanned_at"] is not None


def test_scan_history_returns_newest_first(monkeypatch):
    setup_test_environment(monkeypatch)

    db = api_module.SessionLocal()

    try:
        base_time = datetime(
            2026,
            10,
            30,
            tzinfo=timezone.utc,
        )

        create_test_scan(
            db,
            "https://old.example.com",
            base_time,
        )

        create_test_scan(
            db,
            "https://new.example.com",
            base_time + timedelta(hours=2),
        )
    finally:
        db.close()

    with TestClient(api_module.app) as client:
        response = client.get(
            "/scans",
            headers=auth_headers(),
        )

    assert response.status_code == 200

    scans = response.json()["scans"]

    assert len(scans) == 2
    assert scans[0]["original_url"] == "https://new.example.com"
    assert scans[1]["original_url"] == "https://old.example.com"


def test_scan_history_pagination(monkeypatch):
    setup_test_environment(monkeypatch)

    db = api_module.SessionLocal()

    try:
        base_time = datetime(
            2026,
            10,
            30,
            tzinfo=timezone.utc,
        )

        for index in range(3):
            create_test_scan(
                db,
                f"https://example{index}.com",
                base_time + timedelta(hours=index),
            )
    finally:
        db.close()

    with TestClient(api_module.app) as client:
        response = client.get(
            "/scans?limit=2&offset=1",
            headers=auth_headers(),
        )

    assert response.status_code == 200

    data = response.json()

    assert data["total"] == 3
    assert data["limit"] == 2
    assert data["offset"] == 1
    assert data["items_returned"] == 2

    assert data["scans"][0]["original_url"] == "https://example1.com"
    assert data["scans"][1]["original_url"] == "https://example0.com"


@pytest.mark.parametrize(
    "query",
    [
        "?limit=0",
        "?limit=101",
        "?offset=-1",
    ],
)
def test_scan_history_rejects_invalid_pagination(query):
    with TestClient(api_module.app) as client:
        response = client.get(
            f"/scans{query}",
            headers=auth_headers(),
        )

    assert response.status_code == 422