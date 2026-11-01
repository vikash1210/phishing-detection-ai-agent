
import threading

from fastapi.testclient import TestClient

import phishing_detection.api as api_module


class FakeGraph:
    def __init__(self, error):
        self.error = error

    def invoke(self, state):
        raise self.error


def create_test_client(monkeypatch, error):
    fake_graph = FakeGraph(error)

    # Mock classifier and retriever to avoid loading real dependencies.
    monkeypatch.setattr(
        api_module,
        "PhishingURLClassifier",
        lambda: object(),
    )

    monkeypatch.setattr(
        api_module,
        "SemanticRetriever",
        lambda: object(),
    )

    # Provide the fake graph used by the API endpoint.
    monkeypatch.setattr(
        api_module,
        "build_phishing_graph",
        lambda classifier, retriever: fake_graph,
    )

    # Mock API key retrieval.
    monkeypatch.setenv(
        "GMAIL_ADDON_API_KEY",
        "test-api-key",
    )

    monkeypatch.setattr(
        api_module,
        "get_secret",
        lambda name: "test-api-key",
    )

    # Initialize application state required by the API.
    monkeypatch.setattr(
        api_module.app.state,
        "graph",
        fake_graph,
        raising=False,
    )

    monkeypatch.setattr(
        api_module.app.state,
        "rate_limit_store",
        {},
        raising=False,
    )

    monkeypatch.setattr(
        api_module.app.state,
        "rate_limit_lock",
        threading.Lock(),
        raising=False,
    )

    return TestClient(
        api_module.app,
        raise_server_exceptions=False,
    )


def test_unhandled_exception_returns_sanitized_500(monkeypatch):
    secret_message = (
        "SECRET_INTERNAL_PATH C:\\private\\server\\database"
    )

    client = create_test_client(
        monkeypatch,
        RuntimeError(secret_message),
    )

    with client:
        response = client.post(
            "/predict",
            json={"url": "https://example.com"},
            headers={"X-API-Key": "test-api-key"},
        )

    assert response.status_code == 500

    assert response.json() == {
        "detail": (
            "An unexpected server error occurred. "
            "Please try again later."
        )
    }

    assert secret_message not in response.text
    assert "SECRET_INTERNAL_PATH" not in response.text
    assert "Traceback" not in response.text


def test_value_error_returns_sanitized_422(monkeypatch):
    secret_message = (
        "SECRET_INTERNAL_PATH C:\\private\\server\\model"
    )

    client = create_test_client(
        monkeypatch,
        ValueError(secret_message),
    )

    with client:
        response = client.post(
            "/predict",
            json={"url": "https://example.com"},
            headers={"X-API-Key": "test-api-key"},
        )

    assert response.status_code == 422

    assert response.json() == {
        "detail": "The submitted URL could not be processed."
    }

    assert secret_message not in response.text
    assert "SECRET_INTERNAL_PATH" not in response.text
