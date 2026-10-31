
from fastapi.testclient import TestClient

import phishing_detection.api as api_module


class FakeGraph:
    def __init__(self, error):
        self.error = error

    def invoke(self, state):
        raise self.error


def create_test_client(monkeypatch, error):
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

    monkeypatch.setattr(
        api_module,
        "build_phishing_graph",
        lambda classifier, retriever: FakeGraph(error),
    )

    return TestClient(
        api_module.app,
        raise_server_exceptions=False,
    )


def test_unexpected_exception_does_not_expose_internal_details(
    monkeypatch,
):
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


def test_value_error_does_not_expose_internal_details(monkeypatch):
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
        )

    assert response.status_code == 422

    assert response.json() == {
        "detail": "The submitted URL could not be processed."
    }

    assert secret_message not in response.text
    assert "SECRET_INTERNAL_PATH" not in response.text
