
import os
from typing import Any
from urllib.parse import urlparse

import httpx
from typing_extensions import TypedDict
from langgraph.graph import END, START, StateGraph


class PhishingAgentState(TypedDict, total=False):
    """State shared between nodes in the phishing detection graph."""

    url: str
    normalized_url: str
    prediction: dict[str, Any]
    evidence: list[dict[str, Any]]
    evidence_note: str
    threat_intelligence: dict[str, Any]
    error: str


EVIDENCE_NOTE = (
    "Retrieved evidence contains general security guidance. "
    "It does not independently verify whether this specific URL is malicious."
)

SAFE_BROWSING_ENDPOINT = (
    "https://safebrowsing.googleapis.com/v4/threatMatches:find"
)


def check_google_safe_browsing(url: str) -> dict[str, Any]:
    """Check a URL against Google Safe Browsing threat lists.

    The submitted URL is sent to Google's lookup API as data.
    This function never opens or visits the submitted URL.
    """
    api_key = os.getenv("GOOGLE_SAFE_BROWSING_API_KEY")

    if not api_key:
        return {
            "status": "not_configured",
            "is_threat": None,
            "matches": [],
            "message": "Google Safe Browsing API key is not configured.",
        }

    payload = {
        "client": {
            "clientId": "phishing-detection-ai-agent",
            "clientVersion": "0.1.0",
        },
        "threatInfo": {
            "threatTypes": [
                "MALWARE",
                "SOCIAL_ENGINEERING",
                "UNWANTED_SOFTWARE",
            ],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}],
        },
    }

    try:
        response = httpx.post(
            SAFE_BROWSING_ENDPOINT,
            params={"key": api_key},
            json=payload,
            timeout=5.0,
        )
        response.raise_for_status()
        data = response.json()

    except (httpx.HTTPError, ValueError):
        return {
            "status": "unavailable",
            "is_threat": None,
            "matches": [],
            "message": "Google Safe Browsing lookup failed.",
        }

    matches = data.get("matches", [])

    if matches:
        return {
            "status": "threat_found",
            "is_threat": True,
            "matches": [
                {
                    "threat_type": match.get("threatType"),
                    "platform_type": match.get("platformType"),
                    "threat_entry_type": match.get("threatEntryType"),
                }
                for match in matches
            ],
            "message": "Google Safe Browsing reported a threat match.",
        }

    return {
        "status": "no_match",
        "is_threat": False,
        "matches": [],
        "message": (
            "No matching threat was returned by Google Safe Browsing. "
            "This does not guarantee that the URL is safe."
        ),
    }


def validate_url_node(
    state: PhishingAgentState,
) -> dict[str, Any]:
    """Validate and normalize the input URL before processing."""
    url = state.get("url")

    if not isinstance(url, str) or not url.strip():
        return {"error": "URL must be a non-empty string."}

    normalized_url = url.strip()

    try:
        parsed = urlparse(normalized_url)
        hostname = parsed.hostname

        # Accessing port also detects malformed port values.
        _ = parsed.port

        if (
            parsed.scheme not in {"http", "https"}
            or not hostname
            or any(character.isspace() for character in normalized_url)
            or parsed.username is not None
            or parsed.password is not None
        ):
            return {
                "error": "URL must be a valid HTTP or HTTPS URL."
            }

    except ValueError:
        return {
            "error": "URL must be a valid HTTP or HTTPS URL."
        }

    return {"normalized_url": normalized_url}


def route_after_validation(state: PhishingAgentState) -> str:
    """Route invalid URLs directly to the end."""
    if state.get("error"):
        return "invalid"

    return "valid"


def build_phishing_graph(classifier, retriever):
    """Build a reusable classifier, threat-intelligence and RAG workflow."""

    def classify_url_node(
        state: PhishingAgentState,
    ) -> dict[str, Any]:
        """Run the existing pretrained phishing classifier."""
        prediction = classifier.predict(state["normalized_url"])
        return {"prediction": prediction}

    def check_threat_intelligence_node(
        state: PhishingAgentState,
    ) -> dict[str, Any]:
        """Check the URL against Google Safe Browsing."""
        result = check_google_safe_browsing(state["normalized_url"])
        return {"threat_intelligence": result}

    def retrieve_evidence_node(
        state: PhishingAgentState,
    ) -> dict[str, Any]:
        """Retrieve relevant general security guidance."""
        query = (
            "What security checks should be considered when "
            f"evaluating this URL: {state['normalized_url']}"
        )

        evidence = retriever.retrieve(query, top_k=3)

        return {
            "evidence": evidence,
            "evidence_note": EVIDENCE_NOTE,
        }

    builder = StateGraph(PhishingAgentState)

    builder.add_node("validate_url", validate_url_node)
    builder.add_node("classify_url", classify_url_node)
    builder.add_node(
        "check_threat_intelligence",
        check_threat_intelligence_node,
    )
    builder.add_node("retrieve_evidence", retrieve_evidence_node)

    builder.add_edge(START, "validate_url")

    builder.add_conditional_edges(
        "validate_url",
        route_after_validation,
        {
            "valid": "classify_url",
            "invalid": END,
        },
    )

    builder.add_edge("classify_url", "check_threat_intelligence")
    builder.add_edge(
        "check_threat_intelligence",
        "retrieve_evidence",
    )
    builder.add_edge("retrieve_evidence", END)

    return builder.compile()
