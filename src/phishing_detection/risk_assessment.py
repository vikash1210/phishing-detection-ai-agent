
from typing import Any


def assess_risk(
    prediction: dict[str, Any],
    threat_intelligence: dict[str, Any],
) -> dict[str, Any]:
    """Combine ML and threat-intelligence signals conservatively."""

    threat_status = threat_intelligence.get("status", "unavailable")
    is_threat = threat_intelligence.get("is_threat")
    model_prediction = prediction.get("prediction", "unknown")

    # A confirmed external threat always has the highest priority.
    if threat_status == "threat_found" and is_threat is True:
        return {
            "risk_level": "HIGH RISK",
            "reasons": [
                "Google Safe Browsing reported a threat match.",
            ],
            "verification_status": "threat_confirmed_by_external_feed",
        }

    # Handle inconsistent threat-intelligence responses.
    known_statuses = {
        "threat_found",
        "no_match",
        "unavailable",
        "not_configured",
    }

    if threat_status not in known_statuses:
        threat_status = "unavailable"

    inconsistent_signal = (
        threat_status == "threat_found" and is_threat is not True
    )

    # An ML phishing prediction must never be treated as safe.
    if model_prediction == "phishing":
        reasons = [
            "The ML classifier identified phishing indicators.",
        ]

        if inconsistent_signal:
            reasons.append(
                "Google Safe Browsing returned an inconsistent threat response."
            )
        elif threat_status in {"unavailable", "not_configured"}:
            reasons.append(
                "Google Safe Browsing verification was unavailable."
            )
        elif threat_status == "no_match":
            reasons.append(
                "Google Safe Browsing returned no match, "
                "which does not establish safety."
            )

        return {
            "risk_level": "SUSPICIOUS",
            "reasons": reasons,
            "verification_status": (
                "external_signal_inconsistent"
                if inconsistent_signal
                else "external_check_unavailable"
                if threat_status in {"unavailable", "not_configured"}
                else "not_confirmed_by_external_feed"
            ),
        }

    # Unknown ML predictions cannot be treated as legitimate.
    if model_prediction != "legitimate":
        reasons = [
            "The ML classifier did not return a recognized prediction.",
            "The available signals do not establish that this URL is safe.",
        ]

        return {
            "risk_level": "UNVERIFIED",
            "reasons": reasons,
            "verification_status": (
                "external_signal_inconsistent"
                if inconsistent_signal
                else "external_check_unavailable"
                if threat_status in {"unavailable", "not_configured"}
                else "not_confirmed_by_external_feed"
            ),
        }

    # A legitimate ML prediction is not proof that a URL is safe.
    reasons = [
        "The available signals do not establish that this URL is safe.",
    ]

    if inconsistent_signal:
        reasons.append(
            "Google Safe Browsing returned an inconsistent threat response."
        )
        verification_status = "external_signal_inconsistent"

    elif threat_status in {"unavailable", "not_configured"}:
        reasons.append(
            "Google Safe Browsing could not verify this URL."
        )
        verification_status = "external_check_unavailable"

    else:
        reasons.append(
            "No matching threat was returned by Google Safe Browsing."
        )
        verification_status = "not_confirmed_by_external_feed"

    return {
        "risk_level": "UNVERIFIED",
        "reasons": reasons,
        "verification_status": verification_status,
    }
