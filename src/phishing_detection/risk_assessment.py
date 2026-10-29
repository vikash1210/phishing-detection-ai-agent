
from typing import Any


def assess_risk(
    prediction: dict[str, Any],
    threat_intelligence: dict[str, Any],
) -> dict[str, Any]:
    """Combine ML and threat-intelligence signals into a risk assessment."""

    threat_status = threat_intelligence.get("status", "unavailable")
    is_threat = threat_intelligence.get("is_threat")
    model_prediction = prediction.get("prediction", "unknown")

    if threat_status == "threat_found" and is_threat is True:
        return {
            "risk_level": "HIGH RISK",
            "reasons": [
                "Google Safe Browsing reported a threat match.",
            ],
            "verification_status": "threat_confirmed_by_external_feed",
        }

    if model_prediction == "phishing":
        reasons = [
            "The ML classifier identified phishing indicators.",
        ]

        if threat_status == "unavailable":
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
                "external_check_unavailable"
                if threat_status in {"unavailable", "not_configured"}
                else "not_confirmed_by_external_feed"
            ),
        }

    reasons = [
        "The available signals do not establish that this URL is safe.",
    ]

    if threat_status in {"unavailable", "not_configured"}:
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
