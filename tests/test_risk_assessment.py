from phishing_detection.risk_assessment import assess_risk


def test_threat_match_means_high_risk():
    result = assess_risk(
        {"prediction": "legitimate"},
        {"status": "threat_found", "is_threat": True},
    )

    assert result["risk_level"] == "HIGH RISK"


def test_ml_phishing_without_threat_match_is_suspicious():
    result = assess_risk(
        {"prediction": "phishing"},
        {"status": "no_match", "is_threat": False},
    )

    assert result["risk_level"] == "SUSPICIOUS"


def test_legitimate_and_no_match_is_unverified():
    result = assess_risk(
        {"prediction": "legitimate"},
        {"status": "no_match", "is_threat": False},
    )

    assert result["risk_level"] == "UNVERIFIED"


def test_unavailable_lookup_does_not_mean_safe():
    result = assess_risk(
        {"prediction": "legitimate"},
        {"status": "unavailable", "is_threat": None},
    )

    assert result["risk_level"] == "UNVERIFIED"
    assert result["verification_status"] == "external_check_unavailable"