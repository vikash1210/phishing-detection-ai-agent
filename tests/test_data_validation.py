import pandas as pd
import pytest

from phishing_detection.data_validation import DatasetValidationError, validate_dataset


def test_normalizes_labels_and_trims_urls():
    data = pd.DataFrame(
        {
            "url": [" https://example.com/path ", "http://bad.example/login"],
            "label": ["Legitimate", " phishing "],
        }
    )

    result = validate_dataset(data)

    assert result.to_dict("records") == [
        {"url": "https://example.com/path", "label": 0},
        {"url": "http://bad.example/login", "label": 1},
    ]
    assert data.to_dict("records") == [
        {"url": " https://example.com/path ", "label": "Legitimate"},
        {"url": "http://bad.example/login", "label": " phishing "},
    ]


@pytest.mark.parametrize(
    ("data", "message"),
    [
        (pd.DataFrame(columns=["url"]), "missing columns: label"),
        (pd.DataFrame({"url": [], "label": []}), "dataset contains no rows"),
        (pd.DataFrame({"url": ["https://example.com"], "label": ["unknown"]}), "unsupported label"),
        (
            pd.DataFrame({"url": ["//example.com"], "label": ["benign"]}),
            "absolute HTTP",
        ),
        (
            pd.DataFrame(
                {
                    "url": ["https://example.com", "https://example.com"],
                    "label": ["benign", "phishing"],
                }
            ),
            "duplicate URLs",
        ),
        (
            pd.DataFrame(
                {
                    "url": ["https://example.com"],
                    "label": ["benign"],
                    "source": ["feed"],
                }
            ),
            "unexpected columns: source",
        ),
    ],
)
def test_rejects_invalid_dataset(data, message):
    with pytest.raises(DatasetValidationError, match=message):
        validate_dataset(data)


def test_rejects_missing_values():
    data = pd.DataFrame({"url": [None], "label": ["phishing"]})

    with pytest.raises(DatasetValidationError, match="url must be a non-empty string"):
        validate_dataset(data)


@pytest.mark.parametrize(
    ("url", "message"),
    [
        ("https://example.com:abc/path", "invalid authority"),
        ("https://example.com:-1/path", "invalid authority"),
        ("https://example.com:65536/path", "invalid authority"),
        ("https://example.com:/path", "empty port"),
        ("https://example.com:80:90/path", "invalid authority"),
        ("https:///path", "hostname"),
        ("https://[not-ipv6]/path", "invalid authority"),
        ("https://example..com/path", "invalid hostname"),
        ("https://bad_host.example/path", "invalid hostname"),
        ("https://-bad.example/path", "invalid hostname"),
        (f"https://{'a' * 64}.example/path", "invalid hostname"),
        (f"https://{'.'.join(['a' * 63] * 4)}.example/path", "invalid hostname"),
        ("https://999.999.999.999/path", "invalid IPv4 hostname"),
        ("https://xn--.example/path", "invalid hostname"),
        ("https://user@@example.com/path", "invalid authority"),
        ("https://user|name@example.com/path", "invalid authority"),
        ("https://example.com/%zz", "percent escape"),
        ("https://example.com/a b", "whitespace"),
        ("https://example.com\\@evil.example/path", "backslash"),
    ],
)
def test_rejects_malformed_http_urls(url, message):
    data = pd.DataFrame({"url": [url], "label": ["legitimate"]}, index=[17])

    with pytest.raises(DatasetValidationError, match="row 2") as error:
        validate_dataset(data)

    assert message in str(error.value)
    assert data.loc[17, "url"] == url


@pytest.mark.parametrize(
    "url",
    [
        "https://example.com:443/path",
        "http://127.0.0.1:8080/path",
        "https://[2001:db8::1]/path",
        "https://subdomain.example.com./path",
        "https://bücher.example/path",
    ],
)
def test_accepts_valid_http_authorities(url):
    data = pd.DataFrame({"url": [url], "label": ["benign"]})

    result = validate_dataset(data)

    assert result.loc[0, "url"] == url
    assert result.loc[0, "label"] == 0
