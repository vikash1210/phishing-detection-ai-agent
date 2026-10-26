"""Validation for the raw URL dataset used by the project."""

from __future__ import annotations

import ipaddress
from urllib.parse import urlsplit

import pandas as pd

REQUIRED_COLUMNS = ("url", "label")
LABELS = {
    "0": 0,
    "benign": 0,
    "legitimate": 0,
    "1": 1,
    "malicious": 1,
    "phishing": 1,
}


def _url_validation_error(url: str) -> str | None:
    """Return a reason when a URL is invalid, or ``None`` when it is valid."""
    if any(
        character.isspace() or ord(character) < 0x20 or ord(character) == 0x7F
        for character in url
    ):
        return "url contains whitespace or control characters"
    if "\\" in url:
        return "url contains an invalid backslash"
    for index, character in enumerate(url):
        if character == "%" and (
            index + 2 >= len(url)
            or any(digit not in "0123456789abcdefABCDEF" for digit in url[index + 1 : index + 3])
        ):
            return "url contains an invalid percent escape"

    try:
        parsed = urlsplit(url)
        if parsed.scheme.lower() not in {"http", "https"}:
            return "url must be an absolute HTTP(S) URL with a hostname"
        if not parsed.netloc or not parsed.hostname:
            return "url must be an absolute HTTP(S) URL with a hostname"
        if parsed.netloc.count("@") > 1:
            return "url contains an invalid authority"

        userinfo, separator, authority = parsed.netloc.rpartition("@")
        if separator:
            allowed_userinfo = (
                "abcdefghijklmnopqrstuvwxyz"
                "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                "0123456789-._~!$&'()*+,;=:"
            )
            index = 0
            while index < len(userinfo):
                if userinfo[index] == "%":
                    index += 3
                    continue
                if userinfo[index] not in allowed_userinfo:
                    return "url contains an invalid authority"
                index += 1

        if authority.startswith("["):
            closing_bracket = authority.find("]")
            port_suffix = authority[closing_bracket + 1 :]
            if port_suffix and not port_suffix.startswith(":"):
                return "url contains an invalid authority"
            port_text = port_suffix[1:] if port_suffix else None
        else:
            if authority.count(":") > 1:
                return "url contains an invalid authority"
            _, separator, port_text = authority.rpartition(":")
            if not separator:
                port_text = None

        if port_text == "":
            return "url contains an empty port"
        if port_text is not None and any(
            character not in "0123456789" for character in port_text
        ):
            return "url contains an invalid authority"
        _port = parsed.port

        hostname = parsed.hostname
        if ":" in hostname:
            address = ipaddress.ip_address(hostname)
            if address.version != 6:
                return "url contains an invalid IPv6 hostname"
            return None

        if all(character.isdigit() or character == "." for character in hostname) and "." in hostname:
            try:
                ipaddress.IPv4Address(hostname)
            except ipaddress.AddressValueError:
                return "url contains an invalid IPv4 hostname"
            return None

        try:
            ascii_hostname = hostname.encode("idna").decode("ascii")
        except UnicodeError:
            return "url contains an invalid hostname"
        dns_name = ascii_hostname[:-1] if ascii_hostname.endswith(".") else ascii_hostname
        labels = dns_name.split(".")
        if (
            len(dns_name) > 253
            or not dns_name
            or any(
                not label
                or len(label) > 63
                or not label[0].isalnum()
                or not label[-1].isalnum()
                or any(not (character.isalnum() or character == "-") for character in label)
                for label in labels
            )
        ):
            return "url contains an invalid hostname"
        try:
            dns_name.encode("ascii").decode("idna")
        except UnicodeError:
            return "url contains an invalid hostname"
    except (ValueError, UnicodeError):
        return "url is malformed or contains an invalid authority"

    return None


class DatasetValidationError(ValueError):
    """Report that a dataset does not satisfy the documented URL/label CSV contract."""


def validate_dataset(data: pd.DataFrame) -> pd.DataFrame:
    """Validate every row and return a normalized copy of a valid URL/label dataframe.

    The function rejects missing or extra columns, empty datasets, invalid URLs,
    unsupported labels, and duplicate URLs. It trims URLs, normalizes accepted
    labels to integer values, and leaves the input dataframe unchanged.
    """
    if not isinstance(data, pd.DataFrame):
        raise TypeError("data must be a pandas DataFrame")

    missing_columns = [column for column in REQUIRED_COLUMNS if column not in data.columns]
    extra_columns = [column for column in data.columns if column not in REQUIRED_COLUMNS]
    if missing_columns or extra_columns:
        details = []
        if missing_columns:
            details.append(f"missing columns: {', '.join(missing_columns)}")
        if extra_columns:
            details.append(f"unexpected columns: {', '.join(map(str, extra_columns))}")
        raise DatasetValidationError("; ".join(details))

    if data.empty:
        raise DatasetValidationError("dataset contains no rows")

    normalized = data.loc[:, REQUIRED_COLUMNS].copy()
    normalized["url"] = normalized["url"].map(
        lambda value: value.strip() if isinstance(value, str) else value
    )
    normalized["label"] = normalized["label"].map(
        lambda value: str(value).strip().lower() if pd.notna(value) else ""
    )

    errors: list[str] = []
    for row_number, (_, row) in enumerate(normalized.iterrows(), start=2):
        url = row["url"]
        if not isinstance(url, str) or not url:
            errors.append(f"row {row_number}: url must be a non-empty string")
        else:
            url_error = _url_validation_error(url)
            if url_error:
                errors.append(f"row {row_number}: {url_error}")

        if row["label"] not in LABELS:
            errors.append(f"row {row_number}: unsupported label {row['label']!r}")

    duplicate_mask = normalized["url"].duplicated(keep=False)
    if duplicate_mask.any():
        duplicate_rows = [
            str(row_number)
            for row_number, is_duplicate in enumerate(duplicate_mask, start=2)
            if is_duplicate
        ]
        errors.append(f"duplicate URLs found on rows: {', '.join(duplicate_rows)}")

    if errors:
        raise DatasetValidationError("Dataset validation failed:\n- " + "\n- ".join(errors))

    normalized["label"] = normalized["label"].map(LABELS).astype("int8")
    return normalized.reset_index(drop=True)
