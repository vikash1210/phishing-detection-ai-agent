"""Tests for dataset metadata and file integrity helpers."""

import hashlib

from phishing_detection.dataset_metadata import calculate_sha256


def test_calculate_sha256_returns_expected_checksum(tmp_path):
    """Check that the function returns the correct SHA-256 checksum."""
    test_file = tmp_path / "sample.txt"
    test_content = b"phishing detection dataset"
    test_file.write_bytes(test_content)

    expected_checksum = hashlib.sha256(test_content).hexdigest()

    assert calculate_sha256(test_file) == expected_checksum


def test_calculate_sha256_handles_empty_file(tmp_path):
    """Check that an empty file produces the correct checksum."""
    test_file = tmp_path / "empty.txt"
    test_file.write_bytes(b"")

    expected_checksum = hashlib.sha256(b"").hexdigest()

    assert calculate_sha256(test_file) == expected_checksum


def test_calculate_sha256_handles_content_larger_than_one_chunk(tmp_path):
    """Check that the function correctly hashes content larger than one chunk."""
    test_file = tmp_path / "large.txt"
    test_content = b"A" * (1024 * 1024 + 100)
    test_file.write_bytes(test_content)

    expected_checksum = hashlib.sha256(test_content).hexdigest()

    assert calculate_sha256(test_file) == expected_checksum