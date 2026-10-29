
from pathlib import Path

import pytest

from phishing_detection.rag.document_loader import (
    load_documents,
    split_into_chunks,
)


def test_load_documents_reads_text_files(tmp_path: Path):
    knowledge_dir = tmp_path / "knowledge_base"
    knowledge_dir.mkdir()
    (knowledge_dir / "security.txt").write_text(
        "Check the URL hostname carefully.",
        encoding="utf-8",
    )

    documents = load_documents(knowledge_dir)

    assert len(documents) == 1
    assert documents[0]["source"] == "security.txt"
    assert documents[0]["text"] == "Check the URL hostname carefully."


def test_load_documents_rejects_missing_directory(tmp_path: Path):
    missing_dir = tmp_path / "missing"

    with pytest.raises(FileNotFoundError):
        load_documents(missing_dir)


def test_load_documents_skips_empty_text_files(tmp_path: Path):
    knowledge_dir = tmp_path / "knowledge_base"
    knowledge_dir.mkdir()
    (knowledge_dir / "empty.txt").write_text("   ", encoding="utf-8")

    documents = load_documents(knowledge_dir)

    assert documents == []


def test_split_into_chunks_returns_empty_list_for_empty_text():
    assert split_into_chunks("   ") == []


def test_split_into_chunks_preserves_overlap():
    chunks = split_into_chunks("abcdefghijklmnopqrst", chunk_size=10, overlap=3)

    assert chunks == ["abcdefghij", "hijklmnopq", "opqrst"]


def test_split_into_chunks_rejects_invalid_chunk_size():
    with pytest.raises(ValueError):
        split_into_chunks("Some text", chunk_size=0)


def test_split_into_chunks_rejects_invalid_overlap():
    with pytest.raises(ValueError):
        split_into_chunks("Some text", chunk_size=5, overlap=5)
