import pandas as pd
import pytest

from phishing_detection.data_ingestion import DatasetIngestionError, load_dataset
from phishing_detection.data_validation import DatasetValidationError


def test_loads_and_normalizes_valid_csv(tmp_path):
    csv_path = tmp_path / "urls.csv"
    csv_path.write_text(
        "url,label\n https://example.com/path , Legitimate \n"
        "https://bad.example/login, phishing \n",
        encoding="utf-8",
    )
    original_contents = csv_path.read_text(encoding="utf-8")

    result = load_dataset(csv_path)

    assert result.to_dict("records") == [
        {"url": "https://example.com/path", "label": 0},
        {"url": "https://bad.example/login", "label": 1},
    ]
    assert csv_path.read_text(encoding="utf-8") == original_contents


def test_preserves_label_text_for_validation(tmp_path):
    csv_path = tmp_path / "urls.csv"
    csv_path.write_text("url,label\nhttps://example.com,01\n", encoding="utf-8")

    with pytest.raises(DatasetValidationError, match="unsupported label '01'"):
        load_dataset(csv_path)


def test_rejects_missing_file(tmp_path):
    csv_path = tmp_path / "missing.csv"

    with pytest.raises(DatasetIngestionError, match="does not exist"):
        load_dataset(csv_path)


@pytest.mark.parametrize(
    ("contents", "message"),
    [
        ("", "empty or has no header"),
        ('url,label\n"https://example.com,phishing\n', "malformed"),
    ],
)
def test_rejects_empty_or_malformed_csv(tmp_path, contents, message):
    csv_path = tmp_path / "urls.csv"
    csv_path.write_text(contents, encoding="utf-8")

    with pytest.raises(DatasetIngestionError, match=message):
        load_dataset(csv_path)


def test_rejects_invalid_dataset_without_dropping_rows(tmp_path):
    csv_path = tmp_path / "urls.csv"
    csv_path.write_text(
        "url,label\nhttps://example.com,legitimate\nnot-a-url,phishing\n",
        encoding="utf-8",
    )

    with pytest.raises(DatasetValidationError, match="row 3"):
        load_dataset(csv_path)


def test_returns_dataframe_with_existing_normalized_schema(tmp_path):
    csv_path = tmp_path / "urls.csv"
    csv_path.write_text("url,label\nhttps://example.com,0\n", encoding="utf-8")

    result = load_dataset(csv_path)

    assert isinstance(result, pd.DataFrame)
    assert list(result.columns) == ["url", "label"]
    assert str(result["label"].dtype) == "int8"
