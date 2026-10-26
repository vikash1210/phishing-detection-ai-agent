"""Load and validate a URL dataset from a CSV file."""

from __future__ import annotations

from pathlib import Path

import pandas as pd

from phishing_detection.data_validation import validate_dataset


class DatasetIngestionError(ValueError):
    """Raised when a dataset CSV cannot be read."""


def load_dataset(path: str | Path) -> pd.DataFrame:
    """Read a CSV as strings and return it only after complete validation."""
    csv_path = Path(path)
    if not csv_path.exists():
        raise DatasetIngestionError(f"Dataset file does not exist: {csv_path}")
    if not csv_path.is_file():
        raise DatasetIngestionError(f"Dataset path is not a file: {csv_path}")

    try:
        data = pd.read_csv(csv_path, dtype=str, keep_default_na=False)
    except pd.errors.EmptyDataError as error:
        raise DatasetIngestionError(
            f"Dataset CSV is empty or has no header: {csv_path}"
        ) from error
    except pd.errors.ParserError as error:
        raise DatasetIngestionError(
            f"Dataset CSV is malformed; check its delimiters and quoting: {csv_path}"
        ) from error
    except UnicodeDecodeError as error:
        raise DatasetIngestionError(
            f"Dataset CSV must be valid UTF-8: {csv_path}"
        ) from error

    return validate_dataset(data)
