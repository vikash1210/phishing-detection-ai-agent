"""Validate and normalize a URL/label CSV without modifying its source."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

import pandas as pd

from phishing_detection.data_validation import DatasetValidationError, validate_dataset


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", type=Path, help="source CSV containing url,label columns")
    parser.add_argument("--output", required=True, type=Path, help="path for validated CSV")
    args = parser.parse_args()

    input_path = args.input.resolve()
    output_path = args.output.resolve()
    if input_path == output_path:
        parser.error("output path must differ from input path")
    if not input_path.is_file():
        parser.error(f"input file does not exist: {input_path}")

    try:
        validated = validate_dataset(pd.read_csv(input_path, dtype=str, keep_default_na=False))
    except (DatasetValidationError, pd.errors.EmptyDataError, pd.errors.ParserError) as error:
        print(str(error), file=sys.stderr)
        return 1

    output_path.parent.mkdir(parents=True, exist_ok=True)
    validated.to_csv(output_path, index=False)
    print(f"Validated {len(validated)} rows; wrote {output_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
