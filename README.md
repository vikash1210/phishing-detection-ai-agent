# Phishing Detection AI

A staged project for detecting phishing URLs. The initial implementation focuses
on a reproducible input dataset contract; model, API, frontend, and deployment
work will be added only after review of the preceding stage.

## Implementation plan

1. **Dataset selection and validation** — define a raw URL/label CSV contract,
   document data provenance expectations, and validate input before training.
2. **URL features and baseline model** — extract URL-only features and train a
   scikit-learn baseline.
3. **Evaluation** — keep train, validation, and test data separate; report
   precision, recall, F1-score, and a confusion matrix from actual runs.
4. **Prediction API** — add FastAPI prediction and health endpoints with
   Pydantic request validation.
5. **Tests and error handling** — expand unit and API tests, and make failures
   explicit.
6. **Web frontend** — add a React.js interface for URL predictions.
7. **Delivery and infrastructure** — add Docker, GitHub Actions CI, and
   Terraform/AWS deployment configuration.

Each stage is intended to be reviewed before beginning the next.

## Initial project structure

```text
.
├── data/
│   └── README.md
├── src/
│   └── phishing_detection/
│       ├── __init__.py
│       └── data_validation.py
├── tests/
│   └── test_data_validation.py
├── tools/
│   └── validate_dataset.py
└── pyproject.toml
```

## Stage 1: dataset contract

The accepted input is a UTF-8 CSV containing exactly `url` and `label` columns.
Labels are normalized to `0` (legitimate) or `1` (phishing). See
[`data/README.md`](data/README.md) for the proposed dataset sources, provenance
requirements, and validation command.

This repository does not include a dataset. No training or model metrics are
claimed at this stage.
