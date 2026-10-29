# Phishing Detection AI Agent

An AI-assisted phishing URL analysis application that combines a pretrained machine-learning classifier, Google Safe Browsing threat intelligence, LangGraph orchestration, and retrieval-augmented generation (RAG) for security guidance.

## Features

- **ML-based URL classification:** Classifies URLs as phishing or legitimate using a pretrained model.
- **Threat intelligence:** Checks URLs against Google Safe Browsing when configured.
- **RAG-based guidance:** Retrieves relevant security guidance from a local knowledge base.
- **Risk assessment:** Combines available signals into `HIGH RISK`, `SUSPICIOUS`, or `UNVERIFIED` outcomes.
- **FastAPI backend:** Exposes health and prediction endpoints.
- **Streamlit frontend:** Provides an interactive interface for URL analysis.
- **Automated tests:** Covers API, agent graph, RAG components, threat intelligence, and risk assessment.

> Important: A legitimate ML classification or no match from Google Safe Browsing does not guarantee that a URL is safe. The model score is not necessarily a calibrated probability.

## Architecture

1. The user submits a URL through the Streamlit interface.
2. Streamlit sends the URL to the FastAPI `/predict` endpoint.
3. The LangGraph workflow coordinates URL validation, ML classification, threat-intelligence lookup, and retrieval of security guidance.
4. The API produces a risk assessment from the available signals.
5. Streamlit displays the classification, threat-intelligence result, assessment reasons, and retrieved evidence.

## Tech Stack

- Python
- FastAPI and Uvicorn
- Streamlit
- LangGraph
- ONNX Runtime
- Sentence Transformers
- RAG and semantic retrieval
- Google Safe Browsing API
- Pytest

## Prerequisites

- A compatible Python version (Python 3.10 or later according to `pyproject.toml`)
- `uv`
- A Google Safe Browsing API key for external threat-intelligence checks

## Setup

Clone the repository and enter its directory:

```bash
git clone <YOUR_REPOSITORY_URL>
cd <YOUR_PROJECT_DIRECTORY>
```

Install dependencies:

```bash
uv sync
```

Create a `.env` file in the project root with the following configuration:

```dotenv
GOOGLE_SAFE_BROWSING_API_KEY=your_api_key_here
PHISHING_API_URL=http://127.0.0.1:8000
```

Replace the API-key placeholder with your own key. Never commit `.env` or real credentials.

For the Streamlit application, `PHISHING_API_URL` defaults to `http://127.0.0.1:8000` when it is not set.

## Run the application

### 1. Start the FastAPI backend

```bash
uv run uvicorn phishing_detection.api:app --app-dir src --reload
```

API documentation is available at:

- `http://127.0.0.1:8000/docs`
- Health check: `http://127.0.0.1:8000/health`

### 2. Start the Streamlit frontend

Open a second terminal in the project directory and run:

```bash
uv run streamlit run src/phishing_detection/streamlit_app.py
```

Open the local URL printed by Streamlit in your browser.

## API endpoints

### Health check

`GET /health`

### URL prediction

`POST /predict`

Example request:

```json
{
  "url": "https://example.com"
}
```

The response includes the model classification and score, retrieved evidence, threat-intelligence status, and final risk assessment.

## Run tests

Run the automated test suite:

```bash
uv run pytest -q
```

The most recently recorded test run passed 83 tests. Run the suite again after making changes to verify the current state.

## Knowledge base and data

Security guidance is stored under `data/knowledge_base/`. Dataset documentation is available under `data/README.md` and `data/SOURCES.md`.

Raw datasets are excluded from Git by the current `.gitignore`. Follow the relevant dataset licensing and provenance requirements before redistributing data.

## Limitations

- A threat-intelligence no-match result does not establish that a URL is safe.
- Model scores should not be interpreted as calibrated probabilities unless calibration has been evaluated.
- Retrieved security guidance provides context; it does not independently verify the submitted URL.
- Detection quality depends on model performance, input validation, and the coverage and freshness of external threat feeds.

## Development status

This project is an actively developed prototype. Passing automated tests demonstrates tested behavior, not guaranteed detection accuracy or production readiness. Further evaluation, security review, and deployment validation are required before production use.
