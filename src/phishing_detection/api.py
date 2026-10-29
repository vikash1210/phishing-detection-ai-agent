from contextlib import asynccontextmanager
from typing import Any

from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException, Request
from pydantic import BaseModel, Field

from phishing_detection.agent.graph import build_phishing_graph
from phishing_detection.model import PhishingURLClassifier
from phishing_detection.rag.retriever import SemanticRetriever
from phishing_detection.risk_assessment import assess_risk


# Load environment variables from the project's .env file.
load_dotenv()


@asynccontextmanager
async def lifespan(app: FastAPI):
    classifier = PhishingURLClassifier()
    retriever = SemanticRetriever()

    app.state.classifier = classifier
    app.state.retriever = retriever
    app.state.graph = build_phishing_graph(classifier, retriever)

    yield


app = FastAPI(
    title="Phishing Detection AI Agent",
    description=(
        "API for pretrained phishing URL classification, "
        "Google Safe Browsing threat intelligence, LangGraph "
        "orchestration, RAG-based security guidance, and risk assessment."
    ),
    version="0.5.0",
    lifespan=lifespan,
)


class PredictionRequest(BaseModel):
    url: str = Field(min_length=1, max_length=4096)


class EvidenceItem(BaseModel):
    text: str
    source: str
    chunk_id: str
    similarity: float


class RiskAssessment(BaseModel):
    risk_level: str
    reasons: list[str]
    verification_status: str


class PredictionResponse(BaseModel):
    url: str
    label: int
    prediction: str
    phishing_score: float
    evidence: list[EvidenceItem]
    evidence_note: str
    threat_intelligence: dict[str, Any]
    risk_assessment: RiskAssessment


@app.get("/health")
def health():
    return {
        "status": "healthy",
        "app": "Phishing Detection AI Agent",
    }


@app.post("/predict", response_model=PredictionResponse)
def predict_url(
    request: PredictionRequest,
    http_request: Request,
):
    graph = http_request.app.state.graph

    try:
        result = graph.invoke({"url": request.url})

        if result.get("error"):
            raise HTTPException(
                status_code=422,
                detail=result["error"],
            )

        prediction = result["prediction"]

        threat_intelligence = result.get(
            "threat_intelligence",
            {
                "status": "unavailable",
                "is_threat": None,
                "matches": [],
                "message": (
                    "Threat intelligence was not returned by the graph."
                ),
            },
        )

        risk_assessment = assess_risk(
            prediction=prediction,
            threat_intelligence=threat_intelligence,
        )

        return {
            **prediction,
            "evidence": result.get("evidence", []),
            "evidence_note": result.get(
                "evidence_note",
                (
                    "Retrieved passages provide general security guidance. "
                    "They do not independently verify whether this specific "
                    "URL is malicious or legitimate."
                ),
            ),
            "threat_intelligence": threat_intelligence,
            "risk_assessment": risk_assessment,
        }

    except HTTPException:
        raise

    except ValueError as exc:
        raise HTTPException(
            status_code=422,
            detail=str(exc),
        ) from exc