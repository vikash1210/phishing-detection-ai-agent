
import logging
import time
import uuid
from collections import defaultdict, deque
from contextlib import asynccontextmanager
from threading import Lock
from typing import Any

from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from phishing_detection.agent.graph import build_phishing_graph
from phishing_detection.model import PhishingURLClassifier
from phishing_detection.rag.retriever import SemanticRetriever
from phishing_detection.risk_assessment import assess_risk


load_dotenv()

logger = logging.getLogger(__name__)

RATE_LIMIT_REQUESTS = 10
RATE_LIMIT_WINDOW_SECONDS = 60


@asynccontextmanager
async def lifespan(app: FastAPI):
    classifier = PhishingURLClassifier()
    retriever = SemanticRetriever()

    app.state.classifier = classifier
    app.state.retriever = retriever
    app.state.graph = build_phishing_graph(classifier, retriever)

    app.state.rate_limit_requests = defaultdict(deque)
    app.state.rate_limit_lock = Lock()

    yield


app = FastAPI(
    title="Phishing Detection AI Agent",
    description=(
        "API for pretrained phishing URL classification, "
        "Google Safe Browsing threat intelligence, LangGraph "
        "orchestration, RAG-based security guidance, and risk assessment."
    ),
    version="0.6.0",
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


@app.middleware("http")
async def request_tracking_middleware(
    request: Request,
    call_next,
):
    """Assign a unique ID and log request processing details."""

    request_id = str(uuid.uuid4())
    request.state.request_id = request_id

    start_time = time.perf_counter()

    response = await call_next(request)

    duration_ms = round(
        (time.perf_counter() - start_time) * 1000,
        2,
    )

    response.headers["X-Request-ID"] = request_id

    logger.info(
        "request_completed",
        extra={
            "request_id": request_id,
            "method": request.method,
            "path": request.url.path,
            "status_code": response.status_code,
            "duration_ms": duration_ms,
        },
    )

    return response


@app.exception_handler(Exception)
async def handle_unexpected_exception(
    request: Request,
    exc: Exception,
):
    """Log internal errors without exposing details to API clients."""

    request_id = getattr(
        request.state,
        "request_id",
        "unknown",
    )

    logger.exception(
        "unhandled_api_exception",
        extra={
            "request_id": request_id,
            "method": request.method,
            "path": request.url.path,
        },
    )

    return JSONResponse(
        status_code=500,
        content={
            "detail": (
                "An unexpected server error occurred. "
                "Please try again later."
            )
        },
        headers={"X-Request-ID": request_id},
    )


def enforce_rate_limit(request: Request) -> None:
    """Allow a limited number of requests per client IP in a time window."""

    client_host = (
        request.client.host
        if request.client is not None
        else "unknown"
    )

    now = time.monotonic()

    request_times = request.app.state.rate_limit_requests
    lock = request.app.state.rate_limit_lock

    with lock:
        client_requests = request_times[client_host]

        while (
            client_requests
            and now - client_requests[0] >= RATE_LIMIT_WINDOW_SECONDS
        ):
            client_requests.popleft()

        if len(client_requests) >= RATE_LIMIT_REQUESTS:
            raise HTTPException(
                status_code=429,
                detail=(
                    "Rate limit exceeded. "
                    "Please try again after one minute."
                ),
                headers={"Retry-After": str(RATE_LIMIT_WINDOW_SECONDS)},
            )

        client_requests.append(now)


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
    enforce_rate_limit(http_request)

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
        logger.warning(
            "prediction_request_rejected",
            extra={
                "request_id": getattr(
                    http_request.state,
                    "request_id",
                    "unknown",
                ),
                "error_type": type(exc).__name__,
            },
        )

        raise HTTPException(
            status_code=422,
            detail="The submitted URL could not be processed.",
        ) from exc
