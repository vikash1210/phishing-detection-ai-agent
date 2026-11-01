
import logging
import os
import secrets
import time
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from threading import Lock
from urllib.parse import urlsplit

from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from sqlalchemy.exc import SQLAlchemyError

from phishing_detection.agent.graph import build_phishing_graph
from phishing_detection.database import SessionLocal
from phishing_detection.db_models import ScannedURL, ScanResult
from phishing_detection.model import PhishingURLClassifier
from phishing_detection.rag.retriever import SemanticRetriever
from phishing_detection.risk_assessment import assess_risk


load_dotenv()

logger = logging.getLogger(__name__)

RATE_LIMIT = 10
RATE_LIMIT_WINDOW = 60


@asynccontextmanager
async def lifespan(app: FastAPI):
    classifier = PhishingURLClassifier()
    retriever = SemanticRetriever()

    app.state.classifier = classifier
    app.state.retriever = retriever
    app.state.graph = build_phishing_graph(classifier, retriever)

    app.state.rate_limit_store = {}
    app.state.rate_limit_lock = Lock()

    yield


app = FastAPI(
    title="Phishing Detection AI Agent",
    description="Phishing URL detection using ML, threat intelligence and RAG.",
    version="0.2.0",
    lifespan=lifespan,
)


class PredictionRequest(BaseModel):
    url: str = Field(min_length=1, max_length=4096)


class PredictionResponse(BaseModel):
    url: str
    label: int
    prediction: str
    phishing_score: float
    threat_intelligence: dict
    risk_assessment: dict
    evidence: list
    evidence_note: str


def verify_api_key(http_request: Request) -> None:
    expected_api_key = os.getenv("GMAIL_ADDON_API_KEY")
    provided_api_key = http_request.headers.get("X-API-Key", "")

    if not expected_api_key:
        raise HTTPException(
            status_code=503,
            detail="API authentication is not configured.",
        )

    if not secrets.compare_digest(provided_api_key, expected_api_key):
        raise HTTPException(
            status_code=401,
            detail="Invalid or missing API key.",
        )


def check_rate_limit(http_request: Request) -> None:
    client_ip = (
        http_request.client.host
        if http_request.client
        else "unknown"
    )

    now = time.monotonic()
    store = http_request.app.state.rate_limit_store
    lock = http_request.app.state.rate_limit_lock

    with lock:
        request_times = store.get(client_ip, [])

        request_times = [
            timestamp
            for timestamp in request_times
            if now - timestamp < RATE_LIMIT_WINDOW
        ]

        if len(request_times) >= RATE_LIMIT:
            store[client_ip] = request_times
            raise HTTPException(
                status_code=429,
                detail="Rate limit exceeded. Please try again after one minute.",
                headers={"Retry-After": "60"},
            )

        request_times.append(now)
        store[client_ip] = request_times


def save_scan(
    original_url: str,
    prediction: dict,
    threat_intelligence: dict,
    risk_assessment: dict,
) -> None:
    db = SessionLocal()

    try:
        normalized_url = prediction.get("normalized_url") or original_url
        parsed_url = urlsplit(normalized_url)

        scanned_url = ScannedURL(
            original_url=original_url,
            normalized_url=normalized_url,
            domain=parsed_url.hostname or "",
        )

        db.add(scanned_url)
        db.flush()

        scan_result = ScanResult(
            scanned_url_id=scanned_url.id,
            model_label=prediction["label"],
            prediction=prediction["prediction"],
            phishing_score=prediction["phishing_score"],
            threat_status=threat_intelligence.get("status", "unavailable"),
            threat_match=bool(threat_intelligence.get("is_threat")),
            risk_level=risk_assessment["risk_level"],
            verification_status=risk_assessment["verification_status"],
            evidence=prediction.get("evidence", []),
            reasons=risk_assessment.get("reasons", []),
            agent_version="0.2.0",
            scanned_at=datetime.now(timezone.utc),
        )

        db.add(scan_result)
        db.commit()

    except (SQLAlchemyError, ValueError, KeyError):
        db.rollback()
        logger.exception("Unable to save phishing scan history.")
    finally:
        db.close()


@app.exception_handler(Exception)
async def unexpected_exception_handler(
    request: Request,
    exc: Exception,
):
    logger.exception("Unexpected API error.")
    return JSONResponse(
        status_code=500,
        content={
            "detail": (
                "An unexpected server error occurred. "
                "Please try again later."
            )
        },
    )


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
    verify_api_key(http_request)
    check_rate_limit(http_request)

    try:
        graph = http_request.app.state.graph

        result = graph.invoke({"url": request.url})

        if result.get("error"):
            raise HTTPException(
                status_code=422,
                detail="The submitted URL could not be processed.",
            )

        prediction = result.get("prediction")

        if not isinstance(prediction, dict):
            raise ValueError("Invalid classifier response.")

        threat_intelligence = result.get(
            "threat_intelligence",
            {"status": "unavailable", "is_threat": None, "matches": []},
        )

        risk_result = assess_risk(
            prediction,
            threat_intelligence,
        )

        response_data = {
            "url": result.get("normalized_url", request.url),
            "label": prediction["label"],
            "prediction": prediction["prediction"],
            "phishing_score": prediction["phishing_score"],
            "threat_intelligence": threat_intelligence,
            "risk_assessment": risk_result,
            "evidence": result.get("evidence", []),
            "evidence_note": result.get(
                "evidence_note",
                "Retrieved evidence is general security guidance, not independent URL verification.",
            ),
        }

        save_scan(
            request.url,
            {
                **prediction,
                "normalized_url": result.get(
                    "normalized_url",
                    request.url,
                ),
                "evidence": response_data["evidence"],
            },
            threat_intelligence,
            risk_result,
        )

        return response_data

    except HTTPException:
        raise

    except ValueError as exc:
        logger.warning("URL processing failed: %s", exc)
        raise HTTPException(
            status_code=422,
            detail="The submitted URL could not be processed.",
        ) from exc

    except Exception as exc:
        logger.exception("Prediction pipeline failed.")
        raise HTTPException(
            status_code=500,
            detail=(
                "An unexpected server error occurred. "
                "Please try again later."
            ),
        ) from exc


@app.get("/scans")
def get_scans(
    http_request: Request,
    limit: int = 20,
    offset: int = 0,
):
    verify_api_key(http_request)

    if limit < 1 or limit > 100:
        raise HTTPException(
            status_code=422,
            detail="Limit must be between 1 and 100.",
        )

    if offset < 0:
        raise HTTPException(
            status_code=422,
            detail="Offset cannot be negative.",
        )

    db = SessionLocal()

    try:
        query = (
            db.query(ScannedURL, ScanResult)
            .join(
                ScanResult,
                ScanResult.scanned_url_id == ScannedURL.id,
            )
        )

        total = query.count()

        records = (
            query.order_by(ScanResult.scanned_at.desc())
            .offset(offset)
            .limit(limit)
            .all()
        )

        scans = []

        for scanned_url, scan_result in records:
            scans.append({
                "id": str(scan_result.id),
                "url": scanned_url.original_url,
                "original_url": scanned_url.original_url,
                "normalized_url": scanned_url.normalized_url,
                "domain": scanned_url.domain,
                "label": scan_result.model_label,
                "prediction": scan_result.prediction,
                "phishing_score": scan_result.phishing_score,
                "threat_status": scan_result.threat_status,
                "risk_level": scan_result.risk_level,
                "verification_status": scan_result.verification_status,
                "scanned_at": (
                    scan_result.scanned_at.isoformat()
                    if scan_result.scanned_at
                    else None
                ),
            })

        return {
            "total": total,
            "items_returned": len(scans),
            "limit": limit,
            "offset": offset,
            "scans": scans,
        }

    except SQLAlchemyError as exc:
        logger.exception("Unable to retrieve scan history.")
        raise HTTPException(
            status_code=500,
            detail="Unable to retrieve scan history.",
        ) from exc

    finally:
        db.close()
    if limit < 1 or limit > 100:
        raise HTTPException(
            status_code=422,
            detail="Limit must be between 1 and 100.",
        )

    if offset < 0:
        raise HTTPException(
            status_code=422,
            detail="Offset cannot be negative.",
        )

    db = SessionLocal()

    try:
        query = (
            db.query(ScannedURL, ScanResult)
            .join(
                ScanResult,
                ScanResult.scanned_url_id == ScannedURL.id,
            )
        )

        total = query.count()

        records = (
            query.order_by(ScanResult.scanned_at.desc())
            .offset(offset)
            .limit(limit)
            .all()
        )

        scans = []

        for scanned_url, scan_result in records:
                scans.append({
    "id": str(scan_result.id),
    "url": scanned_url.original_url,
    "original_url": scanned_url.original_url,
                "normalized_url": scanned_url.normalized_url,
                "domain": scanned_url.domain,
                "label": scan_result.model_label,
                "prediction": scan_result.prediction,
                "phishing_score": scan_result.phishing_score,
                "threat_status": scan_result.threat_status,
                "risk_level": scan_result.risk_level,
                "verification_status": scan_result.verification_status,
                "scanned_at": (
                    scan_result.scanned_at.isoformat()
                    if scan_result.scanned_at
                    else None
                ),
            })

        return {
            "total": total,
            "items_returned": len(scans),
            "limit": limit,
            "offset": offset,
            "scans": scans,
        }

    except SQLAlchemyError as exc:
        logger.exception("Unable to retrieve scan history.")
        raise HTTPException(
            status_code=500,
            detail="Unable to retrieve scan history.",
        ) from exc

    finally:
        db.close()
