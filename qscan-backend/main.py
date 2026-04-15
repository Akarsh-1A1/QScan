import asyncio
import json
import os
import sys
import shutil
import subprocess
import tempfile
import uuid
import hashlib
import hmac
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional
from contextlib import asynccontextmanager
import traceback

# ── Backend-local config (must import before adding parent to sys.path) ──
from config import settings

# ── Fix import path so ai_ml, crypto, utils are visible from backend ──
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import redis
import redis.asyncio as aioredis

from fastapi import BackgroundTasks, FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from pydantic import BaseModel

from ai_ml.risk_scoring_model import RiskScoringModel
from ai_ml.anomaly_detection import CryptoAnomalyDetector
from crypto.hndl_simulator import compute_hndl_risk

try:
    from groq import Groq
    if settings.GROQ_API_KEY:
        groq_client = Groq(api_key=settings.GROQ_API_KEY)
    else:
        groq_client = None
except Exception:
    groq_client = None


# -----------------------------------------------------------
# Windows UTF8 fix
# -----------------------------------------------------------

os.environ["PYTHONUTF8"] = "1"


# -----------------------------------------------------------
# ML Models
# -----------------------------------------------------------

risk_model = RiskScoringModel()
anomaly_detector = CryptoAnomalyDetector()


# -----------------------------------------------------------
# Redis helpers
# -----------------------------------------------------------

_async_redis: aioredis.Redis | None = None


def _scan_key(scan_id: str) -> str:
    return f"scan:{scan_id}"


def _serialize(record: dict) -> str:
    payload = {
        **record,
        "status": (
            record["status"].value
            if isinstance(record["status"], ScanStatus)
            else record["status"]
        ),
    }
    return json.dumps(payload, ensure_ascii=False)


def _deserialize(raw: str | bytes) -> dict:
    data = json.loads(raw)
    data["status"] = ScanStatus(data["status"])
    return data


async def _aget_record(scan_id: str) -> dict:

    raw = await _async_redis.get(_scan_key(scan_id))

    if raw is None:
        raise HTTPException(
            status_code=404,
            detail=f"Scan '{scan_id}' not found.",
        )

    return _deserialize(raw)


def _sync_redis():

    return redis.Redis(
        host=settings.REDIS_HOST,
        port=settings.REDIS_PORT,
        db=settings.REDIS_DB,
        password=settings.REDIS_PASSWORD,
        decode_responses=True,
    )


def _redis_save(r, record: dict):

    r.set(_scan_key(record["scan_id"]), _serialize(record))


# -----------------------------------------------------------
# FastAPI lifespan (connect Redis)
# -----------------------------------------------------------

@asynccontextmanager
async def lifespan(app: FastAPI):

    global _async_redis

    _async_redis = aioredis.Redis(
        host=settings.REDIS_HOST,
        port=settings.REDIS_PORT,
        db=settings.REDIS_DB,
        password=settings.REDIS_PASSWORD,
        decode_responses=True,
    )

    await _async_redis.ping()

    yield

    await _async_redis.aclose()


# -----------------------------------------------------------
# App
# -----------------------------------------------------------

app = FastAPI(title="QScan API", version="1.0.0", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins_list,
    allow_methods=["*"],
    allow_headers=["*"],
)


# -----------------------------------------------------------
# Enums
# -----------------------------------------------------------

class ScanStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


# -----------------------------------------------------------
# Schemas
# -----------------------------------------------------------

class StartScanRequest(BaseModel):
    target: str
    scan_types: list[str] = []
    discover: bool = False
    ports: Optional[list[int]] = None


class StartScanResponse(BaseModel):
    scan_id: str
    status: ScanStatus
    message: str


class ScanStatusResponse(BaseModel):
    scan_id: str
    status: ScanStatus
    progress: int
    logs: list[str]
    error: Optional[str]


class ScanResultsResponse(BaseModel):
    scan_id: str
    target: str
    cbom: Optional[dict]
    scan_results: Optional[list]
    assets_found: int
    risk_score: Optional[float]


class CbomResponse(BaseModel):
    metadata: Optional[dict]
    summary: Optional[dict]
    crypto_assets: Optional[list]
    risk_matrix: Optional[list]
    pqc_migration_plan: Optional[dict]



class HealthResponse(BaseModel):
    status: str


class ComputeHNDLRequest(BaseModel):
    scan_id: str
    migration_years: int = 3
    data_life_years: int = 7

class ChatMessage(BaseModel):
    role: str
    content: str


class ChatRequest(BaseModel):
    messages: list[ChatMessage]
    scan_context: Optional[dict] = None


class ComputeHNDLResponse(BaseModel):
    scan_id: str
    hndl_risk: dict


# -----------------------------------------------------------
# Helpers
# -----------------------------------------------------------

def _append_log(record: dict, line: str):

    record["logs"].append(
        f"[{datetime.now(timezone.utc).isoformat()}] {line}"
    )


def _read_json(path: str) -> Any:

    if not os.path.exists(path):
        return None

    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)


# -----------------------------------------------------------
# Scan worker
# -----------------------------------------------------------

def _run_qscan(scan_id: str, target: str, discover: bool, output_dir: str, ports: list[int] | None):

    r = _sync_redis()

    record = {
        "scan_id": scan_id,
        "target": target,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "status": ScanStatus.RUNNING,
        "progress": 10,
        "logs": [],
        "error": None,
        "cbom": None,
        "scan_results": None,
        "assets_data": None,
        "assets_found": 0,
        "risk_score": None,
        "ML_risk_score": None,
        "anomaly_detection": None,
    }

    _PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    _MAIN_PY = os.path.join(_PROJECT_ROOT, "main.py")

    cmd = [sys.executable, _MAIN_PY, "--domain", target, "--output", output_dir, "--cbom"]

    if discover:
        cmd.append("--discover")

    if ports:
        cmd.extend(["--ports", ",".join(str(p) for p in ports)])

    _append_log(record, f"Running: {' '.join(cmd)}")
    _redis_save(r, record)

    try:

        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=settings.QSCAN_TIMEOUT,
        )

        if proc.stdout:
            for line in proc.stdout.splitlines():
                _append_log(record, line)

        if proc.stderr:
            for line in proc.stderr.splitlines():
                _append_log(record, f"[stderr] {line}")

        record["progress"] = 70

        if proc.returncode != 0:
            raise RuntimeError(f"qscan exited with code {proc.returncode}")

        cbom = _read_json(os.path.join(output_dir, "cbom.json"))
        results = _read_json(os.path.join(output_dir, "scan_results.json"))
        assets = _read_json(os.path.join(output_dir, "discovered_assets.json"))

        record["cbom"] = cbom
        record["scan_results"] = results if isinstance(results, list) else [results]
        record["assets_data"] = assets

        if record["scan_results"]:

            first_result = record["scan_results"][0]

            record["risk_score"] = first_result.get("quantum_risk_score")

            # ML risk scoring
            try:

                ml_score = risk_model.predict(first_result)

                if isinstance(ml_score, list):
                    ml_score = ml_score[0]

                record["ML_risk_score"] = ml_score

            except Exception as e:
                _append_log(record, f"ML scoring error: {e}")

            # anomaly detection
            try:

                anomaly = anomaly_detector.detect(first_result)
                record["anomaly_detection"] = anomaly

            except Exception as e:
                _append_log(record, f"Anomaly detection error: {e}")

        if cbom:

            record["assets_found"] = cbom.get(
                "metadata", {}
            ).get("total_assets_scanned", 0)
        record["progress"] = 100
        record["status"] = ScanStatus.COMPLETED

        _append_log(record, "Scan completed successfully.")

    except subprocess.TimeoutExpired:

        record["status"] = ScanStatus.FAILED
        record["error"] = f"qscan timed out after {settings.QSCAN_TIMEOUT}"

    except Exception as exc:

        record["status"] = ScanStatus.FAILED
        record["error"] = str(exc)

    finally:

        shutil.rmtree(output_dir, ignore_errors=True)
        _redis_save(r, record)
        r.close()


async def _run_qscan_async(scan_id: str, target: str, discover: bool, output_dir: str, ports):

    await asyncio.to_thread(_run_qscan, scan_id, target, discover, output_dir, ports)


# -----------------------------------------------------------
# Routes
# -----------------------------------------------------------

@app.get("/api/v1/health", response_model=HealthResponse)
async def health():

    await _async_redis.ping()
    return {"status": "ok"}


@app.post("/api/v1/scan", response_model=StartScanResponse, status_code=202)
async def start_scan(body: StartScanRequest, background_tasks: BackgroundTasks):

    scan_id = str(uuid.uuid4())
    output_dir = tempfile.mkdtemp(prefix=f"qscan_{scan_id}_")

    discover = body.discover or ("discover" in body.scan_types)

    record = {
        "scan_id": scan_id,
        "target": body.target,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "status": ScanStatus.PENDING,
        "progress": 0,
        "logs": [],
        "error": None,
        "cbom": None,
        "scan_results": None,
        "assets_data": None,
        "assets_found": 0,
        "risk_score": None,
    }

    await _async_redis.set(_scan_key(scan_id), _serialize(record))

    background_tasks.add_task(
        _run_qscan_async,
        scan_id,
        body.target,
        discover,
        output_dir,
        body.ports,
    )

    return {
        "scan_id": scan_id,
        "status": ScanStatus.PENDING,
        "message": f"Scan queued for target '{body.target}'.",
    }


@app.get("/api/v1/scan/{scan_id}", response_model=ScanStatusResponse)
async def get_scan_status(scan_id: str):

    record = await _aget_record(scan_id)

    return {
        "scan_id": scan_id,
        "status": record["status"],
        "progress": record["progress"],
        "logs": record["logs"],
        "error": record["error"],
    }


@app.get("/api/v1/scan/{scan_id}/results", response_model=ScanResultsResponse)
async def get_scan_results(scan_id: str):

    record = await _aget_record(scan_id)

    if record["status"] != ScanStatus.COMPLETED:
        raise HTTPException(
            status_code=409,
            detail="Scan not completed yet",
        )

    return {
        "scan_id": scan_id,
        "target": record["target"],
        "cbom": record["cbom"],
        "scan_results": record["scan_results"],
        "assets_found": record["assets_found"],
        "risk_score": record["risk_score"],
    }


@app.get("/api/v1/scan/{scan_id}/cbom", response_model=CbomResponse)
async def get_cbom(scan_id: str):

    record = await _aget_record(scan_id)

    if record["status"] != ScanStatus.COMPLETED:
        raise HTTPException(
            status_code=409,
            detail="Scan not completed yet",
        )

    cbom = record.get("cbom") or {}

    return {
        "metadata": cbom.get("metadata"),
        "summary": cbom.get("summary"),
        "crypto_assets": cbom.get("crypto_assets"),
        "risk_matrix": cbom.get("risk_matrix"),
        "pqc_migration_plan": cbom.get("pqc_migration_plan"),
    }


@app.post("/api/v1/hndl-risk", response_model=ComputeHNDLResponse)
async def compute_hndl(body: ComputeHNDLRequest):
    """
    Compute HNDL Mosca Inequality risk for a completed scan.

    Parameters:
    - scan_id: ID of the completed scan
    - migration_years: X parameter (default 3)
    - data_life_years: Y parameter (default 7)

    Returns: HNDL risk analysis with breach window and urgency
    """
    record = await _aget_record(body.scan_id)

    status = record["status"]
    status_val = status.value if isinstance(status, ScanStatus) else str(status)
    if status_val != ScanStatus.COMPLETED.value:
        raise HTTPException(
            status_code=409,
            detail="Scan not completed — cannot compute HNDL risk yet",
        )

    scan_results = record.get("scan_results") or []

    if not scan_results:
        raise HTTPException(
            status_code=400,
            detail="No scan results found — cannot compute HNDL risk",
        )

    # Use the first scan result (most critical asset)
    first_result = scan_results[0]

    try:
        hndl_result = compute_hndl_risk(
            scan_result=first_result,
            migration_years=body.migration_years,
            data_life_years=body.data_life_years,
        )
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"HNDL risk computation failed: {str(e)}",
        )

    return {
        "scan_id": body.scan_id,
        "hndl_risk": hndl_result,
    }


@app.get("/api/v1/history")
async def get_history():
    """
    Get scan history from Redis.
    Returns all scan records with their status and basic info.
    """
    try:
        r = _sync_redis()

        # Get all scan keys
        scan_keys = r.keys("scan:*")

        history = []

        for key in scan_keys:
            try:
                raw = r.get(key)
                if raw:
                    record = _deserialize(raw)
                    history.append({
                        "scan_id": record["scan_id"],
                        "target": record["target"],
                        "timestamp": record["timestamp"],
                        "status": record["status"].value if isinstance(record["status"], ScanStatus) else record["status"],
                        "assets_found": record.get("assets_found", 0),
                        "risk_score": record.get("risk_score"),
                    })
            except Exception:
                continue

        r.close()

        # Sort by timestamp descending (newest first)
        history.sort(key=lambda x: x["timestamp"], reverse=True)

        return history

    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Failed to retrieve scan history: {str(e)}",
        )

    

@app.delete("/api/v1/scan/{scan_id}")
async def delete_scan(scan_id: str):
    """
    Delete a scan record from Redis.
    """
    try:
        r = _sync_redis()
        r.delete(f"scan:{scan_id}")
        r.close()

        return {"message": f"Scan {scan_id} deleted successfully"}

    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Failed to delete scan: {str(e)}",
        )


# -----------------------------------------------------------
<<<<<<< HEAD
# PQC Certificate System
# -----------------------------------------------------------

_CERT_SECRET = os.environ.get("QSCAN_CERT_SECRET", "qscan-pnb-hackathon-2026-secret-key")

def _compute_cert_status(cbom):
    """
    Compute PQC certificate status from CBOM data.
    Returns (status, detected_pqc_algorithms, risk_score).
    """
    assets = cbom.get("crypto_assets", [])
    summary = cbom.get("summary", {})
    avg_risk = summary.get("average_risk_score", 100)
    pqc_dist = summary.get("pqc_status_distribution", {})
    total = summary.get("total_assets", 0)
    pqc_ready = pqc_dist.get("PQC_READY", 0)
    hybrid = pqc_dist.get("HYBRID_PQC", 0)
    critical_count = summary.get("risk_distribution", {}).get("CRITICAL", 0)

    # Collect detected PQC algorithms
    pqc_algos = set()
    for asset in assets:
        kex = asset.get("cipher_analysis", {}).get("key_exchange") or {}
        auth = asset.get("cipher_analysis", {}).get("authentication") or {}
        if kex.get("quantum_safe"):
            pqc_algos.add(kex.get("algorithm", "Unknown"))
        if auth.get("quantum_safe"):
            pqc_algos.add(auth.get("algorithm", "Unknown"))

    # Determine status
    if critical_count > 0 or avg_risk >= 80:
        status = "CRITICAL"
    elif total > 0 and pqc_ready == total:
        status = "PQC_READY"
    elif hybrid > 0 or pqc_ready > 0:
        status = "HYBRID_PQC"
    else:
        status = "MIGRATION_NEEDED"

    return status, list(pqc_algos), avg_risk


def _sign_certificate(cert_data):
    """Generate HMAC-SHA256 signature for certificate integrity."""
    payload = json.dumps({
        k: v for k, v in cert_data.items() if k != "signature"
    }, sort_keys=True)
    return hmac.new(
        _CERT_SECRET.encode(),
        payload.encode(),
        hashlib.sha256
    ).hexdigest()


@app.post("/api/v1/certificate/{scan_id}")
async def issue_certificate(scan_id: str):
    """
    Issue a PQC readiness certificate for a completed scan.
    The certificate is signed with HMAC-SHA256 and stored in Redis.
    """
    record = await _aget_record(scan_id)

    status = record["status"]
    status_val = status.value if isinstance(status, ScanStatus) else str(status)
    if status_val != ScanStatus.COMPLETED.value:
        raise HTTPException(
            status_code=409,
            detail=f"Scan not completed (status: {status_val}) — cannot issue certificate",
        )

    cbom_data = record.get("cbom")
    if not cbom_data:
        raise HTTPException(status_code=400, detail="No CBOM data found")

    status, pqc_algos, avg_risk = _compute_cert_status(cbom_data)
    cert_id = f"PQC-{uuid.uuid4().hex[:12].upper()}"
    issued_at = datetime.now(timezone.utc).isoformat()
    valid_until = datetime(
        datetime.now(timezone.utc).year,
        datetime.now(timezone.utc).month,
        datetime.now(timezone.utc).day,
        tzinfo=timezone.utc,
    )
    # 90-day validity
    from datetime import timedelta
    valid_until = (datetime.now(timezone.utc) + timedelta(days=90)).isoformat()

    # CBOM hash for tamper evidence
    cbom_hash = hashlib.sha256(
        json.dumps(cbom_data, sort_keys=True).encode()
    ).hexdigest()

    cert = {
        "certificate_id": cert_id,
        "scan_id": scan_id,
        "issued_to": record["target"],
        "status": status,
        "nist_algorithms": pqc_algos if pqc_algos else ["None detected"],
        "total_assets": cbom_data.get("summary", {}).get("total_assets", 0),
        "risk_score": round(avg_risk, 1),
        "issued_at": issued_at,
        "valid_until": valid_until,
        "cbom_hash": cbom_hash[:32],
        "issuer": "QScan Quantum Readiness Assessment Platform",
        "standard": "NIST FIPS 203/204/205",
    }

    cert["signature"] = _sign_certificate(cert)

    # Store in Redis
    try:
        r = _sync_redis()
        r.set(f"cert:{cert_id}", json.dumps(cert), ex=90 * 86400)  # 90 days TTL
        r.close()
    except Exception:
        pass  # Certificate is still valid even if Redis storage fails

    return cert


@app.get("/api/v1/verify/{cert_id}")
async def verify_certificate(cert_id: str):
    """
    Verify a PQC certificate by its ID.
    Check signature integrity and expiry.
    """
    try:
        r = _sync_redis()
        raw = r.get(f"cert:{cert_id}")
        r.close()
    except Exception:
        raise HTTPException(status_code=500, detail="Certificate store unavailable")

    if not raw:
        raise HTTPException(status_code=404, detail="Certificate not found or expired")

    cert = json.loads(raw)

    # Verify HMAC signature
    stored_sig = cert.get("signature")
    expected_sig = _sign_certificate(cert)
    sig_valid = hmac.compare_digest(stored_sig or "", expected_sig)

    # Check expiry
    valid_until = datetime.fromisoformat(cert["valid_until"])
    is_expired = datetime.now(timezone.utc) > valid_until

    return {
        "certificate": cert,
        "verification": {
            "signature_valid": sig_valid,
            "is_expired": is_expired,
            "verified_at": datetime.now(timezone.utc).isoformat(),
        }
    }
=======
# Quanta AI Chatbot (Groq-powered)
# -----------------------------------------------------------

def _build_system_prompt(scan_context: dict | None) -> str:
    """Build a system prompt for Quanta with scan report context."""
    base = (
        "You are Quanta, a friendly and knowledgeable AI assistant for QScan — "
        "a Quantum Readiness Assessment Platform. You help users understand "
        "their scan results, explain quantum computing threats to cryptography, "
        "and guide them on post-quantum migration.\n\n"
        "Personality: You are warm, approachable, and slightly playful. "
        "You explain complex quantum security concepts in simple terms. "
        "Use analogies when helpful. You refer to yourself as Quanta.\n\n"
        "Key knowledge areas:\n"
        "- Post-Quantum Cryptography (PQC) standards: FIPS 203 (ML-KEM/Kyber), "
        "FIPS 204 (ML-DSA/Dilithium), FIPS 205 (SLH-DSA/SPHINCS+)\n"
        "- Quantum threats: Shor's algorithm breaks RSA/ECC, Grover's halves symmetric key strength\n"
        "- HNDL (Harvest Now, Decrypt Later) attacks and Mosca Inequality\n"
        "- TLS/SSL protocol security and cipher suite analysis\n"
        "- NIST migration timelines (IR 8547) — deprecated by 2035\n"
        "- CBOM (Cryptographic Bill of Materials)\n\n"
        "Guidelines:\n"
        "- Always be helpful and educational\n"
        "- If asked about something outside quantum security, politely redirect\n"
        "- Use emojis sparingly for friendliness\n"
        "- Keep responses concise but thorough\n"
        "- When referencing scan data, cite specific findings\n"
    )

    if scan_context:
        base += "\n--- SCAN REPORT CONTEXT ---\n"
        base += "The user has just completed a scan. Here are the results:\n\n"

        # CBOM summary
        cbom = scan_context.get("cbom")
        if cbom:
            meta = cbom.get("metadata", {})
            summary = cbom.get("summary", {})
            base += f"Domain: {meta.get('organization_domain', 'Unknown')}\n"
            base += f"Total Assets Scanned: {summary.get('total_assets', 0)}\n"
            base += f"Average Risk Score: {summary.get('average_risk_score', 'N/A')}\n"
            base += f"Quantum Readiness: {summary.get('overall_quantum_readiness', 'Unknown')}\n"

            risk_dist = summary.get("risk_distribution", {})
            if risk_dist:
                base += f"Risk Distribution: CRITICAL={risk_dist.get('CRITICAL', 0)}, "
                base += f"HIGH={risk_dist.get('HIGH', 0)}, "
                base += f"MEDIUM={risk_dist.get('MEDIUM', 0)}, "
                base += f"LOW={risk_dist.get('LOW', 0)}, "
                base += f"SAFE={risk_dist.get('SAFE', 0)}\n"

            pqc_dist = summary.get("pqc_status_distribution", {})
            if pqc_dist:
                base += f"PQC Status: PQC_READY={pqc_dist.get('PQC_READY', 0)}, "
                base += f"MIGRATION_NEEDED={pqc_dist.get('MIGRATION_NEEDED', 0)}, "
                base += f"CRITICAL={pqc_dist.get('CRITICAL', 0)}\n"

            base += f"Forward Secrecy: {summary.get('forward_secrecy_adoption', 'N/A')}\n\n"

            # Crypto assets details
            assets = cbom.get("crypto_assets", [])
            for i, asset in enumerate(assets[:5]):  # Limit to first 5
                base += f"Asset {i+1}: {asset.get('host', '?')}:{asset.get('port', '?')}\n"
                tls = asset.get("tls_configuration", {})
                base += f"  TLS: {tls.get('protocol_version', '?')}\n"
                base += f"  Cipher: {tls.get('negotiated_cipher', '?')}\n"
                qa = asset.get("quantum_assessment", {})
                base += f"  Risk Score: {qa.get('risk_score', '?')}\n"
                base += f"  Risk Level: {qa.get('risk_level', '?')}\n"
                base += f"  PQC Status: {qa.get('pqc_status', '?')}\n"
                ta = qa.get("threat_assessment", {})
                if ta:
                    base += f"  Quantum Threat ETA: {ta.get('estimated_quantum_threat', '?')}\n"
                    base += f"  Migration Deadline: {ta.get('migration_deadline', '?')}\n"
                    base += f"  Urgency: {ta.get('urgency', '?')}\n"

                recs = asset.get("recommendations", [])
                if recs:
                    base += "  Recommendations:\n"
                    for rec in recs:
                        base += f"    - {rec.get('component', '?')}: {rec.get('current', '?')} → {rec.get('recommended', '?')} ({rec.get('nist_standard', '')})\n"
                base += "\n"

            # Migration plan
            migration = cbom.get("pqc_migration_plan", {})
            if migration:
                imm = migration.get("immediate_actions", [])
                if imm:
                    base += f"IMMEDIATE ACTIONS NEEDED: {len(imm)} items\n"
                    for a in imm[:3]:
                        base += f"  - {a.get('host', '?')}:{a.get('port', '?')} — {a.get('component', '?')}: migrate to {a.get('recommended', '?')}\n"

        # Scan results (ML scores)
        results = scan_context.get("scan_results", [])
        if results:
            base += "\nML Risk Scores:\n"
            for i, r in enumerate(results[:5]):
                ml = r.get("ml_risk_score")
                anomaly = r.get("anomaly_detection", {})
                base += f"  Asset {i+1}: ML Score={ml}, "
                base += f"Anomaly={anomaly.get('is_anomaly', False)}"
                reasons = anomaly.get("reasons", [])
                if reasons:
                    base += f" ({', '.join(reasons[:2])})"
                base += "\n"

        base += "\n--- END SCAN CONTEXT ---\n"

    return base


def _stream_groq_response(messages: list[dict]):
    """Generator that yields SSE-formatted chunks from Groq."""
    try:
        completion = groq_client.chat.completions.create(
            model=settings.GROQ_MODEL,
            messages=messages,
            temperature=0.7,
            max_completion_tokens=4096,
            top_p=0.9,
            stream=True,
            stop=None,
        )

        for chunk in completion:
            content = chunk.choices[0].delta.content
            if content:
                # SSE format
                yield f"data: {json.dumps({'content': content})}\n\n"

        yield "data: [DONE]\n\n"

    except Exception as e:
        yield f"data: {json.dumps({'error': str(e)})}\n\n"
        yield "data: [DONE]\n\n"


@app.post("/api/v1/chat")
async def chat_stream(body: ChatRequest):
    """
    Quanta AI chatbot — streams responses via SSE.
    Accepts conversation history + optional scan context.
    """
    if groq_client is None:
        raise HTTPException(
            status_code=503,
            detail="Groq client not configured. Set the GROQ_API_KEY environment variable.",
        )

    # Build messages with system prompt
    system_prompt = _build_system_prompt(body.scan_context)
    messages = [{"role": "system", "content": system_prompt}]

    for msg in body.messages:
        messages.append({"role": msg.role, "content": msg.content})

    return StreamingResponse(
        _stream_groq_response(messages),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )
>>>>>>> origin/main
