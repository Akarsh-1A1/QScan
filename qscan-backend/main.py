import asyncio
import json
import os
import sys
import shutil
import subprocess
import tempfile
import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional
from contextlib import asynccontextmanager

# ── Backend-local config (must import before adding parent to sys.path) ──
from config import settings

# ── Fix import path so ai_ml, crypto, utils are visible from backend ──
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import redis
import redis.asyncio as aioredis

from fastapi import BackgroundTasks, FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from ai_ml.risk_scoring_model import RiskScoringModel
from ai_ml.anomaly_detection import CryptoAnomalyDetector
from crypto.hndl_simulator import compute_hndl_risk


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

    if record["status"] != ScanStatus.COMPLETED:
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
