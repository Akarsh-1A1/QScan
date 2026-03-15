import asyncio
import json
import os
import shutil
import subprocess
import tempfile
import uuid
from datetime import datetime, timezone

from enum import Enum
from typing import Any, Optional

from fastapi import BackgroundTasks, FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel


# -----------------------------------------------------------
# Fix Windows encoding issues
# -----------------------------------------------------------
os.environ["PYTHONUTF8"] = "1"


# -----------------------------------------------------------
# App setup
# -----------------------------------------------------------

app = FastAPI(title="QScan API", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


# -----------------------------------------------------------
# In-memory store
# -----------------------------------------------------------

scans: dict[str, dict] = {}


# -----------------------------------------------------------
# Enums & schemas
# -----------------------------------------------------------

class ScanStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


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


class HistoryItem(BaseModel):
    scan_id: str
    target: str
    timestamp: str
    assets_found: int
    risk_score: Optional[float]
    status: ScanStatus


class DeleteResponse(BaseModel):
    message: str


class HealthResponse(BaseModel):
    status: str


# -----------------------------------------------------------
# Background worker
# -----------------------------------------------------------

def _append_log(scan_id: str, line: str) -> None:
    scans[scan_id]["logs"].append(
        f"[{datetime.now(timezone.utc).isoformat()}] {line}"
    )


def _run_qscan(scan_id: str, target: str, discover: bool, output_dir: str) -> None:
    record = scans[scan_id]
    record["status"] = ScanStatus.RUNNING
    record["progress"] = 10

    cmd = ["qscan", "--domain", target, "--output", output_dir]

    if discover:
        cmd.append("--discover")

    cmd.append("--cbom")

    _append_log(scan_id, f"Running: {' '.join(cmd)}")

    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=300,
        )

        if proc.stdout:
            for line in proc.stdout.splitlines():
                _append_log(scan_id, line)

        if proc.stderr:
            for line in proc.stderr.splitlines():
                _append_log(scan_id, f"[stderr] {line}")

        record["progress"] = 70

        if proc.returncode != 0:
            raise RuntimeError(f"qscan exited with code {proc.returncode}")

        # ---------------------------------------------------
        # Parse outputs
        # ---------------------------------------------------

        cbom_path = os.path.join(output_dir, "cbom.json")
        results_path = os.path.join(output_dir, "scan_results.json")
        assets_path = os.path.join(output_dir, "discovered_assets.json")

        cbom_data = _read_json(cbom_path)
        results_data = _read_json(results_path)

        assets_data = (
            _read_json(assets_path)
            if os.path.exists(assets_path)
            else None
        )

        record["cbom"] = cbom_data
        record["scan_results"] = (
            results_data
            if isinstance(results_data, list)
            else [results_data]
        )

        record["assets_data"] = assets_data

        if isinstance(results_data, list) and results_data:
            record["risk_score"] = results_data[0].get(
                "quantum_risk_score"
            )
        elif cbom_data:
            record["risk_score"] = cbom_data.get(
                "summary", {}
            ).get("average_risk_score")
        else:
            record["risk_score"] = None

        total = 0

        if cbom_data:
            total = cbom_data.get(
                "metadata", {}
            ).get("total_assets_scanned", 0)

        record["assets_found"] = total

        record["progress"] = 100
        record["status"] = ScanStatus.COMPLETED

        _append_log(scan_id, "Scan completed successfully.")

    except subprocess.TimeoutExpired:

        record["status"] = ScanStatus.FAILED
        record["error"] = "qscan timed out after 300 seconds."

        _append_log(scan_id, record["error"])

    except Exception as exc:

        record["status"] = ScanStatus.FAILED
        record["error"] = str(exc)

        _append_log(scan_id, f"Error: {exc}")

    finally:

        record["output_dir"] = output_dir


def _read_json(path: str) -> Any:
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)


async def _run_qscan_async(scan_id: str, target: str, discover: bool, output_dir: str):
    await asyncio.to_thread(_run_qscan, scan_id, target, discover, output_dir)


# -----------------------------------------------------------
# Routes
# -----------------------------------------------------------

@app.get("/api/v1/health", response_model=HealthResponse)
def health():
    return {"status": "ok"}


@app.post("/api/v1/scan", response_model=StartScanResponse, status_code=202)
async def start_scan(body: StartScanRequest, background_tasks: BackgroundTasks):

    scan_id = str(uuid.uuid4())
    output_dir = tempfile.mkdtemp(prefix=f"qscan_{scan_id}_")

    discover = body.discover or ("discover" in body.scan_types)

    scans[scan_id] = {
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
        "output_dir": output_dir,
    }

    background_tasks.add_task(
        _run_qscan_async,
        scan_id,
        body.target,
        discover,
        output_dir,
    )

    return {
        "scan_id": scan_id,
        "status": ScanStatus.PENDING,
        "message": f"Scan queued for target '{body.target}'.",
    }


@app.get("/api/v1/scan/{scan_id}", response_model=ScanStatusResponse)
def get_scan_status(scan_id: str):

    record = _get_record(scan_id)

    return {
        "scan_id": scan_id,
        "status": record["status"],
        "progress": record["progress"],
        "logs": record["logs"],
        "error": record["error"],
    }


@app.get("/api/v1/scan/{scan_id}/results", response_model=ScanResultsResponse)
def get_scan_results(scan_id: str):

    record = _get_record(scan_id)

    _require_completed(record)

    return {
        "scan_id": scan_id,
        "target": record["target"],
        "cbom": record["cbom"],
        "scan_results": record["scan_results"],
        "assets_found": record["assets_found"],
        "risk_score": record["risk_score"],
    }


@app.get("/api/v1/scan/{scan_id}/cbom")
def get_cbom(scan_id: str):

    record = _get_record(scan_id)

    _require_completed(record)

    return record["cbom"]


@app.get("/api/v1/history", response_model=list[HistoryItem])
def get_history():

    return [
        {
            "scan_id": r["scan_id"],
            "target": r["target"],
            "timestamp": r["timestamp"],
            "assets_found": r["assets_found"],
            "risk_score": r["risk_score"],
            "status": r["status"],
        }
        for r in scans.values()
    ]


@app.delete("/api/v1/scan/{scan_id}", response_model=DeleteResponse)
def delete_scan(scan_id: str):

    record = _get_record(scan_id)

    output_dir = record.get("output_dir")

    if output_dir and os.path.isdir(output_dir):
        shutil.rmtree(output_dir, ignore_errors=True)

    del scans[scan_id]

    return {"message": f"Scan {scan_id} deleted."}


# -----------------------------------------------------------
# Helpers
# -----------------------------------------------------------

def _get_record(scan_id: str):

    if scan_id not in scans:
        raise HTTPException(
            status_code=404,
            detail=f"Scan '{scan_id}' not found.",
        )

    return scans[scan_id]


def _require_completed(record: dict):

    if record["status"] != ScanStatus.COMPLETED:
        raise HTTPException(
            status_code=409,
            detail=f"Scan is not completed yet (status: {record['status']}).",
        )


# -----------------------------------------------------------
# Entry point
# -----------------------------------------------------------

if __name__ == "__main__":

    import uvicorn

    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=8000,
        reload=True,
    )