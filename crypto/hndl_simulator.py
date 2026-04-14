"""
QScan - HNDL (Harvest Now, Decrypt Later) Risk Simulator
Implements Mosca Inequality: X + Y > Z determines breach window
"""

from datetime import datetime
from typing import Dict
from utils.logger import get_logger

logger = get_logger(__name__)


CRQC_TIMELINES = {
    "RSA": {"years": 7, "source": "NIST IR 8547"},
    "DH": {"years": 7, "source": "NIST IR 8547"},
    "ECDHE": {"years": 9, "source": "NIST IR 8547"},
    "ECDH": {"years": 9, "source": "NIST IR 8547"},
    "ECDSA": {"years": 9, "source": "NIST IR 8547"},
    "RSA-PSS": {"years": 7, "source": "NIST IR 8547"},
    "RSA-2048": {"years": 7, "source": "NIST IR 8547"},
    "RSA-4096": {"years": 8, "source": "NIST IR 8547"},
    "DHE": {"years": 7, "source": "NIST IR 8547"},
    "X25519": {"years": 9, "source": "NIST IR 8547"},
    "P-256": {"years": 9, "source": "NIST IR 8547"},
    "P-384": {"years": 9, "source": "NIST IR 8547"},
}

PQC_SAFE_ALGORITHMS = {"ML-KEM", "ML-DSA", "KYBER", "DILITHIUM", "SLH-DSA", "FN-DSA", "FALCON"}


def compute_hndl_risk(
    scan_result: dict,
    migration_years: int = 3,
    data_life_years: int = 7,
    daily_sessions: int = 50_000
) -> Dict:
    """
    Compute the HNDL (Harvest Now, Decrypt Later) risk using the Mosca Inequality.
    
    Mosca Inequality: X + Y > Z
    - X = migration lead-time in years (default: 3)
    - Y = data confidentiality shelf-life in years (default: 7 for RBI banking mandate)
    - Z = years until a CRQC can break the detected algorithm (NIST IR 8547)
    - If X + Y > Z → breach window is OPEN → urgency = IMMEDIATE
    
    If the detected algorithm is in PQC_SAFE_ALGORITHMS, returns early with urgency=NONE
    and no breach window (the asset is quantum-safe).
    
    Args:
        scan_result: dict containing cipher_analysis.key_exchange.algorithm
        migration_years: X parameter (default 3)
        data_life_years: Y parameter (default 7)
        daily_sessions: Estimated sessions per day for risk calculations (default 50,000)
    
    Returns:
        dict with mosca_breach, urgency, breach_window_year, sessions_at_risk, data_at_risk_gb
    """
    try:
        # Extract algorithm with safe fallback
        alg = (
            scan_result
            .get("cipher_analysis", {})
            .get("key_exchange", {})
            .get("algorithm", "RSA")
        )
        
        if not alg:
            alg = "RSA"
    except Exception as e:
        logger.warning(f"Failed to extract algorithm from scan_result: {e}")
        alg = "RSA"

    # Short-circuit for PQC-safe algorithms
    if alg.upper() in PQC_SAFE_ALGORITHMS:
        logger.debug(f"HNDL Analysis: {alg} is PQC-safe, skipping Mosca calculation")
        return {
            "mosca_breach": False,
            "urgency": "NONE",
            "algorithm_assessed": alg,
            "crqc_timeline_years": None,
            "crqc_source": "N/A — PQC-safe algorithm",
            "migration_years_x": migration_years,
            "data_life_years_y": data_life_years,
            "mosca_sum": None,
            "breach_window_year": None,
            "current_year": datetime.now().year,
            "years_until_breach": None,
            "daily_sessions_assumed": daily_sessions,
            "sessions_at_risk": 0,
            "data_at_risk_gb": 0.0,
            "recommendation": (
                f"{alg} is a NIST-standardised PQC algorithm. "
                "This asset is quantum-safe. No migration needed."
            ),
        }

    # Get CRQC timeline for this algorithm
    crqc_info = CRQC_TIMELINES.get(
        alg.upper(),
        {"years": 10, "source": "Conservative estimate"}
    )
    
    Z = crqc_info["years"]
    X = migration_years
    Y = data_life_years

    # Mosca Inequality check: is breach window open?
    mosca_breach = (X + Y) > Z
    
    # Calculate when breach window opens (current year + years remaining)
    current_year = datetime.now().year
    breach_window_year = current_year + max(0, Z - X - Y)

    # Session/data at risk calculations
    # Assumption: ~daily_sessions sessions/day * 365 days * X years
    sessions_at_risk = daily_sessions * 365 * X
    # Assumption: ~1KB per session = 0.001 GB per session
    data_at_risk_gb = round(daily_sessions * 365 * X * 0.001, 1)

    # Generate recommendation based on breach status
    if mosca_breach:
        recommendation = (
            "Migrate immediately — adversaries can already be harvesting encrypted sessions."
        )
    else:
        recommendation = (
            f"Begin PQC migration planning. Breach window opens around {breach_window_year}."
        )

    result = {
        "mosca_breach": mosca_breach,
        "urgency": "IMMEDIATE" if mosca_breach else "PLANNED",
        "algorithm_assessed": alg,
        "crqc_timeline_years": Z,
        "crqc_source": crqc_info["source"],
        "migration_years_x": X,
        "data_life_years_y": Y,
        "mosca_sum": X + Y,
        "breach_window_year": breach_window_year,
        "current_year": current_year,
        "years_until_breach": max(0, breach_window_year - current_year),
        "daily_sessions_assumed": daily_sessions,
        "sessions_at_risk": sessions_at_risk,
        "data_at_risk_gb": data_at_risk_gb,
        "recommendation": recommendation,
    }

    logger.debug(
        f"HNDL Analysis: {alg} | Breach: {mosca_breach} | "
        f"X({X}) + Y({Y}) > Z({Z}) = {X + Y} > {Z}"
    )

    return result
