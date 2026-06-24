"""FastAPI application — Route 53 Optimizer."""
from __future__ import annotations

import secrets
from pathlib import Path
from typing import Annotated, Any

from fastapi import FastAPI, Header, HTTPException
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from api.analyzer.engine import analyze_zone
from api.analyzer.models import AnalysisSummary, ZoneAnalysis
from api.r53_client import Credentials, R53Client

app = FastAPI(
    title="Route 53 Optimizer",
    description="Analyzes Route 53 hosted zone configurations and surfaces optimization opportunities.",
    version="1.0.0",
)

STATIC_DIR = Path(__file__).parent / "static"
app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

# ── In-memory session store ────────────────────────────────────────────────────
# Maps session token → Credentials.  Cleared on server restart.
_sessions: dict[str, Credentials] = {}

SessionToken = Annotated[str | None, Header(alias="X-Session-Token")]


def _get_client(token: SessionToken, demo: bool = False) -> R53Client:
    """Resolve the correct R53Client for this request."""
    if demo:
        return R53Client(demo=True)
    if token and token in _sessions:
        return R53Client(credentials=_sessions[token])
    # No valid session and not demo — will fail if live AWS also unavailable
    return R53Client(demo=False)


# ── Frontend ──────────────────────────────────────────────────────────────────

@app.get("/", include_in_schema=False)
def index() -> FileResponse:
    return FileResponse(str(STATIC_DIR / "index.html"))


# ── Auth ──────────────────────────────────────────────────────────────────────

class AuthRequest(BaseModel):
    access_key_id: str
    secret_access_key: str
    region: str = "us-east-1"


@app.post("/api/auth")
def authenticate(body: AuthRequest) -> dict[str, Any]:
    """
    Validate AWS credentials via STS GetCallerIdentity, then issue a
    session token the frontend sends as X-Session-Token on subsequent calls.
    """
    creds = Credentials(
        access_key_id=body.access_key_id.strip(),
        secret_access_key=body.secret_access_key.strip(),
        region=body.region,
    )
    ok, error, identity = creds.validate()
    if not ok:
        raise HTTPException(status_code=401, detail=error)

    token = secrets.token_urlsafe(32)
    _sessions[token] = creds
    return {
        "token": token,
        "account_id": identity["account_id"],
        "arn": identity["arn"],
    }


@app.delete("/api/auth")
def logout(x_session_token: SessionToken = None) -> dict[str, str]:
    if x_session_token and x_session_token in _sessions:
        del _sessions[x_session_token]
    return {"status": "logged out"}


@app.get("/api/auth/status")
def auth_status(x_session_token: SessionToken = None) -> dict[str, Any]:
    """Let the frontend check whether its session token is still valid."""
    if x_session_token and x_session_token in _sessions:
        return {"valid": True, "mode": "live"}
    return {"valid": False, "mode": None}


# ── Analysis ──────────────────────────────────────────────────────────────────

@app.get("/api/analysis", response_model=AnalysisSummary)
def analyze_all_zones(
    x_session_token: SessionToken = None,
    demo: bool = False,
) -> AnalysisSummary:
    client = _get_client(x_session_token, demo=demo)
    try:
        zones = client.list_hosted_zones()
        analyses: list[ZoneAnalysis] = []
        for zone in zones:
            zone_id = zone["Id"].split("/")[-1]
            records = client.list_records(zone_id)
            analyses.append(analyze_zone(zone, records))

        return AnalysisSummary(
            zone_count=len(analyses),
            record_count=sum(a.record_count for a in analyses),
            critical_count=sum(a.critical_count for a in analyses),
            warning_count=sum(a.warning_count for a in analyses),
            info_count=sum(a.info_count for a in analyses),
            zones=analyses,
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/zones/{zone_id}/analysis", response_model=ZoneAnalysis)
def analyze_single_zone(
    zone_id: str,
    x_session_token: SessionToken = None,
    demo: bool = False,
) -> ZoneAnalysis:
    client = _get_client(x_session_token, demo=demo)
    try:
        zones = client.list_hosted_zones()
        zone = next((z for z in zones if z["Id"].split("/")[-1] == zone_id), None)
        if zone is None:
            raise HTTPException(status_code=404, detail=f"Zone {zone_id} not found")
        records = client.list_records(zone_id)
        return analyze_zone(zone, records)
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
