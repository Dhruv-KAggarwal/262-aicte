from __future__ import annotations

import base64
import csv
import hashlib
import hmac
import io
import json
import os
import secrets
import sqlite3
import uuid
from contextlib import asynccontextmanager
from datetime import date, datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from fastapi import Depends, FastAPI, File, Form, HTTPException, Request, Response, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, Field

ROOT = Path(__file__).resolve().parents[1]
DB_PATH = Path(os.getenv("DATABASE_PATH", str(ROOT / "data" / "aicte_demo.db")))
UPLOAD_DIR = Path(os.getenv("UPLOAD_DIR", str(ROOT / "private_uploads")))
SECRET = os.getenv("APP_SECRET", "local-demo-only-change-before-deployment")
ALLOWED_UPLOADS = {".pdf", ".png", ".jpg", ".jpeg"}
security = HTTPBearer(auto_error=False)

@asynccontextmanager
async def lifespan(_: FastAPI):
    seed()
    yield


app = FastAPI(
    title="AICTE Approval Operations API",
    version="0.1.0",
    description="Synthetic demonstration API. Not connected to AICTE systems.",
    lifespan=lifespan,
)
app.add_middleware(
    CORSMiddleware,
    allow_origins=[os.getenv("FRONTEND_ORIGIN", "http://localhost:3000")],
    allow_credentials=True,
    allow_methods=["GET", "POST"],
    allow_headers=["Authorization", "Content-Type"],
)

MIGRATIONS_DIR = ROOT / "migrations"


def now_utc() -> datetime:
    return datetime.now(timezone.utc)


def iso(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat(timespec="seconds")


def get_db() -> sqlite3.Connection:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH, timeout=10)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA journal_mode = WAL")
    return conn


def apply_migrations(db: sqlite3.Connection) -> None:
    db.execute(
        "CREATE TABLE IF NOT EXISTS schema_migrations (version TEXT PRIMARY KEY, applied_at TEXT NOT NULL)"
    )
    applied = {row["version"] for row in db.execute("SELECT version FROM schema_migrations")}
    for migration in sorted(MIGRATIONS_DIR.glob("*.sql")):
        if migration.stem in applied:
            continue
        db.executescript(migration.read_text(encoding="utf-8"))
        db.execute(
            "INSERT INTO schema_migrations(version,applied_at) VALUES(?,?)",
            (migration.stem, iso(now_utc())),
        )
    db.commit()


def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 240_000)
    return f"{base64.urlsafe_b64encode(salt).decode()}:{base64.urlsafe_b64encode(digest).decode()}"


def verify_password(password: str, encoded: str) -> bool:
    try:
        salt_text, digest_text = encoded.split(":", 1)
        salt = base64.urlsafe_b64decode(salt_text.encode())
        expected = base64.urlsafe_b64decode(digest_text.encode())
        actual = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 240_000)
        return hmac.compare_digest(actual, expected)
    except (ValueError, TypeError):
        return False


def create_token(user: sqlite3.Row) -> str:
    expires = int((now_utc() + timedelta(hours=8)).timestamp())
    payload = base64.urlsafe_b64encode(
        json.dumps({"sub": user["id"], "exp": expires}, separators=(",", ":")).encode()
    ).decode().rstrip("=")
    signature = hmac.new(SECRET.encode(), payload.encode(), hashlib.sha256).hexdigest()
    return f"{payload}.{signature}"


def token_user(token: str) -> dict[str, Any]:
    try:
        payload, signature = token.split(".", 1)
        expected = hmac.new(SECRET.encode(), payload.encode(), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(signature, expected):
            raise ValueError("signature")
        data = json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))
        if int(data["exp"]) < int(now_utc().timestamp()):
            raise ValueError("expired")
        with get_db() as db:
            row = db.execute(
                "SELECT id, name, email, role, region_id, institution_id FROM users WHERE id=?",
                (data["sub"],),
            ).fetchone()
        if row is None:
            raise ValueError("user")
        return dict(row)
    except (ValueError, KeyError, TypeError, json.JSONDecodeError):
        raise HTTPException(status_code=401, detail="Invalid or expired session") from None


def current_user(
    request: Request,
    credentials: HTTPAuthorizationCredentials | None = Depends(security),
) -> dict[str, Any]:
    token = credentials.credentials if credentials else request.cookies.get("aicte_session")
    if not token:
        raise HTTPException(status_code=401, detail="Authentication required")
    return token_user(token)


def require_roles(*roles: str):
    def dependency(user: dict[str, Any] = Depends(current_user)) -> dict[str, Any]:
        if user["role"] not in roles:
            raise HTTPException(status_code=403, detail="This action is not permitted for your role")
        return user
    return dependency


def audit(
    db: sqlite3.Connection, actor: str, action: str, entity_type: str, entity_id: str,
    reason: str = "", previous: Any = None, new: Any = None,
) -> None:
    db.execute(
        """INSERT INTO audit_events
        (id,actor_id,action,entity_type,entity_id,reason,previous_state,new_state,created_at)
        VALUES(?,?,?,?,?,?,?,?,?)""",
        (
            str(uuid.uuid4()), actor, action, entity_type, entity_id, reason,
            json.dumps(previous, default=str) if previous is not None else None,
            json.dumps(new, default=str) if new is not None else None, iso(now_utc()),
        ),
    )


def visible_application(user: dict[str, Any], row: sqlite3.Row) -> bool:
    if user["role"] == "institution":
        return row["institution_id"] == user["institution_id"]
    if user["role"] == "regional_officer":
        with get_db() as db:
            inst = db.execute("SELECT region FROM institutions WHERE id=?", (row["institution_id"],)).fetchone()
        return bool(inst and inst["region"] == user["region_id"])
    if user["role"] in {"scrutiny_officer", "evc_member"}:
        return row["assigned_to"] == user["id"]
    return user["role"] in {"super_admin", "central_officer"}


def serialize_application(db: sqlite3.Connection, row: sqlite3.Row) -> dict[str, Any]:
    institution = db.execute("SELECT * FROM institutions WHERE id=?", (row["institution_id"],)).fetchone()
    assignee = db.execute("SELECT name FROM users WHERE id=?", (row["assigned_to"],)).fetchone() if row["assigned_to"] else None
    return {
        **dict(row),
        "institution_name": institution["name"] if institution else "Unknown institution",
        "region": institution["region"] if institution else None,
        "assignee": assignee["name"] if assignee else "Unassigned",
    }


def seed() -> None:
    with get_db() as db:
        apply_migrations(db)
        has_seed_data = db.execute("SELECT COUNT(*) FROM users").fetchone()[0] > 0
        users = [
            ("u-admin", "Aarav Mehta", "admin@demo.aicte.local", "super_admin", None, None),
            ("u-central", "Kavya Rao", "central@demo.aicte.local", "central_officer", None, None),
            ("u-north", "Rohan Verma", "north@demo.aicte.local", "regional_officer", "Northern Region", None),
            ("u-scrutiny", "Isha Nair", "scrutiny@demo.aicte.local", "scrutiny_officer", "Northern Region", None),
            ("u-scrutiny-west", "Mira Desai", "west.scrutiny@demo.aicte.local", "scrutiny_officer", "Western Region", None),
            ("u-evc", "Dev Patel", "evc@demo.aicte.local", "evc_member", "Northern Region", None),
            ("u-inst", "Ananya Sharma", "institution@demo.aicte.local", "institution", None, "inst-001"),
        ]
        for ident, name, email, role, region, institution in users:
            if not db.execute("SELECT 1 FROM users WHERE id=?", (ident,)).fetchone():
                db.execute(
                    "INSERT INTO users VALUES(?,?,?,?,?,?,?)",
                    (ident, name, email, hash_password("DemoPass!2026"), role, region, institution),
                )
        if has_seed_data:
            db.commit()
            return
        insts = [
            ("inst-001", "North Valley Institute of Technology", "NVI-2048", "Northern Region", "Dehradun", "Active"),
            ("inst-002", "Saraswati College of Engineering", "SCE-1192", "Northern Region", "Jaipur", "Active"),
            ("inst-003", "Coastal School of Applied Sciences", "CSA-3864", "Western Region", "Pune", "Active"),
        ]
        db.executemany("INSERT INTO institutions VALUES(?,?,?,?,?,?)", insts)
        today = now_utc()
        apps = [
            ("app-001", "inst-001", "AICTE/2026/NVI/0142", "Extension of Approval", "2026-27", "Scrutiny", "In review", today-timedelta(days=2), today+timedelta(days=3), "u-scrutiny", 2, "Renewal package submitted; land lease evidence requires review."),
            ("app-002", "inst-002", "AICTE/2026/SCE/0098", "New Institution", "2026-27", "EVC", "Scheduled", today-timedelta(days=8), today+timedelta(days=5), "u-evc", 1, "Initial application passed document screening."),
            ("app-003", "inst-001", "AICTE/2026/NVI/0117", "Increase in Intake", "2026-27", "Correction", "Returned", today-timedelta(days=14), today-timedelta(days=1), "u-scrutiny", 2, "Clarification requested on faculty appointment records."),
            ("app-004", "inst-003", "AICTE/2026/CSA/0221", "Extension of Approval", "2026-27", "Committee review", "Pending", today-timedelta(days=20), today+timedelta(days=9), "u-central", 1, "Expert visit report received; committee recommendation pending."),
            ("app-005", "inst-001", "AICTE/2026/NVI/0196", "New Programme", "2026-27", "Completed", "Completed", today-timedelta(days=25), today-timedelta(days=3), "u-central", 1, "Application completed in demonstration workflow."),
        ]
        workflow_ids = {
            "app-001": "wf-evc-v1",
            "app-002": "wf-evc-v1",
            "app-003": "wf-evc-v1",
            "app-004": "wf-standard-v1",
            "app-005": "wf-direct-v1",
        }
        for approw in apps:
            db.execute(
                """INSERT INTO applications
                (id,institution_id,reference,application_type,cycle,stage,status,submitted_at,due_at,
                 assigned_to,workflow_version,summary,updated_at,workflow_version_id)
                VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (*approw[:7], iso(approw[7]), iso(approw[8]), *approw[9:], iso(today), workflow_ids[approw[0]]),
            )
        obligations = [
            ("obl-001", "inst-001", "app-001", "Submit updated land lease deed", today+timedelta(days=4), "Awaiting submission", "u-north"),
            ("obl-002", "inst-001", "app-003", "Faculty qualification evidence", today-timedelta(days=2), "Overdue", "u-scrutiny"),
            ("obl-003", "inst-002", "app-002", "Upload fire safety certificate", today+timedelta(days=12), "Under verification", "u-north"),
            ("obl-004", "inst-003", "app-004", "Annual compliance undertaking", today+timedelta(days=24), "Upcoming", "u-central"),
        ]
        for ob in obligations:
            db.execute(
                """INSERT INTO compliance_obligations
                (id,institution_id,application_id,title,due_at,status,assigned_to,updated_at)
                VALUES(?,?,?,?,?,?,?,?)""",
                (*ob[:4], iso(ob[4]), *ob[5:], iso(today)),
            )
        docs = [
            ("doc-001", "inst-001", "Land lease deed", "lease-deed-2026.pdf", today+timedelta(days=17), "Verified"),
            ("doc-002", "inst-001", "Fire safety certificate", "fire-safety-certificate.pdf", today+timedelta(days=75), "Verified"),
            ("doc-003", "inst-002", "Building completion certificate", "building-completion.pdf", today-timedelta(days=6), "Action required"),
            ("doc-004", "inst-003", "Occupancy certificate", "occupancy-certificate.pdf", today+timedelta(days=184), "Under verification"),
        ]
        for doc in docs:
            db.execute(
                """INSERT INTO institutional_documents
                (id,institution_id,category,file_name,expires_at,status,storage_key,uploaded_at)
                VALUES(?,?,?,?,?,?,?,?)""",
                (*doc[:4], iso(doc[4]), *doc[5:], f"synthetic/{doc[0]}", iso(today)),
            )
        db.execute(
            "INSERT INTO evc_events VALUES(?,?,?,?,?,?,?,?)",
            ("evc-001", "app-002", iso(today+timedelta(days=3)), "Jaipur, Rajasthan", "Committee North-04", "Scheduled", "u-north", "Initial scheduled visit (synthetic)."),
        )
        for item in apps:
            db.execute(
                """INSERT INTO stage_events VALUES(?,?,?,?,?,?,?,?)""",
                (str(uuid.uuid4()), item[0], None, item[5], "Application seeded", "Synthetic demonstration record", "u-admin", iso(today)),
            )
        db.commit()


class LoginRequest(BaseModel):
    email: str
    password: str


class TransitionRequest(BaseModel):
    action: str
    reason: str = Field(min_length=5, max_length=1000)


class CreateApplication(BaseModel):
    institution_id: str
    application_type: str = Field(min_length=3, max_length=120)
    cycle: str = Field(min_length=4, max_length=20)
    workflow_version_id: str
    summary: str = Field(default="", max_length=2000)


class ComplianceDecision(BaseModel):
    status: str
    reason: str = Field(min_length=5, max_length=1000)


class ComplianceSubmission(BaseModel):
    evidence_name: str = Field(min_length=1, max_length=255)
    submission_note: str = Field(default="", max_length=1000)


class EvcSchedule(BaseModel):
    application_id: str
    scheduled_at: datetime
    location: str = Field(min_length=3, max_length=300)
    committee: str = Field(min_length=3, max_length=200)
    reason: str = Field(min_length=5, max_length=1000)


class WorkflowVersionCreate(BaseModel):
    stages: list[str] = Field(min_length=2, max_length=4)


class EscalationResolution(BaseModel):
    reason: str = Field(min_length=5, max_length=1000)


@app.get("/api/health")
def health() -> dict[str, str]:
    return {"status": "ok", "mode": "synthetic-demo"}


@app.post("/api/auth/login")
def login(payload: LoginRequest, response: Response) -> dict[str, Any]:
    with get_db() as db:
        user = db.execute("SELECT * FROM users WHERE email=?", (payload.email.lower().strip(),)).fetchone()
        if not user or not verify_password(payload.password, user["password_hash"]):
            raise HTTPException(status_code=401, detail="Email or password is incorrect")
        response.set_cookie(
            "aicte_session",
            create_token(user),
            httponly=True,
            secure=os.getenv("SECURE_COOKIE", "false").lower() == "true",
            samesite="lax",
            max_age=8 * 60 * 60,
            path="/",
        )
        return {"user": {k: user[k] for k in ("id", "name", "email", "role", "region_id", "institution_id")}}


@app.post("/api/auth/logout")
def logout(response: Response) -> dict[str, str]:
    response.delete_cookie("aicte_session", httponly=True, samesite="lax", path="/")
    return {"status": "signed out"}


@app.get("/api/auth/me")
def me(user: dict[str, Any] = Depends(current_user)) -> dict[str, Any]:
    return user


@app.get("/api/dashboard")
def dashboard(user: dict[str, Any] = Depends(current_user)) -> dict[str, Any]:
    with get_db() as db:
        rows = db.execute("SELECT * FROM applications ORDER BY submitted_at DESC").fetchall()
        apps = [serialize_application(db, row) for row in rows if visible_application(user, row)]
        if user["role"] == "institution":
            obligations = db.execute("SELECT * FROM compliance_obligations WHERE institution_id=?", (user["institution_id"],)).fetchall()
            documents = db.execute("SELECT * FROM institutional_documents WHERE institution_id=?", (user["institution_id"],)).fetchall()
        elif user["role"] == "regional_officer":
            obligations = db.execute(
                """SELECT o.* FROM compliance_obligations o JOIN institutions i ON i.id=o.institution_id
                WHERE i.region=?""", (user["region_id"],)
            ).fetchall()
            documents = db.execute(
                """SELECT d.* FROM institutional_documents d JOIN institutions i ON i.id=d.institution_id
                WHERE i.region=?""", (user["region_id"],)
            ).fetchall()
        elif user["role"] in {"scrutiny_officer", "evc_member"}:
            obligations = db.execute(
                """SELECT o.* FROM compliance_obligations o WHERE o.institution_id IN
                (SELECT institution_id FROM applications WHERE assigned_to=?)""", (user["id"],)
            ).fetchall()
            documents = db.execute(
                """SELECT d.* FROM institutional_documents d WHERE d.institution_id IN
                (SELECT institution_id FROM applications WHERE assigned_to=?)""", (user["id"],)
            ).fetchall()
        else:
            obligations = db.execute("SELECT * FROM compliance_obligations").fetchall()
            documents = db.execute("SELECT * FROM institutional_documents").fetchall()
        stages: dict[str, int] = {}
        for item in apps:
            stages[item["stage"]] = stages.get(item["stage"], 0) + 1
        today = now_utc().date()
        expiring = sum(1 for row in documents if row["expires_at"] and today <= datetime.fromisoformat(row["expires_at"]).date() <= today + timedelta(days=90))
        overdue = sum(1 for row in apps if datetime.fromisoformat(row["due_at"]).date() < today and row["stage"] != "Completed")
        return {
            "refreshed_at": iso(now_utc()),
            "counts": {
                "total_applications": len(apps),
                "in_progress": sum(1 for row in apps if row["stage"] != "Completed"),
                "awaiting_scrutiny": stages.get("Scrutiny", 0),
                "awaiting_evc": stages.get("EVC", 0),
                "returned": stages.get("Correction", 0),
                "overdue": overdue,
                "obligations_due_soon": sum(1 for row in obligations if today <= datetime.fromisoformat(row["due_at"]).date() <= today + timedelta(days=7)),
                "documents_expiring": expiring,
            },
            "stage_distribution": [{"stage": key, "count": value} for key, value in stages.items()],
            "applications": apps[:5],
        }


@app.get("/api/applications")
def applications(user: dict[str, Any] = Depends(current_user), q: str = "", stage: str = "") -> list[dict[str, Any]]:
    with get_db() as db:
        rows = db.execute("SELECT * FROM applications ORDER BY submitted_at DESC").fetchall()
        result = [serialize_application(db, row) for row in rows if visible_application(user, row)]
        if stage:
            result = [item for item in result if item["stage"].lower() == stage.lower()]
        if q:
            text = q.lower()
            result = [item for item in result if text in item["reference"].lower() or text in item["institution_name"].lower()]
        return result


@app.get("/api/workflows/templates")
def workflow_templates(user: dict[str, Any] = Depends(current_user)) -> list[dict[str, Any]]:
    with get_db() as db:
        rows = db.execute(
            """SELECT t.id AS template_id,t.name,t.description,v.id AS workflow_version_id,
            v.version,v.stages_json FROM workflow_templates t JOIN workflow_versions v
            ON v.id=t.active_version_id WHERE v.status='Published' ORDER BY t.name"""
        ).fetchall()
        return [
            {**dict(row), "stages": json.loads(row["stages_json"])}
            for row in rows
        ]


@app.get("/api/workflows")
def list_workflows(user: dict[str, Any] = Depends(require_roles("super_admin"))) -> list[dict[str, Any]]:
    with get_db() as db:
        rows = db.execute(
            """SELECT v.*,t.name AS template_name,t.active_version_id FROM workflow_versions v
            JOIN workflow_templates t ON t.id=v.template_id ORDER BY t.name,v.version DESC"""
        ).fetchall()
        return [{**dict(row), "stages": json.loads(row["stages_json"])} for row in rows]


@app.post("/api/workflows/{template_id}/versions", status_code=201)
def create_workflow_version(
    template_id: str,
    payload: WorkflowVersionCreate,
    user: dict[str, Any] = Depends(require_roles("super_admin")),
) -> dict[str, Any]:
    allowed = ["Scrutiny", "EVC", "Committee review", "Completed"]
    if payload.stages[0] != "Scrutiny" or payload.stages[-1] != "Completed":
        raise HTTPException(status_code=422, detail="A route must begin with Scrutiny and end with Completed")
    if len(set(payload.stages)) != len(payload.stages) or any(stage not in allowed for stage in payload.stages):
        raise HTTPException(status_code=422, detail="Route contains duplicate or unsupported stages")
    if payload.stages != [stage for stage in allowed if stage in payload.stages]:
        raise HTTPException(status_code=422, detail="Stages must follow the supported configured order")
    with get_db() as db:
        template = db.execute("SELECT * FROM workflow_templates WHERE id=?", (template_id,)).fetchone()
        if not template:
            raise HTTPException(status_code=404, detail="Workflow template not found")
        version = db.execute("SELECT COALESCE(MAX(version),0)+1 FROM workflow_versions WHERE template_id=?", (template_id,)).fetchone()[0]
        ident = str(uuid.uuid4())
        created = iso(now_utc())
        db.execute(
            """INSERT INTO workflow_versions
            (id,template_id,version,stages_json,status,created_by,created_at)
            VALUES(?,?,?,?,?,?,?)""",
            (ident, template_id, version, json.dumps(payload.stages), "Draft", user["id"], created),
        )
        audit(db, user["id"], "Workflow version drafted", "workflow_version", ident, "Administrator created a validated draft route", None, {"version": version, "stages": payload.stages})
        db.commit()
        return {"id": ident, "template_id": template_id, "template_name": template["name"], "version": version, "stages": payload.stages, "status": "Draft", "created_at": created}


@app.post("/api/workflow-versions/{version_id}/publish")
def publish_workflow_version(
    version_id: str,
    user: dict[str, Any] = Depends(require_roles("super_admin")),
) -> dict[str, Any]:
    with get_db() as db:
        row = db.execute(
            "SELECT * FROM workflow_versions WHERE id=?", (version_id,)
        ).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Workflow version not found")
        if row["status"] != "Draft":
            raise HTTPException(status_code=409, detail="Only a draft workflow version can be published")
        stages = json.loads(row["stages_json"])
        if stages[0] != "Scrutiny" or stages[-1] != "Completed":
            raise HTTPException(status_code=422, detail="Workflow validation failed")
        old_version = db.execute(
            "SELECT active_version_id FROM workflow_templates WHERE id=?", (row["template_id"],)
        ).fetchone()["active_version_id"]
        published = iso(now_utc())
        if old_version:
            db.execute("UPDATE workflow_versions SET status='Superseded' WHERE id=?", (old_version,))
        db.execute(
            "UPDATE workflow_versions SET status='Published',published_at=? WHERE id=?",
            (published, version_id),
        )
        db.execute(
            "UPDATE workflow_templates SET active_version_id=? WHERE id=?",
            (version_id, row["template_id"]),
        )
        audit(db, user["id"], "Workflow version published", "workflow_version", version_id, "Validated draft published for new applications", {"active_version_id": old_version}, {"active_version_id": version_id, "stages": stages})
        db.commit()
        return {"id": version_id, "version": row["version"], "status": "Published", "published_at": published, "stages": stages}


@app.post("/api/applications", status_code=201)
def create_application(payload: CreateApplication, user: dict[str, Any] = Depends(require_roles("super_admin", "central_officer", "regional_officer", "institution"))) -> dict[str, Any]:
    with get_db() as db:
        inst = db.execute("SELECT * FROM institutions WHERE id=?", (payload.institution_id,)).fetchone()
        if not inst or (user["role"] == "institution" and user["institution_id"] != payload.institution_id):
            raise HTTPException(status_code=404, detail="Institution not found in your authorised scope")
        if user["role"] == "regional_officer" and inst["region"] != user["region_id"]:
            raise HTTPException(status_code=403, detail="Institution is outside your region")
        assignee = db.execute(
            "SELECT id FROM users WHERE role='scrutiny_officer' AND region_id=? ORDER BY id LIMIT 1",
            (inst["region"],),
        ).fetchone()
        if not assignee:
            assignee = db.execute(
                "SELECT id FROM users WHERE role='regional_officer' AND region_id=? ORDER BY id LIMIT 1",
                (inst["region"],),
            ).fetchone()
        if not assignee:
            assignee = db.execute("SELECT id FROM users WHERE role='central_officer' ORDER BY id LIMIT 1").fetchone()
        if not assignee:
            raise HTTPException(status_code=409, detail="No authorised initial assignee is configured")
        workflow = db.execute(
            """SELECT * FROM workflow_versions WHERE id=? AND status='Published'""",
            (payload.workflow_version_id,),
        ).fetchone()
        if not workflow:
            raise HTTPException(status_code=422, detail="Select a currently published workflow route")
        ident = str(uuid.uuid4())
        reference = f"AICTE/DEMO/{now_utc().year}/{ident[:8].upper()}"
        deadline = iso(now_utc() + timedelta(days=15))
        db.execute(
            """INSERT INTO applications
            (id,institution_id,reference,application_type,cycle,stage,status,submitted_at,due_at,assigned_to,workflow_version,summary,updated_at,workflow_version_id)
            VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (ident,payload.institution_id,reference,payload.application_type,payload.cycle,"Scrutiny","In review",iso(now_utc()),deadline,assignee["id"],workflow["version"],payload.summary,iso(now_utc()),workflow["id"]),
        )
        db.execute(
            "INSERT INTO stage_events VALUES(?,?,?,?,?,?,?,?)",
            (str(uuid.uuid4()), ident, None, "Scrutiny", "Application submitted", "Initial submission", user["id"], iso(now_utc())),
        )
        audit(db, user["id"], "Application created", "application", ident, "New synthetic demo submission", None, {"reference": reference, "stage": "Scrutiny"})
        db.commit()
        row = db.execute("SELECT * FROM applications WHERE id=?", (ident,)).fetchone()
        return serialize_application(db, row)


ACTION_ROLES = {
    "return": {"scrutiny_officer", "regional_officer"},
    "resubmit": {"institution"},
}
COMPLETE_ROLES_BY_STAGE = {
    "Scrutiny": {"scrutiny_officer", "regional_officer"},
    "EVC": {"evc_member", "central_officer", "regional_officer"},
    "Committee review": {"central_officer", "super_admin"},
}


@app.post("/api/applications/{application_id}/transition")
def transition(application_id: str, payload: TransitionRequest, user: dict[str, Any] = Depends(current_user)) -> dict[str, Any]:
    with get_db() as db:
        row = db.execute("SELECT * FROM applications WHERE id=?", (application_id,)).fetchone()
        if not row or not visible_application(user, row):
            raise HTTPException(status_code=404, detail="Application not found")
        if payload.action == "complete":
            if row["stage"] not in COMPLETE_ROLES_BY_STAGE:
                raise HTTPException(status_code=409, detail=f"Application cannot advance from stage '{row['stage']}'")
            if user["role"] not in COMPLETE_ROLES_BY_STAGE.get(row["stage"], set()):
                raise HTTPException(status_code=403, detail="This action is not permitted for your role at this stage")
        elif user["role"] not in ACTION_ROLES.get(payload.action, set()):
            raise HTTPException(status_code=403, detail="This action is not permitted for your role")

        version = db.execute(
            "SELECT stages_json FROM workflow_versions WHERE id=?",
            (row["workflow_version_id"],),
        ).fetchone()
        if not version:
            raise HTTPException(status_code=409, detail="Application has no valid retained workflow version")
        stages = json.loads(version["stages_json"])
        return_to_stage = row["return_to_stage"]
        if payload.action == "return":
            if row["stage"] != "Scrutiny":
                raise HTTPException(status_code=409, detail="Only scrutiny-stage applications can be returned")
            next_stage, status, return_to_stage = "Correction", "Returned", row["stage"]
        elif payload.action == "resubmit":
            if row["stage"] != "Correction":
                raise HTTPException(status_code=409, detail="Only returned applications can be resubmitted")
            if row["institution_id"] != user["institution_id"]:
                raise HTTPException(status_code=403, detail="Only the owning institution may resubmit this application")
            next_stage = return_to_stage if return_to_stage in stages else stages[0]
            status, return_to_stage = "Resubmitted", None
        elif payload.action == "complete":
            if row["stage"] not in stages or stages.index(row["stage"]) >= len(stages) - 1:
                raise HTTPException(status_code=409, detail=f"Application cannot advance from stage '{row['stage']}'")
            next_stage = stages[stages.index(row["stage"]) + 1]
            status = "Completed" if next_stage == "Completed" else "Pending"
        else:
            raise HTTPException(status_code=422, detail="Unsupported workflow action")
        old = {"stage": row["stage"], "status": row["status"]}
        db.execute(
            "UPDATE applications SET stage=?,status=?,return_to_stage=?,updated_at=? WHERE id=?",
            (next_stage, status, return_to_stage, iso(now_utc()), application_id),
        )
        db.execute(
            "INSERT INTO stage_events VALUES(?,?,?,?,?,?,?,?)",
            (str(uuid.uuid4()), application_id, row["stage"], next_stage, payload.action, payload.reason, user["id"], iso(now_utc())),
        )
        audit(db, user["id"], payload.action, "application", application_id, payload.reason, old, {"stage": next_stage, "status": status})
        db.commit()
        updated = db.execute("SELECT * FROM applications WHERE id=?", (application_id,)).fetchone()
        return serialize_application(db, updated)


@app.get("/api/applications/{application_id}/timeline")
def timeline(application_id: str, user: dict[str, Any] = Depends(current_user)) -> list[dict[str, Any]]:
    with get_db() as db:
        row = db.execute("SELECT * FROM applications WHERE id=?", (application_id,)).fetchone()
        if not row or not visible_application(user, row):
            raise HTTPException(status_code=404, detail="Application not found")
        return [dict(item) for item in db.execute(
            "SELECT e.*,u.name AS actor FROM stage_events e JOIN users u ON u.id=e.actor_id WHERE application_id=? ORDER BY created_at DESC, e.rowid DESC",
            (application_id,),
        ).fetchall()]


@app.get("/api/compliance")
def compliance(user: dict[str, Any] = Depends(current_user)) -> list[dict[str, Any]]:
    with get_db() as db:
        sql = """SELECT o.*,i.name AS institution_name,i.region FROM compliance_obligations o
                 JOIN institutions i ON i.id=o.institution_id"""
        params: tuple[Any, ...] = ()
        if user["role"] == "institution":
            sql += " WHERE o.institution_id=?"
            params = (user["institution_id"],)
        elif user["role"] == "regional_officer":
            sql += " WHERE i.region=?"
            params = (user["region_id"],)
        elif user["role"] in {"scrutiny_officer", "evc_member"}:
            sql += " WHERE o.institution_id IN (SELECT institution_id FROM applications WHERE assigned_to=?)"
            params = (user["id"],)
        return [dict(row) for row in db.execute(sql + " ORDER BY o.due_at", params).fetchall()]


@app.post("/api/compliance/{obligation_id}/decision")
def compliance_decision(obligation_id: str, payload: ComplianceDecision, user: dict[str, Any] = Depends(current_user)) -> dict[str, Any]:
    if payload.status not in {"Verified", "Correction required", "Under verification"}:
        raise HTTPException(status_code=422, detail="Unsupported compliance decision")
    if user["role"] not in {"super_admin", "central_officer", "regional_officer", "scrutiny_officer"}:
        raise HTTPException(status_code=403, detail="Only an authorised officer may review evidence")
    with get_db() as db:
        row = db.execute("SELECT * FROM compliance_obligations WHERE id=?", (obligation_id,)).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Obligation not found")
        if user["role"] == "regional_officer":
            institution = db.execute("SELECT region FROM institutions WHERE id=?", (row["institution_id"],)).fetchone()
            if not institution or institution["region"] != user["region_id"]:
                raise HTTPException(status_code=404, detail="Obligation not found")
        if user["role"] == "scrutiny_officer":
            assigned = db.execute(
                """SELECT 1 FROM applications WHERE assigned_to=? AND institution_id=?
                AND (? IS NULL OR id=?) LIMIT 1""",
                (user["id"], row["institution_id"], row["application_id"], row["application_id"]),
            ).fetchone()
            if not assigned:
                raise HTTPException(status_code=404, detail="Obligation not found")
        old = dict(row)
        db.execute("UPDATE compliance_obligations SET status=?,updated_at=? WHERE id=?", (payload.status, iso(now_utc()), obligation_id))
        audit(db, user["id"], "Compliance decision", "compliance_obligation", obligation_id, payload.reason, old, {"status": payload.status})
        db.commit()
        updated = db.execute("SELECT * FROM compliance_obligations WHERE id=?", (obligation_id,)).fetchone()
        return dict(updated)


@app.post("/api/compliance/{obligation_id}/submit")
def submit_compliance(
    obligation_id: str,
    payload: ComplianceSubmission,
    user: dict[str, Any] = Depends(require_roles("institution")),
) -> dict[str, Any]:
    with get_db() as db:
        row = db.execute("SELECT * FROM compliance_obligations WHERE id=?", (obligation_id,)).fetchone()
        if not row or row["institution_id"] != user["institution_id"]:
            raise HTTPException(status_code=404, detail="Obligation not found")
        if row["status"] in {"Verified", "Closed"}:
            raise HTTPException(status_code=409, detail="A closed or verified obligation cannot be resubmitted")
        previous = {"status": row["status"], "evidence_name": row["evidence_name"]}
        db.execute(
            """UPDATE compliance_obligations SET status='Under verification',submitted_at=?,
            evidence_name=?,updated_at=? WHERE id=?""",
            (iso(now_utc()), payload.evidence_name, iso(now_utc()), obligation_id),
        )
        audit(
            db, user["id"], "Compliance evidence submitted", "compliance_obligation", obligation_id,
            payload.submission_note or "Evidence submitted by institution for authorised verification",
            previous, {"status": "Under verification", "evidence_name": payload.evidence_name},
        )
        db.commit()
        return dict(db.execute("SELECT * FROM compliance_obligations WHERE id=?", (obligation_id,)).fetchone())


@app.get("/api/documents")
def documents(user: dict[str, Any] = Depends(current_user)) -> list[dict[str, Any]]:
    with get_db() as db:
        sql = """SELECT d.*,i.name AS institution_name,i.region FROM institutional_documents d
                 JOIN institutions i ON i.id=d.institution_id"""
        params: tuple[Any, ...] = ()
        if user["role"] == "institution":
            sql += " WHERE d.institution_id=?"
            params = (user["institution_id"],)
        elif user["role"] == "regional_officer":
            sql += " WHERE i.region=?"
            params = (user["region_id"],)
        elif user["role"] in {"scrutiny_officer", "evc_member"}:
            sql += " WHERE d.institution_id IN (SELECT institution_id FROM applications WHERE assigned_to=?)"
            params = (user["id"],)
        rows = db.execute(sql + " ORDER BY d.expires_at", params).fetchall()
        today = now_utc().date()
        output = []
        for row in rows:
            item = dict(row)
            item["days_to_expiry"] = (datetime.fromisoformat(row["expires_at"]).date() - today).days if row["expires_at"] else None
            output.append(item)
        return output


@app.post("/api/documents/upload", status_code=201)
async def upload_document(
    institution_id: str = Form(..., min_length=1),
    category: str = Form(..., min_length=2, max_length=120),
    expires_at: date | None = Form(default=None),
    file: UploadFile = File(...),
    user: dict[str, Any] = Depends(current_user),
) -> dict[str, Any]:
    if user["role"] == "institution" and institution_id != user["institution_id"]:
        raise HTTPException(status_code=404, detail="Institution not found")
    if user["role"] not in {"institution", "super_admin", "central_officer", "regional_officer"}:
        raise HTTPException(status_code=403, detail="Document upload is not permitted")
    with get_db() as db:
        inst = db.execute("SELECT id,region FROM institutions WHERE id=?", (institution_id,)).fetchone()
        if not inst or (user["role"] == "institution" and inst["id"] != user["institution_id"]):
            raise HTTPException(status_code=404, detail="Institution not found")
        if user["role"] == "regional_officer" and inst["region"] != user["region_id"]:
            raise HTTPException(status_code=403, detail="Institution is outside your region")
    suffix = Path(file.filename or "").suffix.lower()
    if suffix not in ALLOWED_UPLOADS:
        raise HTTPException(status_code=415, detail="Only PDF, PNG, and JPEG files are accepted")
    contents = await file.read(10 * 1024 * 1024 + 1)
    if len(contents) > 10 * 1024 * 1024:
        raise HTTPException(status_code=413, detail="Maximum file size is 10 MB")
    if not contents:
        raise HTTPException(status_code=400, detail="Empty files are not accepted")
    signatures = {
        ".pdf": contents.startswith(b"%PDF-"),
        ".png": contents.startswith(b"\x89PNG\r\n\x1a\n"),
        ".jpg": contents.startswith(b"\xff\xd8\xff"),
        ".jpeg": contents.startswith(b"\xff\xd8\xff"),
    }
    if not signatures[suffix]:
        raise HTTPException(status_code=415, detail="File contents do not match the selected document type")
    with get_db() as db:
        ident = str(uuid.uuid4())
        UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
        key = f"{ident}{suffix}"
        (UPLOAD_DIR / key).write_bytes(contents)
        db.execute(
            """INSERT INTO institutional_documents
            (id,institution_id,category,file_name,expires_at,status,storage_key,uploaded_at)
            VALUES(?,?,?,?,?,?,?,?)""",
            (ident,institution_id,category,Path(file.filename or "upload").name,expires_at.isoformat() if expires_at else None,"Under verification",key,iso(now_utc())),
        )
        audit(db, user["id"], "Document uploaded", "document", ident, "Evidence submitted for human verification", None, {"category": category})
        db.commit()
        row = db.execute("SELECT * FROM institutional_documents WHERE id=?", (ident,)).fetchone()
        return dict(row)


@app.post("/api/documents/{document_id}/decision")
def document_decision(
    document_id: str,
    payload: ComplianceDecision,
    user: dict[str, Any] = Depends(require_roles("super_admin", "central_officer", "regional_officer", "scrutiny_officer")),
) -> dict[str, Any]:
    if payload.status not in {"Verified", "Correction required", "Under verification"}:
        raise HTTPException(status_code=422, detail="Unsupported document decision")
    with get_db() as db:
        row = db.execute("SELECT * FROM institutional_documents WHERE id=?", (document_id,)).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Document not found")
        if user["role"] == "regional_officer":
            institution = db.execute("SELECT region FROM institutions WHERE id=?", (row["institution_id"],)).fetchone()
            if not institution or institution["region"] != user["region_id"]:
                raise HTTPException(status_code=404, detail="Document not found")
        if user["role"] == "scrutiny_officer":
            assigned = db.execute(
                "SELECT 1 FROM applications WHERE assigned_to=? AND institution_id=? LIMIT 1",
                (user["id"], row["institution_id"]),
            ).fetchone()
            if not assigned:
                raise HTTPException(status_code=404, detail="Document not found")
        previous = {"status": row["status"]}
        verified = payload.status == "Verified"
        db.execute(
            """UPDATE institutional_documents SET status=?,verified_by=?,verified_at=? WHERE id=?""",
            (payload.status, user["id"] if verified else None, iso(now_utc()) if verified else None, document_id),
        )
        audit(db, user["id"], "Document decision", "document", document_id, payload.reason, previous, {"status": payload.status})
        db.commit()
        return dict(db.execute("SELECT * FROM institutional_documents WHERE id=?", (document_id,)).fetchone())


@app.get("/api/evc")
def evc_queue(user: dict[str, Any] = Depends(current_user)) -> list[dict[str, Any]]:
    if user["role"] not in {"super_admin", "central_officer", "regional_officer", "evc_member"}:
        raise HTTPException(status_code=403, detail="EVC workspace is not available for your role")
    with get_db() as db:
        rows = db.execute(
            """SELECT e.*,a.reference,i.name AS institution_name,i.region FROM evc_events e
            JOIN applications a ON a.id=e.application_id JOIN institutions i ON i.id=a.institution_id
            ORDER BY e.scheduled_at"""
        ).fetchall()
        if user["role"] == "regional_officer":
            rows = [row for row in rows if row["region"] == user["region_id"]]
        elif user["role"] == "evc_member":
            assigned = {row["id"] for row in db.execute("SELECT id FROM applications WHERE assigned_to=?", (user["id"],)).fetchall()}
            rows = [row for row in rows if row["application_id"] in assigned]
        return [dict(row) for row in rows]


@app.post("/api/evc", status_code=201)
def schedule_evc(payload: EvcSchedule, user: dict[str, Any] = Depends(require_roles("super_admin", "central_officer", "regional_officer"))) -> dict[str, Any]:
    scheduled_at = payload.scheduled_at
    if scheduled_at.tzinfo is None:
        raise HTTPException(status_code=422, detail="scheduled_at must include a timezone")
    scheduled_at = scheduled_at.astimezone(timezone.utc)
    if scheduled_at <= now_utc():
        raise HTTPException(status_code=422, detail="Visit must be scheduled in the future")
    with get_db() as db:
        application = db.execute("SELECT * FROM applications WHERE id=?", (payload.application_id,)).fetchone()
        if not application or application["stage"] != "EVC":
            raise HTTPException(status_code=409, detail="Only applications currently at the EVC stage may be scheduled")
        if user["role"] == "regional_officer":
            inst = db.execute("SELECT region FROM institutions WHERE id=?", (application["institution_id"],)).fetchone()
            if not inst or inst["region"] != user["region_id"]:
                raise HTTPException(status_code=404, detail="Application not found")
        conflict = db.execute(
            "SELECT id FROM evc_events WHERE committee=? AND scheduled_at=? AND status='Scheduled'",
            (payload.committee, iso(scheduled_at)),
        ).fetchone()
        if conflict:
            raise HTTPException(status_code=409, detail="This committee already has a visit at the selected time")
        previous = {"status": application["status"]}
        ident = str(uuid.uuid4())
        db.execute(
            "INSERT INTO evc_events VALUES(?,?,?,?,?,?,?,?)",
            (ident, payload.application_id, iso(scheduled_at), payload.location, payload.committee, "Scheduled", user["id"], payload.reason),
        )
        db.execute("UPDATE applications SET status='Scheduled',updated_at=? WHERE id=?", (iso(now_utc()), payload.application_id))
        audit(db, user["id"], "EVC scheduled", "application", payload.application_id, payload.reason, previous, {"status": "Scheduled", "scheduled_at": iso(scheduled_at)})
        db.execute(
            "INSERT INTO stage_events VALUES(?,?,?,?,?,?,?,?)",
            (str(uuid.uuid4()), payload.application_id, "EVC", "EVC", "EVC scheduled", payload.reason, user["id"], iso(now_utc())),
        )
        db.commit()
        return dict(db.execute("SELECT * FROM evc_events WHERE id=?", (ident,)).fetchone())


@app.get("/api/notifications")
def notifications(user: dict[str, Any] = Depends(current_user)) -> list[dict[str, Any]]:
    with get_db() as db:
        return [dict(row) for row in db.execute(
            "SELECT * FROM notifications WHERE user_id=? ORDER BY created_at DESC", (user["id"],)
        ).fetchall()]


@app.get("/api/audit")
def audit_events(user: dict[str, Any] = Depends(require_roles("super_admin", "central_officer", "regional_officer"))) -> list[dict[str, Any]]:
    with get_db() as db:
        rows = db.execute(
            """SELECT a.*,u.name AS actor FROM audit_events a JOIN users u ON u.id=a.actor_id
            ORDER BY a.created_at DESC LIMIT 200"""
        ).fetchall()
        result = [dict(row) for row in rows]
        if user["role"] == "regional_officer":
            allowed: set[tuple[str, str]] = set()
            for row in db.execute(
                """SELECT a.id FROM applications a JOIN institutions i ON i.id=a.institution_id WHERE i.region=?""",
                (user["region_id"],),
            ).fetchall():
                allowed.add(("application", row["id"]))
            for table, entity_type in (("compliance_obligations", "compliance_obligation"), ("institutional_documents", "document")):
                for row in db.execute(
                    f"""SELECT t.id FROM {table} t JOIN institutions i ON i.id=t.institution_id
                    WHERE i.region=?""", (user["region_id"],)
                ).fetchall():
                    allowed.add((entity_type, row["id"]))
            return [item for item in result if (item["entity_type"], item["entity_id"]) in allowed]
        return result


@app.get("/api/reports/summary")
def report_summary(
    user: dict[str, Any] = Depends(require_roles("super_admin", "central_officer", "regional_officer")),
) -> dict[str, Any]:
    with get_db() as db:
        rows = db.execute("SELECT * FROM applications ORDER BY submitted_at DESC").fetchall()
        applications = [serialize_application(db, row) for row in rows if visible_application(user, row)]
        stages: dict[str, int] = {}
        regions: dict[str, int] = {}
        ageing = {"0-7 days": 0, "8-30 days": 0, "31-60 days": 0, "Over 60 days": 0}
        overdue_by_unit: dict[str, int] = {}
        today = now_utc().date()
        for item in applications:
            stages[item["stage"]] = stages.get(item["stage"], 0) + 1
            if item["stage"] == "Completed":
                continue
            regions[item["region"]] = regions.get(item["region"], 0) + 1
            age = max(0, (today - datetime.fromisoformat(item["submitted_at"]).date()).days)
            bucket = "0-7 days" if age <= 7 else "8-30 days" if age <= 30 else "31-60 days" if age <= 60 else "Over 60 days"
            ageing[bucket] += 1
            if datetime.fromisoformat(item["due_at"]).date() < today:
                unit = item["assignee"]
                overdue_by_unit[unit] = overdue_by_unit.get(unit, 0) + 1
        return {
            "generated_at": iso(now_utc()),
            "total_applications": len(applications),
            "stage_distribution": [{"stage": name, "count": count} for name, count in sorted(stages.items())],
            "region_pendency": [{"region": name, "count": count} for name, count in sorted(regions.items())],
            "ageing": [{"band": name, "count": count} for name, count in ageing.items()],
            "overdue_by_unit": [{"unit": name, "count": count} for name, count in sorted(overdue_by_unit.items())],
        }


@app.get("/api/reports/applications.csv")
def export_applications(
    user: dict[str, Any] = Depends(require_roles("super_admin", "central_officer", "regional_officer")),
) -> Response:
    with get_db() as db:
        rows = db.execute("SELECT * FROM applications ORDER BY submitted_at DESC").fetchall()
        applications = [serialize_application(db, row) for row in rows if visible_application(user, row)]
    output = io.StringIO(newline="")
    writer = csv.writer(output)
    writer.writerow(["Application reference", "Institution", "Region", "Application type", "Cycle", "Stage", "Status", "Assigned to", "Submitted at (UTC)", "Due at (UTC)"])

    def safe_cell(value: Any) -> str:
        text = "" if value is None else str(value)
        if text.lstrip(" \t\r\n").startswith(("=", "+", "-", "@")):
            return "'" + text
        return text

    for item in applications:
        writer.writerow([
            safe_cell(item["reference"]), safe_cell(item["institution_name"]), safe_cell(item["region"]),
            safe_cell(item["application_type"]), safe_cell(item["cycle"]), safe_cell(item["stage"]),
            safe_cell(item["status"]), safe_cell(item["assignee"]), safe_cell(item["submitted_at"]),
            safe_cell(item["due_at"]),
        ])
    return Response(
        content=output.getvalue(),
        media_type="text/csv; charset=utf-8",
        headers={"Content-Disposition": 'attachment; filename="authorised-applications.csv"'},
    )


@app.post("/api/admin/run-deadline-check")
def run_deadline_check(user: dict[str, Any] = Depends(require_roles("super_admin"))) -> dict[str, int]:
    """Idempotent demo job. Reminder windows and dates here are demo-only, not official policy."""
    created = 0
    escalation_count = 0
    today = now_utc().date()
    with get_db() as db:
        due_items = db.execute(
            """SELECT id,institution_id,title,due_at,status,'obligation' AS kind
            FROM compliance_obligations WHERE status NOT IN ('Verified','Closed')
            UNION ALL
            SELECT id,institution_id,reference AS title,due_at,stage AS status,'application' AS kind
            FROM applications WHERE stage != 'Completed'"""
        ).fetchall()
        for item in due_items:
            due = datetime.fromisoformat(item["due_at"]).date()
            if due < today:
                cursor = db.execute(
                    """INSERT OR IGNORE INTO escalation_events
                    (id,entity_type,entity_id,reason,status,created_at)
                    VALUES(?,?,?,?,?,?)""",
                    (
                        str(uuid.uuid4()),
                        "application" if item["kind"] == "application" else "compliance_obligation",
                        item["id"],
                        f"Recorded deadline {due.isoformat()} has passed; officer follow-up is required.",
                        "Open",
                        iso(now_utc()),
                    ),
                )
                escalation_count += cursor.rowcount
            if (due - today).days > 3:
                continue
            recipient = db.execute(
                "SELECT id FROM users WHERE institution_id=?", (item["institution_id"],)
            ).fetchone()
            if recipient:
                title = "Action overdue" if due < today else "Deadline approaching"
                body = f"{item['title']} is due {due.isoformat()}. Please review the recorded requirement."
                cursor = db.execute(
                    """INSERT OR IGNORE INTO notifications
                    (id,user_id,title,body,category,related_id,created_at)
                    VALUES(?,?,?,?,?,?,?)""",
                    (str(uuid.uuid4()),recipient["id"],title,body,f"{item['kind']}_deadline",item["id"],iso(now_utc())),
                )
                created += cursor.rowcount
        expiring_documents = db.execute(
            """SELECT id,institution_id,category,expires_at FROM institutional_documents
            WHERE expires_at IS NOT NULL AND status NOT IN ('Verified renewed','Closed')"""
        ).fetchall()
        for item in expiring_documents:
            expiry = datetime.fromisoformat(item["expires_at"]).date()
            if (expiry - today).days > 30:
                continue
            recipient = db.execute(
                "SELECT id FROM users WHERE institution_id=?", (item["institution_id"],)
            ).fetchone()
            if recipient:
                cursor = db.execute(
                    """INSERT OR IGNORE INTO notifications
                    (id,user_id,title,body,category,related_id,created_at)
                    VALUES(?,?,?,?,?,?,?)""",
                    (str(uuid.uuid4()),recipient["id"],"Document expiry follow-up",
                     f"{item['category']} has a recorded expiry date of {expiry.isoformat()}. Review renewal requirements.",
                     "document_expiry",item["id"],iso(now_utc())),
                )
                created += cursor.rowcount
        db.commit()
    return {"notifications_created": created, "escalations_created": escalation_count}


@app.get("/api/escalations")
def escalations(
    user: dict[str, Any] = Depends(require_roles("super_admin", "central_officer", "regional_officer")),
) -> list[dict[str, Any]]:
    with get_db() as db:
        rows = db.execute("SELECT * FROM escalation_events ORDER BY status,created_at DESC").fetchall()
        result = []
        for row in rows:
            item = dict(row)
            if row["entity_type"] == "application":
                entity = db.execute(
                    """SELECT a.reference,i.name AS institution_name,i.region FROM applications a
                    JOIN institutions i ON i.id=a.institution_id WHERE a.id=?""",
                    (row["entity_id"],),
                ).fetchone()
            else:
                entity = db.execute(
                    """SELECT o.title AS reference,i.name AS institution_name,i.region
                    FROM compliance_obligations o JOIN institutions i ON i.id=o.institution_id
                    WHERE o.id=?""",
                    (row["entity_id"],),
                ).fetchone()
            if not entity or (user["role"] == "regional_officer" and entity["region"] != user["region_id"]):
                continue
            item.update(dict(entity))
            result.append(item)
        return result


@app.post("/api/escalations/{escalation_id}/resolve")
def resolve_escalation(
    escalation_id: str,
    payload: EscalationResolution,
    user: dict[str, Any] = Depends(require_roles("super_admin", "central_officer", "regional_officer")),
) -> dict[str, Any]:
    with get_db() as db:
        row = db.execute("SELECT * FROM escalation_events WHERE id=?", (escalation_id,)).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Escalation not found")
        if user["role"] == "regional_officer":
            table = "applications" if row["entity_type"] == "application" else "compliance_obligations"
            institution = db.execute(f"SELECT institution_id FROM {table} WHERE id=?", (row["entity_id"],)).fetchone()
            region = db.execute(
                "SELECT region FROM institutions WHERE id=?", (institution["institution_id"],)
            ).fetchone() if institution else None
            if not region or region["region"] != user["region_id"]:
                raise HTTPException(status_code=404, detail="Escalation not found")
        if row["status"] != "Open":
            raise HTTPException(status_code=409, detail="Escalation is already resolved")
        db.execute(
            "UPDATE escalation_events SET status='Resolved',resolved_at=?,resolved_by=? WHERE id=?",
            (iso(now_utc()), user["id"], escalation_id),
        )
        audit(db, user["id"], "Escalation resolved", row["entity_type"], row["entity_id"], payload.reason, {"status": "Open"}, {"status": "Resolved"})
        db.commit()
        return dict(db.execute("SELECT * FROM escalation_events WHERE id=?", (escalation_id,)).fetchone())


@app.get("/api/institutions")
def institutions(user: dict[str, Any] = Depends(current_user)) -> list[dict[str, Any]]:
    with get_db() as db:
        if user["role"] == "institution":
            rows = db.execute("SELECT * FROM institutions WHERE id=?", (user["institution_id"],)).fetchall()
        elif user["role"] == "regional_officer":
            rows = db.execute("SELECT * FROM institutions WHERE region=?", (user["region_id"],)).fetchall()
        elif user["role"] in {"scrutiny_officer", "evc_member"}:
            rows = db.execute(
                """SELECT DISTINCT i.* FROM institutions i JOIN applications a ON a.institution_id=i.id
                WHERE a.assigned_to=? ORDER BY i.name""",
                (user["id"],),
            ).fetchall()
        else:
            rows = db.execute("SELECT * FROM institutions ORDER BY name").fetchall()
        return [dict(row) for row in rows]
