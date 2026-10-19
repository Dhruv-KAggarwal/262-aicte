from datetime import timedelta

import pytest
from fastapi.testclient import TestClient

from app import main


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setattr(main, "DB_PATH", tmp_path / "demo.db")
    monkeypatch.setattr(main, "UPLOAD_DIR", tmp_path / "private_uploads")
    monkeypatch.setattr(main, "SECRET", "test-secret")
    with TestClient(main.app) as test_client:
        yield test_client


def sign_in(client: TestClient, email: str) -> TestClient:
    response = client.post("/api/auth/login", json={"email": email, "password": "DemoPass!2026"})
    assert response.status_code == 200
    assert "httponly" in response.headers["set-cookie"].lower()
    return client


def test_login_uses_http_only_session_cookie(client: TestClient):
    sign_in(client, "admin@demo.aicte.local")
    response = client.get("/api/auth/me")
    assert response.status_code == 200
    assert response.json()["role"] == "super_admin"


def test_institution_is_scoped_to_own_applications(client: TestClient):
    sign_in(client, "institution@demo.aicte.local")
    response = client.get("/api/applications")
    assert response.status_code == 200
    assert {row["institution_name"] for row in response.json()} == {"North Valley Institute of Technology"}
    denied = client.get("/api/applications/app-002/timeline")
    assert denied.status_code == 404


def test_transition_requires_valid_stage_and_records_audit(client: TestClient):
    sign_in(client, "scrutiny@demo.aicte.local")
    invalid = client.post(
        "/api/applications/app-003/transition",
        json={"action": "complete", "reason": "Attempt invalid transition"},
    )
    assert invalid.status_code == 409
    returned = client.post(
        "/api/applications/app-001/transition",
        json={"action": "return", "reason": "Lease evidence requires a readable renewed copy"},
    )
    assert returned.status_code == 200
    assert returned.json()["stage"] == "Correction"
    events = client.get("/api/applications/app-001/timeline").json()
    assert events[0]["action"] == "return"


def test_institution_resubmission_and_officer_verification(client: TestClient):
    sign_in(client, "institution@demo.aicte.local")
    submission = client.post(
        "/api/compliance/obl-001/submit",
        json={"evidence_name": "renewed-lease-deed.pdf", "submission_note": "Renewed copy attached"},
    )
    assert submission.status_code == 200
    assert submission.json()["status"] == "Under verification"
    client.post("/api/auth/logout")
    sign_in(client, "north@demo.aicte.local")
    decision = client.post(
        "/api/compliance/obl-001/decision",
        json={"status": "Verified", "reason": "Renewal evidence reviewed and legible"},
    )
    assert decision.status_code == 200
    assert decision.json()["status"] == "Verified"


def test_institution_cannot_submit_evidence_for_another_institution(client: TestClient):
    sign_in(client, "institution@demo.aicte.local")
    response = client.post(
        "/api/compliance/obl-003/submit",
        json={"evidence_name": "evidence.pdf"},
    )
    assert response.status_code == 404


def test_deadline_job_is_idempotent(client: TestClient):
    sign_in(client, "admin@demo.aicte.local")
    first = client.post("/api/admin/run-deadline-check")
    second = client.post("/api/admin/run-deadline-check")
    assert first.status_code == second.status_code == 200
    assert first.json()["notifications_created"] >= 1
    assert second.json()["notifications_created"] == 0
    assert first.json()["escalations_created"] >= 1
    assert second.json()["escalations_created"] == 0
    events = client.get("/api/escalations").json()
    assert events and all(item["status"] == "Open" for item in events)
    resolved = client.post(
        f"/api/escalations/{events[0]['id']}/resolve",
        json={"reason": "Officer reviewed the recorded deadline and contacted the institution"},
    )
    assert resolved.status_code == 200
    assert resolved.json()["status"] == "Resolved"
    after_resolve = client.post("/api/admin/run-deadline-check")
    assert after_resolve.json()["escalations_created"] == 0


def test_evc_schedule_requires_eligible_case_and_avoids_conflicts(client: TestClient):
    sign_in(client, "north@demo.aicte.local")
    when = (main.now_utc() + timedelta(days=10)).isoformat()
    payload = {
        "application_id": "app-002",
        "scheduled_at": when,
        "location": "Jaipur, Rajasthan",
        "committee": "Committee North-09",
        "reason": "Assign an available committee for the next review visit",
    }
    created = client.post("/api/evc", json=payload)
    assert created.status_code == 201
    conflict = client.post("/api/evc", json=payload)
    assert conflict.status_code == 409
    not_eligible = client.post(
        "/api/evc",
        json={**payload, "application_id": "app-001", "committee": "Committee North-10"},
    )
    assert not_eligible.status_code == 409


def test_published_routes_are_versioned_and_drive_transitions(client: TestClient):
    sign_in(client, "admin@demo.aicte.local")
    invalid = client.post(
        "/api/workflows/workflow-evc/versions",
        json={"stages": ["EVC", "Scrutiny", "Completed"]},
    )
    assert invalid.status_code == 422
    draft = client.post(
        "/api/workflows/workflow-evc/versions",
        json={"stages": ["Scrutiny", "Committee review", "Completed"]},
    )
    assert draft.status_code == 201
    version_id = draft.json()["id"]
    published = client.post(f"/api/workflow-versions/{version_id}/publish", json={})
    assert published.status_code == 200
    assert published.json()["status"] == "Published"
    templates = client.get("/api/workflows/templates").json()
    selected = next(item for item in templates if item["template_id"] == "workflow-evc")
    assert selected["workflow_version_id"] == version_id

    client.post("/api/auth/logout")
    sign_in(client, "institution@demo.aicte.local")
    created = client.post(
        "/api/applications",
        json={
            "institution_id": "inst-001",
            "application_type": "New Programme",
            "cycle": "2026-27",
            "workflow_version_id": version_id,
            "summary": "Route-specific workflow test",
        },
    )
    assert created.status_code == 201
    application_id = created.json()["id"]
    client.post("/api/auth/logout")
    sign_in(client, "scrutiny@demo.aicte.local")
    advanced = client.post(
        f"/api/applications/{application_id}/transition",
        json={"action": "complete", "reason": "Initial scrutiny is complete"},
    )
    assert advanced.status_code == 200
    assert advanced.json()["stage"] == "Committee review"
    assert advanced.json()["workflow_version_id"] == version_id


def test_upload_checks_scope_and_file_signature(client: TestClient):
    sign_in(client, "institution@demo.aicte.local")
    denied = client.post(
        "/api/documents/upload",
        data={"institution_id": "inst-002", "category": "Lease deed"},
        files={"file": ("lease.pdf", b"%PDF-1.4", "application/pdf")},
    )
    assert denied.status_code == 404
    invalid_file = client.post(
        "/api/documents/upload",
        data={"institution_id": "inst-001", "category": "Lease deed"},
        files={"file": ("lease.pdf", b"not a pdf", "application/pdf")},
    )
    assert invalid_file.status_code == 415
    accepted = client.post(
        "/api/documents/upload",
        data={"institution_id": "inst-001", "category": "Renewed lease deed"},
        files={"file": ("lease.pdf", b"%PDF-1.4\nsynthetic", "application/pdf")},
    )
    assert accepted.status_code == 201
    assert accepted.json()["status"] == "Under verification"


def test_regional_upload_scope_is_enforced(client: TestClient):
    sign_in(client, "north@demo.aicte.local")
    response = client.post(
        "/api/documents/upload",
        data={"institution_id": "inst-003", "category": "Occupancy certificate"},
        files={"file": ("certificate.pdf", b"%PDF-1.4\nsynthetic", "application/pdf")},
    )
    assert response.status_code == 403


def test_reports_and_csv_export_respect_regional_scope(client: TestClient):
    sign_in(client, "north@demo.aicte.local")
    summary = client.get("/api/reports/summary")
    assert summary.status_code == 200
    assert summary.json()["total_applications"] == 4
    export = client.get("/api/reports/applications.csv")
    assert export.status_code == 200
    assert "Coastal School of Applied Sciences" not in export.text
    assert "North Valley Institute of Technology" in export.text


def test_csv_export_neutralizes_spreadsheet_formulas(client: TestClient):
    sign_in(client, "admin@demo.aicte.local")
    created = client.post(
        "/api/applications",
        json={
            "institution_id": "inst-001",
            "application_type": "=HYPERLINK(\"https://example.invalid\")",
            "cycle": "2026-27",
            "workflow_version_id": "wf-direct-v1",
            "summary": "CSV formula handling",
        },
    )
    assert created.status_code == 201
    export = client.get("/api/reports/applications.csv")
    assert export.status_code == 200
    assert "'=HYPERLINK" in export.text
