# AICTE Approval Operations (Demonstration)

A runnable demonstration of an approval-workflow and institutional-compliance workspace. It uses synthetic records only and is **not connected to AICTE systems**. Dates, routes, and reminders are demonstration data, not official AICTE timelines or policy.

## Architecture

- **Frontend:** Next.js, React, TypeScript, responsive CSS.
- **API:** FastAPI with validated JSON and multipart endpoints.
- **Local persistence:** SQLite with versioned SQL migrations under `backend/migrations/`.
- **Documents:** Private local filesystem adapter; random storage keys, file-size and content-signature checks. Documents are not served through a public static path.
- **Authentication:** PBKDF2 password hashes and a signed, expiring, HttpOnly session cookie. Role and institution/region/assignment scope are enforced by the API.
- **Automation:** Idempotent deadline-check endpoint; the demonstration uses short synthetic dates. A production scheduler/provider is intentionally not configured.

PostgreSQL, managed object storage, mail/SMS delivery, production identity management, and an authorised APH/workflow configuration process are not configured in this demonstration. Do not deploy the SQLite/local-storage configuration as a production service.

## Run locally (Windows PowerShell)

### 1. Start the API

```powershell
cd backend
py -3.13 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
$env:APP_SECRET = "replace-with-a-long-random-local-secret"
uvicorn app.main:app --reload --port 8000
```

On first start the API applies `backend/migrations/001_initial.sql`, creates `backend/data/aicte_demo.db`, and seeds the demonstration records. API docs are available at `http://localhost:8000/docs`.

### 2. Start the frontend

In another PowerShell window, from the project root:

```powershell
npm install
$env:NEXT_PUBLIC_API_URL = "http://localhost:8000"
npm run dev
```

Open `http://localhost:3000`. Cookie-based browser requests are allowed only from `FRONTEND_ORIGIN` (default `http://localhost:3000`).

### Docker Compose

```powershell
docker compose up --build
```

The compose setup is for local demonstration only. Set `APP_SECRET` to a private random value before using it and do not expose the local SQLite volume publicly.

## Demo accounts

All accounts use `DemoPass!2026` in the seeded local demonstration database:

| Role | Email |
|---|---|
| Super administrator | `admin@demo.aicte.local` |
| Central officer | `central@demo.aicte.local` |
| Regional officer (Northern Region) | `north@demo.aicte.local` |
| Scrutiny officer | `scrutiny@demo.aicte.local` |
| Scrutiny officer (Western Region) | `west.scrutiny@demo.aicte.local` |
| EVC committee member | `evc@demo.aicte.local` |
| Institution administrator | `institution@demo.aicte.local` |

These credentials are for local demonstration only. Never reuse them in a deployed environment. The seed runs only when the database has no user records.

## Demonstration flow

1. Sign in as an institution, inspect its scoped applications, and register an application.
2. Sign in as the assigned scrutiny officer, open a case, and return it with a reason or complete scrutiny.
3. Sign in as the institution and resubmit a correction from the correction stage.
4. Complete scrutiny to move the demo route to EVC; schedule an EVC visit as a regional or central officer.
5. Submit compliance evidence from the institution account; verify or request correction as an authorised officer.
6. Upload a PDF/JPEG/PNG for human verification; inspect its expiry and status in the document registry.
7. Sign in as administrator and run `POST /api/admin/run-deadline-check` (Swagger UI or an authenticated API client) more than once. Uniqueness constraints prevent duplicate reminders.
8. As administrator, open Workflow studio, draft and publish a validated route. New applications can select a published route; existing applications retain their recorded version.
9. Inspect the audit trail and application timeline.

## Tests and checks

```powershell
cd backend
python -m pytest
cd ..
npm run typecheck
npm run build
```

The API tests cover session authentication, institution scope, invalid transitions, compliance submission and review, EVC scheduling conflicts, upload validation, audit history, and reminder idempotence.

## Security and operational notes

- Configure a high-entropy `APP_SECRET` and set `SECURE_COOKIE=true` behind HTTPS.
- Set `DATABASE_PATH`, `UPLOAD_DIR`, and `FRONTEND_ORIGIN` to managed, access-controlled locations.
- Use a managed identity provider, CSRF strategy appropriate to the deployment topology, rate limiting, malware scanning, object-storage access policies, database backups, and operational monitoring before production use.
- The frontend displays available controls, but the API is the authority for permission checks and workflow stage validation.
- Upload validation checks the extension, size and basic file signature; it is not a substitute for malware scanning or content disarm/reconstruction.
- Audit events are append-only through the API; database administrators can still alter the local SQLite file.
- Demonstration workflow routes are versioned and configurable from the administrator studio, but they are synthetic examples only. They are not official APH-derived rules. Production still needs an authorised policy governance process, pause/holiday calculations, and competent-authority statutory decisions.
- AI/OCR, external email/SMS, and official integrations are not enabled. No approval, rejection, or compliance determination is made autonomously.
