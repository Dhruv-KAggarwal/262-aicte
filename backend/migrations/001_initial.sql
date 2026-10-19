PRAGMA foreign_keys = ON;
BEGIN IMMEDIATE;

CREATE TABLE users (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  email TEXT NOT NULL UNIQUE,
  password_hash TEXT NOT NULL,
  role TEXT NOT NULL,
  region_id TEXT,
  institution_id TEXT
);

CREATE TABLE institutions (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  code TEXT NOT NULL UNIQUE,
  region TEXT NOT NULL,
  city TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'Active'
);

CREATE TABLE applications (
  id TEXT PRIMARY KEY,
  institution_id TEXT NOT NULL REFERENCES institutions(id),
  reference TEXT NOT NULL UNIQUE,
  application_type TEXT NOT NULL,
  cycle TEXT NOT NULL,
  stage TEXT NOT NULL,
  status TEXT NOT NULL,
  submitted_at TEXT NOT NULL,
  due_at TEXT NOT NULL,
  assigned_to TEXT REFERENCES users(id),
  workflow_version INTEGER NOT NULL DEFAULT 1,
  summary TEXT NOT NULL DEFAULT '',
  updated_at TEXT NOT NULL
);
CREATE INDEX ix_applications_stage_due ON applications(stage, due_at);
CREATE INDEX ix_applications_institution ON applications(institution_id);

CREATE TABLE stage_events (
  id TEXT PRIMARY KEY,
  application_id TEXT NOT NULL REFERENCES applications(id),
  from_stage TEXT,
  to_stage TEXT NOT NULL,
  action TEXT NOT NULL,
  reason TEXT NOT NULL,
  actor_id TEXT NOT NULL REFERENCES users(id),
  created_at TEXT NOT NULL
);

CREATE TABLE compliance_obligations (
  id TEXT PRIMARY KEY,
  institution_id TEXT NOT NULL REFERENCES institutions(id),
  application_id TEXT REFERENCES applications(id),
  title TEXT NOT NULL,
  due_at TEXT NOT NULL,
  status TEXT NOT NULL,
  assigned_to TEXT REFERENCES users(id),
  submitted_at TEXT,
  evidence_name TEXT,
  updated_at TEXT NOT NULL
);
CREATE INDEX ix_compliance_due ON compliance_obligations(due_at, status);

CREATE TABLE institutional_documents (
  id TEXT PRIMARY KEY,
  institution_id TEXT NOT NULL REFERENCES institutions(id),
  category TEXT NOT NULL,
  file_name TEXT NOT NULL,
  expires_at TEXT,
  status TEXT NOT NULL,
  storage_key TEXT NOT NULL,
  uploaded_at TEXT NOT NULL,
  verified_by TEXT REFERENCES users(id),
  verified_at TEXT
);
CREATE INDEX ix_documents_expiry ON institutional_documents(expires_at, status);

CREATE TABLE evc_events (
  id TEXT PRIMARY KEY,
  application_id TEXT NOT NULL REFERENCES applications(id),
  scheduled_at TEXT NOT NULL,
  location TEXT NOT NULL,
  committee TEXT NOT NULL,
  status TEXT NOT NULL,
  created_by TEXT NOT NULL REFERENCES users(id),
  reason TEXT NOT NULL
);
CREATE INDEX ix_evc_schedule ON evc_events(committee, scheduled_at);

CREATE TABLE notifications (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id),
  title TEXT NOT NULL,
  body TEXT NOT NULL,
  category TEXT NOT NULL,
  related_id TEXT,
  created_at TEXT NOT NULL,
  read_at TEXT,
  UNIQUE(user_id, category, related_id)
);

CREATE TABLE audit_events (
  id TEXT PRIMARY KEY,
  actor_id TEXT NOT NULL REFERENCES users(id),
  action TEXT NOT NULL,
  entity_type TEXT NOT NULL,
  entity_id TEXT NOT NULL,
  reason TEXT NOT NULL,
  previous_state TEXT,
  new_state TEXT,
  created_at TEXT NOT NULL
);
CREATE INDEX ix_audit_entity ON audit_events(entity_type, entity_id);
CREATE INDEX ix_audit_time ON audit_events(created_at);
COMMIT;
