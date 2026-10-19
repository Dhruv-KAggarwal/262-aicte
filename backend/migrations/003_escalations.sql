BEGIN IMMEDIATE;

CREATE TABLE escalation_events (
  id TEXT PRIMARY KEY,
  entity_type TEXT NOT NULL,
  entity_id TEXT NOT NULL,
  reason TEXT NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('Open', 'Resolved')),
  created_at TEXT NOT NULL,
  resolved_at TEXT,
  resolved_by TEXT REFERENCES users(id),
  UNIQUE(entity_type, entity_id)
);
CREATE INDEX ix_escalations_status_time ON escalation_events(status, created_at);
COMMIT;
