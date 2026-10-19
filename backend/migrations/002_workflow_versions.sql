BEGIN IMMEDIATE;

CREATE TABLE workflow_templates (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL UNIQUE,
  description TEXT NOT NULL,
  active_version_id TEXT
);

CREATE TABLE workflow_versions (
  id TEXT PRIMARY KEY,
  template_id TEXT NOT NULL REFERENCES workflow_templates(id),
  version INTEGER NOT NULL,
  stages_json TEXT NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('Draft', 'Published', 'Superseded')),
  created_by TEXT REFERENCES users(id),
  created_at TEXT NOT NULL,
  published_at TEXT,
  UNIQUE(template_id, version)
);
CREATE INDEX ix_workflow_versions_status ON workflow_versions(template_id, status, version);

ALTER TABLE applications ADD COLUMN workflow_version_id TEXT REFERENCES workflow_versions(id);
ALTER TABLE applications ADD COLUMN return_to_stage TEXT;

INSERT INTO workflow_templates(id,name,description)
VALUES
  ('workflow-evc','Scrutiny, EVC and committee','Demonstration route with an expert visit and committee review.'),
  ('workflow-standard','Scrutiny and committee','Demonstration route without an EVC stage.'),
  ('workflow-direct','Scrutiny only','Demonstration route with direct completion after scrutiny.');

INSERT INTO workflow_versions(id,template_id,version,stages_json,status,created_at,published_at)
VALUES
  ('wf-evc-v1','workflow-evc',1,'["Scrutiny","EVC","Committee review","Completed"]','Published','2026-01-01T00:00:00+00:00','2026-01-01T00:00:00+00:00'),
  ('wf-standard-v1','workflow-standard',1,'["Scrutiny","Committee review","Completed"]','Published','2026-01-01T00:00:00+00:00','2026-01-01T00:00:00+00:00'),
  ('wf-direct-v1','workflow-direct',1,'["Scrutiny","Completed"]','Published','2026-01-01T00:00:00+00:00','2026-01-01T00:00:00+00:00');

UPDATE workflow_templates SET active_version_id='wf-evc-v1' WHERE id='workflow-evc';
UPDATE workflow_templates SET active_version_id='wf-standard-v1' WHERE id='workflow-standard';
UPDATE workflow_templates SET active_version_id='wf-direct-v1' WHERE id='workflow-direct';
UPDATE applications SET workflow_version_id='wf-evc-v1' WHERE workflow_version_id IS NULL;
COMMIT;
