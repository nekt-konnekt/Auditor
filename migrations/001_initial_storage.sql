-- Initial durable storage for Auditor reports and internal lead tracking.
-- Apply to the dedicated Auditor Neon database.

CREATE TABLE IF NOT EXISTS audit_reports (
  id text PRIMARY KEY,
  created_at timestamptz NOT NULL,
  target_url text NOT NULL,
  target_type text NOT NULL CHECK (target_type IN ('url', 'code')),
  verdict text NOT NULL CHECK (verdict IN ('Ready', 'Risky', 'Not ready')),
  overall_score integer NOT NULL CHECK (overall_score BETWEEN 0 AND 100),
  report jsonb NOT NULL,
  has_exposure_finding boolean NOT NULL DEFAULT false,
  is_unlisted boolean NOT NULL DEFAULT false,
  previous_report_id text REFERENCES audit_reports(id) ON DELETE SET NULL
);

CREATE INDEX IF NOT EXISTS audit_reports_created_at_idx
  ON audit_reports (created_at DESC);
CREATE INDEX IF NOT EXISTS audit_reports_target_url_idx
  ON audit_reports (target_url);
CREATE INDEX IF NOT EXISTS audit_reports_verdict_idx
  ON audit_reports (verdict);

CREATE TABLE IF NOT EXISTS audit_leads (
  audit_id text PRIMARY KEY REFERENCES audit_reports(id) ON DELETE CASCADE,
  status text NOT NULL DEFAULT 'Not contacted'
    CHECK (status IN ('Not contacted', 'Contacted', 'Replied', 'Interested in monitoring', 'Not interested')),
  owner_contact text,
  source_note text,
  contact_channel text,
  notes text,
  updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS audit_leads_status_idx
  ON audit_leads (status);
