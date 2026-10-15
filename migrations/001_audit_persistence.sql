-- Auditor durable report and lead-tracker storage.
-- These app-specific tables are separate from the pre-existing auditor_reports/auditor_leads tables.
CREATE TABLE IF NOT EXISTS public.audit_reports (
  id text PRIMARY KEY,
  created_at timestamptz NOT NULL,
  target_value text NOT NULL,
  target_type text NOT NULL,
  verdict text NOT NULL,
  overall_score integer NOT NULL,
  report jsonb NOT NULL,
  has_exposure_finding boolean NOT NULL DEFAULT false,
  is_unlisted boolean NOT NULL DEFAULT false
);

CREATE INDEX IF NOT EXISTS audit_reports_created_at_idx
  ON public.audit_reports (created_at DESC);

CREATE TABLE IF NOT EXISTS public.audit_leads (
  audit_id text PRIMARY KEY REFERENCES public.audit_reports(id) ON DELETE CASCADE,
  status text NOT NULL DEFAULT 'Not contacted',
  owner_contact text NOT NULL DEFAULT '',
  source_note text NOT NULL DEFAULT '',
  contact_channel text NOT NULL DEFAULT '',
  notes text NOT NULL DEFAULT '',
  updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS audit_leads_status_idx
  ON public.audit_leads (status);
