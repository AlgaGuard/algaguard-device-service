ALTER TABLE credential_bootstrap_sessions
  ADD COLUMN IF NOT EXISTS organization_id uuid,
  ADD COLUMN IF NOT EXISTS ownership_version bigint,
  ADD COLUMN IF NOT EXISTS claim_session_id uuid,
  ADD COLUMN IF NOT EXISTS purpose text NOT NULL DEFAULT 'CSR_ISSUE',
  ADD COLUMN IF NOT EXISTS contract_version text NOT NULL DEFAULT '1.0.0';

ALTER TABLE credential_bootstrap_sessions
  ADD CONSTRAINT credential_bootstrap_purpose_check
  CHECK (purpose = 'CSR_ISSUE') NOT VALID;

CREATE UNIQUE INDEX IF NOT EXISTS credential_bootstrap_claim_session_unique
  ON credential_bootstrap_sessions(claim_session_id)
  WHERE claim_session_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS credential_bootstrap_token_expiry_lookup
  ON credential_bootstrap_sessions(token_hash, expires_at)
  WHERE consumed_at IS NULL AND invalidated_at IS NULL;
