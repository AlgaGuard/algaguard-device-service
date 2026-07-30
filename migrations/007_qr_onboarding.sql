CREATE TABLE IF NOT EXISTS qr_onboarding_nonces (
  nonce_hash char(64) PRIMARY KEY,
  device_id varchar(9) NOT NULL REFERENCES devices(device_id),
  organization_id uuid NOT NULL,
  ownership_version bigint NOT NULL,
  session_id uuid NOT NULL UNIQUE REFERENCES bootstrap_sessions(id),
  capability_version smallint NOT NULL CHECK (capability_version = 1),
  invitation_issued_at timestamptz NOT NULL,
  invitation_expires_at timestamptz NOT NULL,
  created_by text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  CHECK (nonce_hash ~ '^[0-9a-f]{64}$'),
  CHECK (invitation_expires_at > invitation_issued_at)
);

CREATE INDEX IF NOT EXISTS qr_onboarding_nonces_device_expiry_idx
  ON qr_onboarding_nonces(device_id, invitation_expires_at DESC);
