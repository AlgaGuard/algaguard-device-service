CREATE TABLE IF NOT EXISTS credential_bootstrap_sessions (
  authorization_id uuid PRIMARY KEY,
  device_uuid uuid NOT NULL REFERENCES devices(device_uuid),
  device_id text NOT NULL REFERENCES devices(device_id),
  token_hash text NOT NULL UNIQUE CHECK (token_hash ~ '^[0-9a-f]{64}$'),
  attempts_remaining integer NOT NULL CHECK (attempts_remaining BETWEEN 0 AND 20),
  created_by text NOT NULL,
  created_at timestamptz NOT NULL,
  expires_at timestamptz NOT NULL,
  consumed_at timestamptz,
  invalidated_at timestamptz,
  CHECK (expires_at > created_at)
);

CREATE UNIQUE INDEX IF NOT EXISTS one_active_credential_bootstrap
  ON credential_bootstrap_sessions(device_uuid)
  WHERE consumed_at IS NULL AND invalidated_at IS NULL;

CREATE TABLE IF NOT EXISTS device_credentials (
  credential_id uuid PRIMARY KEY,
  device_uuid uuid NOT NULL REFERENCES devices(device_uuid),
  device_id text NOT NULL REFERENCES devices(device_id),
  purpose text NOT NULL CHECK (purpose IN ('INITIAL','ROTATION','RECOVERY')),
  idempotency_key uuid NOT NULL,
  csr_fingerprint_sha256 text NOT NULL CHECK (csr_fingerprint_sha256 ~ '^[0-9a-f]{64}$'),
  certificate_serial text UNIQUE CHECK (certificate_serial IS NULL OR certificate_serial ~ '^[0-9A-F]{2,80}$'),
  fingerprint_sha256 text UNIQUE CHECK (fingerprint_sha256 IS NULL OR fingerprint_sha256 ~ '^[0-9a-f]{64}$'),
  certificate_pem text CHECK (certificate_pem IS NULL OR length(certificate_pem) BETWEEN 128 AND 16384),
  issuer_dn text,
  subject_dn text,
  san_uris text[] NOT NULL DEFAULT '{}',
  not_before timestamptz,
  not_after timestamptz,
  issued_at timestamptz,
  activated_at timestamptz,
  revoked_at timestamptz,
  revocation_reason text CHECK (
    revocation_reason IS NULL OR revocation_reason IN
      ('ROTATED','EXPIRED','COMPROMISED','ADMIN_REVOKED','DEVICE_RETIRED','ISSUANCE_ERROR','RECOVERY_REPLACED')
  ),
  status text NOT NULL CHECK (status IN ('PENDING','ACTIVE','ROTATING','REVOKED','EXPIRED','COMPROMISED','FAILED')),
  parent_credential_id uuid REFERENCES device_credentials(credential_id),
  child_credential_id uuid REFERENCES device_credentials(credential_id),
  rotation_id uuid,
  last_authenticated_at timestamptz,
  created_at timestamptz NOT NULL,
  updated_at timestamptz NOT NULL,
  UNIQUE (device_uuid, idempotency_key),
  CHECK (not_after IS NULL OR not_before IS NULL OR not_after > not_before),
  CHECK (cardinality(san_uris) <= 1)
);

CREATE INDEX IF NOT EXISTS device_credentials_history
  ON device_credentials(device_uuid, created_at DESC);
CREATE INDEX IF NOT EXISTS device_credentials_broker_lookup
  ON device_credentials(fingerprint_sha256)
  WHERE fingerprint_sha256 IS NOT NULL;

CREATE TABLE IF NOT EXISTS credential_rotations (
  rotation_id uuid PRIMARY KEY,
  device_uuid uuid NOT NULL REFERENCES devices(device_uuid),
  device_id text NOT NULL REFERENCES devices(device_id),
  current_credential_id uuid NOT NULL REFERENCES device_credentials(credential_id),
  new_credential_id uuid REFERENCES device_credentials(credential_id),
  requested_by text NOT NULL,
  request_key uuid NOT NULL,
  reason text NOT NULL CHECK (reason IN ('SCHEDULED','EXPIRING','ADMIN_REQUESTED','RECOVERY')),
  overlap_seconds integer NOT NULL CHECK (overlap_seconds BETWEEN 30 AND 86400),
  requested_at timestamptz NOT NULL,
  expires_at timestamptz NOT NULL,
  acknowledged_at timestamptz,
  status text NOT NULL CHECK (status IN ('REQUESTED','ISSUING','OVERLAP','COMPLETED','FAILED','EXPIRED')),
  failure_code text,
  created_at timestamptz NOT NULL,
  updated_at timestamptz NOT NULL,
  UNIQUE (device_uuid, request_key),
  CHECK (expires_at > requested_at)
);

CREATE UNIQUE INDEX IF NOT EXISTS one_active_credential_rotation
  ON credential_rotations(device_uuid)
  WHERE status IN ('REQUESTED','ISSUING','OVERLAP');

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint
     WHERE conname = 'device_credentials_rotation_id_fkey'
  ) THEN
    ALTER TABLE device_credentials
      ADD CONSTRAINT device_credentials_rotation_id_fkey
      FOREIGN KEY (rotation_id) REFERENCES credential_rotations(rotation_id);
  END IF;
END
$$;

CREATE TABLE IF NOT EXISTS credential_audit (
  audit_id uuid PRIMARY KEY,
  device_uuid uuid NOT NULL REFERENCES devices(device_uuid),
  device_id text NOT NULL,
  credential_id uuid REFERENCES device_credentials(credential_id),
  rotation_id uuid REFERENCES credential_rotations(rotation_id),
  action text NOT NULL,
  actor_type text NOT NULL CHECK (actor_type IN ('HUMAN','DEVICE','SERVICE','SYSTEM')),
  actor_id text NOT NULL,
  details jsonb NOT NULL DEFAULT '{}',
  occurred_at timestamptz NOT NULL
);

CREATE INDEX IF NOT EXISTS credential_audit_device_history
  ON credential_audit(device_uuid, occurred_at, audit_id);

CREATE OR REPLACE FUNCTION reject_credential_history_delete()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  RAISE EXCEPTION 'credential history is append-only' USING ERRCODE = '23514';
END
$$;

DROP TRIGGER IF EXISTS device_credentials_no_delete ON device_credentials;
CREATE TRIGGER device_credentials_no_delete
  BEFORE DELETE ON device_credentials
  FOR EACH ROW EXECUTE FUNCTION reject_credential_history_delete();

DROP TRIGGER IF EXISTS credential_rotations_no_delete ON credential_rotations;
CREATE TRIGGER credential_rotations_no_delete
  BEFORE DELETE ON credential_rotations
  FOR EACH ROW EXECUTE FUNCTION reject_credential_history_delete();

DROP TRIGGER IF EXISTS credential_audit_no_delete ON credential_audit;
CREATE TRIGGER credential_audit_no_delete
  BEFORE DELETE ON credential_audit
  FOR EACH ROW EXECUTE FUNCTION reject_credential_history_delete();
