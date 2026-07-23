DO $$
BEGIN
  IF EXISTS (
    SELECT 1 FROM information_schema.columns
     WHERE table_schema = current_schema() AND table_name = 'devices'
       AND column_name = 'id' AND data_type = 'uuid'
  ) AND to_regclass('devices_legacy') IS NULL THEN
    ALTER TABLE device_claims RENAME TO device_claims_legacy;
    ALTER TABLE devices RENAME TO devices_legacy;
  END IF;
END
$$;

CREATE SEQUENCE IF NOT EXISTS device_number_sequence MINVALUE 1 MAXVALUE 999999 NO CYCLE;

CREATE TABLE IF NOT EXISTS devices (
  device_id text PRIMARY KEY CHECK (device_id ~ '^AG-[0-9]{6}$'),
  organization_id uuid NOT NULL,
  tank_id uuid,
  hardware_model text NOT NULL,
  firmware_version text NOT NULL,
  lifecycle text NOT NULL CHECK (lifecycle IN ('UNCLAIMED','CLAIMED','PROVISIONING','PROVISIONED','REVOKED')),
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS devices_organization ON devices(organization_id, device_id);

CREATE TABLE IF NOT EXISTS device_claims (
  id uuid PRIMARY KEY,
  device_id text NOT NULL REFERENCES devices(device_id),
  token_hash text NOT NULL UNIQUE CHECK (token_hash ~ '^[0-9a-f]{64}$'),
  fallback_hash text NOT NULL UNIQUE CHECK (fallback_hash ~ '^[0-9a-f]{64}$'),
  expires_at timestamptz NOT NULL,
  consumed_at timestamptz,
  invalidated_at timestamptz,
  created_by text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX IF NOT EXISTS one_active_device_claim_v2
  ON device_claims(device_id)
  WHERE consumed_at IS NULL AND invalidated_at IS NULL;

CREATE TABLE IF NOT EXISTS bootstrap_sessions (
  id uuid PRIMARY KEY,
  device_id text NOT NULL REFERENCES devices(device_id),
  token_hash text NOT NULL UNIQUE CHECK (token_hash ~ '^[0-9a-f]{64}$'),
  expires_at timestamptz NOT NULL,
  consumed_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS claim_failures (
  id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  device_id text NOT NULL,
  subject_id text NOT NULL,
  attempted_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS claim_failures_window
  ON claim_failures(subject_id, device_id, attempted_at DESC);

CREATE TABLE IF NOT EXISTS device_transitions (
  id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  device_id text NOT NULL REFERENCES devices(device_id),
  from_lifecycle text,
  to_lifecycle text NOT NULL,
  actor_subject_id text NOT NULL,
  reason text NOT NULL,
  occurred_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS device_status_projection (
  device_id text PRIMARY KEY REFERENCES devices(device_id),
  status jsonb NOT NULL,
  observed_at timestamptz NOT NULL,
  updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS device_health_projection (
  device_id text PRIMARY KEY REFERENCES devices(device_id),
  health jsonb NOT NULL,
  observed_at timestamptz NOT NULL,
  updated_at timestamptz NOT NULL DEFAULT now()
);
