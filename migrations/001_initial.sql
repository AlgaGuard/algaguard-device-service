CREATE TABLE devices (id uuid PRIMARY KEY, organization_id uuid, tank_id uuid, status text NOT NULL, hardware_model text NOT NULL, created_at timestamptz NOT NULL DEFAULT now());
CREATE TABLE device_claims (id uuid PRIMARY KEY, device_id uuid NOT NULL REFERENCES devices(id), code_hash text NOT NULL, expires_at timestamptz NOT NULL, consumed_at timestamptz);
CREATE UNIQUE INDEX one_active_device_claim ON device_claims(device_id) WHERE consumed_at IS NULL;

