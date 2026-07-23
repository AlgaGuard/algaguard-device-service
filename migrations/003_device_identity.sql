ALTER TABLE devices
  ADD COLUMN IF NOT EXISTS device_uuid uuid NOT NULL DEFAULT gen_random_uuid(),
  ADD COLUMN IF NOT EXISTS ownership_version bigint NOT NULL DEFAULT 1 CHECK (ownership_version > 0);

ALTER TABLE devices
  DROP CONSTRAINT IF EXISTS devices_device_id_key;
ALTER TABLE devices
  ADD CONSTRAINT devices_device_id_key UNIQUE (device_id);

DO $$
DECLARE
  foreign_key record;
  primary_key text;
BEGIN
  FOR foreign_key IN
    SELECT conrelid::regclass AS relation_name, conname
      FROM pg_constraint
     WHERE contype = 'f' AND confrelid = 'devices'::regclass
  LOOP
    EXECUTE format(
      'ALTER TABLE %s DROP CONSTRAINT %I',
      foreign_key.relation_name,
      foreign_key.conname
    );
  END LOOP;

  SELECT conname INTO primary_key
    FROM pg_constraint
   WHERE conrelid = 'devices'::regclass AND contype = 'p';
  IF primary_key IS NOT NULL THEN
    EXECUTE format('ALTER TABLE devices DROP CONSTRAINT %I', primary_key);
  END IF;
END
$$;

ALTER TABLE devices ADD CONSTRAINT devices_device_uuid_pkey PRIMARY KEY (device_uuid);

ALTER TABLE device_claims
  ADD CONSTRAINT device_claims_device_id_fkey FOREIGN KEY (device_id) REFERENCES devices(device_id);
ALTER TABLE bootstrap_sessions
  ADD CONSTRAINT bootstrap_sessions_device_id_fkey FOREIGN KEY (device_id) REFERENCES devices(device_id);
ALTER TABLE device_transitions
  ADD CONSTRAINT device_transitions_device_id_fkey FOREIGN KEY (device_id) REFERENCES devices(device_id);
ALTER TABLE device_status_projection
  ADD CONSTRAINT device_status_projection_device_id_fkey FOREIGN KEY (device_id) REFERENCES devices(device_id);
ALTER TABLE device_health_projection
  ADD CONSTRAINT device_health_projection_device_id_fkey FOREIGN KEY (device_id) REFERENCES devices(device_id);

ALTER TABLE devices DROP CONSTRAINT IF EXISTS devices_lifecycle_check;
ALTER TABLE devices
  ADD CONSTRAINT devices_lifecycle_check
  CHECK (lifecycle IN ('UNCLAIMED','CLAIMED','PROVISIONING','PROVISIONED','ACTIVE','INACTIVE','REVOKED'));

CREATE TABLE IF NOT EXISTS device_ownership_history (
  id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  device_uuid uuid NOT NULL REFERENCES devices(device_uuid),
  device_id text NOT NULL,
  previous_organization_id uuid NOT NULL,
  organization_id uuid NOT NULL,
  ownership_version bigint NOT NULL CHECK (ownership_version > 0),
  actor_subject_id text NOT NULL,
  occurred_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS device_ownership_history_device
  ON device_ownership_history(device_uuid, ownership_version DESC);

CREATE OR REPLACE FUNCTION reject_device_id_change()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF NEW.device_id IS DISTINCT FROM OLD.device_id THEN
    RAISE EXCEPTION 'device_id is immutable' USING ERRCODE = '23514';
  END IF;
  RETURN NEW;
END
$$;

DROP TRIGGER IF EXISTS devices_device_id_immutable ON devices;
CREATE TRIGGER devices_device_id_immutable
  BEFORE UPDATE OF device_id ON devices
  FOR EACH ROW EXECUTE FUNCTION reject_device_id_change();
