CREATE TABLE IF NOT EXISTS device_ownership_saga (
  saga_id uuid PRIMARY KEY,
  device_uuid uuid NOT NULL,
  saga_type text NOT NULL CHECK (saga_type IN (
    'DEVICE_CREATION','CLAIM_CONSUMPTION','OWNERSHIP_TRANSFER','PHYSICAL_UNPAIR_NOTIFY'
  )),
  from_organization_id uuid,
  to_organization_id uuid NOT NULL,
  event_id uuid,
  state text NOT NULL DEFAULT 'PENDING' CHECK (state IN (
    'PENDING','IN_FLIGHT','COMPLETED','COMPENSATING','COMPENSATED'
  )),
  attempts integer NOT NULL DEFAULT 0 CHECK (attempts >= 0),
  next_attempt_at timestamptz NOT NULL DEFAULT now(),
  locked_until timestamptz,
  last_error text,
  created_at timestamptz NOT NULL DEFAULT now(),
  completed_at timestamptz
);
CREATE INDEX IF NOT EXISTS device_ownership_saga_pending
  ON device_ownership_saga(state, next_attempt_at);
CREATE INDEX IF NOT EXISTS device_ownership_saga_device
  ON device_ownership_saga(device_uuid);

CREATE TABLE IF NOT EXISTS device_ownership_saga_transitions (
  id uuid PRIMARY KEY,
  saga_id uuid NOT NULL REFERENCES device_ownership_saga(saga_id),
  state text NOT NULL,
  occurred_at timestamptz NOT NULL DEFAULT now(),
  details jsonb NOT NULL DEFAULT '{}'::jsonb
);
CREATE INDEX IF NOT EXISTS device_ownership_saga_transitions_saga_time
  ON device_ownership_saga_transitions(saga_id, occurred_at);
