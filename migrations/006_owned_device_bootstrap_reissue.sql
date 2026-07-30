ALTER TABLE bootstrap_sessions
  ADD COLUMN IF NOT EXISTS invalidated_at timestamptz;

UPDATE bootstrap_sessions
   SET invalidated_at = now()
 WHERE consumed_at IS NULL
   AND invalidated_at IS NULL
   AND expires_at <= now();

CREATE UNIQUE INDEX IF NOT EXISTS one_open_bootstrap_session_per_device
  ON bootstrap_sessions(device_id)
  WHERE consumed_at IS NULL AND invalidated_at IS NULL;
