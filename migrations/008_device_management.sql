ALTER TABLE devices
  ADD COLUMN IF NOT EXISTS display_name text;

ALTER TABLE devices
  DROP CONSTRAINT IF EXISTS devices_display_name_shape;

ALTER TABLE devices
  ADD CONSTRAINT devices_display_name_shape
  CHECK (
    display_name IS NULL OR (
      char_length(display_name) BETWEEN 1 AND 64
      AND display_name = btrim(display_name)
      AND display_name !~ '[[:cntrl:]]'
    )
  );
