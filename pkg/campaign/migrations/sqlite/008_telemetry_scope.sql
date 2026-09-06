ALTER TABLE telemetry_events ADD COLUMN instance_id VARCHAR(32);
ALTER TABLE telemetry_events ADD COLUMN host VARCHAR(255);

CREATE INDEX IF NOT EXISTS idx_telemetry_events_instance_id ON telemetry_events(instance_id);
CREATE INDEX IF NOT EXISTS idx_telemetry_events_host ON telemetry_events(host);
