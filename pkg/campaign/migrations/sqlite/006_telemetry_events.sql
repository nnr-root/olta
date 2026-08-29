CREATE TABLE IF NOT EXISTS telemetry_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id VARCHAR(32) NOT NULL,
    timestamp DATETIME NOT NULL,
    stage VARCHAR(32) NOT NULL,
    outcome VARCHAR(32) NOT NULL,
    techniques VARCHAR(255),
    campaign_id BIGINT,
    rid VARCHAR(255),
    actor TEXT,
    detail TEXT
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_telemetry_events_event_id ON telemetry_events(event_id);
CREATE INDEX IF NOT EXISTS idx_telemetry_events_campaign_id ON telemetry_events(campaign_id);
CREATE INDEX IF NOT EXISTS idx_telemetry_events_rid ON telemetry_events(rid);
CREATE INDEX IF NOT EXISTS idx_telemetry_events_timestamp ON telemetry_events(timestamp);
