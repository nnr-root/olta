CREATE TABLE IF NOT EXISTS telemetry_events (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    event_id VARCHAR(32) NOT NULL,
    timestamp DATETIME NOT NULL,
    stage VARCHAR(32) NOT NULL,
    outcome VARCHAR(32) NOT NULL,
    techniques VARCHAR(255),
    campaign_id BIGINT,
    rid VARCHAR(255),
    actor TEXT,
    detail TEXT,
    UNIQUE KEY idx_telemetry_events_event_id (event_id),
    KEY idx_telemetry_events_campaign_id (campaign_id),
    KEY idx_telemetry_events_rid (rid),
    KEY idx_telemetry_events_timestamp (timestamp)
);
