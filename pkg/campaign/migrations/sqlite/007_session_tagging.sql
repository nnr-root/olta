ALTER TABLE results ADD COLUMN tag VARCHAR(120);
ALTER TABLE results ADD COLUMN notes VARCHAR(2000);
ALTER TABLE results ADD COLUMN session_status VARCHAR(32) NOT NULL DEFAULT 'untriaged';

CREATE INDEX IF NOT EXISTS idx_results_tag ON results(tag);
CREATE INDEX IF NOT EXISTS idx_results_session_status ON results(session_status);
