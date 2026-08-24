ALTER TABLE users ADD COLUMN api_key_hash VARCHAR(64);
CREATE UNIQUE INDEX IF NOT EXISTS idx_users_api_key_hash ON users(api_key_hash);
