-- Olta v1 unified SQLite schema.
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username VARCHAR(255) NOT NULL UNIQUE,
    hash VARCHAR(255),
    api_key VARCHAR(255) NOT NULL UNIQUE,
    role_id INTEGER,
    password_change_required BOOLEAN NOT NULL DEFAULT 0,
    account_locked BOOLEAN NOT NULL DEFAULT 0,
    last_login DATETIME
);

CREATE TABLE IF NOT EXISTS templates (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id BIGINT,
    name VARCHAR(255),
    envelope_sender VARCHAR(255),
    subject VARCHAR(255),
    text TEXT,
    html TEXT,
    modified_date DATETIME
);

CREATE TABLE IF NOT EXISTS attachments (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    template_id BIGINT,
    content TEXT,
    type VARCHAR(255),
    name VARCHAR(255)
);

CREATE TABLE IF NOT EXISTS targets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    first_name VARCHAR(255),
    last_name VARCHAR(255),
    email VARCHAR(255),
    position VARCHAR(255),
    department VARCHAR(255),
    role VARCHAR(255),
    company VARCHAR(255),
    manager_name VARCHAR(255)
);

CREATE TABLE IF NOT EXISTS groups (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id BIGINT,
    name VARCHAR(255),
    modified_date DATETIME
);

CREATE TABLE IF NOT EXISTS group_targets (group_id BIGINT, target_id BIGINT);

CREATE TABLE IF NOT EXISTS smtp (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id BIGINT,
    interface_type VARCHAR(255),
    name VARCHAR(255),
    host VARCHAR(255),
    username VARCHAR(255),
    password VARCHAR(255),
    from_address VARCHAR(255),
    modified_date DATETIME DEFAULT CURRENT_TIMESTAMP,
    ignore_cert_errors BOOLEAN NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS headers (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    key VARCHAR(255),
    value VARCHAR(255),
    smtp_id BIGINT
);

CREATE TABLE IF NOT EXISTS sms (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id BIGINT,
    name VARCHAR(255),
    twilio_account_sid VARCHAR(255),
    twilio_auth_token VARCHAR(255),
    sms_from VARCHAR(255),
    modified_date DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS campaigns (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id BIGINT,
    name VARCHAR(255) NOT NULL,
    created_date DATETIME,
    launch_date DATETIME,
    send_by_date DATETIME,
    completed_date DATETIME,
    template_id BIGINT,
    page_id BIGINT,
    status VARCHAR(255),
    smtp_id BIGINT,
    sms_id BIGINT,
    url VARCHAR(1000),
    qr_size VARCHAR(255),
    min_send_delay BIGINT NOT NULL DEFAULT 0,
    max_send_delay BIGINT NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS campaign_template_variants (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    campaign_id BIGINT NOT NULL,
    template_id BIGINT NOT NULL,
    name VARCHAR(255) NOT NULL,
    position INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS results (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    campaign_id BIGINT,
    user_id BIGINT,
    r_id VARCHAR(255),
    email VARCHAR(255),
    first_name VARCHAR(255),
    last_name VARCHAR(255),
    position VARCHAR(255),
    department VARCHAR(255),
    role VARCHAR(255),
    company VARCHAR(255),
    manager_name VARCHAR(255),
    status VARCHAR(255) NOT NULL,
    ip VARCHAR(255),
    latitude REAL,
    longitude REAL,
    send_date DATETIME,
    reported BOOLEAN NOT NULL DEFAULT 0,
    modified_date DATETIME,
    sms_target BOOLEAN NOT NULL DEFAULT 0,
    template_variant_id BIGINT NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    campaign_id BIGINT,
    email VARCHAR(255),
    time DATETIME,
    message VARCHAR(255),
    details BLOB
);

CREATE TABLE IF NOT EXISTS mail_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    campaign_id INTEGER,
    user_id INTEGER,
    send_date DATETIME,
    send_attempt INTEGER,
    r_id VARCHAR(255),
    processing BOOLEAN NOT NULL DEFAULT 0,
    target VARCHAR(255)
);

CREATE TABLE IF NOT EXISTS sms_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    campaign_id INTEGER,
    user_id INTEGER,
    send_date DATETIME,
    send_attempt INTEGER,
    r_id VARCHAR(255),
    processing BOOLEAN NOT NULL DEFAULT 0,
    target VARCHAR(255)
);

CREATE TABLE IF NOT EXISTS email_requests (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    template_id INTEGER,
    page_id INTEGER,
    first_name VARCHAR(255),
    last_name VARCHAR(255),
    email VARCHAR(255),
    position VARCHAR(255),
    department VARCHAR(255),
    role VARCHAR(255),
    company VARCHAR(255),
    manager_name VARCHAR(255),
    url VARCHAR(1000),
    r_id VARCHAR(255),
    from_address VARCHAR(255)
);

CREATE TABLE IF NOT EXISTS roles (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    slug VARCHAR(255) NOT NULL UNIQUE,
    name VARCHAR(255) NOT NULL UNIQUE,
    description VARCHAR(255)
);

CREATE TABLE IF NOT EXISTS permissions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    slug VARCHAR(255) NOT NULL UNIQUE,
    name VARCHAR(255) NOT NULL UNIQUE,
    description VARCHAR(255)
);

CREATE TABLE IF NOT EXISTS role_permissions (
    role_id INTEGER NOT NULL,
    permission_id INTEGER NOT NULL,
    PRIMARY KEY (role_id, permission_id)
);

CREATE TABLE IF NOT EXISTS webhooks (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name VARCHAR(255),
    url VARCHAR(1000),
    secret VARCHAR(255),
    is_active BOOLEAN NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS imap (
    user_id BIGINT,
    host VARCHAR(255),
    port INTEGER,
    username VARCHAR(255),
    password VARCHAR(255),
    modified_date DATETIME DEFAULT CURRENT_TIMESTAMP,
    tls BOOLEAN,
    enabled BOOLEAN,
    folder VARCHAR(255),
    restrict_domain VARCHAR(255),
    delete_reported_campaign_email BOOLEAN,
    last_login DATETIME,
    imap_freq INTEGER,
    ignore_cert_errors BOOLEAN
);

CREATE INDEX IF NOT EXISTS idx_templates_user_id ON templates(user_id);
CREATE INDEX IF NOT EXISTS idx_attachments_template_id ON attachments(template_id);
CREATE INDEX IF NOT EXISTS idx_groups_user_id ON groups(user_id);
CREATE INDEX IF NOT EXISTS idx_group_targets_group_id ON group_targets(group_id);
CREATE INDEX IF NOT EXISTS idx_group_targets_target_id ON group_targets(target_id);
CREATE INDEX IF NOT EXISTS idx_smtp_user_id ON smtp(user_id);
CREATE INDEX IF NOT EXISTS idx_headers_smtp_id ON headers(smtp_id);
CREATE INDEX IF NOT EXISTS idx_sms_user_id ON sms(user_id);
CREATE INDEX IF NOT EXISTS idx_campaigns_user_id ON campaigns(user_id);
CREATE INDEX IF NOT EXISTS idx_results_campaign_id ON results(campaign_id);
CREATE INDEX IF NOT EXISTS idx_campaign_template_variants_campaign_id ON campaign_template_variants(campaign_id);
CREATE UNIQUE INDEX IF NOT EXISTS idx_campaign_template_variants_position ON campaign_template_variants(campaign_id, position);
CREATE INDEX IF NOT EXISTS idx_results_template_variant_id ON results(template_variant_id);
CREATE UNIQUE INDEX IF NOT EXISTS idx_results_r_id ON results(r_id);
CREATE INDEX IF NOT EXISTS idx_events_campaign_id ON events(campaign_id);
CREATE INDEX IF NOT EXISTS idx_mail_logs_schedule ON mail_logs(processing, send_date);
CREATE INDEX IF NOT EXISTS idx_sms_logs_schedule ON sms_logs(processing, send_date);
CREATE INDEX IF NOT EXISTS idx_email_requests_r_id ON email_requests(r_id);

INSERT OR IGNORE INTO roles(slug, name, description) VALUES
    ('admin', 'Admin', 'Olta system administrator with full permissions'),
    ('user', 'User', 'Olta user with campaign and object permissions');

INSERT OR IGNORE INTO permissions(slug, name, description) VALUES
    ('view_objects', 'View Objects', 'View objects in Olta'),
    ('modify_objects', 'Modify Objects', 'Create and edit objects in Olta'),
    ('modify_system', 'Modify System', 'Manage Olta system-wide configuration');

INSERT OR IGNORE INTO role_permissions(role_id, permission_id)
SELECT roles.id, permissions.id FROM roles, permissions
WHERE roles.slug IN ('admin', 'user') AND permissions.slug IN ('view_objects', 'modify_objects');

INSERT OR IGNORE INTO role_permissions(role_id, permission_id)
SELECT roles.id, permissions.id FROM roles, permissions
WHERE roles.slug = 'admin' AND permissions.slug = 'modify_system';
