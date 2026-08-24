-- Olta v1 unified MySQL schema.
CREATE TABLE IF NOT EXISTS `users` (
    `id` BIGINT PRIMARY KEY AUTO_INCREMENT,
    `username` VARCHAR(255) NOT NULL UNIQUE,
    `hash` VARCHAR(255),
    `api_key` VARCHAR(255) NOT NULL UNIQUE,
    `api_key_hash` VARCHAR(64),
    `role_id` BIGINT,
    `password_change_required` BOOLEAN NOT NULL DEFAULT FALSE,
    `account_locked` BOOLEAN NOT NULL DEFAULT FALSE,
    `last_login` DATETIME,
    UNIQUE INDEX `idx_users_api_key_hash` (`api_key_hash`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS `templates` (
    `id` BIGINT PRIMARY KEY AUTO_INCREMENT,
    `user_id` BIGINT,
    `name` VARCHAR(255),
    `envelope_sender` VARCHAR(255),
    `subject` VARCHAR(255),
    `text` MEDIUMTEXT,
    `html` MEDIUMTEXT,
    `modified_date` DATETIME,
    INDEX `idx_templates_user_id` (`user_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS `attachments` (
    `id` BIGINT PRIMARY KEY AUTO_INCREMENT,
    `template_id` BIGINT,
    `content` LONGTEXT,
    `type` VARCHAR(255),
    `name` VARCHAR(255),
    INDEX `idx_attachments_template_id` (`template_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS `targets` (
    `id` BIGINT PRIMARY KEY AUTO_INCREMENT,
    `first_name` VARCHAR(255),
    `last_name` VARCHAR(255),
    `email` VARCHAR(255),
    `position` VARCHAR(255),
    `department` VARCHAR(255),
    `role` VARCHAR(255),
    `company` VARCHAR(255),
    `manager_name` VARCHAR(255),
    `language` VARCHAR(32)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS `groups` (
    `id` BIGINT PRIMARY KEY AUTO_INCREMENT,
    `user_id` BIGINT,
    `name` VARCHAR(255),
    `modified_date` DATETIME,
    INDEX `idx_groups_user_id` (`user_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS `group_targets` (
    `group_id` BIGINT,
    `target_id` BIGINT,
    INDEX `idx_group_targets_group_id` (`group_id`),
    INDEX `idx_group_targets_target_id` (`target_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS `smtp` (
    `id` BIGINT PRIMARY KEY AUTO_INCREMENT,
    `user_id` BIGINT,
    `interface_type` VARCHAR(255),
    `name` VARCHAR(255),
    `host` VARCHAR(255),
    `username` VARCHAR(255),
    `password` TEXT,
    `from_address` VARCHAR(255),
    `modified_date` DATETIME DEFAULT CURRENT_TIMESTAMP,
    `ignore_cert_errors` BOOLEAN NOT NULL DEFAULT FALSE,
    INDEX `idx_smtp_user_id` (`user_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS `headers` (
    `id` BIGINT PRIMARY KEY AUTO_INCREMENT,
    `key` VARCHAR(255),
    `value` VARCHAR(255),
    `smtp_id` BIGINT,
    INDEX `idx_headers_smtp_id` (`smtp_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS `sms` (
    `id` BIGINT PRIMARY KEY AUTO_INCREMENT,
    `user_id` BIGINT,
    `name` VARCHAR(255),
    `twilio_account_sid` VARCHAR(255),
    `twilio_auth_token` TEXT,
    `sms_from` VARCHAR(255),
    `modified_date` DATETIME DEFAULT CURRENT_TIMESTAMP,
    INDEX `idx_sms_user_id` (`user_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS `campaigns` (
    `id` BIGINT PRIMARY KEY AUTO_INCREMENT,
    `user_id` BIGINT,
    `name` VARCHAR(255) NOT NULL,
    `created_date` DATETIME,
    `launch_date` DATETIME,
    `send_by_date` DATETIME,
    `completed_date` DATETIME,
    `template_id` BIGINT,
    `page_id` BIGINT,
    `status` VARCHAR(255),
    `smtp_id` BIGINT,
    `sms_id` BIGINT,
    `url` VARCHAR(1000),
    `qr_size` VARCHAR(255),
    `min_send_delay` BIGINT NOT NULL DEFAULT 0,
    `max_send_delay` BIGINT NOT NULL DEFAULT 0,
    INDEX `idx_campaigns_user_id` (`user_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS `campaign_template_variants` (
    `id` BIGINT PRIMARY KEY AUTO_INCREMENT,
    `campaign_id` BIGINT NOT NULL,
    `template_id` BIGINT NOT NULL,
    `name` VARCHAR(255) NOT NULL,
    `position` INTEGER NOT NULL,
    INDEX `idx_campaign_template_variants_campaign_id` (`campaign_id`),
    UNIQUE INDEX `idx_campaign_template_variants_position` (`campaign_id`, `position`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS `results` (
    `id` BIGINT PRIMARY KEY AUTO_INCREMENT,
    `campaign_id` BIGINT,
    `user_id` BIGINT,
    `r_id` VARCHAR(255),
    `email` VARCHAR(255),
    `first_name` VARCHAR(255),
    `last_name` VARCHAR(255),
    `position` VARCHAR(255),
    `department` VARCHAR(255),
    `role` VARCHAR(255),
    `company` VARCHAR(255),
    `manager_name` VARCHAR(255),
    `language` VARCHAR(32),
    `status` VARCHAR(255) NOT NULL,
    `ip` VARCHAR(255),
    `latitude` DOUBLE,
    `longitude` DOUBLE,
    `send_date` DATETIME,
    `reported` BOOLEAN NOT NULL DEFAULT FALSE,
    `modified_date` DATETIME,
    `sms_target` BOOLEAN NOT NULL DEFAULT FALSE,
    `template_variant_id` BIGINT NOT NULL DEFAULT 0,
    INDEX `idx_results_campaign_id` (`campaign_id`),
    INDEX `idx_results_template_variant_id` (`template_variant_id`),
    UNIQUE INDEX `idx_results_r_id` (`r_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS `events` (
    `id` BIGINT PRIMARY KEY AUTO_INCREMENT,
    `campaign_id` BIGINT,
    `email` VARCHAR(255),
    `time` DATETIME,
    `message` VARCHAR(255),
    `details` BLOB,
    INDEX `idx_events_campaign_id` (`campaign_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS `mail_logs` (
    `id` BIGINT PRIMARY KEY AUTO_INCREMENT,
    `campaign_id` BIGINT,
    `user_id` BIGINT,
    `send_date` DATETIME,
    `send_attempt` INTEGER,
    `r_id` VARCHAR(255),
    `processing` BOOLEAN NOT NULL DEFAULT FALSE,
    `target` VARCHAR(255),
    INDEX `idx_mail_logs_schedule` (`processing`, `send_date`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS `sms_logs` (
    `id` BIGINT PRIMARY KEY AUTO_INCREMENT,
    `campaign_id` BIGINT,
    `user_id` BIGINT,
    `send_date` DATETIME,
    `send_attempt` INTEGER,
    `r_id` VARCHAR(255),
    `processing` BOOLEAN NOT NULL DEFAULT FALSE,
    `target` VARCHAR(255),
    INDEX `idx_sms_logs_schedule` (`processing`, `send_date`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS `email_requests` (
    `id` BIGINT PRIMARY KEY AUTO_INCREMENT,
    `user_id` BIGINT,
    `template_id` BIGINT,
    `page_id` BIGINT,
    `first_name` VARCHAR(255),
    `last_name` VARCHAR(255),
    `email` VARCHAR(255),
    `position` VARCHAR(255),
    `department` VARCHAR(255),
    `role` VARCHAR(255),
    `company` VARCHAR(255),
    `manager_name` VARCHAR(255),
    `language` VARCHAR(32),
    `url` VARCHAR(1000),
    `r_id` VARCHAR(255),
    `from_address` VARCHAR(255),
    INDEX `idx_email_requests_r_id` (`r_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS `roles` (
    `id` BIGINT PRIMARY KEY AUTO_INCREMENT,
    `slug` VARCHAR(255) NOT NULL UNIQUE,
    `name` VARCHAR(255) NOT NULL UNIQUE,
    `description` VARCHAR(255)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS `permissions` (
    `id` BIGINT PRIMARY KEY AUTO_INCREMENT,
    `slug` VARCHAR(255) NOT NULL UNIQUE,
    `name` VARCHAR(255) NOT NULL UNIQUE,
    `description` VARCHAR(255)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS `role_permissions` (
    `role_id` BIGINT NOT NULL,
    `permission_id` BIGINT NOT NULL,
    PRIMARY KEY (`role_id`, `permission_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS `webhooks` (
    `id` BIGINT PRIMARY KEY AUTO_INCREMENT,
    `name` VARCHAR(255),
    `url` VARCHAR(1000),
    `secret` TEXT,
    `is_active` BOOLEAN NOT NULL DEFAULT FALSE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS `imap` (
    `user_id` BIGINT,
    `host` VARCHAR(255),
    `port` INTEGER,
    `username` VARCHAR(255),
    `password` TEXT,
    `modified_date` DATETIME DEFAULT CURRENT_TIMESTAMP,
    `tls` BOOLEAN,
    `enabled` BOOLEAN,
    `folder` VARCHAR(255),
    `restrict_domain` VARCHAR(255),
    `delete_reported_campaign_email` BOOLEAN,
    `last_login` DATETIME,
    `imap_freq` INTEGER,
    `ignore_cert_errors` BOOLEAN
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

INSERT IGNORE INTO `roles` (`slug`, `name`, `description`) VALUES
    ('admin', 'Admin', 'Olta system administrator with full permissions'),
    ('user', 'User', 'Olta user with campaign and object permissions');

INSERT IGNORE INTO `permissions` (`slug`, `name`, `description`) VALUES
    ('view_objects', 'View Objects', 'View objects in Olta'),
    ('modify_objects', 'Modify Objects', 'Create and edit objects in Olta'),
    ('modify_system', 'Modify System', 'Manage Olta system-wide configuration');

INSERT IGNORE INTO `role_permissions` (`role_id`, `permission_id`)
SELECT roles.id, permissions.id FROM roles, permissions
WHERE roles.slug IN ('admin', 'user') AND permissions.slug IN ('view_objects', 'modify_objects');

INSERT IGNORE INTO `role_permissions` (`role_id`, `permission_id`)
SELECT roles.id, permissions.id FROM roles, permissions
WHERE roles.slug = 'admin' AND permissions.slug = 'modify_system';
