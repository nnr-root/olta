ALTER TABLE `users` ADD COLUMN `api_key_hash` VARCHAR(64) NULL;
CREATE UNIQUE INDEX `idx_users_api_key_hash` ON `users` (`api_key_hash`);
ALTER TABLE `smtp` MODIFY COLUMN `password` TEXT;
ALTER TABLE `sms` MODIFY COLUMN `twilio_auth_token` TEXT;
ALTER TABLE `webhooks` MODIFY COLUMN `secret` TEXT;
ALTER TABLE `imap` MODIFY COLUMN `password` TEXT;
