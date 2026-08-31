ALTER TABLE `results`
    ADD COLUMN `tag` VARCHAR(120),
    ADD COLUMN `notes` VARCHAR(2000),
    ADD COLUMN `session_status` VARCHAR(32) NOT NULL DEFAULT 'untriaged';

CREATE INDEX `idx_results_tag` ON `results` (`tag`);
CREATE INDEX `idx_results_session_status` ON `results` (`session_status`);
