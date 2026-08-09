ALTER TABLE `campaigns` ADD COLUMN `min_send_delay` BIGINT NOT NULL DEFAULT 0;
ALTER TABLE `campaigns` ADD COLUMN `max_send_delay` BIGINT NOT NULL DEFAULT 0;
ALTER TABLE `results` ADD COLUMN `template_variant_id` BIGINT NOT NULL DEFAULT 0;

CREATE TABLE IF NOT EXISTS `campaign_template_variants` (
    `id` BIGINT PRIMARY KEY AUTO_INCREMENT,
    `campaign_id` BIGINT NOT NULL,
    `template_id` BIGINT NOT NULL,
    `name` VARCHAR(255) NOT NULL,
    `position` INTEGER NOT NULL,
    INDEX `idx_campaign_template_variants_campaign_id` (`campaign_id`),
    UNIQUE INDEX `idx_campaign_template_variants_position` (`campaign_id`, `position`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

INSERT INTO `campaign_template_variants` (`campaign_id`, `template_id`, `name`, `position`)
SELECT campaigns.id, campaigns.template_id, 'Variant A', 0
FROM `campaigns`
LEFT JOIN `campaign_template_variants`
    ON campaign_template_variants.campaign_id = campaigns.id
WHERE COALESCE(campaigns.smtp_id, 0) != 0
  AND campaign_template_variants.id IS NULL;

UPDATE `results`
JOIN `campaign_template_variants`
    ON campaign_template_variants.campaign_id = results.campaign_id
   AND campaign_template_variants.position = 0
SET results.template_variant_id = campaign_template_variants.id
WHERE results.sms_target = FALSE AND results.template_variant_id = 0;

CREATE INDEX `idx_results_template_variant_id` ON `results` (`template_variant_id`);
