ALTER TABLE campaigns ADD COLUMN min_send_delay BIGINT NOT NULL DEFAULT 0;
ALTER TABLE campaigns ADD COLUMN max_send_delay BIGINT NOT NULL DEFAULT 0;
ALTER TABLE results ADD COLUMN template_variant_id BIGINT NOT NULL DEFAULT 0;

CREATE TABLE IF NOT EXISTS campaign_template_variants (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    campaign_id BIGINT NOT NULL,
    template_id BIGINT NOT NULL,
    name VARCHAR(255) NOT NULL,
    position INTEGER NOT NULL
);

INSERT INTO campaign_template_variants (campaign_id, template_id, name, position)
SELECT campaigns.id, campaigns.template_id, 'Variant A', 0
FROM campaigns
WHERE COALESCE(campaigns.smtp_id, 0) != 0
  AND NOT EXISTS (
      SELECT 1 FROM campaign_template_variants
      WHERE campaign_template_variants.campaign_id = campaigns.id
  );

UPDATE results
SET template_variant_id = COALESCE((
    SELECT campaign_template_variants.id
    FROM campaign_template_variants
    WHERE campaign_template_variants.campaign_id = results.campaign_id
      AND campaign_template_variants.position = 0
), 0)
WHERE results.sms_target = 0 AND results.template_variant_id = 0;

CREATE INDEX IF NOT EXISTS idx_campaign_template_variants_campaign_id ON campaign_template_variants(campaign_id);
CREATE UNIQUE INDEX IF NOT EXISTS idx_campaign_template_variants_position ON campaign_template_variants(campaign_id, position);
CREATE INDEX IF NOT EXISTS idx_results_template_variant_id ON results(template_variant_id);
