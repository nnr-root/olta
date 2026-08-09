package models

import (
	"errors"
	"fmt"
	"strings"

	"github.com/jinzhu/gorm"
)

// CampaignTemplateVariant associates a named A/B variant with one stored
// template for a campaign. Position provides stable recipient distribution.
type CampaignTemplateVariant struct {
	Id         int64         `json:"id"`
	CampaignId int64         `json:"-"`
	TemplateId int64         `json:"-"`
	Name       string        `json:"name"`
	Position   int           `json:"position"`
	Template   Template      `json:"template" gorm:"-"`
	Stats      CampaignStats `json:"stats" gorm:"-"`
}

var (
	// ErrTemplateVariantNotFound indicates a result references an unknown
	// campaign template variant.
	ErrTemplateVariantNotFound = errors.New("template variant not found")
	// ErrDuplicateTemplateVariant indicates that variant names are not unique.
	ErrDuplicateTemplateVariant = errors.New("template variant names must be unique")
)

// TemplateVariantName returns a spreadsheet-style deterministic label:
// Variant A, Variant B, ..., Variant Z, Variant AA.
func TemplateVariantName(index int) string {
	if index < 0 {
		return ""
	}
	label := ""
	for index >= 0 {
		label = string(rune('A'+index%26)) + label
		index = index/26 - 1
	}
	return "Variant " + label
}

// AssignTemplateVariant deterministically balances recipients across variants
// using round-robin assignment.
func AssignTemplateVariant(recipientIndex int, variants []CampaignTemplateVariant) (CampaignTemplateVariant, error) {
	if recipientIndex < 0 || len(variants) == 0 {
		return CampaignTemplateVariant{}, ErrTemplateVariantNotFound
	}
	return variants[recipientIndex%len(variants)], nil
}

func (c *Campaign) resolveTemplateVariants(uid int64) error {
	variants := append([]CampaignTemplateVariant(nil), c.TemplateVariants...)
	if len(variants) == 0 {
		variants = []CampaignTemplateVariant{{Name: TemplateVariantName(0), Template: c.Template}}
	}

	names := make(map[string]struct{}, len(variants))
	for index := range variants {
		if strings.TrimSpace(variants[index].Name) == "" {
			variants[index].Name = TemplateVariantName(index)
		}
		key := strings.ToLower(strings.TrimSpace(variants[index].Name))
		if _, exists := names[key]; exists {
			return ErrDuplicateTemplateVariant
		}
		names[key] = struct{}{}
		if variants[index].Template.Name == "" {
			return ErrTemplateNotSpecified
		}
		template, err := GetTemplateByName(variants[index].Template.Name, uid)
		if err == gorm.ErrRecordNotFound {
			return ErrTemplateNotFound
		}
		if err != nil {
			return err
		}
		variants[index].Template = template
		variants[index].TemplateId = template.Id
		variants[index].Position = index
	}

	c.TemplateVariants = variants
	c.Template = variants[0].Template
	c.TemplateId = variants[0].TemplateId
	return nil
}

func (c *Campaign) saveTemplateVariants(tx *gorm.DB) error {
	for index := range c.TemplateVariants {
		variant := &c.TemplateVariants[index]
		variant.CampaignId = c.Id
		variant.Position = index
		if err := tx.Table("campaign_template_variants").Save(variant).Error; err != nil {
			return err
		}
	}
	return nil
}

func (c *Campaign) loadTemplateVariants(includeStats bool) error {
	variants := []CampaignTemplateVariant{}
	if err := db.Table("campaign_template_variants").Where("campaign_id = ?", c.Id).Order("position ASC").Find(&variants).Error; err != nil {
		return err
	}
	for index := range variants {
		template := Template{}
		err := db.Table("templates").Where("id = ?", variants[index].TemplateId).Find(&template).Error
		if err != nil && err != gorm.ErrRecordNotFound {
			return err
		}
		if err == gorm.ErrRecordNotFound {
			template = Template{Name: "[Deleted]"}
		} else if err := db.Where("template_id = ?", template.Id).Find(&template.Attachments).Error; err != nil && err != gorm.ErrRecordNotFound {
			return err
		}
		variants[index].Template = template
		if includeStats {
			stats, err := getCampaignStatsForVariant(c.Id, variants[index].Id)
			if err != nil {
				return err
			}
			variants[index].Stats = stats
		}
	}
	c.TemplateVariants = variants
	return nil
}

// TemplateForVariant returns the template assigned to a persisted result.
func (c *Campaign) TemplateForVariant(variantID int64) (Template, error) {
	if variantID == 0 {
		return c.Template, nil
	}
	for _, variant := range c.TemplateVariants {
		if variant.Id == variantID {
			return variant.Template, nil
		}
	}
	return Template{}, fmt.Errorf("%w: %d", ErrTemplateVariantNotFound, variantID)
}
