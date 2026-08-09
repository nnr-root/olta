package personalizer

import "strings"

// RecipientMetadata contains the rule inputs used by the category router.
type RecipientMetadata struct {
	Department string
	Position   string
	Role       string
}

var categoryKeywords = []struct {
	category Category
	values   map[string]struct{}
}{
	{StudentScenarioCategory, keywordSet("student", "ogrenci", "fakulte")},
	{FinanceScenarioCategory, keywordSet("finance", "muhasebe", "finans", "accounting", "satinalma")},
	{ITScenarioCategory, keywordSet("it", "software", "yazilim", "devops", "engineering", "sistem")},
}

// Route selects a scenario category from department, position, and role. It
// uses token matching so short keys such as "it" do not match unrelated words.
func Route(metadata RecipientMetadata) Category {
	tokens := metadataTokens(metadata)
	for _, rule := range categoryKeywords {
		for token := range tokens {
			for keyword := range rule.values {
				if token == keyword || (len(keyword) > 3 && strings.HasPrefix(token, keyword)) {
					return rule.category
				}
			}
		}
	}
	return GeneralHRScenarioCategory
}

// RouteCategory is a convenience wrapper for callers with separate fields.
func RouteCategory(department, position, role string) Category {
	return Route(RecipientMetadata{Department: department, Position: position, Role: role})
}

func metadataTokens(metadata RecipientMetadata) map[string]struct{} {
	normalized := normalize(strings.Join([]string{metadata.Department, metadata.Position, metadata.Role}, " "))
	tokens := make(map[string]struct{})
	for _, token := range strings.FieldsFunc(normalized, func(r rune) bool {
		return !(r >= 'a' && r <= 'z') && !(r >= '0' && r <= '9')
	}) {
		tokens[token] = struct{}{}
	}
	return tokens
}

func normalize(value string) string {
	value = strings.ToLower(value)
	return strings.NewReplacer(
		"ç", "c", "ğ", "g", "ı", "i", "ö", "o", "ş", "s", "ü", "u",
		"â", "a", "î", "i", "û", "u",
	).Replace(value)
}

func keywordSet(values ...string) map[string]struct{} {
	result := make(map[string]struct{}, len(values))
	for _, value := range values {
		result[value] = struct{}{}
	}
	return result
}
