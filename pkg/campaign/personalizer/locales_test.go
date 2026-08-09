package personalizer

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestEmbeddedLocalesLoad(t *testing.T) {
	library, err := LoadLibrary("")
	if err != nil {
		t.Fatalf("LoadLibrary() error = %v", err)
	}
	for _, language := range []string{"tr", "en", "de", "es"} {
		for _, category := range []Category{
			StudentScenarioCategory, GeneralHRScenarioCategory,
			FinanceScenarioCategory, ITScenarioCategory,
		} {
			templates := library.Templates(language, category)
			if len(templates) < 2 {
				t.Fatalf("Templates(%q, %q) count = %d, want at least 2", language, category, len(templates))
			}
			if templates[0].Language != language || templates[0].Category != category {
				t.Fatalf("template metadata = %q/%q, want %q/%q", templates[0].Language, templates[0].Category, language, category)
			}
		}
	}
}

func TestLocalizedTemplateSelectionAndFallbacks(t *testing.T) {
	engine := New(Options{EnableRoleRouting: true})
	tests := []struct {
		name      string
		recipient Recipient
		language  string
		category  Category
	}{
		{name: "Turkish finance", recipient: Recipient{Language: "tr-TR", Department: "Finans"}, language: "tr", category: FinanceScenarioCategory},
		{name: "German IT", recipient: Recipient{Language: "de", Position: "Software Engineering"}, language: "de", category: ITScenarioCategory},
		{name: "Spanish student", recipient: Recipient{Language: "es", Role: "student"}, language: "es", category: StudentScenarioCategory},
		{name: "unknown language defaults to English HR", recipient: Recipient{Language: "fr", Department: "Sales"}, language: "en", category: GeneralHRScenarioCategory},
		{name: "empty language defaults to English", recipient: Recipient{Position: "Accounting"}, language: "en", category: FinanceScenarioCategory},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			template, ok := engine.SelectTemplate(test.recipient)
			if !ok {
				t.Fatal("SelectTemplate() returned no template")
			}
			if template.Language != test.language || template.Category != test.category {
				t.Fatalf("selected %q/%q, want %q/%q", template.Language, template.Category, test.language, test.category)
			}
		})
	}
}

func TestLibraryFallsBackToLocalizedHR(t *testing.T) {
	library := &Library{templates: map[string]map[Category][]ScenarioTemplate{
		"de": {
			GeneralHRScenarioCategory: {{ID: "de-fallback", Language: "de", Category: GeneralHRScenarioCategory, Subject: "HR", Text: "Body"}},
		},
	}}
	templates := library.Templates("de", FinanceScenarioCategory)
	if len(templates) != 1 || templates[0].ID != "de-fallback" {
		t.Fatalf("localized fallback = %+v, want de-fallback", templates)
	}
}

func TestCustomLocaleOverridesEmbeddedCategory(t *testing.T) {
	directory := t.TempDir()
	if err := os.MkdirAll(filepath.Join(directory, "de"), 0o755); err != nil {
		t.Fatal(err)
	}
	definition := `{
  "language":"de",
  "category":"it",
  "templates":[{"id":"custom-de-it","name":"Custom","variant":"A","subject":"Eigener Betreff","text":"Eigener Text","html":""}]
}`
	if err := os.WriteFile(filepath.Join(directory, "de", "it.json"), []byte(definition), 0o600); err != nil {
		t.Fatal(err)
	}
	library, err := LoadLibrary(directory)
	if err != nil {
		t.Fatalf("LoadLibrary(custom) error = %v", err)
	}
	custom := library.Templates("de", ITScenarioCategory)
	if len(custom) != 1 || custom[0].ID != "custom-de-it" {
		t.Fatalf("custom templates = %+v", custom)
	}
	if embedded := library.Templates("es", ITScenarioCategory); len(embedded) == 0 || !strings.HasPrefix(embedded[0].ID, "es-") {
		t.Fatalf("unmodified embedded locale missing: %+v", embedded)
	}
}
