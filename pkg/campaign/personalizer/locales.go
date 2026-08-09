package personalizer

import (
	"embed"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

const DefaultLanguage = "en"

var supportedLanguages = map[string]struct{}{
	"tr": {},
	"en": {},
	"de": {},
	"es": {},
}

var localeCategories = map[string]Category{
	"student": StudentScenarioCategory,
	"hr":      GeneralHRScenarioCategory,
	"finance": FinanceScenarioCategory,
	"it":      ITScenarioCategory,
}

//go:embed locales/*/*.json
var embeddedLocaleFiles embed.FS

type localeDefinition struct {
	Language  string             `json:"language"`
	Category  string             `json:"category"`
	Templates []ScenarioTemplate `json:"templates"`
}

// Library stores immutable localized scenario collections.
type Library struct {
	templates map[string]map[Category][]ScenarioTemplate
}

// LoadLibrary loads the embedded library and optionally replaces individual
// language/category collections from customDir. A custom directory may contain
// either {lang}/{category}.json or locales/{lang}/{category}.json.
func LoadLibrary(customDir string) (*Library, error) {
	library := &Library{templates: make(map[string]map[Category][]ScenarioTemplate)}
	if err := library.load(embeddedLocaleFiles, "locales", false); err != nil {
		return nil, fmt.Errorf("load embedded localized templates: %w", err)
	}
	if strings.TrimSpace(customDir) == "" {
		return library, nil
	}
	root, err := filepath.Abs(customDir)
	if err != nil {
		return nil, fmt.Errorf("resolve custom templates directory: %w", err)
	}
	info, err := os.Stat(root)
	if err != nil {
		return nil, fmt.Errorf("open custom templates directory: %w", err)
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("custom templates path %q is not a directory", root)
	}
	prefix := "."
	if nested, statErr := os.Stat(filepath.Join(root, "locales")); statErr == nil && nested.IsDir() {
		prefix = "locales"
	}
	if err := library.load(os.DirFS(root), prefix, true); err != nil {
		return nil, fmt.Errorf("load custom localized templates: %w", err)
	}
	return library, nil
}

func (library *Library) load(files fs.FS, prefix string, replace bool) error {
	pattern := "*/*.json"
	if prefix != "." {
		pattern = strings.TrimSuffix(prefix, "/") + "/*/*.json"
	}
	paths, err := fs.Glob(files, pattern)
	if err != nil {
		return err
	}
	if len(paths) == 0 && replace {
		return fmt.Errorf("no locale JSON files found")
	}
	sort.Strings(paths)
	for _, name := range paths {
		contents, err := fs.ReadFile(files, name)
		if err != nil {
			return fmt.Errorf("read %s: %w", name, err)
		}
		var definition localeDefinition
		decoder := json.NewDecoder(strings.NewReader(string(contents)))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&definition); err != nil {
			return fmt.Errorf("decode %s: %w", name, err)
		}
		language := NormalizeLanguage(definition.Language)
		if language != strings.ToLower(strings.TrimSpace(definition.Language)) {
			return fmt.Errorf("%s declares unsupported language %q", name, definition.Language)
		}
		category, ok := localeCategories[strings.ToLower(strings.TrimSpace(definition.Category))]
		if !ok {
			return fmt.Errorf("%s declares unsupported category %q", name, definition.Category)
		}
		if len(definition.Templates) == 0 {
			return fmt.Errorf("%s contains no templates", name)
		}
		for index := range definition.Templates {
			template := &definition.Templates[index]
			if template.ID == "" || template.Subject == "" || (template.Text == "" && template.HTML == "") {
				return fmt.Errorf("%s template %d is incomplete", name, index)
			}
			template.Language = language
			template.Category = category
		}
		if library.templates[language] == nil {
			library.templates[language] = make(map[Category][]ScenarioTemplate)
		}
		if replace || len(library.templates[language][category]) == 0 {
			library.templates[language][category] = append([]ScenarioTemplate(nil), definition.Templates...)
		}
	}
	return nil
}

// Templates returns a copy of the localized templates, falling back to
// English and then general HR when needed.
func (library *Library) Templates(language string, category Category) []ScenarioTemplate {
	if library == nil {
		return nil
	}
	language = NormalizeLanguage(language)
	lookups := [][2]string{
		{language, string(category)},
		{language, string(GeneralHRScenarioCategory)},
		{DefaultLanguage, string(category)},
		{DefaultLanguage, string(GeneralHRScenarioCategory)},
	}
	for _, lookup := range lookups {
		items := library.templates[lookup[0]][Category(lookup[1])]
		if len(items) > 0 {
			return append([]ScenarioTemplate(nil), items...)
		}
	}
	return nil
}

// NormalizeLanguage converts BCP-47-like values to a supported base language.
func NormalizeLanguage(language string) string {
	language = strings.ToLower(strings.TrimSpace(language))
	if separator := strings.IndexAny(language, "-_"); separator >= 0 {
		language = language[:separator]
	}
	if _, ok := supportedLanguages[language]; !ok {
		return DefaultLanguage
	}
	return language
}

var defaultLibrary = func() *Library {
	library, err := LoadLibrary("")
	if err != nil {
		panic(err)
	}
	return library
}()
