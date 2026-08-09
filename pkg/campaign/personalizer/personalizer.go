package personalizer

import (
	"bytes"
	"text/template"
)

// Context contains the supported rule-based placeholder values.
type Context struct {
	FirstName   string
	LastName    string
	Position    string
	Department  string
	Role        string
	Company     string
	ManagerName string
	PhishingURL string
	Language    string
}

// Recipient contains locale and routing metadata for template selection.
type Recipient struct {
	Language   string
	Department string
	Position   string
	Role       string
}

// Options controls independent parts of personalization.
type Options struct {
	EnableSpintax     bool
	EnableRoleRouting bool
}

// Personalizer combines scenario routing, spintax, and placeholder rendering.
type Personalizer struct {
	options Options
	spintax *Spintax
	library *Library
}

// New creates a reusable, concurrency-safe personalizer.
func New(options Options) *Personalizer {
	return &Personalizer{options: options, spintax: NewSpintax(), library: defaultLibrary}
}

// NewWithSpintax creates a personalizer with an injected evaluator.
func NewWithSpintax(options Options, spintax *Spintax) *Personalizer {
	if spintax == nil {
		spintax = NewSpintax()
	}
	return &Personalizer{options: options, spintax: spintax, library: defaultLibrary}
}

// NewWithLibrary creates a personalizer using a loaded embedded/custom library.
func NewWithLibrary(options Options, library *Library) *Personalizer {
	if library == nil {
		library = defaultLibrary
	}
	return &Personalizer{options: options, spintax: NewSpintax(), library: library}
}

// Options reports the active feature switches.
func (p *Personalizer) Options() Options {
	if p == nil {
		return Options{}
	}
	return p.options
}

// Expand applies spintax when enabled.
func (p *Personalizer) Expand(input string) string {
	if p == nil || !p.options.EnableSpintax {
		return input
	}
	return p.spintax.Evaluate(input)
}

// SelectScenario selects one coherent built-in scenario for the recipient.
// The boolean is false when role routing is disabled.
func (p *Personalizer) SelectScenario(context Context) (ScenarioTemplate, bool) {
	if p == nil || !p.options.EnableRoleRouting {
		return ScenarioTemplate{}, false
	}
	return p.SelectTemplate(Recipient{
		Language: context.Language, Department: context.Department,
		Position: context.Position, Role: context.Role,
	})
}

// SelectTemplate chooses a localized category template for recipient.
func (p *Personalizer) SelectTemplate(recipient Recipient) (ScenarioTemplate, bool) {
	if p == nil || !p.options.EnableRoleRouting {
		return ScenarioTemplate{}, false
	}
	category := Route(RecipientMetadata{
		Department: recipient.Department,
		Position:   recipient.Position,
		Role:       recipient.Role,
	})
	library := p.library
	if library == nil {
		library = defaultLibrary
	}
	templates := library.Templates(recipient.Language, category)
	if len(templates) == 0 {
		return ScenarioTemplate{}, false
	}
	return templates[p.spintax.Intn(len(templates))], true
}

// SelectTemplate selects from the embedded locale library with role routing
// enabled. Callers needing custom templates should use a Personalizer instance.
func SelectTemplate(recipient Recipient) (ScenarioTemplate, bool) {
	return New(Options{EnableRoleRouting: true}).SelectTemplate(recipient)
}

// Personalize expands spintax and then evaluates supported placeholders.
func (p *Personalizer) Personalize(input string, context Context) (string, error) {
	return Substitute(p.Expand(input), context)
}

// Substitute evaluates supported placeholders using Go's template syntax.
func Substitute(input string, context Context) (string, error) {
	parsed, err := template.New("personalized-message").Option("missingkey=zero").Parse(input)
	if err != nil {
		return "", err
	}
	var output bytes.Buffer
	if err := parsed.Execute(&output, context); err != nil {
		return "", err
	}
	return output.String(), nil
}
