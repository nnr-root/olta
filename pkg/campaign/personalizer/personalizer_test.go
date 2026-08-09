package personalizer

import (
	"math/rand"
	"strings"
	"testing"
)

func TestSpintaxNestedExpansionAndRandomness(t *testing.T) {
	engine := NewSpintaxWithSource(rand.NewSource(42))
	input := `{Dear|Hello|{Hi|Greetings}} {{.FirstName}}, {action required|please review} on your {{.Department}} account.`
	outputs := make(map[string]struct{})
	for i := 0; i < 100; i++ {
		output := engine.Evaluate(input)
		if strings.ContainsAny(output, "{}|") {
			// Go template actions are the only braces that should remain.
			withoutTemplates := strings.ReplaceAll(strings.ReplaceAll(output, "{{.FirstName}}", ""), "{{.Department}}", "")
			if strings.ContainsAny(withoutTemplates, "{}|") {
				t.Fatalf("unexpanded spintax in %q", output)
			}
		}
		outputs[output] = struct{}{}
	}
	if len(outputs) < 4 {
		t.Fatalf("generated %d distinct outputs, want at least 4", len(outputs))
	}
}

func TestSpintaxPreservesTemplatesAndOrdinaryBraces(t *testing.T) {
	engine := NewSpintaxWithSource(rand.NewSource(1))
	input := `{{if .FirstName}}{{.FirstName}}{{end}} body { color: red; } {one|two}`
	output := engine.Evaluate(input)
	if !strings.Contains(output, `{{if .FirstName}}{{.FirstName}}{{end}}`) {
		t.Fatalf("Go template actions changed: %q", output)
	}
	if !strings.Contains(output, `{ color: red; }`) {
		t.Fatalf("ordinary braces changed: %q", output)
	}
	if strings.Contains(output, `{one|two}`) {
		t.Fatalf("spintax was not expanded: %q", output)
	}
}

func TestRoute(t *testing.T) {
	tests := []struct {
		name     string
		metadata RecipientMetadata
		want     Category
	}{
		{name: "student role", metadata: RecipientMetadata{Role: "Öğrenci"}, want: StudentScenarioCategory},
		{name: "faculty department", metadata: RecipientMetadata{Department: "Mühendislik Fakültesi"}, want: StudentScenarioCategory},
		{name: "finance position", metadata: RecipientMetadata{Position: "Senior Accounting Specialist"}, want: FinanceScenarioCategory},
		{name: "purchase department", metadata: RecipientMetadata{Department: "Satınalma"}, want: FinanceScenarioCategory},
		{name: "software role", metadata: RecipientMetadata{Role: "Software Engineering"}, want: ITScenarioCategory},
		{name: "short it token does not match word", metadata: RecipientMetadata{Position: "Auditor"}, want: GeneralHRScenarioCategory},
		{name: "fallback", metadata: RecipientMetadata{Department: "Sales", Position: "Representative"}, want: GeneralHRScenarioCategory},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := Route(test.metadata); got != test.want {
				t.Fatalf("Route(%+v) = %q, want %q", test.metadata, got, test.want)
			}
		})
	}
}

func TestSubstituteRichContext(t *testing.T) {
	context := Context{
		FirstName: "Ada", LastName: "Lovelace", Position: "Engineer",
		Department: "Software", Company: "Olta", ManagerName: "Grace Hopper",
		PhishingURL: "https://training.example.test/r/123",
	}
	input := `{{.FirstName}}|{{.LastName}}|{{.Position}}|{{.Department}}|{{.Company}}|{{.ManagerName}}|{{.PhishingURL}}`
	got, err := Substitute(input, context)
	if err != nil {
		t.Fatal(err)
	}
	want := `Ada|Lovelace|Engineer|Software|Olta|Grace Hopper|https://training.example.test/r/123`
	if got != want {
		t.Fatalf("Substitute() = %q, want %q", got, want)
	}
}

func TestBuiltInScenarioLibrary(t *testing.T) {
	wants := map[Category]int{
		StudentScenarioCategory:   4,
		GeneralHRScenarioCategory: 4,
		FinanceScenarioCategory:   2,
		ITScenarioCategory:        2,
	}
	for category, count := range wants {
		scenarios := Scenarios(category)
		if len(scenarios) != count {
			t.Fatalf("Scenarios(%q) count = %d, want %d", category, len(scenarios), count)
		}
		for _, scenario := range scenarios {
			if scenario.Subject == "" || scenario.Text == "" || scenario.HTML == "" {
				t.Fatalf("scenario %q has empty content", scenario.ID)
			}
		}
	}
}

func BenchmarkSpintaxEvaluate(b *testing.B) {
	engine := NewSpintaxWithSource(rand.NewSource(42))
	input := `{Dear|Hello|{Hi|Greetings}} {{.FirstName}}, {action required|please review} on your {{.Department}} account.`
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = engine.Evaluate(input)
	}
}
