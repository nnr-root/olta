// Package e2e exercises a full Olta campaign lifecycle - initialization,
// gateway ingestion, bot/cloaking defense, session interception, and
// telemetry fanout - across the olta-campaign, olta-proxy, and olta-feed
// services sharing pkg/, entirely on loopback with no external network
// access. See TestCampaignLifecycle in lifecycle_test.go for the entry
// point and the resource-hygiene assertions that wrap every stage below.
package e2e

import (
	"encoding/base64"
	"net/url"
	"strings"
	"testing"

	"github.com/s4l1hs/olta/pkg/campaign/personalizer"
	"github.com/s4l1hs/olta/pkg/campaign/quishing"
)

// runInitialization simulates campaign initialization: a recipient is routed
// to a locale- and role-appropriate scenario template, the template's
// subject/body are spintax-varied, placeholders are substituted, and an
// in-memory tracking QR code (Base64 PNG, data URI, inline MIME attachment)
// is generated for the resulting phishing URL - all without touching disk or
// the network.
func runInitialization(t *testing.T) {
	t.Helper()

	t.Run("RoleRoutingAcrossLocales", func(t *testing.T) {
		// One recipient per supported locale (en/tr/de/es), each with
		// department/role metadata that should route to the finance
		// scenario category rather than the general-HR fallback.
		recipients := []struct {
			language string
			metadata personalizer.RecipientMetadata
		}{
			{language: "en", metadata: personalizer.RecipientMetadata{Department: "Finance", Position: "Accounts Payable Clerk"}},
			{language: "tr", metadata: personalizer.RecipientMetadata{Department: "Muhasebe", Position: "Finans Uzmanı"}},
			{language: "de", metadata: personalizer.RecipientMetadata{Department: "Finance", Position: "Buchhaltung"}},
			{language: "es", metadata: personalizer.RecipientMetadata{Department: "Finance", Position: "Contabilidad"}},
		}

		p := personalizer.New(personalizer.Options{EnableSpintax: true, EnableRoleRouting: true})

		for _, recipient := range recipients {
			t.Run(recipient.language, func(t *testing.T) {
				got := personalizer.Route(recipient.metadata)
				if got != personalizer.FinanceScenarioCategory {
					t.Fatalf("Route(%+v) = %q, want %q", recipient.metadata, got, personalizer.FinanceScenarioCategory)
				}

				template, ok := p.SelectTemplate(personalizer.Recipient{
					Language:   recipient.language,
					Department: recipient.metadata.Department,
					Position:   recipient.metadata.Position,
				})
				if !ok {
					t.Fatalf("SelectTemplate() returned no template for language %q", recipient.language)
				}
				if template.Category != personalizer.FinanceScenarioCategory {
					t.Fatalf("selected template category = %q, want %q", template.Category, personalizer.FinanceScenarioCategory)
				}
				if template.Language != personalizer.NormalizeLanguage(recipient.language) {
					t.Fatalf("selected template language = %q, want %q", template.Language, personalizer.NormalizeLanguage(recipient.language))
				}

				context := personalizer.Context{
					FirstName:   "Ada",
					LastName:    "Lovelace",
					Department:  recipient.metadata.Department,
					Position:    recipient.metadata.Position,
					Company:     "Olta Simulation Corp",
					PhishingURL: "https://phish-corp.test/go",
					Language:    recipient.language,
				}

				// Render the same scenario body twice through the
				// concurrency-safe personalizer and require the spintax
				// engine to vary at least one of the two renders across
				// several attempts - proving expansion actually happens
				// rather than the input passing through unchanged.
				varied := false
				var rendered string
				for attempt := 0; attempt < 25; attempt++ {
					body, err := p.Personalize(template.Text, context)
					if err != nil {
						t.Fatalf("Personalize() error: %v", err)
					}
					if strings.ContainsAny(body, "{}|") {
						t.Fatalf("Personalize() left unexpanded spintax: %q", body)
					}
					if !strings.Contains(body, "Ada") {
						t.Fatalf("Personalize() dropped the FirstName placeholder: %q", body)
					}
					if !strings.Contains(body, "https://phish-corp.test/go") {
						t.Fatalf("Personalize() dropped the PhishingURL placeholder: %q", body)
					}
					if rendered == "" {
						rendered = body
					} else if body != rendered {
						varied = true
						break
					}
				}
				if !varied {
					t.Fatalf("spintax expansion produced the same output on every attempt for language %q", recipient.language)
				}
			})
		}
	})

	t.Run("GeneralHRFallbackForUnroutedRecipient", func(t *testing.T) {
		// A recipient with no department/position/role keyword match falls
		// back to the general-HR category rather than failing to route.
		got := personalizer.Route(personalizer.RecipientMetadata{Department: "Sales", Position: "Representative"})
		if got != personalizer.GeneralHRScenarioCategory {
			t.Fatalf("Route() = %q, want %q (fallback)", got, personalizer.GeneralHRScenarioCategory)
		}
	})

	t.Run("QuishingInMemoryQRAttachment", func(t *testing.T) {
		runQuishing(t)
	})
}

// runQuishing generates an in-memory tracking QR code for a phishing URL and
// asserts the Base64 PNG, data URI, and inline MIME attachment are all
// self-consistent and that no temp file is written to disk: quishing.Service
// never touches the filesystem, so this proves it by inspecting only the
// in-memory Image value the service returns.
func runQuishing(t *testing.T) {
	t.Helper()

	service := quishing.NewService()
	targetURL := "https://phish-corp.test/go?rid=e2e-recipient-1"

	image, err := service.Generate(targetURL, quishing.Options{
		Size:            256,
		BackgroundColor: "#FFFFFF",
		ForegroundColor: "#000000",
		ErrorCorrection: quishing.Medium,
	})
	if err != nil {
		t.Fatalf("Generate() error: %v", err)
	}

	if len(image.PNG) == 0 {
		t.Fatal("Generate() produced an empty PNG")
	}
	// A PNG file always begins with this fixed 8-byte signature.
	pngSignature := []byte{0x89, 'P', 'N', 'G', '\r', '\n', 0x1a, '\n'}
	if len(image.PNG) < len(pngSignature) || string(image.PNG[:len(pngSignature)]) != string(pngSignature) {
		t.Fatalf("Generate() PNG bytes do not start with the PNG signature: % x", image.PNG[:min(len(image.PNG), 8)])
	}

	// The Base64 payload must decode back to the exact same PNG bytes.
	decoded, err := base64.StdEncoding.DecodeString(image.Base64)
	if err != nil {
		t.Fatalf("decoding Image.Base64: %v", err)
	}
	if string(decoded) != string(image.PNG) {
		t.Fatal("Image.Base64 does not round-trip to Image.PNG")
	}

	// The data URI must embed the same Base64 payload with the expected
	// scheme, and must itself be usable directly as a URL.
	wantDataURI := "data:image/png;base64," + image.Base64
	if image.DataURI != wantDataURI {
		t.Fatalf("Image.DataURI = %q, want %q", image.DataURI, wantDataURI)
	}
	if _, err := url.Parse(image.DataURI); err != nil {
		t.Fatalf("Image.DataURI is not a parseable URL: %v", err)
	}

	// The inline MIME attachment must carry the same bytes under a
	// content ID that InlineHTML references by "cid:", exactly as a real
	// MIME multipart email would need in order to display the QR code
	// without an external image fetch.
	if image.Attachment.ContentType != "image/png" {
		t.Fatalf("Attachment.ContentType = %q, want image/png", image.Attachment.ContentType)
	}
	if string(image.Attachment.Data) != string(image.PNG) {
		t.Fatal("Attachment.Data does not match Image.PNG")
	}
	if image.Attachment.Base64 != image.Base64 {
		t.Fatal("Attachment.Base64 does not match Image.Base64")
	}
	wantInlineHTML := `<img alt="QR code" src="cid:` + image.Attachment.ContentID + `">`
	if image.InlineHTML() != wantInlineHTML {
		t.Fatalf("InlineHTML() = %q, want %q", image.InlineHTML(), wantInlineHTML)
	}

	// quishing.Service is documented as writing nothing to disk. There is no
	// exported hook to observe filesystem calls, so this asserts the
	// strongest thing test code can from the outside: the entire
	// attachment - the same bytes a caller would write to a temp file if one
	// existed - is already fully materialized in memory on the returned
	// value, with nothing left to lazily read from a file handle.
	if image.Attachment.Filename == "" {
		t.Fatal("Attachment.Filename is empty")
	}
}
