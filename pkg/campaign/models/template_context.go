package models

import (
	"bytes"
	"net/mail"
	"net/url"
	"path"
	"text/template"

	"github.com/s4l1hs/olta/pkg/campaign/bitb"
	"github.com/s4l1hs/olta/pkg/campaign/evilginx"
	"github.com/s4l1hs/olta/pkg/campaign/oauthconsent"
)

// TemplateContext is an interface that allows both campaigns and email
// requests to have a PhishingTemplateContext generated for them.
type TemplateContext interface {
	getFromAddress() string
	getBaseURL() string
	getQRSize() string
}

// PhishingTemplateContext is the context that is sent to any template, such
// as the email or landing page content.
type PhishingTemplateContext struct {
	From        string
	URL         string
	Tracker     string
	TrackingURL string
	RId         string
	BaseURL     string
	QRBase64    string
	QRName      string
	QR          string
	QRCode      string
	RIdQR       string
	BaseRecipient
}

// BITBFrame renders an OS-aware simulated browser pop-up around the supplied
// address. It is available to campaign templates as {{.BITBFrame "https://..."}}.
func (p PhishingTemplateContext) BITBFrame(rawURL string) (string, error) {
	rendered, err := bitb.Render(rawURL)
	return string(rendered), err
}

// BITBFrameTheme renders a simulated browser pop-up with a fixed "windows11",
// "macos", or "linux" theme. The "auto" theme selects from the browser platform.
func (p PhishingTemplateContext) BITBFrameTheme(rawURL, theme string) (string, error) {
	rendered, err := bitb.RenderTheme(rawURL, bitb.Theme(theme))
	return string(rendered), err
}

// OAuthConsent renders a consent component. Scopes may be comma- or
// semicolon-separated OAuth identifiers or friendly permission names.
func (p PhishingTemplateContext) OAuthConsent(applicationName, publisherName, scopes, redirectURI string) (string, error) {
	metadata := oauthconsent.NewMetadata(
		applicationName,
		publisherName,
		oauthconsent.ParseScopeList(scopes),
		redirectURI,
	)
	rendered, err := oauthconsent.Render(metadata)
	return string(rendered), err
}

// NewPhishingTemplateContext returns a populated PhishingTemplateContext,
// parsing the correct fields from the provided TemplateContext and recipient.
func NewPhishingTemplateContext(ctx TemplateContext, r BaseRecipient, rid string) (PhishingTemplateContext, error) {
	f, err := mail.ParseAddress(ctx.getFromAddress())
	if err != nil {
		return PhishingTemplateContext{}, err
	}
	fn := f.Name
	if fn == "" {
		fn = f.Address
	}
	templateURL, err := ExecuteTemplate(ctx.getBaseURL(), r)
	if err != nil {
		return PhishingTemplateContext{}, err
	}

	// For the base URL, we'll reset the the path and the query
	// This will create a URL in the form of http://example.com
	baseURL, err := url.Parse(templateURL)
	if err != nil {
		return PhishingTemplateContext{}, err
	}
	baseURL.Path = ""
	baseURL.RawQuery = ""

	phishURL, _ := url.Parse(templateURL)
	q := phishURL.Query()
	phishURL.RawQuery = ""

	q.Set("fname", r.FirstName)
	q.Set("lname", r.LastName)
	q.Set("email", r.Email)
	q.Set("rid", rid)

	phishUrlString := evilginx.CreatePhishUrl(phishURL.String(), &q)

	trackingURL, _ := url.Parse(templateURL)
	q = trackingURL.Query()
	trackingURL.RawQuery = ""

	q.Set("rid", rid)
	q.Set("o", "track")

	trackerUrlString := evilginx.CreatePhishUrl(trackingURL.String(), &q)

	//fmt.Print(trackerUrlString)

	// Prepare QR code
	qrBase64 := ""
	qrName := ""
	qr := ""
	qrSize := ctx.getQRSize()
	if qrSize != "" {
		qrBase64, qrName, err = generateQRCode(phishUrlString, qrSize)
		if err != nil {
			return PhishingTemplateContext{}, err
		}
		qr = "<img src=\"cid:" + qrName + "\">"
	}

	return PhishingTemplateContext{
		BaseRecipient: r,
		BaseURL:       baseURL.String(),
		URL:           phishUrlString,
		TrackingURL:   trackerUrlString,
		Tracker:       "<img alt='' style='display: none' src='" + trackerUrlString + "'/>",
		From:          fn,
		RId:           rid,
		QRBase64:      qrBase64,
		QRName:        qrName,
		QR:            qr,
		QRCode:        qr,
		RIdQR:         qr,
	}, nil
}

// NewPhishingTemplateContext returns a populated PhishingTemplateContext,
// parsing the correct fields from the provided TemplateContext and recipient.
func NewPhishingTemplateContextSms(ctx TemplateContext, r BaseRecipient, rid string) (PhishingTemplateContext, error) {
	fn := ctx.getFromAddress()

	templateURL, err := ExecuteTemplate(ctx.getBaseURL(), r)
	if err != nil {
		return PhishingTemplateContext{}, err
	}

	// For the base URL, we'll reset the the path and the query
	// This will create a URL in the form of http://example.com
	baseURL, err := url.Parse(templateURL)
	if err != nil {
		return PhishingTemplateContext{}, err
	}
	baseURL.Path = ""
	baseURL.RawQuery = ""

	phishURL, _ := url.Parse(templateURL)
	q := phishURL.Query()
	q.Set(RecipientParameter, rid)
	phishURL.RawQuery = q.Encode()

	trackingURL, _ := url.Parse(templateURL)
	trackingURL.Path = path.Join(trackingURL.Path, "/track")
	trackingURL.RawQuery = q.Encode()

	// Prepare QR code
	qrBase64 := ""
	qrName := ""
	qr := ""
	qrSize := ctx.getQRSize()
	if qrSize != "" {
		qrBase64, qrName, err = generateQRCode(phishURL.String(), qrSize)
		if err != nil {
			return PhishingTemplateContext{}, err
		}
		qr = "<img src=\"cid:" + qrName + "\">"
	}

	return PhishingTemplateContext{
		BaseRecipient: r,
		BaseURL:       baseURL.String(),
		URL:           phishURL.String(),
		TrackingURL:   trackingURL.String(),
		Tracker:       "<img alt='' style='display: none' src='" + trackingURL.String() + "'/>",
		From:          fn,
		RId:           rid,
		QRBase64:      qrBase64,
		QRName:        qrName,
		QR:            qr,
		QRCode:        qr,
		RIdQR:         qr,
	}, nil
}

// ExecuteTemplate creates a templated string based on the provided
// template body and data.
func ExecuteTemplate(text string, data interface{}) (string, error) {
	buff := bytes.Buffer{}
	tmpl, err := template.New("template").Parse(text)
	if err != nil {
		return buff.String(), err
	}
	err = tmpl.Execute(&buff, data)
	return buff.String(), err
}

// ValidationContext is used for validating templates and pages
type ValidationContext struct {
	FromAddress string
	BaseURL     string
	QRSize      string
}

func (vc ValidationContext) getFromAddress() string {
	return vc.FromAddress
}

func (vc ValidationContext) getBaseURL() string {
	return vc.BaseURL
}

func (vc ValidationContext) getQRSize() string {
	return vc.QRSize
}

// ValidateTemplate ensures that the provided text in the page or template
// uses the supported template variables correctly.
func ValidateTemplate(text string) error {
	vc := ValidationContext{
		FromAddress: "foo@bar.com",
		BaseURL:     "http://example.com",
	}
	td := Result{
		BaseRecipient: BaseRecipient{
			Email:     "foo@bar.com",
			FirstName: "Foo",
			LastName:  "Bar",
			Position:  "Test",
		},
		RId: "123456",
	}
	ptx, err := NewPhishingTemplateContext(vc, td.BaseRecipient, td.RId)
	if err != nil {
		return err
	}
	_, err = ExecuteTemplate(text, ptx)
	if err != nil {
		return err
	}
	return nil
}
