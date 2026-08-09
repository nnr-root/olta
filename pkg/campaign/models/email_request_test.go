package models

import (
	"bytes"
	"errors"
	"fmt"
	"math/rand"
	"regexp"
	"strings"

	"github.com/gophish/gomail"
	"github.com/jordan-wright/email"
	"github.com/s4l1hs/olta/pkg/campaign/personalizer"
	check "gopkg.in/check.v1"
)

func (s *ModelsSuite) TestEmailNotPresent(ch *check.C) {
	req := &EmailRequest{}
	ch.Assert(req.Validate(), check.Equals, ErrEmailNotSpecified)
	req.Email = "test@example.com"
	ch.Assert(req.Validate(), check.Equals, ErrFromAddressNotSpecified)
	req.FromAddress = "from@example.com"
	ch.Assert(req.Validate(), check.Equals, nil)
}

func (s *ModelsSuite) TestEmailRequestBackoff(ch *check.C) {
	req := &EmailRequest{
		ErrorChan: make(chan error),
	}
	expected := errors.New("Temporary Error")
	go func() {
		err := req.Backoff(expected)
		ch.Assert(err, check.Equals, nil)
	}()
	ch.Assert(<-req.ErrorChan, check.Equals, expected)
}

func (s *ModelsSuite) TestEmailRequestError(ch *check.C) {
	req := &EmailRequest{
		ErrorChan: make(chan error),
	}
	expected := errors.New("Temporary Error")
	go func() {
		err := req.Error(expected)
		ch.Assert(err, check.Equals, nil)
	}()
	ch.Assert(<-req.ErrorChan, check.Equals, expected)
}

func (s *ModelsSuite) TestEmailRequestSuccess(ch *check.C) {
	req := &EmailRequest{
		ErrorChan: make(chan error),
	}
	go func() {
		err := req.Success()
		ch.Assert(err, check.Equals, nil)
	}()
	ch.Assert(<-req.ErrorChan, check.Equals, nil)
}

func (s *ModelsSuite) TestEmailRequestGenerate(ch *check.C) {
	smtp := SMTP{
		FromAddress: "from@example.com",
	}
	template := Template{
		Name:    "Test Template",
		Subject: "{{.FirstName}} - Subject",
		Text:    "{{.Email}} - Text",
		HTML:    "{{.Email}} - HTML",
	}
	req := &EmailRequest{
		SMTP:     smtp,
		Template: template,
		BaseRecipient: BaseRecipient{
			FirstName: "First",
			LastName:  "Last",
			Email:     "firstlast@example.com",
		},
		FromAddress: smtp.FromAddress,
	}

	msg := gomail.NewMessage()
	err := req.Generate(msg)
	ch.Assert(err, check.Equals, nil)

	expected := &email.Email{
		Subject: fmt.Sprintf("%s - Subject", req.FirstName),
		Text:    []byte(fmt.Sprintf("%s - Text", req.Email)),
		HTML:    []byte(fmt.Sprintf("%s - HTML", req.Email)),
	}

	msgBuff := &bytes.Buffer{}
	_, err = msg.WriteTo(msgBuff)
	ch.Assert(err, check.Equals, nil)

	got, err := email.NewEmailFromReader(msgBuff)
	ch.Assert(err, check.Equals, nil)
	ch.Assert(got.Subject, check.Equals, expected.Subject)
	ch.Assert(string(got.Text), check.Equals, string(expected.Text))
	ch.Assert(string(got.HTML), check.Equals, string(expected.HTML))
}

func (s *ModelsSuite) TestEmailRequestGeneratePersonalized(ch *check.C) {
	req := &EmailRequest{
		SMTP:        SMTP{FromAddress: "from@example.com"},
		Template:    Template{Name: "Original", Subject: "Original subject", Text: "Original body"},
		URL:         "https://training.example.test/login",
		RId:         "preview-personalized",
		FromAddress: "from@example.com",
		BaseRecipient: BaseRecipient{
			FirstName: "Ada", LastName: "Lovelace", Email: "ada@example.com",
			Position: "Controller", Department: "Finance", Company: "Olta",
		},
	}
	engine := personalizer.NewWithSpintax(
		personalizer.Options{EnableSpintax: true, EnableRoleRouting: true},
		personalizer.NewSpintaxWithSource(rand.NewSource(42)),
	)
	msg := gomail.NewMessage()
	ch.Assert(req.GeneratePersonalized(msg, engine), check.IsNil)

	var raw bytes.Buffer
	_, err := msg.WriteTo(&raw)
	ch.Assert(err, check.IsNil)
	generated, err := email.NewEmailFromReader(bytes.NewReader(raw.Bytes()))
	ch.Assert(err, check.IsNil)
	ch.Assert(generated.Subject, check.Not(check.Equals), "Original subject")
	ch.Assert(strings.Contains(string(generated.Text), "Ada"), check.Equals, true)
	ch.Assert(strings.Contains(string(generated.Text), "training.example.test"), check.Equals, true)
	ch.Assert(strings.ContainsAny(generated.Subject, "{}|"), check.Equals, false)
}

func (s *ModelsSuite) TestEmailRequestGenerateQRCodeInline(ch *check.C) {
	req := &EmailRequest{
		SMTP: SMTP{FromAddress: "from@example.com"},
		Template: Template{
			Name: "QR Template",
			HTML: `<html><body>{{.QRCode}}</body></html>`,
		},
		URL:    "https://example.com/campaign",
		QRSize: "256",
		RId:    "recipient-qr-id",
		BaseRecipient: BaseRecipient{
			FirstName: "QR",
			LastName:  "Recipient",
			Email:     "qr@example.com",
		},
		FromAddress: "from@example.com",
	}
	msg := gomail.NewMessage()
	err := req.Generate(msg)
	ch.Assert(err, check.IsNil)
	var raw bytes.Buffer
	_, err = msg.WriteTo(&raw)
	ch.Assert(err, check.IsNil)

	parsed, err := email.NewEmailFromReader(bytes.NewReader(raw.Bytes()))
	ch.Assert(err, check.IsNil)
	match := regexp.MustCompile(`cid:(qr-[a-f0-9]+\.png)`).FindStringSubmatch(string(parsed.HTML))
	ch.Assert(match, check.HasLen, 2)
	qrName := match[1]

	message := raw.String()
	ch.Assert(strings.Contains(message, "Content-Disposition: inline"), check.Equals, true)
	ch.Assert(strings.Contains(message, "Content-ID: <"+qrName+">"), check.Equals, true)
}

func (s *ModelsSuite) TestGetSmtpFrom(ch *check.C) {
	smtp := SMTP{
		FromAddress: "from@example.com",
	}
	template := Template{
		Name:    "Test Template",
		Subject: "{{.FirstName}} - Subject",
		Text:    "{{.Email}} - Text",
		HTML:    "{{.Email}} - HTML",
	}
	req := &EmailRequest{
		SMTP:     smtp,
		Template: template,
		URL:      "http://127.0.0.1/{{.Email}}",
		BaseRecipient: BaseRecipient{
			FirstName: "First",
			LastName:  "Last",
			Email:     "firstlast@example.com",
		},
		FromAddress: smtp.FromAddress,
		RId:         fmt.Sprintf("%s-foobar", PreviewPrefix),
	}

	msg := gomail.NewMessage()
	err := req.Generate(msg)
	smtp_from, err := req.GetSmtpFrom()

	ch.Assert(err, check.Equals, nil)
	ch.Assert(smtp_from, check.Equals, "from@example.com")
}

func (s *ModelsSuite) TestEmailRequestURLTemplating(ch *check.C) {
	smtp := SMTP{
		FromAddress: "from@example.com",
	}
	template := Template{
		Name:    "Test Template",
		Subject: "{{.URL}}",
		Text:    "{{.URL}}",
		HTML:    "{{.URL}}",
	}
	req := &EmailRequest{
		SMTP:     smtp,
		Template: template,
		URL:      "http://127.0.0.1/{{.Email}}",
		BaseRecipient: BaseRecipient{
			FirstName: "First",
			LastName:  "Last",
			Email:     "firstlast@example.com",
		},
		FromAddress: smtp.FromAddress,
		RId:         fmt.Sprintf("%s-foobar", PreviewPrefix),
	}

	msg := gomail.NewMessage()
	err := req.Generate(msg)
	ch.Assert(err, check.Equals, nil)

	msgBuff := &bytes.Buffer{}
	_, err = msg.WriteTo(msgBuff)
	ch.Assert(err, check.Equals, nil)

	got, err := email.NewEmailFromReader(msgBuff)
	ch.Assert(err, check.Equals, nil)
	parsed, values, err := decodeOltaURL(got.Subject)
	ch.Assert(err, check.Equals, nil)
	ch.Assert(parsed.Scheme, check.Equals, "http")
	ch.Assert(parsed.Host, check.Equals, "127.0.0.1")
	ch.Assert(parsed.Path, check.Equals, "/"+req.Email)
	ch.Assert(values.Get("rid"), check.Equals, req.RId)
	ch.Assert(values.Get("email"), check.Equals, req.Email)
	ch.Assert(string(got.Text), check.Equals, got.Subject)
	ch.Assert(string(got.HTML), check.Equals, got.Subject)
}
func (s *ModelsSuite) TestEmailRequestGenerateEmptySubject(ch *check.C) {
	smtp := SMTP{
		FromAddress: "from@example.com",
	}
	template := Template{
		Name:    "Test Template",
		Subject: "",
		Text:    "{{.Email}} - Text",
		HTML:    "{{.Email}} - HTML",
	}
	req := &EmailRequest{
		SMTP:     smtp,
		Template: template,
		BaseRecipient: BaseRecipient{
			FirstName: "First",
			LastName:  "Last",
			Email:     "firstlast@example.com",
		},
		FromAddress: smtp.FromAddress,
	}

	msg := gomail.NewMessage()
	err := req.Generate(msg)
	ch.Assert(err, check.Equals, nil)

	expected := &email.Email{
		Subject: "",
		Text:    []byte(fmt.Sprintf("%s - Text", req.Email)),
		HTML:    []byte(fmt.Sprintf("%s - HTML", req.Email)),
	}

	msgBuff := &bytes.Buffer{}
	_, err = msg.WriteTo(msgBuff)
	ch.Assert(err, check.Equals, nil)

	got, err := email.NewEmailFromReader(msgBuff)
	ch.Assert(err, check.Equals, nil)
	ch.Assert(got.Subject, check.Equals, expected.Subject)
}

func (s *ModelsSuite) TestPostSendTestEmailRequest(ch *check.C) {
	smtp := SMTP{
		FromAddress: "from@example.com",
	}
	template := Template{
		Name:    "Test Template",
		Subject: "",
		Text:    "{{.Email}} - Text",
		HTML:    "{{.Email}} - HTML",
		UserId:  1,
	}
	err := PostTemplate(&template)
	ch.Assert(err, check.Equals, nil)

	req := &EmailRequest{
		SMTP:       smtp,
		TemplateId: template.Id,
		BaseRecipient: BaseRecipient{
			FirstName: "First",
			LastName:  "Last",
			Email:     "firstlast@example.com",
		},
	}
	err = PostEmailRequest(req)
	ch.Assert(err, check.Equals, nil)

	got, err := GetEmailRequestByResultId(req.RId)
	ch.Assert(err, check.Equals, nil)
	ch.Assert(got.RId, check.Equals, req.RId)
	ch.Assert(got.Email, check.Equals, req.Email)
}
