package models

import (
	"bytes"
	"errors"
	"fmt"

	"github.com/gophish/gomail"
	"github.com/jordan-wright/email"
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
