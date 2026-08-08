package models

import (
	"crypto/rc4"
	"encoding/base64"
	"errors"
	"fmt"
	"net/url"
	"strings"

	check "gopkg.in/check.v1"
)

func decodeOltaURL(rawURL string) (*url.URL, url.Values, error) {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return nil, nil, err
	}
	encoded := parsed.Query().Get(RecipientParameter)
	if len(encoded) <= 8 {
		return nil, nil, errors.New("missing encrypted Olta recipient payload")
	}
	key := encoded[:8]
	ciphertext, err := base64.RawURLEncoding.DecodeString(encoded[8:])
	if err != nil {
		return nil, nil, err
	}
	if len(ciphertext) < 2 {
		return nil, nil, errors.New("encrypted Olta recipient payload is too short")
	}
	plaintext := make([]byte, len(ciphertext)-1)
	cipher, err := rc4.NewCipher([]byte(key))
	if err != nil {
		return nil, nil, err
	}
	cipher.XORKeyStream(plaintext, ciphertext[1:])
	var checksum byte
	for _, value := range plaintext {
		checksum += value
	}
	if checksum != ciphertext[0] {
		return nil, nil, errors.New("invalid Olta recipient payload checksum")
	}
	values, err := url.ParseQuery(string(plaintext))
	return parsed, values, err
}

type mockTemplateContext struct {
	URL         string
	FromAddress string
	QRSize      string
}

func (m mockTemplateContext) getFromAddress() string {
	return m.FromAddress
}

func (m mockTemplateContext) getBaseURL() string {
	return m.URL
}

func (m mockTemplateContext) getQRSize() string {
	return m.QRSize
}

func (s *ModelsSuite) TestNewTemplateContext(c *check.C) {
	r := Result{
		BaseRecipient: BaseRecipient{
			FirstName: "Foo",
			LastName:  "Bar",
			Email:     "foo@bar.com",
		},
		RId: "1234567",
	}
	ctx := mockTemplateContext{
		URL:         "http://example.com",
		FromAddress: "From Address <from@example.com>",
	}
	got, err := NewPhishingTemplateContext(ctx, r.BaseRecipient, r.RId)
	c.Assert(err, check.Equals, nil)
	c.Assert(got.BaseURL, check.Equals, ctx.URL)
	c.Assert(got.BaseRecipient, check.DeepEquals, r.BaseRecipient)
	c.Assert(got.From, check.Equals, "From Address")
	c.Assert(got.RId, check.Equals, r.RId)

	phishURL, phishValues, err := decodeOltaURL(got.URL)
	c.Assert(err, check.Equals, nil)
	c.Assert(fmt.Sprintf("%s://%s%s", phishURL.Scheme, phishURL.Host, phishURL.Path), check.Equals, ctx.URL)
	c.Assert(phishValues.Get("rid"), check.Equals, r.RId)
	c.Assert(phishValues.Get("email"), check.Equals, r.Email)
	c.Assert(phishValues.Get("fname"), check.Equals, r.FirstName)
	c.Assert(phishValues.Get("lname"), check.Equals, r.LastName)

	_, trackerValues, err := decodeOltaURL(got.TrackingURL)
	c.Assert(err, check.Equals, nil)
	c.Assert(trackerValues.Get("rid"), check.Equals, r.RId)
	c.Assert(trackerValues.Get("o"), check.Equals, "track")
	c.Assert(got.Tracker, check.Equals, "<img alt='' style='display: none' src='"+got.TrackingURL+"'/>")
}

func (s *ModelsSuite) TestQRTemplateAliases(c *check.C) {
	recipient := BaseRecipient{
		FirstName: "QR",
		LastName:  "Recipient",
		Email:     "qr@example.com",
	}
	ctx := mockTemplateContext{
		URL:         "https://example.com/campaign",
		FromAddress: "from@example.com",
		QRSize:      "256",
	}

	got, err := NewPhishingTemplateContext(ctx, recipient, "recipient-qr-id")
	c.Assert(err, check.IsNil)
	c.Assert(got.QRBase64, check.Not(check.Equals), "")
	c.Assert(got.QRName, check.Matches, `qr-[a-f0-9]+\.png`)
	c.Assert(got.QRCode, check.Equals, got.QR)
	c.Assert(got.RIdQR, check.Equals, got.QR)

	rendered, err := ExecuteTemplate(`{{.QRCode}}|{{.RIdQR}}`, got)
	c.Assert(err, check.IsNil)
	c.Assert(strings.Count(rendered, "cid:"+got.QRName), check.Equals, 2)
}
