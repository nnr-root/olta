package models

import "encoding/json"

// MarshalJSON prevents operational credentials from being returned by list
// and detail APIs. Update handlers preserve an existing secret when the field
// is omitted, so callers can edit non-secret fields without learning it.
func (value SMTP) MarshalJSON() ([]byte, error) {
	type alias SMTP
	value.Password = ""
	return json.Marshal(alias(value))
}

func (value SMS) MarshalJSON() ([]byte, error) {
	type alias SMS
	value.TwilioAuthToken = ""
	return json.Marshal(alias(value))
}

func (value IMAP) MarshalJSON() ([]byte, error) {
	type alias IMAP
	value.Password = ""
	return json.Marshal(alias(value))
}

func (value Webhook) MarshalJSON() ([]byte, error) {
	type alias Webhook
	value.Secret = ""
	return json.Marshal(alias(value))
}

func (value User) MarshalJSON() ([]byte, error) {
	type alias User
	value.ApiKey = ""
	return json.Marshal(alias(value))
}
