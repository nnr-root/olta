package middleware

import (
	"encoding/gob"
	"net/http"

	"github.com/gorilla/securecookie"
	"github.com/gorilla/sessions"
	"github.com/s4l1hs/olta/pkg/campaign/models"
	"github.com/s4l1hs/olta/pkg/campaign/secrets"
)

// init registers the necessary models to be saved in the session later
func init() {
	gob.Register(&models.User{})
	gob.Register(&models.Flash{})
	configureStoreOptions(Store)
}

// Store contains the session information for the request
var Store = sessions.NewCookieStore(
	[]byte(securecookie.GenerateRandomKey(64)), //Signing key
	[]byte(securecookie.GenerateRandomKey(32)))

func configureStoreOptions(store *sessions.CookieStore) {
	store.Options.Path = "/"
	store.Options.HttpOnly = true
	store.Options.SameSite = http.SameSiteStrictMode
	// This sets the maxAge to 5 days for all cookies.
	store.MaxAge(86400 * 5)
}

// ConfigureStoreFromMasterKey derives stable cookie keys from OLTA_MASTER_KEY.
// It returns false when no master key is configured and the process-local
// random keys remain in use.
func ConfigureStoreFromMasterKey() bool {
	signingKey, ok := secrets.Derive("campaign/session/signing/v1", 64)
	if !ok {
		return false
	}
	encryptionKey, _ := secrets.Derive("campaign/session/encryption/v1", 32)
	store := sessions.NewCookieStore(signingKey, encryptionKey)
	configureStoreOptions(store)
	Store = store
	return true
}
