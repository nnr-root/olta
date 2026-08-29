package models

import (
	"os"
	"time"

	"github.com/s4l1hs/olta/pkg/campaign/auth"
	"github.com/s4l1hs/olta/pkg/campaign/config"
	campaigndb "github.com/s4l1hs/olta/pkg/campaign/database"
	"github.com/s4l1hs/olta/pkg/campaign/migrations"
	"github.com/s4l1hs/olta/pkg/campaign/secrets"

	"github.com/jinzhu/gorm"
	log "github.com/s4l1hs/olta/pkg/campaign/logger"
)

var db *gorm.DB
var conf *config.Config

// DB returns the package-level database handle. It is nil until Setup runs.
func DB() *gorm.DB { return db }

const MaxDatabaseConnectionAttempts int = 10

// DefaultAdminUsername is the default username for the administrative user
const DefaultAdminUsername = "admin"

// InitialAdminPassword is the environment variable that specifies which
// password to use for the initial root login instead of generating one
// randomly
const InitialAdminPassword = "GOPHISH_INITIAL_ADMIN_PASSWORD"

// InitialAdminApiToken is the environment variable that specifies the
// API token to seed the initial root login instead of generating one
// randomly
const InitialAdminApiToken = "GOPHISH_INITIAL_ADMIN_API_TOKEN"

const (
	CampaignInProgress   string = "In progress"
	CampaignQueued       string = "Queued"
	CampaignCreated      string = "Created"
	CampaignEmailsSent   string = "Emails Sent"
	CampaignComplete     string = "Completed"
	EventSent            string = "Email/SMS Sent"
	EventSendingError    string = "Error Sending Email/SMS"
	EventOpened          string = "Email/SMS Opened"
	EventClicked         string = "Clicked Link"
	EventDataSubmit      string = "Submitted Data"
	EventCapturedSession string = "Captured Session"
	EventReported        string = "Email Reported"
	EventProxyRequest    string = "Proxied request"
	StatusSuccess        string = "Success"
	StatusQueued         string = "Queued"
	StatusSending        string = "Sending"
	StatusUnknown        string = "Unknown"
	StatusScheduled      string = "Scheduled"
	StatusRetry          string = "Retrying"
	Error                string = "Error"
)

// Flash is used to hold flash information for use in templates.
type Flash struct {
	Type    string
	Message string
}

// Response contains the attributes found in an API response
type Response struct {
	Message string      `json:"message"`
	Success bool        `json:"success"`
	Data    interface{} `json:"data"`
}

func createTemporaryPassword(u *User) error {
	var temporaryPassword string
	if envPassword := os.Getenv(InitialAdminPassword); envPassword != "" {
		temporaryPassword = envPassword
	} else {
		// This will result in a 16 character password which could be viewed as an
		// inconvenience, but it should be ok for now.
		temporaryPassword = auth.GenerateSecureKey(auth.MinPasswordLength)
	}
	hash, err := auth.GeneratePasswordHash(temporaryPassword)
	if err != nil {
		return err
	}
	u.Hash = hash
	// Anytime a temporary password is created, we will force the user
	// to change their password
	u.PasswordChangeRequired = true
	err = PutUser(u)
	if err != nil {
		return err
	}
	log.Infof("Please login with the username admin and the password %s", temporaryPassword)
	return nil
}

// Setup initializes the database and runs any needed migrations.
//
// First, it establishes a connection to the database, then runs any migrations
// newer than the version the database is on.
//
// Once the database is up-to-date, we create an admin user (if needed) that
// has a randomly generated API key and password.
func Setup(c *config.Config) error {
	encryptionEnabled, err := secrets.ConfigureFromEnvironment()
	if err != nil {
		return err
	}
	// Setup the package-scoped config
	conf = c
	conf.ApplyDatabaseDefaults()
	connector, err := campaigndb.New(conf.DBName)
	if err != nil {
		return err
	}
	conf.DBName = connector.Driver()

	// Open our database connection
	i := 0
	for {
		db, err = connector.Open(conf.DBPath, conf.DBSSLCaPath)
		if err == nil {
			break
		}
		if err != nil && i >= MaxDatabaseConnectionAttempts {
			log.Error(err)
			return err
		}
		i += 1
		log.Warn("waiting for database to be up...")
		time.Sleep(5 * time.Second)
	}
	db.LogMode(false)
	db.SetLogger(log.Logger)
	db.DB().SetMaxOpenConns(10)
	if err != nil {
		log.Error(err)
		return err
	}
	// Initialize fresh databases from the single embedded Olta schema. Existing
	// databases are accepted only after their final legacy schema is validated.
	err = migrations.Apply(db.DB(), conf.DBName)
	if err != nil {
		log.Error(err)
		return err
	}
	if err := protectStoredSecrets(); err != nil {
		return err
	}
	if !encryptionEnabled && conf.DBPath != ":memory:" {
		log.Warn("OLTA_MASTER_KEY is not configured; operational secrets will remain plaintext at rest")
	}
	// Create the admin user if it doesn't exist
	var userCount int64
	var adminUser User
	db.Model(&User{}).Count(&userCount)
	adminRole, err := GetRoleBySlug(RoleAdmin)
	if err != nil {
		log.Error(err)
		return err
	}
	if userCount == 0 {
		adminUser := User{
			Username:               DefaultAdminUsername,
			Role:                   adminRole,
			RoleID:                 adminRole.ID,
			PasswordChangeRequired: true,
		}

		if envToken := os.Getenv(InitialAdminApiToken); envToken != "" {
			adminUser.ApiKey = envToken
		} else {
			adminUser.ApiKey = auth.GenerateSecureKey(auth.APIKeyLength)
		}

		err = PutUser(&adminUser)
		if err != nil {
			log.Error(err)
			return err
		}
	}
	// If this is the first time the user is installing Olta, then we will
	// generate a temporary password for the admin user.
	//
	// We do this here instead of in the block above where the admin is created
	// since there's the chance the user executes Olta and has some kind of
	// error, then tries restarting it. If they didn't grab the password out of
	// the logs, then they would have lost it.
	//
	// By doing the temporary password here, we will regenerate that temporary
	// password until the user is able to reset the admin password.
	if adminUser.Username == "" {
		adminUser, err = GetUserByUsername(DefaultAdminUsername)
		if err != nil {
			log.Error(err)
			return err
		}
	}
	if adminUser.PasswordChangeRequired {
		err = createTemporaryPassword(&adminUser)
		if err != nil {
			log.Error(err)
			return err
		}
	}
	return nil
}
