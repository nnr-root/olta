package api

import (
	"net/http"

	"github.com/gorilla/mux"
	mid "github.com/s4l1hs/olta/pkg/campaign/middleware"
	"github.com/s4l1hs/olta/pkg/campaign/middleware/ratelimit"
	"github.com/s4l1hs/olta/pkg/campaign/models"
	"github.com/s4l1hs/olta/pkg/campaign/resilience"
	"github.com/s4l1hs/olta/pkg/campaign/smsworker"
	"github.com/s4l1hs/olta/pkg/campaign/worker"
)

// ServerOption is an option to apply to the API server.
type ServerOption func(*Server)

// Server represents the routes and functionality of the Gophish API.
// It's not a server in the traditional sense, in that it isn't started and
// stopped. Rather, it's meant to be used as an http.Handler in the
// AdminServer.
type Server struct {
	handler                 http.Handler
	worker                  worker.Worker
	smsworker               smsworker.Worker
	limiter                 *ratelimit.PostLimiter
	allowedOrigins          []string
	allowInsecureSiteImport bool
	telemetryFeatures       resilience.Features
}

// NewServer returns a new instance of the API handler with the provided
// options applied.
func NewServer(options ...ServerOption) *Server {
	defaultWorker, _ := worker.New()
	defaultSmsWorker, _ := smsworker.New()
	defaultLimiter := ratelimit.NewPostLimiter()
	as := &Server{
		worker:    defaultWorker,
		smsworker: defaultSmsWorker,
		limiter:   defaultLimiter,
	}
	for _, opt := range options {
		opt(as)
	}
	as.registerRoutes()
	return as
}

// WithWorker is an option that sets the background worker.
func WithWorker(w worker.Worker) ServerOption {
	return func(as *Server) {
		as.worker = w
	}
}

// WithSmsWorker is an option that sets the background sms worker.
func WithSmsWorker(s smsworker.Worker) ServerOption {
	return func(as *Server) {
		as.smsworker = s
	}
}

func WithLimiter(limiter *ratelimit.PostLimiter) ServerOption {
	return func(as *Server) {
		as.limiter = limiter
	}
}

// WithAllowedOrigins configures the API CORS allowlist.
func WithAllowedOrigins(origins []string) ServerOption {
	return func(as *Server) {
		as.allowedOrigins = append([]string(nil), origins...)
	}
}

// WithInsecureSiteImport allows importing sites with invalid TLS certificates.
// It should be used only for explicitly authorized lab infrastructure.
func WithInsecureSiteImport(allowed bool) ServerOption {
	return func(as *Server) { as.allowInsecureSiteImport = allowed }
}

// WithTelemetryFeatures sets which optional olta-proxy capabilities were
// enabled for this engagement, so the resilience report can distinguish an
// unmeasured stage from one that was measured and saw nothing.
func WithTelemetryFeatures(features resilience.Features) ServerOption {
	return func(as *Server) { as.telemetryFeatures = features }
}

// Close releases background resources owned by the API handler.
func (as *Server) Close() {
	as.limiter.Close()
}

func (as *Server) registerRoutes() {
	root := mux.NewRouter()
	root = root.StrictSlash(true)
	router := root.PathPrefix("/api/").Subrouter()
	router.Use(mid.RequireAPIKeyWithOrigins(as.allowedOrigins))
	router.Use(mid.EnforceViewOnly)
	router.HandleFunc("/imap/", as.IMAPServer)
	router.HandleFunc("/imap/validate", as.IMAPServerValidate)
	router.HandleFunc("/reset", as.Reset)
	router.HandleFunc("/campaigns/", as.Campaigns)
	router.HandleFunc("/sms_campaigns/", as.SMSCampaigns)
	router.HandleFunc("/campaigns/summary", as.CampaignsSummary)
	router.HandleFunc("/campaigns/{id:[0-9]+}", as.Campaign)
	router.HandleFunc("/campaigns/{id:[0-9]+}/results", as.CampaignResults)
	router.HandleFunc("/campaigns/{id:[0-9]+}/results/{rid}/session", as.SessionTag).Methods(http.MethodPut, http.MethodPost)
	router.HandleFunc("/campaigns/{id:[0-9]+}/summary", as.CampaignSummary)
	router.HandleFunc("/campaigns/{id:[0-9]+}/complete", as.CampaignComplete)
	router.HandleFunc("/campaigns/{id:[0-9]+}/resilience", as.Resilience).Methods("GET")
	router.HandleFunc("/campaigns/{id:[0-9]+}/resilience/navigator", as.ResilienceNavigator).Methods("GET")
	router.HandleFunc("/groups/", as.Groups)
	router.HandleFunc("/groups/summary", as.GroupsSummary)
	router.HandleFunc("/groups/{id:[0-9]+}", as.Group)
	router.HandleFunc("/groups/{id:[0-9]+}/summary", as.GroupSummary)
	router.HandleFunc("/templates/", as.Templates)
	router.HandleFunc("/templates/{id:[0-9]+}", as.Template)
	router.HandleFunc("/quishing/preview", as.QRCodePreview).Methods(http.MethodPost)
	router.HandleFunc("/v1/personalizer/preview", as.PersonalizerPreview).Methods(http.MethodPost)
	router.HandleFunc("/v1/bitb/preview", as.BITBPreview).Methods(http.MethodPost)
	router.HandleFunc("/smtp/", as.SendingProfiles)
	router.HandleFunc("/smtp/{id:[0-9]+}", as.SendingProfile)
	router.HandleFunc("/sms/", as.SMSProfiles)
	router.HandleFunc("/sms/{id:[0-9]+}", as.SMSProfile)
	router.HandleFunc("/users/", mid.Use(as.Users, mid.RequirePermission(models.PermissionModifySystem)))
	router.HandleFunc("/users/{id:[0-9]+}", mid.Use(as.User))
	router.HandleFunc("/util/send_test_email", as.SendTestEmail)
	router.HandleFunc("/import/group", as.ImportGroup)
	router.HandleFunc("/import/email", as.ImportEmail)
	router.HandleFunc("/import/site", as.ImportSite)
	router.HandleFunc("/webhooks/", mid.Use(as.Webhooks, mid.RequirePermission(models.PermissionModifySystem)))
	router.HandleFunc("/webhooks/{id:[0-9]+}/validate", mid.Use(as.ValidateWebhook, mid.RequirePermission(models.PermissionModifySystem)))
	router.HandleFunc("/webhooks/{id:[0-9]+}", mid.Use(as.Webhook, mid.RequirePermission(models.PermissionModifySystem)))
	as.handler = router
}

func (as *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	as.handler.ServeHTTP(w, r)
}
