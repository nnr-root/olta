package main

/*
gophish - Open-Source Phishing Framework

The MIT License (MIT)

Copyright (c) 2013 Jordan Wright

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
*/
import (
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"gopkg.in/alecthomas/kingpin.v2"

	"github.com/s4l1hs/olta/pkg/campaign/config"
	"github.com/s4l1hs/olta/pkg/campaign/controllers"
	"github.com/s4l1hs/olta/pkg/campaign/dialer"
	"github.com/s4l1hs/olta/pkg/campaign/imap"
	log "github.com/s4l1hs/olta/pkg/campaign/logger"
	"github.com/s4l1hs/olta/pkg/campaign/middleware"
	"github.com/s4l1hs/olta/pkg/campaign/models"
	"github.com/s4l1hs/olta/pkg/campaign/webhook"
	"github.com/s4l1hs/olta/pkg/campaign/worker"
	"github.com/s4l1hs/olta/pkg/runtimepath"
)

const (
	modeAll   string = "all"
	modeAdmin string = "admin"
	modePhish string = "phish"
)

var (
	configPath         = kingpin.Flag("config", "Location of config.json (defaults to the command asset directory).").String()
	assetDir           = kingpin.Flag("asset-dir", "Runtime asset directory containing VERSION, templates, and static files.").String()
	disableMailer      = kingpin.Flag("disable-mailer", "Disable the mailer (for use with multi-system deployments)").Bool()
	minSendDelay       = kingpin.Flag("min-send-delay", "Minimum randomized interval between consecutive email sends.").Default("10s").Duration()
	maxSendDelay       = kingpin.Flag("max-send-delay", "Maximum randomized interval between consecutive email sends.").Default("45s").Duration()
	enableSpintax      = kingpin.Flag("enable-spintax", "Enable rule-based spintax expansion for campaign messages.").Default("true").Bool()
	enableRoleRouting  = kingpin.Flag("enable-role-routing", "Enable recipient role and department scenario routing.").Default("true").Bool()
	customTemplatesDir = kingpin.Flag("custom-templates-dir", "Optional directory containing localized JSON template overrides.").String()
	mode               = kingpin.Flag("mode", fmt.Sprintf("Run the binary in one of the modes (%s, %s or %s)", modeAll, modeAdmin, modePhish)).
				Default("all").Enum(modeAll, modeAdmin, modePhish)
)

func main() {
	// Load the version
	resolvedAssets, _ := runtimepath.Resolve("", "olta-campaign", "VERSION", "config.json", "templates", "static")
	version := []byte("development")
	if resolvedAssets != "" {
		if loadedVersion, err := os.ReadFile(filepath.Join(resolvedAssets, "VERSION")); err == nil {
			version = loadedVersion
		}
	}
	kingpin.Version(string(version))

	// Parse the CLI flags and load the config
	kingpin.CommandLine.HelpFlag.Short('h')
	kingpin.Parse()
	if *customTemplatesDir != "" && !filepath.IsAbs(*customTemplatesDir) {
		resolvedTemplatesDir, pathErr := filepath.Abs(*customTemplatesDir)
		if pathErr != nil {
			log.Fatal(pathErr)
		}
		*customTemplatesDir = resolvedTemplatesDir
	}

	resolvedAssets, err := runtimepath.Resolve(*assetDir, "olta-campaign", "VERSION", "config.json", "templates", "static")
	if err != nil {
		log.Fatal(err)
	}
	resolvedConfig := *configPath
	if resolvedConfig == "" {
		resolvedConfig = filepath.Join(resolvedAssets, "config.json")
	} else if !filepath.IsAbs(resolvedConfig) {
		resolvedConfig, err = filepath.Abs(resolvedConfig)
		if err != nil {
			log.Fatal(err)
		}
	}
	if err := os.Chdir(resolvedAssets); err != nil {
		log.Fatal(err)
	}

	// Load the config
	conf, err := config.LoadConfig(resolvedConfig)
	// Just warn if a contact address hasn't been configured
	if err != nil {
		log.Fatal(err)
	}
	if conf.ContactAddress == "" {
		log.Warnf("No contact address has been configured.")
		log.Warnf("Please consider adding a contact_address entry in your config.json")
	}
	config.Version = string(version)

	// Configure our various upstream clients to make sure that we restrict
	// outbound connections as needed.
	dialer.SetAllowedHosts(conf.AdminConf.AllowedInternalHosts)
	webhook.SetTransport(&http.Transport{
		DialContext: dialer.Dialer().DialContext,
	})

	err = log.Setup(conf.Logging)
	if err != nil {
		log.Fatal(err)
	}

	// Provide the option to disable the built-in mailer
	// Setup the global variables and settings
	err = models.Setup(conf)
	if err != nil {
		log.Fatal(err)
	}

	// Unlock any maillogs that may have been locked for processing
	// when Olta Campaign was last shut down.
	err = models.UnlockAllMailLogs()
	if err != nil {
		log.Fatal(err)
	}

	// Create our servers
	adminOptions := []controllers.AdminServerOption{}
	if *disableMailer {
		adminOptions = append(adminOptions, controllers.WithWorker(nil))
	} else {
		campaignWorker, workerErr := worker.New(worker.WithDeliveryOptions(
			*minSendDelay,
			*maxSendDelay,
			*enableSpintax,
			*enableRoleRouting,
			*customTemplatesDir,
		))
		if workerErr != nil {
			log.Fatal(workerErr)
		}
		adminOptions = append(adminOptions, controllers.WithWorker(campaignWorker))
	}
	adminConfig := conf.AdminConf
	adminServer := controllers.NewAdminServer(adminConfig, adminOptions...)
	middleware.Store.Options.Secure = adminConfig.UseTLS

	phishConfig := conf.PhishConf
	phishServer := controllers.NewPhishingServer(phishConfig)

	imapMonitor := imap.NewMonitor()
	if *mode == "admin" || *mode == "all" {
		go adminServer.Start()
		go imapMonitor.Start()
	}
	if *mode == "phish" || *mode == "all" {
		go phishServer.Start()
	}

	// Handle graceful shutdown
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(c)
	<-c
	log.Info("Shutdown signal received; gracefully stopping Olta Campaign servers")
	if *mode == modeAdmin || *mode == modeAll {
		adminServer.Shutdown()
		imapMonitor.Shutdown()
	}
	if *mode == modePhish || *mode == modeAll {
		phishServer.Shutdown()
	}

}
