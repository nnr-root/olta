package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"github.com/s4l1hs/olta/pkg/feed"
	"github.com/s4l1hs/olta/pkg/runtimepath"
)

func main() {
	listenAddress := flag.String("listen", feed.DefaultListenAddress, "HTTP/WebSocket listen address")
	assetDir := flag.String("asset-dir", "", "Runtime asset directory containing app/")
	historySize := flag.Int("history-size", envInt("OLTA_FEED_HISTORY_SIZE", 100), "Number of recent events replayed to new viewers")
	tokenFile := flag.String("token-file", os.Getenv("OLTA_FEED_TOKEN_FILE"), `JSON file holding the accepted tokens ({"publisher": [...], "viewer": [...]}). Overrides the OLTA_FEED_*_TOKEN environment variables and can be reloaded with SIGHUP, so tokens can be rotated without dropping connected viewers`)
	versionFlag := flag.Bool("version", false, "Print the version and exit")
	flag.Parse()

	if *versionFlag {
		fmt.Println(feed.Version)
		return
	}

	resolvedAssets, err := runtimepath.Resolve(*assetDir, "olta-feed", "app/index.html")
	if err != nil {
		log.Fatal(err)
	}
	origins := splitCSV(os.Getenv("OLTA_FEED_ALLOWED_ORIGINS"))
	server, err := feed.NewServer(
		filepath.Join(resolvedAssets, "app"),
		feed.WithPublisherToken(os.Getenv("OLTA_FEED_PUBLISHER_TOKEN")),
		feed.WithViewerToken(os.Getenv("OLTA_FEED_VIEWER_TOKEN")),
		feed.WithTokenFile(*tokenFile),
		feed.WithAllowedOrigins(origins...),
		feed.WithHistorySize(*historySize),
	)
	if err != nil {
		log.Fatal(err)
	}

	if *tokenFile != "" {
		go reloadTokensOnHangup(server)
	}

	if err := server.ListenAndServe(*listenAddress); err != nil {
		log.Fatal(err)
	}
}

// reloadTokensOnHangup re-reads the token file whenever the process is sent
// SIGHUP, which is the conventional "reload your configuration" signal and
// the one an operator's process manager already knows how to send.
//
// A failed reload is logged and the running tokens are kept: a truncated or
// half-written file must not lock every client out of a live feed in the
// middle of an engagement.
func reloadTokensOnHangup(server *feed.Server) {
	hangup := make(chan os.Signal, 1)
	signal.Notify(hangup, syscall.SIGHUP)
	for range hangup {
		if err := server.ReloadTokens(); err != nil {
			log.Printf("feed token reload failed, keeping the tokens already loaded: %v", err)
			continue
		}
		log.Print("feed tokens reloaded")
	}
}

func splitCSV(value string) []string {
	var values []string
	for _, item := range strings.Split(value, ",") {
		if item = strings.TrimSpace(item); item != "" {
			values = append(values, item)
		}
	}
	return values
}

func envInt(name string, fallback int) int {
	value, err := strconv.Atoi(os.Getenv(name))
	if err != nil {
		return fallback
	}
	return value
}
