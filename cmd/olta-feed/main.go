package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/s4l1hs/olta/pkg/feed"
	"github.com/s4l1hs/olta/pkg/runtimepath"
)

func main() {
	listenAddress := flag.String("listen", feed.DefaultListenAddress, "HTTP/WebSocket listen address")
	assetDir := flag.String("asset-dir", "", "Runtime asset directory containing app/")
	historySize := flag.Int("history-size", envInt("OLTA_FEED_HISTORY_SIZE", 100), "Number of recent events replayed to new viewers")
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
	if err := feed.Run(
		*listenAddress,
		filepath.Join(resolvedAssets, "app"),
		feed.WithPublisherToken(os.Getenv("OLTA_FEED_PUBLISHER_TOKEN")),
		feed.WithViewerToken(os.Getenv("OLTA_FEED_VIEWER_TOKEN")),
		feed.WithAllowedOrigins(origins...),
		feed.WithHistorySize(*historySize),
	); err != nil {
		log.Fatal(err)
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
