package main

import (
	"flag"
	"log"
	"path/filepath"

	"github.com/s4l1hs/olta/pkg/feed"
	"github.com/s4l1hs/olta/pkg/runtimepath"
)

func main() {
	listenAddress := flag.String("listen", feed.DefaultListenAddress, "HTTP/WebSocket listen address")
	assetDir := flag.String("asset-dir", "", "Runtime asset directory containing app/")
	flag.Parse()

	resolvedAssets, err := runtimepath.Resolve(*assetDir, "olta-feed", "app/index.html")
	if err != nil {
		log.Fatal(err)
	}
	if err := feed.Run(*listenAddress, filepath.Join(resolvedAssets, "app")); err != nil {
		log.Fatal(err)
	}
}
