package controllers

import (
	"net/http"

	"github.com/gorilla/mux"
	"github.com/s4l1hs/olta/pkg/campaign/bitb"
	"github.com/s4l1hs/olta/pkg/campaign/oauthconsent"
)

// registerCampaignComponentAssets mounts assets embedded in the campaign
// component packages. These routes must be registered before the general
// filesystem-backed static handlers.
func registerCampaignComponentAssets(router *mux.Router) {
	router.PathPrefix(bitb.AssetBasePath).Handler(
		http.StripPrefix(bitb.AssetBasePath, bitb.Handler()),
	).Methods(http.MethodGet, http.MethodHead)
	router.PathPrefix(oauthconsent.AssetBasePath).Handler(
		http.StripPrefix(oauthconsent.AssetBasePath, oauthconsent.Handler()),
	).Methods(http.MethodGet, http.MethodHead)
}
