package api

import (
	"net/http"
	"strconv"
	"strings"

	"github.com/gorilla/mux"
	ctx "github.com/s4l1hs/olta/pkg/campaign/context"
	"github.com/s4l1hs/olta/pkg/campaign/models"
	"github.com/s4l1hs/olta/pkg/campaign/retention"
)

// purgeConfirmation is the exact value a caller must send to run a purge.
//
// A boolean flag would be too easy to send by accident -- a client library
// that serializes every field, a copy-pasted request body, a retry with a
// stale payload. Requiring a specific word means the request cannot be made
// without someone having read what it does.
const purgeConfirmation = "PURGE"

// CampaignPurge removes personal data from a campaign while keeping its
// measurable shape, so the resilience report still works afterwards.
//
// It is POST rather than DELETE because it deletes nothing: the campaign,
// its results and its telemetry all survive, with the personal fields
// cleared. Calling it DELETE would tell an operator their campaign was about
// to disappear.
func (as *Server) CampaignPurge(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	campaignID, err := strconv.ParseInt(vars["id"], 0, 64)
	if err != nil {
		JSONResponse(w, models.Response{Success: false, Message: "Invalid campaign ID"}, http.StatusBadRequest)
		return
	}

	userID := ctx.Get(r, "user_id").(int64)
	// Ownership is checked before anything is written, and resolves as not
	// found rather than forbidden, mirroring every other campaign endpoint:
	// this must not confirm that another user's campaign ID exists.
	if _, err := models.GetCampaign(campaignID, userID); err != nil {
		JSONResponse(w, models.Response{Success: false, Message: "Campaign not found"}, http.StatusNotFound)
		return
	}

	if strings.TrimSpace(r.URL.Query().Get("confirm")) != purgeConfirmation {
		JSONResponse(w, models.Response{
			Success: false,
			Message: "This permanently removes recipient personal data from this campaign and cannot be undone. " +
				"Repeat the request with ?confirm=" + purgeConfirmation + " to proceed.",
		}, http.StatusBadRequest)
		return
	}

	summary, err := retention.PurgeCampaign(models.DB(), campaignID, userID)
	if err != nil {
		JSONResponse(w, models.Response{Success: false, Message: err.Error()}, http.StatusInternalServerError)
		return
	}
	JSONResponse(w, summary, http.StatusOK)
}
