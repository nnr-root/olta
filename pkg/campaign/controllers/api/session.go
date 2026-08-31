package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"

	"github.com/gorilla/mux"
	ctx "github.com/s4l1hs/olta/pkg/campaign/context"
	"github.com/s4l1hs/olta/pkg/campaign/models"
)

// sessionTagRequest is the body accepted by SessionTag. Each field is a
// pointer so the handler -- and models.SetResultSessionMetadata below it
// -- can tell "omitted, leave unchanged" apart from "explicitly set to the
// empty string" (clearing a tag or notes field is a legitimate request).
type sessionTagRequest struct {
	Tag    *string `json:"tag"`
	Notes  *string `json:"notes"`
	Status *string `json:"status"`
}

// SessionTag sets an operator's tag, notes, and/or status on one captured
// session within a campaign the requesting user owns.
//
// Ownership follows the same pattern as every other campaign-scoped
// handler in this file (see Campaign, CampaignResults): the campaign ID
// comes from the route, the user comes from the authenticated request
// context (never the request body), and models.SetResultSessionMetadata
// re-derives ownership from those two values plus the campaign_id already
// stored on the result row -- a caller cannot use this endpoint to tag a
// session in a campaign they do not own, or a session that does not
// actually belong to the campaign named in the URL, even if they happen to
// own some other campaign.
func (as *Server) SessionTag(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPut && r.Method != http.MethodPost {
		JSONResponse(w, models.Response{Success: false, Message: "Method not allowed"}, http.StatusMethodNotAllowed)
		return
	}

	vars := mux.Vars(r)
	campaignID, err := strconv.ParseInt(vars["id"], 0, 64)
	if err != nil {
		JSONResponse(w, models.Response{Success: false, Message: "Invalid campaign ID"}, http.StatusBadRequest)
		return
	}
	rid := vars["rid"]
	if rid == "" {
		JSONResponse(w, models.Response{Success: false, Message: "Invalid session ID"}, http.StatusBadRequest)
		return
	}

	var req sessionTagRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		JSONResponse(w, models.Response{Success: false, Message: "Invalid JSON structure"}, http.StatusBadRequest)
		return
	}

	userID := ctx.Get(r, "user_id").(int64)
	result, err := models.SetResultSessionMetadata(campaignID, userID, rid, req.Tag, req.Notes, req.Status)
	if err != nil {
		switch {
		case errors.Is(err, models.ErrSessionNotFound):
			JSONResponse(w, models.Response{Success: false, Message: "Session not found"}, http.StatusNotFound)
		case errors.Is(err, models.ErrInvalidSessionStatus),
			errors.Is(err, models.ErrSessionTagTooLong),
			errors.Is(err, models.ErrSessionNotesTooLong):
			JSONResponse(w, models.Response{Success: false, Message: err.Error()}, http.StatusBadRequest)
		default:
			JSONResponse(w, models.Response{Success: false, Message: err.Error()}, http.StatusInternalServerError)
		}
		return
	}
	JSONResponse(w, result, http.StatusOK)
}
