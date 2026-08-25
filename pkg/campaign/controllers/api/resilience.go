package api

import (
	"net/http"
	"strconv"

	"github.com/gorilla/mux"
	ctx "github.com/s4l1hs/olta/pkg/campaign/context"
	"github.com/s4l1hs/olta/pkg/campaign/models"
	"github.com/s4l1hs/olta/pkg/campaign/resilience"
)

// Resilience returns the purple-team report for one campaign.
func (as *Server) Resilience(w http.ResponseWriter, r *http.Request) {
	report, ok := as.resilienceReport(w, r)
	if !ok {
		return
	}
	JSONResponse(w, report, http.StatusOK)
}

// navigatorLayer is the MITRE ATT&CK Navigator layer format.
type navigatorLayer struct {
	Name        string               `json:"name"`
	Versions    navigatorVersions    `json:"versions"`
	Domain      string               `json:"domain"`
	Description string               `json:"description"`
	Techniques  []navigatorTechnique `json:"techniques"`
}

type navigatorVersions struct {
	Layer     string `json:"layer"`
	Navigator string `json:"navigator"`
	Attack    string `json:"attack"`
}

type navigatorTechnique struct {
	TechniqueID string `json:"techniqueID"`
	Score       int    `json:"score"`
	Color       string `json:"color"`
	Comment     string `json:"comment"`
	Enabled     bool   `json:"enabled"`
}

// ResilienceNavigator returns an ATT&CK Navigator layer for one campaign.
// Score is the number of distinct targets that reached the stage emulating
// the technique, so an unexercised technique scores zero.
func (as *Server) ResilienceNavigator(w http.ResponseWriter, r *http.Request) {
	report, ok := as.resilienceReport(w, r)
	if !ok {
		return
	}

	techniques := make([]navigatorTechnique, 0, len(report.Funnel))
	for _, stage := range report.Funnel {
		for _, technique := range stage.Techniques {
			comment := string(stage.Stage)
			color := "#8ec843" // exercised but nothing got through
			if !stage.Measured {
				comment += " (not measured)"
				color = "#d3d3d3"
			} else if stage.Targets > 0 {
				color = "#e60d0d" // targets reached this stage
			}
			techniques = append(techniques, navigatorTechnique{
				TechniqueID: string(technique),
				Score:       stage.Targets,
				Color:       color,
				Comment:     comment,
				Enabled:     stage.Measured,
			})
		}
	}

	JSONResponse(w, navigatorLayer{
		Name:        "Olta campaign " + strconv.FormatInt(report.CampaignID, 10),
		Versions:    navigatorVersions{Layer: "4.5", Navigator: "4.9.0", Attack: "14"},
		Domain:      "enterprise-attack",
		Description: "Techniques emulated during an authorized Olta engagement.",
		Techniques:  techniques,
	}, http.StatusOK)
}

// resilienceReport parses the campaign id, authorizes the caller, and
// computes the report. It writes the error response itself and reports
// false when the caller should stop.
//
// Authorization mirrors (as *Server) Campaign in campaign.go exactly: the
// campaign is looked up scoped to the caller's user_id from context, so a
// campaign owned by another user resolves as not found rather than as
// forbidden -- this endpoint exposes per-campaign engagement data and must
// not leak whether a campaign ID belongs to someone else.
func (as *Server) resilienceReport(w http.ResponseWriter, r *http.Request) (resilience.Report, bool) {
	vars := mux.Vars(r)
	campaignID, err := strconv.ParseInt(vars["id"], 0, 64)
	if err != nil {
		JSONResponse(w, models.Response{Success: false, Message: "Invalid campaign ID"}, http.StatusBadRequest)
		return resilience.Report{}, false
	}

	if _, err := models.GetCampaign(campaignID, ctx.Get(r, "user_id").(int64)); err != nil {
		JSONResponse(w, models.Response{Success: false, Message: "Campaign not found"}, http.StatusNotFound)
		return resilience.Report{}, false
	}

	report, err := resilience.Compute(models.DB(), campaignID, as.telemetryFeatures)
	if err != nil {
		JSONResponse(w, models.Response{Success: false, Message: err.Error()}, http.StatusInternalServerError)
		return resilience.Report{}, false
	}
	return report, true
}
