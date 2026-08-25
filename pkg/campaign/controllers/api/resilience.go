package api

import (
	"net/http"
	"strconv"
	"strings"
	"time"

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

// techniqueAggregate accumulates every funnel stage that maps to the same
// ATT&CK technique. Delivery, Open, and Lure all map to T1566.002, and
// Navigator applies a layer's techniques[] entries sequentially, so
// emitting one entry per (stage, technique) pair -- as an earlier version
// of this handler did -- means only the last-processed stage survives on
// screen: Delivery and Open are present in the JSON but invisible after
// Navigator loads it.
type techniqueAggregate struct {
	score    int
	measured bool
	comments []string
}

// ResilienceNavigator returns an ATT&CK Navigator layer for one campaign.
// Score is the number of distinct targets that reached the stage emulating
// the technique, so an unexercised technique scores zero. Every distinct
// techniqueID appears exactly once: when multiple stages share a
// technique, score is the maximum target count across those stages, and
// comment names each contributing stage and its count so no data is
// hidden behind the aggregate.
func (as *Server) ResilienceNavigator(w http.ResponseWriter, r *http.Request) {
	report, ok := as.resilienceReport(w, r)
	if !ok {
		return
	}

	// order preserves first-seen technique order (the funnel's kill-chain
	// order) so the layer is stable and readable rather than shuffled by
	// map iteration.
	order := make([]string, 0, len(report.Funnel))
	aggregates := make(map[string]*techniqueAggregate, len(report.Funnel))
	for _, stage := range report.Funnel {
		for _, technique := range stage.Techniques {
			id := string(technique)
			agg, seen := aggregates[id]
			if !seen {
				agg = &techniqueAggregate{}
				aggregates[id] = agg
				order = append(order, id)
			}
			if stage.Targets > agg.score {
				agg.score = stage.Targets
			}
			agg.measured = agg.measured || stage.Measured
			comment := string(stage.Stage) + ": "
			if stage.Measured {
				comment += strconv.Itoa(stage.Targets)
			} else {
				comment += "not measured"
			}
			agg.comments = append(agg.comments, comment)
		}
	}

	techniques := make([]navigatorTechnique, 0, len(order))
	for _, id := range order {
		agg := aggregates[id]
		color := "#8ec843" // exercised but nothing got through
		if !agg.measured {
			color = "#d3d3d3"
		} else if agg.score > 0 {
			color = "#e60d0d" // targets reached this stage
		}
		techniques = append(techniques, navigatorTechnique{
			TechniqueID: id,
			Score:       agg.score,
			Color:       color,
			Comment:     strings.Join(agg.comments, "; "),
			Enabled:     agg.measured,
		})
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

	campaign, err := models.GetCampaign(campaignID, ctx.Get(r, "user_id").(int64))
	if err != nil {
		JSONResponse(w, models.Response{Success: false, Message: "Campaign not found"}, http.StatusNotFound)
		return resilience.Report{}, false
	}

	report, err := resilience.Compute(models.DB(), campaignID, campaignWindow(campaign), as.telemetryFeatures)
	if err != nil {
		JSONResponse(w, models.Response{Success: false, Message: err.Error()}, http.StatusInternalServerError)
		return resilience.Report{}, false
	}
	return report, true
}

// campaignWindow derives the active period used to bound unattributed
// (campaign_id = 0) cloak/verify events: the resilience package is a pure
// query layer over telemetry_events and does not read the campaigns table
// itself, so this is the one place that translates a campaign row into a
// resilience.Window.
//
// Start is the campaign's launch date. LaunchDate defaults to CreatedDate
// at creation time (see PostCampaign) whenever no explicit launch date was
// given, so it is never zero for a campaign that has actually been posted.
//
// End is the campaign's completed date when the campaign has finished, or
// time.Now() for an in-flight campaign. CompletedDate is the zero value
// until a campaign completes, so using it unconditionally would give an
// in-flight campaign an upper bound in year 1 -- silently excluding every
// unattributed event ever recorded, rather than the intended "everything up
// to now".
func campaignWindow(campaign models.Campaign) resilience.Window {
	end := campaign.CompletedDate
	if end.IsZero() {
		end = time.Now()
	}
	return resilience.Window{Start: campaign.LaunchDate, End: end}
}
