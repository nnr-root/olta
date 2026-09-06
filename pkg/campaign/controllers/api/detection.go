package api

import (
	"net/http"
	"strconv"
	"strings"

	"github.com/gorilla/mux"
	ctx "github.com/s4l1hs/olta/pkg/campaign/context"
	"github.com/s4l1hs/olta/pkg/campaign/detection"
	"github.com/s4l1hs/olta/pkg/campaign/models"
)

// Detections returns the detection pack for one campaign: the engagement's
// own indicators plus generated Sigma rules.
func (as *Server) Detections(w http.ResponseWriter, r *http.Request) {
	pack, ok := as.detectionPack(w, r)
	if !ok {
		return
	}
	JSONResponse(w, pack, http.StatusOK)
}

// DetectionsSigma returns the same pack as a multi-document Sigma bundle,
// which is the form Sigma tooling ingests a rule set in. It is served as a
// download rather than inline so a browser saves it as a file the operator
// can drop straight into a rule repository.
func (as *Server) DetectionsSigma(w http.ResponseWriter, r *http.Request) {
	pack, ok := as.detectionPack(w, r)
	if !ok {
		return
	}
	filename := "olta-campaign-" + strconv.FormatInt(pack.CampaignID, 10) + "-sigma.yml"
	w.Header().Set("Content-Type", "application/yaml; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="`+filename+`"`)
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(pack.SigmaBundle()))
}

// detectionPack parses the campaign id, authorizes the caller, and builds the
// pack. Authorization mirrors resilienceReport exactly: the campaign is
// looked up scoped to the caller's user_id, so another user's campaign
// resolves as not found rather than forbidden.
func (as *Server) detectionPack(w http.ResponseWriter, r *http.Request) (detection.Pack, bool) {
	vars := mux.Vars(r)
	campaignID, err := strconv.ParseInt(vars["id"], 0, 64)
	if err != nil {
		JSONResponse(w, models.Response{Success: false, Message: "Invalid campaign ID"}, http.StatusBadRequest)
		return detection.Pack{}, false
	}

	campaign, err := models.GetCampaign(campaignID, ctx.Get(r, "user_id").(int64))
	if err != nil {
		JSONResponse(w, models.Response{Success: false, Message: "Campaign not found"}, http.StatusNotFound)
		return detection.Pack{}, false
	}

	pack, err := detection.Build(models.DB(), detectionInput(campaign), detectionScope(campaign))
	if err != nil {
		JSONResponse(w, models.Response{Success: false, Message: err.Error()}, http.StatusInternalServerError)
		return detection.Pack{}, false
	}
	return pack, true
}

// detectionInput translates a campaign row into the campaign-side facts the
// detection package does not read for itself, mirroring how campaignScope
// does it for the resilience report.
func detectionInput(campaign models.Campaign) detection.Input {
	return detection.Input{
		CampaignID:      campaign.Id,
		CampaignName:    campaign.Name,
		Hostnames:       campaignHosts(campaign),
		SenderAddresses: campaignSenders(campaign),
		Subjects:        campaignSubjects(campaign),
	}
}

// detectionScope reuses the resilience scope: the same campaign window and
// hostnames bound which unattributed rows belong to this campaign, and having
// the two disagree would mean the pack and the report described different
// engagements.
func detectionScope(campaign models.Campaign) detection.Scope {
	scope := campaignScope(campaign)
	return detection.Scope{Start: scope.Start, End: scope.End, Hosts: scope.Hosts}
}

// campaignSenders returns the addresses this campaign sent from. Both the
// template's envelope sender and the sending profile's from address are
// included when they differ, because a mail rule matching only one of them
// misses messages the other one sent.
func campaignSenders(campaign models.Campaign) []string {
	senders := make([]string, 0, 2)
	for _, candidate := range []string{campaign.SMTP.FromAddress, campaign.Template.EnvelopeSender} {
		if address := extractAddress(candidate); address != "" {
			senders = append(senders, address)
		}
	}
	for _, variant := range campaign.TemplateVariants {
		if address := extractAddress(variant.Template.EnvelopeSender); address != "" {
			senders = append(senders, address)
		}
	}
	return senders
}

// campaignSubjects returns every subject line a recipient could have
// received, including each A/B variant: a defender's mail rule has to match
// whichever one a given recipient got, and matching only the primary would
// under-report delivery for every other variant.
func campaignSubjects(campaign models.Campaign) []string {
	subjects := make([]string, 0, 1+len(campaign.TemplateVariants))
	if subject := strings.TrimSpace(campaign.Template.Subject); subject != "" {
		subjects = append(subjects, subject)
	}
	for _, variant := range campaign.TemplateVariants {
		if subject := strings.TrimSpace(variant.Template.Subject); subject != "" {
			subjects = append(subjects, subject)
		}
	}
	return subjects
}

// extractAddress pulls the bare address out of a "Display Name <a@b>" header
// value. A mail log's sender field carries the address, not the display name,
// so a rule matching the full header value would never fire.
func extractAddress(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	if open := strings.LastIndex(value, "<"); open >= 0 {
		if close := strings.Index(value[open:], ">"); close > 0 {
			value = value[open+1 : open+close]
		}
	}
	value = strings.TrimSpace(value)
	if !strings.Contains(value, "@") {
		return ""
	}
	return value
}
