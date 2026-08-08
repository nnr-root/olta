package controllers

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"net/http"
	"testing"

	"github.com/s4l1hs/olta/pkg/campaign/models"
)

func getFirstCampaign(t *testing.T) models.Campaign {
	campaigns, err := models.GetCampaigns(1)
	if err != nil {
		t.Fatalf("error getting first campaign from database: %v", err)
	}
	return campaigns[0]
}

func getFirstEmailRequest(t *testing.T) models.EmailRequest {
	campaign := getFirstCampaign(t)
	req := models.EmailRequest{
		TemplateId:    campaign.TemplateId,
		Template:      campaign.Template,
		URL:           "http://localhost.localdomain",
		UserId:        1,
		BaseRecipient: campaign.Results[0].BaseRecipient,
		SMTP:          campaign.SMTP,
		FromAddress:   campaign.SMTP.FromAddress,
	}
	err := models.PostEmailRequest(&req)
	if err != nil {
		t.Fatalf("error creating email request: %v", err)
	}
	return req
}

func openEmail(t *testing.T, ctx *testContext, rid string) {
	resp, err := http.Get(fmt.Sprintf("%s/track?%s=%s", ctx.phishServer.URL, models.RecipientParameter, rid))
	if err != nil {
		t.Fatalf("error requesting /track endpoint: %v", err)
	}
	defer resp.Body.Close()
	got, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("error reading response body from /track endpoint: %v", err)
	}
	expected, err := ioutil.ReadFile("static/images/pixel.png")
	if err != nil {
		t.Fatalf("error reading local transparent pixel: %v", err)
	}
	if !bytes.Equal(got, expected) {
		t.Fatalf("unexpected tracking pixel data received. expected %#v got %#v", expected, got)
	}
}

func openEmail404(t *testing.T, ctx *testContext, rid string) {
	resp, err := http.Get(fmt.Sprintf("%s/track?%s=%s", ctx.phishServer.URL, models.RecipientParameter, rid))
	if err != nil {
		t.Fatalf("error requesting /track endpoint: %v", err)
	}
	defer resp.Body.Close()
	got := resp.StatusCode
	expected := http.StatusNotFound
	if got != expected {
		t.Fatalf("invalid status code received for /track endpoint. expected %d got %d", expected, got)
	}
}

func reportedEmail(t *testing.T, ctx *testContext, rid string) {
	resp, err := http.Get(fmt.Sprintf("%s/report?%s=%s", ctx.phishServer.URL, models.RecipientParameter, rid))
	if err != nil {
		t.Fatalf("error requesting /report endpoint: %v", err)
	}
	got := resp.StatusCode
	expected := http.StatusNoContent
	if got != expected {
		t.Fatalf("invalid status code received for /report endpoint. expected %d got %d", expected, got)
	}
}

func reportEmail404(t *testing.T, ctx *testContext, rid string) {
	resp, err := http.Get(fmt.Sprintf("%s/report?%s=%s", ctx.phishServer.URL, models.RecipientParameter, rid))
	if err != nil {
		t.Fatalf("error requesting /report endpoint: %v", err)
	}
	got := resp.StatusCode
	expected := http.StatusNotFound
	if got != expected {
		t.Fatalf("invalid status code received for /report endpoint. expected %d got %d", expected, got)
	}
}

func clickLink404(t *testing.T, ctx *testContext, rid string) {
	resp, err := http.Get(fmt.Sprintf("%s/?%s=%s", ctx.phishServer.URL, models.RecipientParameter, rid))
	if err != nil {
		t.Fatalf("error requesting / endpoint: %v", err)
	}
	defer resp.Body.Close()
	got := resp.StatusCode
	expected := http.StatusNotFound
	if got != expected {
		t.Fatalf("invalid status code received for / endpoint. expected %d got %d", expected, got)
	}
}

func TestOpenedPhishingEmail(t *testing.T) {
	ctx := setupTest(t)
	defer tearDown(t, ctx)
	campaign := getFirstCampaign(t)
	result := campaign.Results[0]
	if result.Status != models.StatusSending {
		t.Fatalf("unexpected result status received. expected %s got %s", models.StatusSending, result.Status)
	}

	openEmail(t, ctx, result.RId)

	campaign = getFirstCampaign(t)
	result = campaign.Results[0]
	lastEvent := campaign.Events[len(campaign.Events)-1]
	if result.Status != models.EventOpened {
		t.Fatalf("unexpected result status received. expected %s got %s", models.EventOpened, result.Status)
	}
	if lastEvent.Message != models.EventOpened {
		t.Fatalf("unexpected event status received. expected %s got %s", lastEvent.Message, models.EventOpened)
	}
	if result.ModifiedDate != lastEvent.Time {
		t.Fatalf("unexpected result modified date received. expected %s got %s", lastEvent.Time, result.ModifiedDate)
	}
}

func TestReportedPhishingEmail(t *testing.T) {
	ctx := setupTest(t)
	defer tearDown(t, ctx)
	campaign := getFirstCampaign(t)
	result := campaign.Results[0]
	if result.Status != models.StatusSending {
		t.Fatalf("unexpected result status received. expected %s got %s", models.StatusSending, result.Status)
	}

	reportedEmail(t, ctx, result.RId)

	campaign = getFirstCampaign(t)
	result = campaign.Results[0]
	lastEvent := campaign.Events[len(campaign.Events)-1]

	if result.Reported != true {
		t.Fatalf("unexpected result report status received. expected %v got %v", true, result.Reported)
	}
	if lastEvent.Message != models.EventReported {
		t.Fatalf("unexpected event status received. expected %s got %s", lastEvent.Message, models.EventReported)
	}
	if result.ModifiedDate != lastEvent.Time {
		t.Fatalf("unexpected result modified date received. expected %s got %s", lastEvent.Time, result.ModifiedDate)
	}
}

func TestNoRecipientID(t *testing.T) {
	ctx := setupTest(t)
	defer tearDown(t, ctx)
	resp, err := http.Get(fmt.Sprintf("%s/track", ctx.phishServer.URL))
	if err != nil {
		t.Fatalf("error requesting /track endpoint: %v", err)
	}
	got := resp.StatusCode
	expected := http.StatusNotFound
	if got != expected {
		t.Fatalf("invalid status code received for /track endpoint. expected %d got %d", expected, got)
	}

	resp, err = http.Get(ctx.phishServer.URL)
	if err != nil {
		t.Fatalf("error requesting /track endpoint: %v", err)
	}
	got = resp.StatusCode
	if got != expected {
		t.Fatalf("invalid status code received for / endpoint. expected %d got %d", expected, got)
	}
}

func TestInvalidRecipientID(t *testing.T) {
	ctx := setupTest(t)
	defer tearDown(t, ctx)
	rid := "XXXXXXXXXX"
	openEmail404(t, ctx, rid)
	clickLink404(t, ctx, rid)
	reportEmail404(t, ctx, rid)
}

func TestCompletedCampaignClick(t *testing.T) {
	ctx := setupTest(t)
	defer tearDown(t, ctx)
	campaign := getFirstCampaign(t)
	result := campaign.Results[0]
	if result.Status != models.StatusSending {
		t.Fatalf("unexpected result status received. expected %s got %s", models.StatusSending, result.Status)
	}

	openEmail(t, ctx, result.RId)

	campaign = getFirstCampaign(t)
	result = campaign.Results[0]
	if result.Status != models.EventOpened {
		t.Fatalf("unexpected result status received. expected %s got %s", models.EventOpened, result.Status)
	}

	models.CompleteCampaign(campaign.Id, 1)
	openEmail404(t, ctx, result.RId)
	clickLink404(t, ctx, result.RId)

	campaign = getFirstCampaign(t)
	result = campaign.Results[0]
	if result.Status != models.EventOpened {
		t.Fatalf("unexpected result status received. expected %s got %s", models.EventOpened, result.Status)
	}
}

func TestRobotsHandler(t *testing.T) {
	ctx := setupTest(t)
	defer tearDown(t, ctx)
	resp, err := http.Get(fmt.Sprintf("%s/robots.txt", ctx.phishServer.URL))
	if err != nil {
		t.Fatalf("error requesting /robots.txt endpoint: %v", err)
	}
	defer resp.Body.Close()
	got := resp.StatusCode
	expectedStatus := http.StatusOK
	if got != expectedStatus {
		t.Fatalf("invalid status code received for /track endpoint. expected %d got %d", expectedStatus, got)
	}
	expected := []byte("User-agent: *\nDisallow: /\n")
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("error reading response body from /robots.txt endpoint: %v", err)
	}
	if !bytes.Equal(body, expected) {
		t.Fatalf("invalid robots.txt response received. expected %s got %s", expected, body)
	}
}

func TestInvalidPreviewID(t *testing.T) {
	ctx := setupTest(t)
	defer tearDown(t, ctx)
	bogusRId := fmt.Sprintf("%sbogus", models.PreviewPrefix)
	openEmail404(t, ctx, bogusRId)
	clickLink404(t, ctx, bogusRId)
	reportEmail404(t, ctx, bogusRId)
}

func TestPreviewTrack(t *testing.T) {
	ctx := setupTest(t)
	defer tearDown(t, ctx)
	req := getFirstEmailRequest(t)
	openEmail(t, ctx, req.RId)
}

func TestInvalidTransparencyRequest(t *testing.T) {
	ctx := setupTest(t)
	defer tearDown(t, ctx)
	bogusRId := fmt.Sprintf("bogus%s", TransparencySuffix)
	openEmail404(t, ctx, bogusRId)
	clickLink404(t, ctx, bogusRId)
	reportEmail404(t, ctx, bogusRId)
}
