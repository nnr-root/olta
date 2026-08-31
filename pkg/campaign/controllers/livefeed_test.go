package controllers

import (
	"context"
	"net/http"
	"net/http/cookiejar"
	"testing"
	"time"

	"github.com/s4l1hs/olta/pkg/campaign/auth"
	"github.com/s4l1hs/olta/pkg/campaign/models"
	"github.com/s4l1hs/olta/pkg/telemetry"
)

// TestLiveFeedHubDisabledIsIdle exercises the "feed_enabled: false, or
// olta-feed simply isn't running" path directly against the hub, without
// any HTTP plumbing: Start must be a no-op, and Subscribe/Publish/
// Unsubscribe must all still work so a dashboard client sees a normal,
// empty, non-hanging feed.
func TestLiveFeedHubDisabledIsIdle(t *testing.T) {
	hub := NewLiveFeedHub("", false)
	hub.Start()
	defer hub.Shutdown()

	ch, replay := hub.Subscribe()
	if len(replay) != 0 {
		t.Fatalf("replay = %v, want empty", replay)
	}
	select {
	case ev := <-ch:
		t.Fatalf("unexpected event on a disabled hub: %+v", ev)
	case <-time.After(50 * time.Millisecond):
	}
	hub.Unsubscribe(ch)
}

// TestLiveFeedHubRingBounded confirms the ring buffer never grows past its
// configured limit even under sustained publishing.
func TestLiveFeedHubRingBounded(t *testing.T) {
	hub := NewLiveFeedHub("", false)
	for i := 0; i < liveFeedRingLimit*3; i++ {
		hub.Publish(telemetry.New(telemetry.StageDelivery, telemetry.OutcomeAllowed).WithCampaign(1, "rid"))
	}
	_, replay := hub.Subscribe()
	if len(replay) != liveFeedRingLimit {
		t.Fatalf("ring length = %d, want %d", len(replay), liveFeedRingLimit)
	}
}

// TestLiveFeedHubPublishSubscribeFiltering confirms a subscriber receives
// only events published after it subscribed, via its channel, in addition
// to the pre-subscription replay snapshot.
func TestLiveFeedHubPublishSubscribeFiltering(t *testing.T) {
	hub := NewLiveFeedHub("", false)
	hub.Publish(telemetry.New(telemetry.StageDelivery, telemetry.OutcomeAllowed).WithCampaign(1, "before"))

	ch, replay := hub.Subscribe()
	defer hub.Unsubscribe(ch)
	if len(replay) != 1 || replay[0].RID != "before" {
		t.Fatalf("replay = %+v, want one event with RID=before", replay)
	}

	hub.Publish(telemetry.New(telemetry.StageDelivery, telemetry.OutcomeAllowed).WithCampaign(1, "after"))
	select {
	case ev := <-ch:
		if ev.RID != "after" {
			t.Fatalf("RID = %q, want %q", ev.RID, "after")
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for live event")
	}
}

// TestCampaignLiveFeedRequiresLogin verifies the SSE route is registered
// behind the same session-cookie auth as the neighbouring dashboard route
// (/campaigns/{id}), not the API's Bearer-token middleware -- a browser
// EventSource cannot attach an Authorization header.
func TestCampaignLiveFeedRequiresLogin(t *testing.T) {
	ctx := setupTest(t)
	defer tearDown(t, ctx)

	client := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	resp, err := client.Get(ctx.adminServer.URL + "/campaigns/1/feed")
	if err != nil {
		t.Fatalf("error requesting feed endpoint: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusTemporaryRedirect {
		t.Fatalf("status = %d, want %d (redirect to login)", resp.StatusCode, http.StatusTemporaryRedirect)
	}
	loc, err := resp.Location()
	if err != nil {
		t.Fatalf("error parsing redirect location: %v", err)
	}
	if loc.Path != "/login" {
		t.Fatalf("redirect path = %q, want /login", loc.Path)
	}
}

// TestCampaignLiveFeedDisabledFeedServesCleanly is the most important test
// in this file: with the feed disabled (the default, and the most common
// real-world state), an authenticated request to the SSE endpoint must
// still return promptly with a 200 and the right content type -- never
// hang, never error -- so the dashboard panel simply renders idle.
func TestCampaignLiveFeedDisabledFeedServesCleanly(t *testing.T) {
	ctx := setupTest(t)
	defer tearDown(t, ctx)

	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatalf("error creating cookie jar: %v", err)
	}
	client := &http.Client{Jar: jar}
	loginResp := attemptLogin(t, ctx, client, "admin", "gophish", "")
	if loginResp.StatusCode != http.StatusOK {
		t.Fatalf("login status = %d, want 200", loginResp.StatusCode)
	}
	// The freshly-provisioned admin account always carries
	// PasswordChangeRequired from setup, which would otherwise redirect
	// every subsequent authenticated request (including this one) to
	// /reset_password regardless of session validity.
	admin, err := models.GetUser(1)
	if err != nil {
		t.Fatalf("error getting admin user: %v", err)
	}
	admin.PasswordChangeRequired = false
	if err := models.PutUser(&admin); err != nil {
		t.Fatalf("error clearing password change requirement: %v", err)
	}

	reqCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, ctx.adminServer.URL+"/campaigns/1/feed", nil)
	if err != nil {
		t.Fatalf("error building feed request: %v", err)
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("error requesting feed endpoint: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); ct != "text/event-stream" {
		t.Fatalf("Content-Type = %q, want text/event-stream", ct)
	}
}

// TestCampaignLiveFeedRejectsUnownedCampaign is the IDOR check: an
// authenticated operator must not be able to stream another user's
// campaign telemetry by guessing its ID.
func TestCampaignLiveFeedRejectsUnownedCampaign(t *testing.T) {
	ctx := setupTest(t)
	defer tearDown(t, ctx)

	// A second, unlocked operator who owns no campaigns; campaign 1
	// belongs to admin. (houdini, the other pre-existing test user, is
	// account-locked and can't log in at all -- not the case this test is
	// after.)
	hash, err := auth.GeneratePasswordHash("gophish")
	if err != nil {
		t.Fatalf("error hashing password: %v", err)
	}
	role, err := models.GetRoleBySlug(models.RoleUser)
	if err != nil {
		t.Fatalf("error getting standard role: %v", err)
	}
	otherOperator := models.User{Username: "otherop", Hash: hash, ApiKey: auth.GenerateSecureKey(auth.APIKeyLength), RoleID: role.ID}
	if err := models.PutUser(&otherOperator); err != nil {
		t.Fatalf("error creating second operator: %v", err)
	}

	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatalf("error creating cookie jar: %v", err)
	}
	client := &http.Client{Jar: jar}
	loginResp := attemptLogin(t, ctx, client, "otherop", "gophish", "")
	if loginResp.StatusCode != http.StatusOK {
		t.Fatalf("login status = %d, want 200", loginResp.StatusCode)
	}

	reqCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, ctx.adminServer.URL+"/campaigns/1/feed", nil)
	if err != nil {
		t.Fatalf("error building feed request: %v", err)
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("error requesting feed endpoint: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("status = %d, want 404 for another operator's campaign", resp.StatusCode)
	}
}
