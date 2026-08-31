// Renders the live telemetry panel on the campaign results page.
//
// Unlike every other panel on this page, this does not go through api.* /
// query() (see gophish.js): it opens a native browser EventSource against
// GET /campaigns/:id/feed, the campaign server's own Server-Sent Events
// endpoint. That endpoint rides the same session-cookie authentication as
// the rest of the dashboard -- EventSource cannot attach an Authorization
// header, so it could never call an /api/* route directly (see the note
// on this in resilience.js). The campaign server is the only thing that
// ever talks to olta-feed; the feed's viewer token never reaches the
// browser.
//
// Olta-feed being disabled, or simply not running, is the normal state for
// most engagements. This panel is written to render an idle "waiting for
// events" state in that case and stay that way -- it never spins, never
// blocks page load, and EventSource retries the connection quietly on its
// own if it drops.

var liveFeedSource = null
var liveFeedRowLimit = 50

// liveFeedStageLabels turns the kill-chain stage identifiers used by
// pkg/telemetry into the short labels operators already see in the
// resilience funnel.
var liveFeedStageLabels = {
    delivery: "Delivery",
    open: "Open",
    lure: "Lure",
    cloak: "Cloak",
    verify: "Verify",
    credential: "Credential",
    capture: "Capture",
    replay: "Replay",
    report: "Report",
    initialization: "Initialization",
    webauthn: "WebAuthn"
}

function liveFeedStageLabel(stage) {
    return liveFeedStageLabels[stage] || stage || ""
}

// liveFeedRow builds one <tr> for an incoming telemetry event. Every field
// is escaped: these events ultimately originate from proxied victim
// traffic (actor IP/user agent, technique tags, etc. flow from there into
// telemetry), so nothing here is trusted.
function liveFeedRow(event) {
    event = event || {}
    var time = event.timestamp ? moment.utc(event.timestamp).local().format('h:mm:ss a') : ""
    var techniques = (event.techniques || []).join(", ")
    return '<tr>' +
        '<td>' + escapeHtml(time) + '</td>' +
        '<td>' + escapeHtml(liveFeedStageLabel(event.stage)) + '</td>' +
        '<td>' + escapeHtml(event.outcome || "") + '</td>' +
        '<td>' + escapeHtml(techniques) + '</td>' +
        '<td>' + escapeHtml(event.rid || "") + '</td>' +
        '</tr>'
}

function liveFeedAppend(event) {
    var body = $("#liveFeedBody")
    if (body.length === 0) {
        return
    }
    $("#liveFeedEmpty").remove()
    body.prepend(liveFeedRow(event))
    var rows = body.find("tr")
    if (rows.length > liveFeedRowLimit) {
        rows.slice(liveFeedRowLimit).remove()
    }
}

// startLiveFeed opens the SSE connection for campaignId. Safe to call even
// when the feed is disabled or olta-feed isn't running: the panel simply
// stays on its empty state, and EventSource retries quietly in the
// background rather than surfacing an error.
function startLiveFeed(campaignId) {
    if (typeof EventSource === "undefined") {
        return
    }
    stopLiveFeed()
    liveFeedSource = new EventSource("/campaigns/" + campaignId + "/feed")
    liveFeedSource.onmessage = function (message) {
        var event
        try {
            event = JSON.parse(message.data)
        } catch (e) {
            return
        }
        liveFeedAppend(event)
    }
    // EventSource retries the connection on its own (that is the whole
    // point of using it here); there is nothing extra to do on error
    // besides not treating a drop as fatal to the page.
    liveFeedSource.onerror = function () {}
}

function stopLiveFeed() {
    if (liveFeedSource) {
        liveFeedSource.close()
        liveFeedSource = null
    }
}

$(window).on("beforeunload", function () {
    stopLiveFeed()
})
