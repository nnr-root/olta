// Renders the purple-team resilience panel on the campaign results page.
//
// Consumes GET /campaigns/:id/resilience and links to
// GET /campaigns/:id/resilience/navigator (an ATT&CK Navigator layer export).
// Loaded once, after the campaign is resolved in campaign_results.js - this
// is a point-in-time summary, not a live view, so it is not put on a
// polling timer.

// humanDuration formats a second count as a short, readable duration.
//
// hasValue distinguishes "no target has reported yet" from a genuine
// zero-second median: median(nil) and a real 0-second median both resolve
// to the number 0 from the API, and treating 0 as falsy (as an earlier
// version of this function did via `!seconds`) rendered both as "n/a",
// silently discarding the real "someone reported instantly" case.
function humanDuration(seconds, hasValue) {
    if (!hasValue || seconds < 0) {
        return "n/a"
    }
    if (seconds < 60) {
        return seconds + "s"
    }
    if (seconds < 3600) {
        return Math.round(seconds / 60) + "m"
    }
    return (seconds / 3600).toFixed(1) + "h"
}

// renderFunnel builds the kill-chain table. A stage whose feature was
// disabled renders "Not measured", never 0: zero reads as "nothing was
// blocked" when the truth is "nothing was watching". The targets count is
// only ever rendered on the branch where measured is true, so a disabled
// stage cannot reach the DOM as a number on any code path.
function renderFunnel(funnel) {
    var rows = ""
    $.each(funnel || [], function (i, stage) {
        var count
        if (stage.measured) {
            count = '<strong>' + escapeHtml(String(stage.targets)) + '</strong>'
        } else {
            count = '<span class="text-muted">Not measured</span>'
        }
        var techniques = ""
        $.each(stage.techniques || [], function (j, t) {
            techniques += '<code>' + escapeHtml(t) + '</code> '
        })
        rows += '<tr>' +
            '<td>' + escapeHtml(stage.stage) + '</td>' +
            '<td>' + techniques + '</td>' +
            '<td class="text-right">' + count + '</td>' +
            '</tr>'
    })
    return '<h4>Kill Chain</h4>' +
        '<table class="table table-condensed table-hover">' +
        '<thead><tr><th>Stage</th><th>ATT&amp;CK</th><th class="text-right">Targets</th></tr></thead>' +
        '<tbody>' + rows + '</tbody></table>'
}

// renderFrictionScope builds the caption required under Defensive Friction:
// cloak/verify events are unattributed by design (they fire before lure
// validation resolves a recipient), so the server can only bound them to
// the campaign's time window, not prove they came from this campaign
// specifically. frictionScope is server-authored plain text (see
// pkg/campaign/resilience.frictionScopeCaption) but is still escaped like
// any other interpolated value.
function renderFrictionScope(frictionScope) {
    if (!frictionScope) {
        return ""
    }
    return '<p class="text-muted"><small>' + escapeHtml(frictionScope) + '</small></p>'
}

// renderFriction shows cloaker enforcement grouped by network owner. A high
// count from a security vendor's ASN is evidence the target's stack
// detonated the link. organization and asn come from a remote cloud IP-range
// feed, so both are escaped like any other untrusted value.
//
// frictionScope is rendered as a caption under the heading on every code
// path, including the empty-friction one: the caveat is about what the
// counts mean when they exist, not something to skip when there happen to
// be none this time.
function renderFriction(friction, frictionScope) {
    if (!friction || friction.length === 0) {
        return '<h4>Defensive Friction</h4>' +
            renderFrictionScope(frictionScope) +
            '<p class="text-muted">No cloaker enforcement recorded.</p>'
    }
    var rows = ""
    $.each(friction, function (i, entry) {
        rows += '<tr>' +
            '<td>' + escapeHtml(entry.organization || "unknown") + '</td>' +
            '<td>' + escapeHtml(entry.asn || "") + '</td>' +
            '<td class="text-right">' + escapeHtml(String(entry.count)) + '</td>' +
            '</tr>'
    })
    return '<h4>Defensive Friction</h4>' +
        renderFrictionScope(frictionScope) +
        '<table class="table table-condensed table-hover">' +
        '<thead><tr><th>Organization</th><th>ASN</th><th class="text-right">Blocked</th></tr></thead>' +
        '<tbody>' + rows + '</tbody></table>'
}

// renderRace answers whether the human layer beat the attacker. Delivered is
// the denominator: every delivered target falls into exactly one of the
// three buckets below, so it is rendered up front rather than left implicit
// -- an earlier version of the underlying report only classified targets
// that were captured or reported, silently omitting delivered targets who
// never engaged at all from the count a reader could see.
function renderRace(race) {
    race = race || {}
    return '<h4>Report vs. Capture</h4>' +
        '<table class="table table-condensed">' +
        '<tr><td>Delivered</td><td class="text-right">' +
        escapeHtml(String(race.delivered || 0)) + '</td></tr>' +
        '<tr><td>Reported before capture</td><td class="text-right"><strong>' +
        escapeHtml(String(race.reported_before_capture || 0)) + '</strong></td></tr>' +
        '<tr><td>Reported after capture</td><td class="text-right">' +
        escapeHtml(String(race.reported_after_capture || 0)) + '</td></tr>' +
        '<tr><td>Never reported</td><td class="text-right">' +
        escapeHtml(String(race.never_reported || 0)) + '</td></tr>' +
        '<tr><td>Median time to report</td><td class="text-right">' +
        escapeHtml(humanDuration(race.median_time_to_report_seconds, race.has_median_time_to_report)) + '</td></tr>' +
        '</table>'
}

// renderNavigatorLink builds the ATT&CK Navigator layer download control.
// The click handler is bound separately in loadResilience() via jQuery,
// not inlined as an onclick attribute, so campaignId never has to be
// serialized into an HTML attribute string.
//
// This cannot be a plain <a href> pointing at the API endpoint: the API
// requires a Bearer Authorization header (see RequireAPIKeyWithOrigins in
// pkg/campaign/middleware/middleware.go) with no cookie or query-param
// fallback, so a bare browser navigation to that URL would 401. Instead this
// fetches the layer through the authenticated api wrapper and hands the
// result to the browser as a Blob, mirroring the pattern exportAsCSV()
// already uses in campaign_results.js for the CSV export buttons.
function renderNavigatorLink() {
    return '<button type="button" id="resilience-navigator-download" class="btn btn-default btn-sm">' +
        '<i class="fa fa-download"></i> Download ATT&amp;CK Navigator layer</button>'
}

// downloadNavigatorLayer fetches the Navigator layer for campaignId and
// saves it client-side as olta-navigator-layer.json.
function downloadNavigatorLayer(campaignId) {
    api.campaignId.resilienceNavigator(campaignId)
        .success(function (layer) {
            var json = JSON.stringify(layer, null, 2)
            var blob = new Blob([json], {
                type: 'application/json;charset=utf-8;'
            })
            var filename = 'olta-navigator-layer.json'
            if (navigator.msSaveBlob) {
                navigator.msSaveBlob(blob, filename)
                return
            }
            var blobURL = window.URL.createObjectURL(blob)
            var dlLink = document.createElement('a')
            dlLink.href = blobURL
            dlLink.setAttribute('download', filename)
            document.body.appendChild(dlLink)
            dlLink.click()
            document.body.removeChild(dlLink)
            window.URL.revokeObjectURL(blobURL)
        })
        .error(function () {
            errorFlash(' Could not download the ATT&CK Navigator layer.')
        })
}

// loadResilience fetches the resilience report for campaignId and renders it
// into #resilience-panel. Called once, after the campaign is resolved.
function loadResilience(campaignId) {
    api.campaignId.resilience(campaignId)
        .success(function (report) {
            report = report || {}
            $("#resilience-panel").html(
                renderFunnel(report.funnel) +
                renderFriction(report.friction, report.friction_scope) +
                renderRace(report.race) +
                renderNavigatorLink()
            )
            $("#resilience-navigator-download").on("click", function () {
                downloadNavigatorLayer(campaignId)
            })
        })
        .error(function () {
            $("#resilience-panel").html(
                '<div class="alert alert-danger">Could not load the resilience report.</div>'
            )
        })
}
