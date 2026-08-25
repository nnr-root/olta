// Renders the purple-team resilience panel on the campaign results page.
//
// Consumes GET /campaigns/:id/resilience and links to
// GET /campaigns/:id/resilience/navigator (an ATT&CK Navigator layer export).
// Loaded once, after the campaign is resolved in campaign_results.js - this
// is a point-in-time summary, not a live view, so it is not put on a
// polling timer.

// humanDuration formats a second count as a short, readable duration.
function humanDuration(seconds) {
    if (!seconds || seconds < 0) {
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

// renderFriction shows cloaker enforcement grouped by network owner. A high
// count from a security vendor's ASN is evidence the target's stack
// detonated the link. organization and asn come from a remote cloud IP-range
// feed, so both are escaped like any other untrusted value.
function renderFriction(friction) {
    if (!friction || friction.length === 0) {
        return '<h4>Defensive Friction</h4><p class="text-muted">No cloaker enforcement recorded.</p>'
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
        '<table class="table table-condensed table-hover">' +
        '<thead><tr><th>Organization</th><th>ASN</th><th class="text-right">Blocked</th></tr></thead>' +
        '<tbody>' + rows + '</tbody></table>'
}

// renderRace answers whether the human layer beat the attacker.
function renderRace(race) {
    race = race || {}
    return '<h4>Report vs. Capture</h4>' +
        '<table class="table table-condensed">' +
        '<tr><td>Reported before capture</td><td class="text-right"><strong>' +
        escapeHtml(String(race.reported_before_capture || 0)) + '</strong></td></tr>' +
        '<tr><td>Reported after capture</td><td class="text-right">' +
        escapeHtml(String(race.reported_after_capture || 0)) + '</td></tr>' +
        '<tr><td>Never reported</td><td class="text-right">' +
        escapeHtml(String(race.never_reported || 0)) + '</td></tr>' +
        '<tr><td>Median time to report</td><td class="text-right">' +
        escapeHtml(humanDuration(race.median_time_to_report_seconds)) + '</td></tr>' +
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
                renderFriction(report.friction) +
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
