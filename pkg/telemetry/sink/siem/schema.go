// Package siem delivers telemetry events to a defender's own analysis
// platform in a schema that platform already understands.
//
// The existing webhook sink speaks Slack, Discord and a generic Olta JSON
// envelope. Those are notification channels: a human reads them once and they
// are gone. A purple-team engagement's value is in what the defender can
// query afterwards -- "show me every cloak event from our own scanner ASN",
// "correlate these captures against our sign-in logs" -- and that requires the
// events to land in the shape the platform indexes on, not in Olta's shape
// with a transformation pipeline in between.
//
// Two schemas are supported, chosen because they are the two a SOC is
// realistically already on: Elastic Common Schema (ECS) and OCSF. Both
// mappings are pure functions over a telemetry.Event, so they are testable
// without a network and reusable by anything that wants the document without
// shipping it anywhere.
//
// The no-loot guarantee carries over unchanged: these mappings read the same
// vetted Event that every other sink receives (see telemetry.WithDetail), and
// they only ever rename and nest its fields. Nothing here can introduce a
// value the event did not already carry.
package siem

import (
	"fmt"
	"strconv"
	"time"

	"github.com/s4l1hs/olta/pkg/telemetry"
)

// Schema selects the document format.
type Schema string

const (
	// SchemaECS is Elastic Common Schema, the format Elasticsearch,
	// OpenSearch and Beats index natively.
	SchemaECS Schema = "ecs"
	// SchemaOCSF is the Open Cybersecurity Schema Framework, used by
	// Amazon Security Lake, Splunk and others.
	SchemaOCSF Schema = "ocsf"
)

// Document renders one event in the selected schema.
func Document(schema Schema, event telemetry.Event) (map[string]any, error) {
	switch schema {
	case SchemaECS:
		return ecsDocument(event), nil
	case SchemaOCSF:
		return ocsfDocument(event), nil
	default:
		return nil, fmt.Errorf("unsupported siem schema %q", schema)
	}
}

// ecsDocument maps an event onto Elastic Common Schema field names.
//
// Field choices worth stating, since a wrong one is worse than a missing one:
//
//   - event.kind is "event" and event.category "intrusion_detection" for
//     every row. These are emulated adversary actions observed by the tool
//     producing them, which is exactly that category.
//   - event.outcome uses ECS's own closed vocabulary (success / failure /
//     unknown), which is NOT the same axis as Olta's outcome. Olta's
//     "blocked" is a defensive success and an adversary failure; ECS's
//     outcome describes the event's own action, so a blocked cloak maps to
//     "failure" -- the proxy's attempt failed. The unmapped Olta outcome is
//     preserved verbatim under olta.outcome so nothing is lost to the
//     translation.
//   - threat.technique.id carries the ATT&CK techniques, which is where
//     Elastic's own detection content looks for them.
//   - source.ip / source.as.* describe the request source, matching Actor's
//     own definition. The victim's identity is never in Actor and so is
//     never here.
func ecsDocument(event telemetry.Event) map[string]any {
	document := map[string]any{
		"@timestamp": event.Timestamp.UTC().Format(time.RFC3339Nano),
		"ecs":        map[string]any{"version": "8.11.0"},
		"event": map[string]any{
			"id":       event.ID,
			"kind":     "event",
			"category": []string{"intrusion_detection"},
			"action":   string(event.Stage),
			"outcome":  ecsOutcome(event.Outcome),
			"module":   "olta",
			"dataset":  "olta.telemetry",
		},
		"observer": map[string]any{
			"vendor":  "Olta",
			"type":    "proxy",
			"product": "olta",
		},
	}

	if len(event.Techniques) > 0 {
		ids := make([]string, len(event.Techniques))
		for i, technique := range event.Techniques {
			ids[i] = string(technique)
		}
		document["threat"] = map[string]any{
			"framework": "MITRE ATT&CK",
			"technique": map[string]any{"id": ids},
		}
	}

	source := map[string]any{}
	if event.Actor.IP != "" {
		source["ip"] = event.Actor.IP
	}
	if event.Actor.ASN != "" || event.Actor.Organization != "" {
		autonomousSystem := map[string]any{}
		if number, ok := asNumber(event.Actor.ASN); ok {
			autonomousSystem["number"] = number
		}
		if event.Actor.Organization != "" {
			autonomousSystem["organization"] = map[string]any{"name": event.Actor.Organization}
		}
		source["as"] = autonomousSystem
	}
	if event.Actor.Country != "" {
		source["geo"] = map[string]any{"country_iso_code": event.Actor.Country}
	}
	if len(source) > 0 {
		document["source"] = source
	}
	if event.Actor.UserAgent != "" {
		document["user_agent"] = map[string]any{"original": event.Actor.UserAgent}
	}
	if event.Host != "" {
		document["url"] = map[string]any{"domain": event.Host}
	}

	// olta.* holds everything with no faithful ECS home. Inventing a
	// standard field for a concept ECS does not have would make the document
	// wrong for every consumer that trusts the schema.
	olta := map[string]any{
		"stage":   string(event.Stage),
		"outcome": string(event.Outcome),
	}
	if event.CampaignID != 0 {
		olta["campaign_id"] = event.CampaignID
	}
	if event.RID != "" {
		olta["recipient_id"] = event.RID
	}
	if event.InstanceID != "" {
		olta["instance_id"] = event.InstanceID
	}
	if event.Actor.ClientProfile != "" {
		olta["client_profile"] = event.Actor.ClientProfile
	}
	if len(event.Detail) > 0 {
		olta["detail"] = event.Detail
	}
	document["olta"] = olta

	return document
}

// ecsOutcome maps to ECS's closed event.outcome vocabulary. See ecsDocument's
// doc comment for why "blocked" becomes "failure" rather than "success".
func ecsOutcome(outcome telemetry.Outcome) string {
	switch outcome {
	case telemetry.OutcomeAllowed, telemetry.OutcomeCaptured:
		return "success"
	case telemetry.OutcomeBlocked, telemetry.OutcomeFailed:
		return "failure"
	default:
		return "unknown"
	}
}

// ocsfDocument maps an event onto OCSF's Detection Finding class (2004).
//
// Detection Finding is the honest class for these events: the tool is
// reporting something it observed and classified, not a raw network or
// authentication record it merely forwarded. severity_id is left at
// Informational for every row on purpose -- Olta cannot know how severe a
// stage is for a given organization, and inventing a severity would give a
// defender's alerting rules a number with nothing behind it.
func ocsfDocument(event telemetry.Event) map[string]any {
	document := map[string]any{
		"activity_id":   1, // Create
		"category_uid":  2, // Findings
		"class_uid":     2004,
		"type_uid":      200401,
		"time":          event.Timestamp.UTC().UnixMilli(),
		"severity_id":   1, // Informational
		"status_id":     ocsfStatusID(event.Outcome),
		"status":        string(event.Outcome),
		"metadata":      ocsfMetadata(event),
		"finding_info":  ocsfFindingInfo(event),
		"unmapped":      ocsfUnmapped(event),
		"observables":   ocsfObservables(event),
		"raw_data_size": 0,
	}
	if source := ocsfSourceEndpoint(event); len(source) > 0 {
		document["src_endpoint"] = source
	}
	return document
}

// ocsfStatusID maps to OCSF's status vocabulary: 1 Success, 2 Failure,
// 0 Unknown. Same reasoning as ECS -- this describes the observed action's
// own result, not whether the defender did well.
func ocsfStatusID(outcome telemetry.Outcome) int {
	switch outcome {
	case telemetry.OutcomeAllowed, telemetry.OutcomeCaptured:
		return 1
	case telemetry.OutcomeBlocked, telemetry.OutcomeFailed:
		return 2
	default:
		return 0
	}
}

func ocsfMetadata(event telemetry.Event) map[string]any {
	product := map[string]any{
		"name":        "Olta",
		"vendor_name": "Olta",
	}
	if event.InstanceID != "" {
		product["uid"] = event.InstanceID
	}
	return map[string]any{
		"version": "1.1.0",
		"product": product,
		"uid":     event.ID,
	}
}

func ocsfFindingInfo(event telemetry.Event) map[string]any {
	info := map[string]any{
		"uid":   event.ID,
		"title": "Olta " + string(event.Stage) + " (" + string(event.Outcome) + ")",
	}
	if len(event.Techniques) > 0 {
		techniques := make([]map[string]any, len(event.Techniques))
		for i, technique := range event.Techniques {
			techniques[i] = map[string]any{"uid": string(technique)}
		}
		info["attacks"] = []map[string]any{{
			"version":    "14",
			"technique":  techniques[0],
			"techniques": techniques,
		}}
	}
	return info
}

func ocsfSourceEndpoint(event telemetry.Event) map[string]any {
	endpoint := map[string]any{}
	if event.Actor.IP != "" {
		endpoint["ip"] = event.Actor.IP
	}
	if event.Host != "" {
		endpoint["domain"] = event.Host
	}
	if event.Actor.ASN != "" || event.Actor.Organization != "" {
		autonomousSystem := map[string]any{}
		if number, ok := asNumber(event.Actor.ASN); ok {
			autonomousSystem["number"] = number
		}
		if event.Actor.Organization != "" {
			autonomousSystem["name"] = event.Actor.Organization
		}
		endpoint["autonomous_system"] = autonomousSystem
	}
	return endpoint
}

func ocsfObservables(event telemetry.Event) []map[string]any {
	observables := make([]map[string]any, 0, 2)
	if event.Actor.IP != "" {
		observables = append(observables, map[string]any{
			"name":    "src_endpoint.ip",
			"type_id": 2, // IP Address
			"value":   event.Actor.IP,
		})
	}
	if event.Host != "" {
		observables = append(observables, map[string]any{
			"name":    "src_endpoint.domain",
			"type_id": 1, // Hostname
			"value":   event.Host,
		})
	}
	return observables
}

func ocsfUnmapped(event telemetry.Event) map[string]any {
	unmapped := map[string]any{
		"stage":   string(event.Stage),
		"outcome": string(event.Outcome),
	}
	if event.CampaignID != 0 {
		unmapped["campaign_id"] = event.CampaignID
	}
	if event.RID != "" {
		unmapped["recipient_id"] = event.RID
	}
	if event.Actor.UserAgent != "" {
		unmapped["user_agent"] = event.Actor.UserAgent
	}
	if event.Actor.ClientProfile != "" {
		unmapped["client_profile"] = event.Actor.ClientProfile
	}
	if len(event.Detail) > 0 {
		unmapped["detail"] = event.Detail
	}
	return unmapped
}

// asNumber parses telemetry.Actor.ASN's display form ("AS15169") back into
// the integer both schemas expect. A value that is not in that form
// contributes no number rather than a wrong one.
func asNumber(asn string) (int64, bool) {
	if len(asn) < 3 || (asn[0] != 'A' && asn[0] != 'a') || (asn[1] != 'S' && asn[1] != 's') {
		return 0, false
	}
	number, err := strconv.ParseInt(asn[2:], 10, 64)
	if err != nil {
		return 0, false
	}
	return number, true
}
