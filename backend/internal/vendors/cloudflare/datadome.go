package cloudflare

import (
	"strings"

	"github.com/menta2k/siem/internal/vendors"
)

// DataDome's Cloudflare integration works by a Worker calling DataDome's protection API
// for every request it guards. Cloudflare logs that call as an ordinary subrequest, so
// the http_requests dataset contains one extra row per protected request — measured on
// production at 549,000 in three hours, a quarter of all Cloudflare events, and the
// second-largest "hostname" in the whole dataset.
//
// Read literally those rows are junk: a POST to api-cloudflare.datadome.co from
// Cloudflare's own egress address. Read correctly they are DataDome's verdict, and the
// only one available — there is no DataDome feed here, so without this the platform has
// no visibility into a vendor that challenges roughly a fifth of the traffic.
const dataDomeHost = "api-cloudflare.datadome.co"

// The protection API answers the Worker with the decision, and Cloudflare records that
// answer's status. Verified against DataDome's own dashboard export for the busiest
// client (1,000 of 1,000 rows) and against the response-size distribution over six
// hours, which forms exactly ONE cluster per status — so there is no second, differently
// shaped 403 hiding behind these numbers.
const (
	dataDomeAllowed    = 200
	dataDomeChallenged = 403
)

// trafficRuleResponse is DataDome's own name for what it decided, carried on the
// protection API's response when Logs Enrichment is enabled.
//
// THE STATUS CODE CANNOT ANSWER THIS. A 403 is returned for a Device Check, for a slider
// CAPTCHA and for a hard block alike, and measured here 11.7% of them are hard blocks —
// roughly 82,000 requests a day that were being recorded as merely challenged. Reading a
// real block as a softer verdict is the wrong direction for a SIEM to be wrong in, and it
// also under-reports disagreement: a DataDome hard block against a Cloudflare allow is an
// allow-vs-block conflict, not allow-vs-challenge.
const trafficRuleResponseHeader = "x-datadome-traffic-rule-response"

// The values DataDome sends. Taken from live traffic rather than from the documentation,
// which describes the set without committing to the spelling.
const (
	dataDomeAuthorize = "authorize"
	// interstitial is the Device Check: a JavaScript challenge the client may still pass.
	dataDomeInterstitial = "interstitial"
	// BLOCK IS A CHALLENGE, not a block. It is DataDome's name for the slider CAPTCHA,
	// and the one value in this set whose name means the opposite of what it does — the
	// hard block is the one below.
	dataDomeBlockChallenge = "block"
	dataDomeHardBlock      = "hard_block"
)

// dataDomeVerdict maps the protection API's answer onto the common model.
//
// IT TAKES BOTH, and neither alone is enough. The STATUS says whether DataDome enforced
// its decision; the RESPONSE TYPE says what that decision was. DataDome's own
// documentation is explicit that the header reports "the response type applied by
// DataDome OR THE TYPE THAT WOULD HAVE BEEN APPLIED if DataDome protection was enabled",
// and production shows both: hard_block appears 338 times with a 403 and 113 times with
// a 200 in the same ten minutes.
//
// A 200 means the request was served whatever the type says, so a hard_block there is
// DataDome reporting what it WOULD have done — detection without enforcement, which is
// what `monitored` means and what Cloudflare's `log` action already maps to. Reading it
// as blocked invents a block that never happened, which is the same error as missing one,
// pointed the other way.
//
// The status alone is the fallback for events stored before Logs Enrichment was enabled.
// It is lossy — it cannot separate a Device Check from a hard block — and errs toward
// `challenged`, which is the reading those events were given when they were written.
// An unrecognised type degrades to it too: this vocabulary will grow, and a new value
// must land on the old behaviour rather than on no verdict at all.
//
// 499 has neither: the client went away before the answer was delivered. DataDome DID
// decide those — its dashboard logs them — but Cloudflare never saw which way, and
// unknown ranks lowest in restrictiveness precisely so a non-observation can never mask
// a real block.
func dataDomeVerdict(status uint16, responseType string) string {
	decision := strings.ToLower(strings.TrimSpace(responseType))

	// Served. The type describes what DataDome decided, not what the visitor got.
	if status == dataDomeAllowed {
		switch decision {
		case dataDomeInterstitial, dataDomeBlockChallenge, dataDomeHardBlock:
			return vendors.VerdictMonitored
		case dataDomeAuthorize:
			return vendors.VerdictAllowed
		default:
			// No type at all, which is every event stored before Logs Enrichment was
			// enabled. A 200 was a plain allow then and stays one now.
			return vendors.VerdictAllowed
		}
	}

	// Enforced. Now the type decides which of the three a 403 actually was.
	if status == dataDomeChallenged {
		switch decision {
		case dataDomeHardBlock:
			return vendors.VerdictBlocked
		case dataDomeInterstitial, dataDomeBlockChallenge:
			return vendors.VerdictChallenged
		default:
			// No type, or one nobody has mapped: the reading these events have always
			// had.
			return vendors.VerdictChallenged
		}
	}

	return vendors.VerdictUnknown
}

// responseHeader reads one header out of the ResponseHeaders map Logpush attaches when a
// custom field is configured for it.
//
// Matched case-insensitively. Cloudflare requires the custom field to be declared in
// lowercase and emits it that way, but a lookup that depends on the vendor's casing is a
// lookup that silently returns nothing the day it changes — and silently returning
// nothing here means falling back to the status code, which is the very ambiguity this
// exists to resolve.
func responseHeader(fields map[string]any, name string) string {
	headers, ok := fields["ResponseHeaders"].(map[string]any)
	if !ok {
		return ""
	}
	for key, value := range headers {
		if strings.EqualFold(key, name) {
			return strings.TrimSpace(vendors.AsString(value))
		}
	}
	return ""
}

// noParentRay is what Cloudflare writes in ParentRayID when a request is NOT a
// subrequest. It is a literal "00", not an empty string — treating it as a real ray
// would key every top-level request in the tenant onto one shared identifier and merge
// unrelated requests into a single correlated record.
const noParentRay = "00"

// parentRay returns the ray of the request this one was made while handling, or empty
// when it is a top-level request.
func parentRay(fields map[string]any) string {
	parent := strings.TrimSpace(vendors.AsString(fields["ParentRayID"]))
	if parent == noParentRay {
		return ""
	}
	return parent
}

// isDataDomeCall reports whether a record is the Worker's call to DataDome rather than
// a request from a real client.
//
// Both conditions are required. The hostname alone would also match a genuine visitor
// browsing that domain, and a parent ray is only ever present on a subrequest — so
// together they identify exactly "a call made while handling some other request".
func isDataDomeCall(fields map[string]any) bool {
	host := strings.ToLower(strings.TrimSpace(vendors.AsString(fields["ClientRequestHost"])))
	if host != dataDomeHost {
		return false
	}
	return parentRay(fields) != ""
}

// normalizeDataDomeCall turns the Worker's subrequest into DataDome's verdict on the
// request that triggered it.
//
// The whole design rests on ParentRayID. It is the ray of the ORIGINAL request, so
// using it as the request id makes this event join the Cloudflare and F5 records of
// that same request through the EXISTING tier-1 exact match — no new correlation
// machinery, no time window, no heuristic. Measured on production, 29,998 of 30,000
// ParentRayIDs resolve to a request already stored.
//
// That is not merely convenient. DataDome's own logs carry no CF-Ray at all — its
// export identifies requests by a DataDome-private id and session id — so a native
// DataDome feed could only ever join heuristically, on IP, host, path and time. This
// derived event is the only DataDome signal that can join exactly.
func normalizeDataDomeCall(fields map[string]any) (vendors.Event, error) {
	eventTime, original, err := vendors.ParseTime(fields["EdgeStartTimestamp"])
	if err != nil {
		return vendors.Event{}, err
	}

	status := vendors.ToStatus(fields["EdgeResponseStatus"])
	extra, unknown := collectExtra(fields)

	// What DataDome says it did, which the status alone cannot express.
	responseType := responseHeader(fields, trafficRuleResponseHeader)
	if responseType != "" {
		// Kept verbatim beside the verdict it produced. The verdict collapses four
		// values into three, and the detail view is where an analyst asks which of the
		// two challenge kinds a request actually got.
		if extra == nil {
			extra = map[string]string{}
		}
		extra["datadome_response_type"] = responseType
	}

	return vendors.Event{
		Vendor: vendors.DataDome,
		// Named for what it is. This is Cloudflare's view of DataDome, not DataDome's
		// own log: it carries the decision and nothing else — no rule, no bot score, no
		// device fingerprint, none of which cross the API boundary into Cloudflare's
		// dataset. An analyst reading "datadome" on a record has to be able to tell
		// which of the two sources it came from.
		VendorAccount:   "cloudflare-worker-integration",
		VendorRequestID: parentRay(fields),
		// The subrequest's own ray, kept so this row can be traced back to the exact
		// Cloudflare log line it was derived from.
		VendorEventID:     strings.TrimSpace(vendors.AsString(fields["RayID"])),
		EventTime:         eventTime,
		EventTimeOriginal: original,

		// Client and request fields are deliberately LEFT EMPTY.
		//
		// On this row they describe the Worker's call to DataDome, not the visitor:
		// ClientIP is Cloudflare's own egress address, the host is DataDome's API and
		// the path is /validate-request/. Copying them would be actively wrong — a
		// correlated record takes each field from the first member that has one, so a
		// populated Cloudflare egress address here could become the client IP of the
		// whole record and defeat a search for the real one. The Cloudflare and F5
		// events of the same request supply all of it correctly.

		// The status the protection API returned. Stored so the observation survives
		// independently of the verdict inferred from it — and it earned that: DataDome
		// does issue hard blocks answering 403, so for every event recorded before Logs
		// Enrichment was enabled this column is the only thing that distinguishes a
		// verdict read from the response type from one guessed from the status.
		HTTPStatus: status,

		Verdict: dataDomeVerdict(status, responseType),
		// No rule id, no score. DataDome reports which model fired — "Offer Scrapers"
		// on the traffic examined — but that never reaches Cloudflare, and inventing a
		// reason here would be a claim the data does not support.
		ScoreKind: vendors.ScoreKindNone,

		// THE PAYLOAD'S OWN FIELDS ARE KEPT, even though the mapped ones above are
		// deliberately sparse. Those two decisions are unrelated and were previously
		// conflated: leaving the request fields empty is about not attributing the
		// Worker's egress address to the visitor, whereas raw_extra is the vendor's
		// bytes rendered for a human — it makes no claim about whose request this was.
		//
		// Dropping it made the detail view show a full raw payload beside an empty
		// field list on every DataDome-attributed event. The 49 fields on one of these
		// records include the JA4 signals, the WAF attack scores and the matched rules
		// of the surrounding request, which is exactly what an analyst opens this view
		// to read.
		RawExtra:      extra,
		UnknownFields: unknown,
	}, nil
}
