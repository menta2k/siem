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

// dataDomeVerdict maps the protection API's answer onto the common model.
//
// 403 is CHALLENGED, not blocked. Every 403 DataDome's dashboard reported was a
// "Device Check" — a JavaScript challenge the client may still pass — and calling that
// a block would manufacture tens of thousands of false allow-vs-block disagreements a
// day against Cloudflare, which allows the same requests. That is the same trap ASM's
// "alerted" status sets, and it is worth being explicit about twice.
//
// Anything else is unknown rather than a verdict. In practice that is 499: the client
// went away before the answer was delivered. DataDome DID decide those — its dashboard
// logs them — but Cloudflare never saw which way, and unknown ranks lowest in
// restrictiveness precisely so a non-observation can never mask a real block.
func dataDomeVerdict(status uint16) string {
	switch status {
	case dataDomeAllowed:
		return vendors.VerdictAllowed
	case dataDomeChallenged:
		return vendors.VerdictChallenged
	default:
		return vendors.VerdictUnknown
	}
}

// isDataDomeCall reports whether a record is the Worker's call to DataDome rather than
// a request from a real client.
//
// Both conditions are required. The hostname alone would also match a genuine visitor
// browsing that domain, and ParentRayID is only ever set on a subrequest — so together
// they identify exactly "a call made while handling some other request".
func isDataDomeCall(fields map[string]any) bool {
	host := strings.ToLower(strings.TrimSpace(vendors.AsString(fields["ClientRequestHost"])))
	if host != dataDomeHost {
		return false
	}
	return strings.TrimSpace(vendors.AsString(fields["ParentRayID"])) != ""
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

	return vendors.Event{
		Vendor: vendors.DataDome,
		// Named for what it is. This is Cloudflare's view of DataDome, not DataDome's
		// own log: it carries the decision and nothing else — no rule, no bot score, no
		// device fingerprint, none of which cross the API boundary into Cloudflare's
		// dataset. An analyst reading "datadome" on a record has to be able to tell
		// which of the two sources it came from.
		VendorAccount:   "cloudflare-worker-integration",
		VendorRequestID: strings.TrimSpace(vendors.AsString(fields["ParentRayID"])),
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
		// independently of the verdict inferred from it: if DataDome ever starts
		// issuing a hard block that also answers 403, this column is what makes the
		// records recoverable without going back to the raw payloads.
		HTTPStatus: status,

		Verdict: dataDomeVerdict(status),
		// No rule id, no score. DataDome reports which model fired — "Offer Scrapers"
		// on the traffic examined — but that never reaches Cloudflare, and inventing a
		// reason here would be a claim the data does not support.
		ScoreKind: vendors.ScoreKindNone,
	}, nil
}
