package cloudflare

import (
	"strconv"
	"testing"

	"github.com/menta2k/siem/internal/vendors"
)

// A real Cloudflare log line for the DataDome Worker's call to its protection API,
// taken verbatim from production apart from the status, which each test sets.
func dataDomeCall(status string) string {
	return `{"ClientIP":"2a06:98c0:3600::103","ClientRequestHost":"api-cloudflare.datadome.co",` +
		`"ClientRequestMethod":"POST","ClientRequestURI":"/validate-request/",` +
		`"EdgeStartTimestamp":"2026-08-08T16:27:08Z","EdgeEndTimestamp":"2026-08-08T16:27:08Z",` +
		`"EdgeResponseStatus":` + status + `,"EdgeResponseBytes":756,"BotScore":0,` +
		`"BotScoreSrc":"Not Computed","WAFAttackScore":100,"SecurityAction":"",` +
		`"ParentRayID":"a27fe3039e6f1216","RayID":"a27fe303ba26703c"}`
}

func normalizeOne(t *testing.T, payload string) vendors.Event {
	t.Helper()

	adapter := New()
	records, err := adapter.Parse([]byte(payload), vendors.FormatNDJSON)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(records) != 1 {
		t.Fatalf("got %d records, want 1", len(records))
	}
	event, err := adapter.Normalize(records[0])
	if err != nil {
		t.Fatalf("Normalize: %v", err)
	}
	return event
}

// THE POINT OF THE WHOLE FEATURE. The Worker's subrequest is not a visitor request —
// it is DataDome's verdict on the request that triggered it, and ParentRayID is what
// attaches it to that request.
//
// Keying on ParentRayID rather than the subrequest's own RayID is what lets the
// EXISTING tier-1 exact join do all the work: no new correlation machinery, no time
// window, no heuristic. On production 29,998 of 30,000 ParentRayIDs resolved to a
// request already stored.
func TestTheDataDomeCallBecomesADataDomeVerdictOnTheParentRequest(t *testing.T) {
	event := normalizeOne(t, dataDomeCall("403"))

	if event.Vendor != vendors.DataDome {
		t.Errorf("Vendor = %q, want datadome — this row is DataDome's decision, not "+
			"a Cloudflare request", event.Vendor)
	}
	if event.VendorRequestID != "a27fe3039e6f1216" {
		t.Errorf("VendorRequestID = %q, want the PARENT ray — keying on the subrequest's "+
			"own ray would join this to nothing", event.VendorRequestID)
	}
	if event.VendorEventID != "a27fe303ba26703c" {
		t.Errorf("VendorEventID = %q, want the subrequest's own ray for traceability",
			event.VendorEventID)
	}
}

// 403 is a Device Check, which the client may still pass. Calling it a block would
// manufacture tens of thousands of false allow-vs-block disagreements a day against
// Cloudflare, which allows the very same requests.
//
// Evidence: DataDome's dashboard reported "Device Check" for 1,000 of 1,000 rows on
// the busiest client, and the response-size distribution over six hours forms exactly
// one cluster per status, so no second kind of 403 is hiding in the numbers.
func TestA403IsChallengedNotBlocked(t *testing.T) {
	event := normalizeOne(t, dataDomeCall("403"))

	if event.Verdict != vendors.VerdictChallenged {
		t.Errorf("Verdict = %q, want challenged — every observed 403 was a Device Check, "+
			"and calling it blocked invents a disagreement that did not happen",
			event.Verdict)
	}
	if event.Verdict == vendors.VerdictBlocked {
		t.Error("a device check was reported as a block")
	}
}

func TestA200IsAllowed(t *testing.T) {
	if got := normalizeOne(t, dataDomeCall("200")).Verdict; got != vendors.VerdictAllowed {
		t.Errorf("Verdict = %q, want allowed", got)
	}
}

// 499 means the client went away before the answer was delivered. DataDome DID decide
// — its dashboard logs those requests — but Cloudflare never saw which way, and
// reporting a guess as a verdict is worse than reporting none.
func TestAnUndeliveredAnswerIsUnknownRatherThanAVerdict(t *testing.T) {
	for _, status := range []string{"499", "502", "0"} {
		if got := normalizeOne(t, dataDomeCall(status)).Verdict; got != vendors.VerdictUnknown {
			t.Errorf("status %s gave verdict %q, want unknown — nothing was observed",
				status, got)
		}
	}
}

// THE TRAP. On this row the client and request fields describe the Worker's call to
// DataDome, not the visitor: ClientIP is Cloudflare's own egress address, the host is
// DataDome's API, the path is /validate-request/.
//
// A correlated record takes each field from the FIRST member that has one, so a
// populated Cloudflare egress address here could become the client IP of the entire
// record — defeating a search for the real client and mislabelling the request.
func TestTheSubrequestsOwnClientAndRequestFieldsAreNotCopied(t *testing.T) {
	event := normalizeOne(t, dataDomeCall("403"))

	if event.ClientIP != nil {
		t.Errorf("ClientIP = %v, want none — that address is Cloudflare's egress, not "+
			"the visitor, and it would poison the correlated record", event.ClientIP)
	}
	if event.RequestHost != "" {
		t.Errorf("RequestHost = %q, want empty — the host here is DataDome's API",
			event.RequestHost)
	}
	if event.RequestPath != "" {
		t.Errorf("RequestPath = %q, want empty — /validate-request/ is not what the "+
			"visitor asked for", event.RequestPath)
	}
}

// BotScore 0 with BotScoreSrc "Not Computed" describes the SUBREQUEST, not the
// visitor's request. Carrying it over would attach a fabricated bot score of zero to a
// request DataDome had just challenged as a scraper.
func TestTheSubrequestsScoresAreNotCarriedOver(t *testing.T) {
	event := normalizeOne(t, dataDomeCall("403"))

	if event.Score != nil {
		t.Errorf("Score = %v, want none — that score belongs to the call to DataDome",
			*event.Score)
	}
	if event.ScoreKind != vendors.ScoreKindNone {
		t.Errorf("ScoreKind = %q, want none", event.ScoreKind)
	}
}

// The observed status is preserved so the record stays interpretable if the verdict
// mapping ever has to change — a hard block that also answered 403 could then be
// separated without going back to the raw payloads.
func TestTheObservedStatusIsStored(t *testing.T) {
	if got := normalizeOne(t, dataDomeCall("403")).HTTPStatus; got != 403 {
		t.Errorf("HTTPStatus = %d, want 403", got)
	}
}

// The source has to be readable off the record. This is Cloudflare's view of DataDome
// — decision only, no rule, no score, no fingerprint — and must not be mistaken for a
// native DataDome feed.
func TestTheDerivedSourceIsNamed(t *testing.T) {
	if got := normalizeOne(t, dataDomeCall("200")).VendorAccount; got == "" {
		t.Error("VendorAccount is empty — an analyst cannot tell this from a real feed")
	}
}

// A genuine visitor browsing that hostname has no ParentRayID, and must stay a
// Cloudflare request. Matching on the hostname alone would silently relabel real
// traffic as a DataDome verdict.
func TestAGenuineRequestToThatHostnameIsStillCloudflare(t *testing.T) {
	payload := `{"ClientIP":"203.0.113.10","ClientRequestHost":"api-cloudflare.datadome.co",` +
		`"ClientRequestMethod":"GET","ClientRequestURI":"/",` +
		`"EdgeStartTimestamp":"2026-08-08T16:27:08Z","EdgeResponseStatus":200,` +
		`"SecurityAction":"","RayID":"a27fe303ba26703c"}`

	event := normalizeOne(t, payload)
	if event.Vendor != vendors.Cloudflare {
		t.Errorf("Vendor = %q, want cloudflare — no ParentRayID means this is not a "+
			"subrequest", event.Vendor)
	}
	if event.VendorRequestID != "a27fe303ba26703c" {
		t.Errorf("VendorRequestID = %q, want its own ray", event.VendorRequestID)
	}
}

// Ordinary traffic must be completely untouched by this branch.
func TestOrdinaryCloudflareTrafficIsUnaffected(t *testing.T) {
	payload := `{"ClientIP":"203.0.113.10","ClientRequestHost":"www.jobs.bg",` +
		`"ClientRequestMethod":"GET","ClientRequestURI":"/job/8564794",` +
		`"EdgeStartTimestamp":"2026-08-08T16:27:08Z","EdgeResponseStatus":200,` +
		`"SecurityAction":"","RayID":"a27fe303ba26703c","ParentRayID":""}`

	event := normalizeOne(t, payload)
	if event.Vendor != vendors.Cloudflare {
		t.Fatalf("Vendor = %q, want cloudflare", event.Vendor)
	}
	if event.RequestHost != "www.jobs.bg" || event.RequestPath != "/job/8564794" {
		t.Errorf("host/path = %q %q, want the real request",
			event.RequestHost, event.RequestPath)
	}
}

// A DataDome-worker record keeps the payload's OWN fields, even though its mapped client
// and request fields are deliberately empty.
//
// Those two decisions are unrelated and were previously conflated. Leaving the request
// fields empty is about not attributing the Worker's egress address to the visitor;
// raw_extra is the vendor's bytes rendered for a human and makes no such claim. Dropping
// it showed the analyst a full raw payload beside an empty field list on every
// DataDome-attributed event — 16% of production traffic.
func TestADataDomeCallKeepsThePayloadsOwnFields(t *testing.T) {
	// Trimmed from a real production record: the host and URI are what identify it as
	// the Worker's call, and the rest is the surrounding request's evidence.
	payload := []byte(`{"ClientIP":"2a06:98c0:3600::103",` +
		`"ClientRequestHost":"api-cloudflare.datadome.co",` +
		`"ClientRequestMethod":"POST","ClientRequestURI":"/validate-request/",` +
		`"EdgeStartTimestamp":"2026-08-11T07:15:39Z","EdgeResponseStatus":200,` +
		`"RayID":"a27533e76c55d999","ParentRayID":"a27533e76c55d101",` +
		`"JA4":"t13d1516h2_8daaf6152771_b186095e22b6","WAFAttackScore":99,` +
		`"BotScore":7,"ZoneName":"jobs.bg"}`)

	adapter := New()
	format, ok := adapter.Detect(payload)
	if !ok {
		t.Fatal("Detect rejected a Cloudflare NDJSON payload")
	}
	records, err := adapter.Parse(payload, format)
	if err != nil || len(records) != 1 {
		t.Fatalf("Parse: %d records, err %v", len(records), err)
	}

	event, err := adapter.Normalize(records[0])
	if err != nil {
		t.Fatalf("Normalize: %v", err)
	}

	// Still a DataDome event with the client fields left alone — the point of the
	// original design, which this must not undo.
	if event.Vendor != vendors.DataDome {
		t.Errorf("vendor = %q, want datadome", event.Vendor)
	}
	if event.ClientIP != nil {
		t.Errorf("client ip = %v, want none: that address is Cloudflare's egress, not "+
			"the visitor's", event.ClientIP)
	}
	if event.RequestHost != "" {
		t.Errorf("request host = %q, want none", event.RequestHost)
	}

	// And now the evidence survives.
	if len(event.RawExtra) == 0 {
		t.Fatal("raw_extra is empty; the detail view shows a payload with no fields")
	}
	for _, key := range []string{"JA4", "WAFAttackScore", "BotScore", "ZoneName"} {
		if event.RawExtra[key] == "" {
			t.Errorf("raw_extra is missing %s, which an analyst opens this view to read", key)
		}
	}
}

// datadomeRecord builds the Worker's subrequest to the protection API, with the response
// type Logs Enrichment attaches.
func datadomeRecord(t *testing.T, status int, responseType string) vendors.RawRecord {
	t.Helper()

	headers := `{}`
	if responseType != "" {
		headers = `{"x-datadome-traffic-rule-response":"` + responseType + `"}`
	}
	payload := `{"ClientRequestHost":"api-cloudflare.datadome.co",` +
		`"ClientRequestURI":"/validate-request/","ClientRequestMethod":"POST",` +
		`"EdgeStartTimestamp":"2026-08-14T12:23:15Z",` +
		`"EdgeResponseStatus":` + strconv.Itoa(status) + `,` +
		`"ParentRayID":"8f1a2b3c4d5e6f70","RayID":"9a2b3c4d5e6f7081",` +
		`"ResponseHeaders":` + headers + `}`

	return recordFrom(t, payload)
}

// THE BUG THIS CLOSES, and it was live. A 403 from the protection API is returned for a
// Device Check, a slider CAPTCHA and a HARD BLOCK alike. The adapter read every one of
// them as challenged, and 11.7% of the 403s in production are hard blocks — roughly
// 82,000 requests a day recorded as a softer verdict than they were.
//
// The four cases below are the four combinations observed on live traffic, with the
// counts they appeared in over six minutes.
func TestDataDomeResponseTypeDecidesTheVerdict(t *testing.T) {
	tests := []struct {
		responseType string
		status       int
		want         string
		seen         string
	}{
		{"authorize", 200, vendors.VerdictAllowed, "3,828"},
		{"interstitial", 403, vendors.VerdictChallenged, "135 — Device Check"},
		{"block", 403, vendors.VerdictChallenged, "9 — slider CAPTCHA, despite the name"},
		{"hard_block", 403, vendors.VerdictBlocked, "19 — a real block"},
	}

	for _, tt := range tests {
		t.Run(tt.responseType, func(t *testing.T) {
			event, err := New().Normalize(datadomeRecord(t, tt.status, tt.responseType))
			if err != nil {
				t.Fatalf("Normalize() error = %v", err)
			}

			if event.Vendor != vendors.DataDome {
				t.Fatalf("vendor = %q, want datadome", event.Vendor)
			}
			if event.Verdict != tt.want {
				t.Errorf("verdict = %q, want %q (seen on %s requests)",
					event.Verdict, tt.want, tt.seen)
			}
			// Kept verbatim, because the verdict collapses four values into three and
			// the detail view is where the distinction is asked for.
			if event.RawExtra["datadome_response_type"] != tt.responseType {
				t.Errorf("response type not preserved: %v", event.RawExtra)
			}
		})
	}
}

// `block` means slider CAPTCHA and `hard_block` means block. The names invite exactly
// the wrong mapping, so the pair is pinned on its own: reading `block` as blocked would
// manufacture false allow-vs-block disagreements against Cloudflare, which is the very
// trap this adapter was originally written to avoid.
func TestDataDomeBlockIsAChallengeAndHardBlockIsNot(t *testing.T) {
	challenge, err := New().Normalize(datadomeRecord(t, 403, "block"))
	if err != nil {
		t.Fatalf("Normalize() error = %v", err)
	}
	if challenge.Verdict != vendors.VerdictChallenged {
		t.Errorf("`block` = %q, want challenged — it is the slider CAPTCHA",
			challenge.Verdict)
	}

	blocked, err := New().Normalize(datadomeRecord(t, 403, "hard_block"))
	if err != nil {
		t.Fatalf("Normalize() error = %v", err)
	}
	if blocked.Verdict != vendors.VerdictBlocked {
		t.Errorf("`hard_block` = %q, want blocked", blocked.Verdict)
	}
}

// Every event recorded before Logs Enrichment was enabled has no response type, and must
// keep the reading it was stored with rather than losing its verdict entirely.
func TestDataDomeFallsBackToTheStatusWithoutAResponseType(t *testing.T) {
	tests := []struct {
		status int
		want   string
	}{
		{200, vendors.VerdictAllowed},
		// Lossy on purpose: without the header a 403 cannot be told apart from a hard
		// block, and challenged is the reading these events were always given.
		{403, vendors.VerdictChallenged},
		// The client went away before the answer arrived. DataDome decided; Cloudflare
		// never saw which way, and unknown ranks lowest so it cannot mask a real block.
		{499, vendors.VerdictUnknown},
	}

	for _, tt := range tests {
		event, err := New().Normalize(datadomeRecord(t, tt.status, ""))
		if err != nil {
			t.Fatalf("Normalize(%d) error = %v", tt.status, err)
		}
		if event.Verdict != tt.want {
			t.Errorf("status %d = %q, want %q", tt.status, event.Verdict, tt.want)
		}
	}
}

// A value nobody has mapped must degrade to the old status-based reading rather than to
// no verdict. This vocabulary will grow, and an unknown addition arriving as `unknown`
// would drop a real decision out of correlation entirely.
func TestAnUnrecognisedResponseTypeFallsBackRatherThanFailing(t *testing.T) {
	event, err := New().Normalize(datadomeRecord(t, 403, "some_future_action"))
	if err != nil {
		t.Fatalf("Normalize() error = %v", err)
	}
	if event.Verdict != vendors.VerdictChallenged {
		t.Errorf("verdict = %q, want the status fallback of challenged", event.Verdict)
	}
	// Still recorded, so an operator can see what the vendor actually said.
	if event.RawExtra["datadome_response_type"] != "some_future_action" {
		t.Errorf("the unmapped value was not preserved: %v", event.RawExtra)
	}
}

// Cloudflare emits the header lowercased today. A lookup depending on that silently
// returns nothing the day it changes — and silently returning nothing here means falling
// back to the status, which is the ambiguity this whole change exists to remove.
func TestTheResponseHeaderLookupIsCaseInsensitive(t *testing.T) {
	payload := `{"ClientRequestHost":"api-cloudflare.datadome.co",` +
		`"ClientRequestURI":"/validate-request/","ClientRequestMethod":"POST",` +
		`"EdgeStartTimestamp":"2026-08-14T12:23:15Z","EdgeResponseStatus":403,` +
		`"ParentRayID":"8f1a2b3c4d5e6f70",` +
		`"ResponseHeaders":{"X-DataDome-Traffic-Rule-Response":"hard_block"}}`

	event, err := New().Normalize(recordFrom(t, payload))
	if err != nil {
		t.Fatalf("Normalize() error = %v", err)
	}
	if event.Verdict != vendors.VerdictBlocked {
		t.Errorf("verdict = %q, want blocked — the header casing lost the lookup",
			event.Verdict)
	}
}
