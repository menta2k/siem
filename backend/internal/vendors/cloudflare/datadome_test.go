package cloudflare

import (
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
