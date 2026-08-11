package window_test

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/menta2k/siem/internal/correlate/window"
)

// SWAPPING A JSON PARSER IS A CORRECTNESS CHANGE, NOT A PERFORMANCE ONE, so it is pinned
// here rather than trusted. Members are ENCODED with the standard library and DECODED with
// goccy, which is only sound if the two agree on this struct in every case that reaches
// production -- including the awkward ones: a nil Score against a zero Score, an absent
// array against an empty one, a UTC timestamp round-tripping to the same instant.
//
// It also covers the rollout, where both versions run at once and each must read what the
// other wrote.
func TestEveryMemberShapeSurvivesTheEncodeDecodeRoundTrip(t *testing.T) {
	zero := float32(0)
	score := float32(0.82)

	cases := []struct {
		name   string
		member window.Member
	}{
		{
			name: "cloudflare row with everything set",
			member: window.Member{
				EventID: "cf-1", Vendor: "cloudflare",
				EventTime:       time.Unix(1770000000, 0).UTC(),
				VendorRequestID: "a28b5c488d915101", LinkedRequestID: "b39c6d599e026201",
				ClientIP: "203.0.113.10", ClientIPShared: true,
				ClientASN: 13335, ClientCountry: "BG",
				RequestHost: "shop.example.com", RequestPath: "/checkout/confirm",
				RequestMethod: "POST", Verdict: "allowed", RuleID: "waf-1",
				RuleIDs: []string{"waf-1", "bot-3"}, Score: &score, ScoreKind: "bot",
			},
		},
		{
			// A DataDome row carries no client address at all, by design. Every optional
			// field being absent is the ordinary case, not an edge case.
			name:   "datadome row with only a verdict",
			member: window.Member{EventID: "dd-1", Vendor: "datadome", Verdict: "blocked"},
		},
		{
			// A ZERO score must survive as a zero score. Collapsing it to nil would turn
			// "this vendor scored it 0" into "this vendor did not score it", which is the
			// difference between agreement and no opinion.
			name: "zero score is not the same as no score",
			member: window.Member{
				EventID: "dd-2", Vendor: "datadome", Score: &zero, ScoreKind: "bot",
			},
		},
		{
			name: "empty rule list",
			member: window.Member{
				EventID: "f5-1", Vendor: "f5", RuleIDs: []string{},
			},
		},
		{
			// Vendors send paths with anything in them. A parser that mishandles escaping
			// would corrupt the request shape a heuristic join depends on.
			name: "escaping and unicode in the request shape",
			member: window.Member{
				EventID: "cf-2", Vendor: "cloudflare",
				RequestHost:   "магазин.example.com",
				RequestPath:   `/search?q="quoted"&tab=a\b` + "\t\n",
				RequestMethod: "GET",
			},
		},
	}

	tenantID := uuid.New()

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// Encoded by the standard library, exactly as Add writes it.
			raw, err := json.Marshal(tc.member)
			if err != nil {
				t.Fatalf("encode: %v", err)
			}

			// Decoded through the real read path, which is where goccy is used.
			store := &fixedStore{byKey: map[string][]string{
				membersKeyFor(tenantID, "w1"): {string(raw)},
			}}
			got, err := window.New(store).MembersMany(t.Context(), tenantID, []string{"w1"})
			if err != nil {
				t.Fatalf("MembersMany: %v", err)
			}
			if len(got["w1"]) != 1 {
				t.Fatalf("decoded %d members, want 1", len(got["w1"]))
			}
			decoded := got["w1"][0]

			// Compared by re-encoding: it catches every field at once, including ones
			// added to Member after this test was written, which a hand-listed comparison
			// would silently skip.
			reencoded, err := json.Marshal(decoded)
			if err != nil {
				t.Fatalf("re-encode: %v", err)
			}
			if string(reencoded) != string(raw) {
				t.Errorf("the two parsers disagree about this member.\n"+
					" written: %s\nread back: %s", raw, reencoded)
			}

			// Score is a pointer, so equal encodings are not quite enough: nil and a
			// pointer to zero encode differently, but a decoder that returned a pointer
			// into shared memory would still re-encode correctly.
			if (tc.member.Score == nil) != (decoded.Score == nil) {
				t.Errorf("score presence changed: wrote %v, read %v",
					tc.member.Score, decoded.Score)
			}
			if tc.member.Score != nil && decoded.Score != nil &&
				*tc.member.Score != *decoded.Score {
				t.Errorf("score = %v, want %v", *decoded.Score, *tc.member.Score)
			}
		})
	}
}

// A malformed entry must fail the same way under the new parser: skipped, never fatal, and
// never a partially-populated member passed off as real evidence.
func TestTheNewParserRejectsMalformedEntriesTheSameWay(t *testing.T) {
	tenantID := uuid.New()

	for _, bad := range []string{
		"{not json",
		`{"event_id": }`,
		`{"event_id":"cf-1","client_asn":"not-a-number"}`,
		`{"event_id":"cf-1","score":"not-a-float"}`,
		"",
	} {
		t.Run(bad, func(t *testing.T) {
			store := &fixedStore{byKey: map[string][]string{
				membersKeyFor(tenantID, "w1"): {bad},
			}}
			got, err := window.New(store).MembersMany(t.Context(), tenantID, []string{"w1"})
			if err != nil {
				t.Fatalf("a corrupt entry must not fail the read: %v", err)
			}
			if len(got["w1"]) != 0 {
				t.Errorf("a malformed entry produced a member: %+v", got["w1"])
			}
		})
	}
}
