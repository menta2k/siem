package service

import (
	"testing"

	chdata "github.com/menta2k/siem/internal/data/clickhouse"
	"github.com/menta2k/siem/internal/vendors"
)

// blockedEvent is a real blocked request from production, reduced to the two fields the
// enrichment reads: the violations the adapter mapped onto RuleIDs, and the signature
// ids that only ever existed inside the payload.
func blockedEvent() (chdata.NormalizedEvent, map[string]string) {
	event := chdata.NormalizedEvent{
		Vendor:  vendors.F5,
		Verdict: vendors.VerdictBlocked,
		RuleIDs: []string{"Attack signature detected", "Illegal cross-origin request"},
	}
	fields := map[string]string{
		"sig_ids":          "200004165",
		"sig_names":        "Executable code file upload",
		"violation_rating": "4",
	}
	return event, fields
}

func TestAsmFindingsExplainsABlockedRequest(t *testing.T) {
	findings := asmFindings(blockedEvent())
	if findings == nil {
		t.Fatal("no findings for a request ASM blocked on two violations and a signature")
	}

	if len(findings.GetViolations()) != 2 {
		t.Fatalf("violations = %d, want 2", len(findings.GetViolations()))
	}
	first := findings.GetViolations()[0]
	if first.GetName() != "VIOL_ATTACK_SIGNATURE" {
		t.Errorf("name = %q, want VIOL_ATTACK_SIGNATURE", first.GetName())
	}
	if first.GetSeverity() == "" {
		t.Error("severity is empty, so the UI cannot rank the block")
	}

	second := findings.GetViolations()[1]
	if second.GetAttackType() != "Cross-site Request Forgery" {
		t.Errorf("attack type = %q, want Cross-site Request Forgery", second.GetAttackType())
	}
	if second.GetRisk() == "" {
		t.Error("risk is empty — that sentence is what decides whether to chase the alert")
	}

	if len(findings.GetSignatures()) != 1 {
		t.Fatalf("signatures = %d, want 1", len(findings.GetSignatures()))
	}
	sig := findings.GetSignatures()[0]
	if sig.GetId() != 200004165 {
		t.Errorf("signature id = %d, want 200004165", sig.GetId())
	}
	if sig.GetName() == "" || sig.GetAccuracy() == "" || sig.GetRisk() == "" {
		t.Errorf("signature under-resolved: %+v", sig)
	}
	if len(sig.GetCves()) == 0 {
		t.Error("no CVEs — the pivot into every other tool the analyst owns")
	}
	if findings.GetViolationRating() != "4" {
		t.Errorf("violation rating = %q, want 4", findings.GetViolationRating())
	}
}

// Absent rather than empty, so a client branches on presence rather than on vendor.
func TestAsmFindingsAreAbsentForOtherVendors(t *testing.T) {
	event, fields := blockedEvent()
	event.Vendor = vendors.Cloudflare

	if findings := asmFindings(event, fields); findings != nil {
		t.Errorf("a Cloudflare event produced ASM findings: %+v", findings)
	}
}

// An allowed F5 request carries no violations and ASM writes its placeholder into the
// signature field. Rendering a panel headed "why this was blocked" on a request that was
// allowed, listing a violation called N/A, is worse than rendering nothing.
func TestAsmFindingsAreAbsentForAnUneventfulRequest(t *testing.T) {
	event := chdata.NormalizedEvent{
		Vendor:  vendors.F5,
		Verdict: vendors.VerdictAllowed,
		RuleIDs: []string{"N/A"},
	}
	fields := map[string]string{"sig_ids": "N/A", "violation_rating": "N/A"}

	if findings := asmFindings(event, fields); findings != nil {
		t.Errorf("an allowed request produced findings: %+v", findings)
	}
}

// THE PAYLOAD EXPIRES BEFORE THE ROW DOES NOT HAVE TO. Violations come from the
// normalized row and signature ids from the rebuilt payload fields, so a block whose
// payload has aged out still explains its violations rather than showing nothing.
func TestViolationsSurviveAMissingPayload(t *testing.T) {
	event, _ := blockedEvent()

	findings := asmFindings(event, nil)
	if findings == nil {
		t.Fatal("no findings once the payload was gone; the violations are on the row")
	}
	if len(findings.GetViolations()) != 2 {
		t.Errorf("violations = %d, want 2 from the row", len(findings.GetViolations()))
	}
	if len(findings.GetSignatures()) != 0 {
		t.Errorf("signatures = %d, want none — the bytes naming them are gone",
			len(findings.GetSignatures()))
	}
}

// ASM's placeholder must not reach the UI as a rating.
func TestNotApplicableRatingIsBlank(t *testing.T) {
	event, fields := blockedEvent()
	fields["violation_rating"] = "N/A"

	if got := asmFindings(event, fields).GetViolationRating(); got != "" {
		t.Errorf("violation rating = %q, want empty", got)
	}
}
