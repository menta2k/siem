package f5catalog

import (
	"strings"
	"testing"
)

func TestCatalogLoads(t *testing.T) {
	if err := Loaded(); err != nil {
		t.Fatalf("the embedded catalogue did not parse: %v", err)
	}

	violations, signatures := Counts()
	// Floors rather than exact counts: a signature update legitimately changes these,
	// and a test that pins them turns every catalogue refresh into a failing build. A
	// file that shrank to nothing is the failure worth catching.
	if violations < 50 {
		t.Errorf("violations = %d, want the full ASM set", violations)
	}
	if signatures < 5000 {
		t.Errorf("signatures = %d, want the full ASM set", signatures)
	}
}

// THE JOIN KEY IS THE TITLE, NOT THE NAME. ASM writes "Illegal file type" into a log
// record's violations field, never VIOL_FILETYPE — so a catalogue indexed by name
// resolves nothing at all against real traffic. These titles are taken verbatim from
// blocked requests in production.
func TestViolationsResolveByTheTitleASMLogs(t *testing.T) {
	tests := []struct {
		title      string
		wantName   string
		wantAttack string
	}{
		{"Attack signature detected", "VIOL_ATTACK_SIGNATURE", ""},
		{"Illegal cross-origin request", "VIOL_CROSS_ORIGIN_REQUEST", "Cross-site Request Forgery"},
		{"Illegal file type", "VIOL_FILETYPE", "Forceful Browsing"},
		{"HTTP protocol compliance failed", "VIOL_HTTP_PROTOCOL", "HTTP Parser Attack"},
		{"Illegal meta character in URL", "VIOL_URL_METACHAR", "Abuse of Functionality"},
		{"Illegal request length", "VIOL_REQUEST_LENGTH", "Buffer Overflow"},
	}

	for _, tt := range tests {
		t.Run(tt.title, func(t *testing.T) {
			v, ok := LookupViolation(tt.title)
			if !ok {
				t.Fatalf("LookupViolation(%q) found nothing", tt.title)
			}
			if v.Name != tt.wantName {
				t.Errorf("name = %q, want %q", v.Name, tt.wantName)
			}
			if tt.wantAttack != "" && v.AttackType != tt.wantAttack {
				t.Errorf("attack type = %q, want %q", v.AttackType, tt.wantAttack)
			}
			if v.Severity == "" {
				t.Error("severity is empty, so the UI has nothing to rank the block by")
			}
		})
	}
}

// A real signature from a blocked upload in production, including the CVEs that are the
// reason an analyst opens this at all.
func TestSignatureResolvesWithItsCVEs(t *testing.T) {
	s, ok := LookupSignature(200004165)
	if !ok {
		t.Fatal("LookupSignature(200004165) found nothing")
	}
	if s.Name == "" {
		t.Error("name is empty")
	}
	if s.Accuracy == "" || s.Risk == "" {
		t.Errorf("accuracy=%q risk=%q, want both — they decide whether this is worth chasing",
			s.Accuracy, s.Risk)
	}
	if len(s.CVEs) == 0 {
		t.Error("no CVEs, but this signature carries them in the BIG-IP dump")
	}
	for _, cve := range s.CVEs {
		if !strings.HasPrefix(cve, "CVE-") {
			t.Errorf("CVE list contains %q, which is not a CVE — the reference split is wrong", cve)
		}
	}
}

// ASM reports a comma-separated list, and the whole point is the multi-violation block.
func TestDescribeViolationsKeepsOrderAndCount(t *testing.T) {
	got := DescribeViolations([]string{
		"Attack signature detected", "Illegal cross-origin request",
	})

	if len(got) != 2 {
		t.Fatalf("got %d violations, want 2", len(got))
	}
	if got[0].Name != "VIOL_ATTACK_SIGNATURE" || got[1].Name != "VIOL_CROSS_ORIGIN_REQUEST" {
		t.Errorf("order was not preserved: %q then %q", got[0].Name, got[1].Name)
	}
}

// An unknown violation must still appear. ASM can report checks this catalogue does not
// carry — a newer policy, a user-defined violation — and dropping them shows an analyst
// four violations where the record says six, which is worse than one with no description.
func TestUnknownViolationsAreKeptRatherThanDropped(t *testing.T) {
	got := DescribeViolations([]string{"Attack signature detected", "Some Future Violation"})

	if len(got) != 2 {
		t.Fatalf("got %d violations, want both kept", len(got))
	}
	if got[1].Title != "Some Future Violation" {
		t.Errorf("unknown violation = %q, want its title carried through", got[1].Title)
	}
	if got[1].Name != "" {
		t.Errorf("unknown violation invented a name: %q", got[1].Name)
	}
}

// ASM writes the literal "N/A" for an absent value. Treating that as a violation title
// would put a violation named N/A on a third of all events.
func TestNotApplicableIsNotAViolation(t *testing.T) {
	if got := DescribeViolations([]string{"N/A"}); len(got) != 0 {
		t.Errorf("DescribeViolations([N/A]) = %v, want none", got)
	}
	if got := DescribeSignatures("N/A"); len(got) != 0 {
		t.Errorf("DescribeSignatures(N/A) = %v, want none", got)
	}
	if got := DescribeSignatures(""); len(got) != 0 {
		t.Errorf("DescribeSignatures(empty) = %v, want none", got)
	}
}

func TestDescribeSignaturesParsesTheCommaSeparatedList(t *testing.T) {
	got := DescribeSignatures("200004165, 200000098")

	if len(got) != 2 {
		t.Fatalf("got %d signatures, want 2", len(got))
	}
	if got[0].ID != 200004165 || got[1].ID != 200000098 {
		t.Errorf("ids = %d, %d — want them parsed and in order", got[0].ID, got[1].ID)
	}
}

// An id the catalogue does not carry is still shown, for the same reason an unknown
// violation is: the record says a signature fired, and hiding it contradicts the record.
func TestUnknownSignatureIDsAreKept(t *testing.T) {
	got := DescribeSignatures("999999999")

	if len(got) != 1 {
		t.Fatalf("got %d signatures, want the unknown id kept", len(got))
	}
	if got[0].ID != 999999999 || got[0].Name != "" {
		t.Errorf("unknown signature = %+v, want the bare id and no invented name", got[0])
	}
}

// Casing is not guaranteed to match across ASM versions, and a case difference must not
// silently lose the description.
func TestViolationLookupIsCaseInsensitive(t *testing.T) {
	if _, ok := LookupViolation("  illegal FILE type  "); !ok {
		t.Error("a differently-cased title did not resolve")
	}
}
