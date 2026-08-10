package asnowner_test

import (
	"bytes"
	"compress/gzip"
	"strings"
	"testing"

	"github.com/menta2k/siem/internal/asnowner"
)

// The published file is address RANGES, so one network spans many lines. Reducing them
// to one row per AS is the entire job of the parser.
func TestParseReducesRangesToOneEntryPerNetwork(t *testing.T) {
	tsv := strings.Join([]string{
		"1.0.0.0\t1.0.0.255\t13335\tUS\tCLOUDFLARENET",
		"78.90.0.0\t78.90.255.255\t8866\tBG\tVIVACOM-AS",
		"95.43.0.0\t95.43.255.255\t8866\tBG\tVIVACOM-AS",
		"212.39.64.0\t212.39.95.255\t8866\tBG\tVIVACOM-AS",
	}, "\n")

	owners, err := asnowner.Parse(strings.NewReader(tsv))
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}

	if len(owners) != 2 {
		t.Fatalf("got %d owners, want 2 — the three VIVACOM ranges are one network: %+v",
			len(owners), owners)
	}
	if owners[0].ASN != 13335 || owners[0].Name != "CLOUDFLARENET" {
		t.Errorf("first entry = %+v, want AS13335 CLOUDFLARENET", owners[0])
	}
	if owners[1].ASN != 8866 || owners[1].Name != "VIVACOM-AS" || owners[1].Country != "BG" {
		t.Errorf("second entry = %+v, want AS8866 VIVACOM-AS in BG", owners[1])
	}
}

// Ranges nobody announces carry AS 0 and a placeholder name. Keeping them would put an
// entry in the table for a number no event can ever report.
func TestParseDropsUnroutedRanges(t *testing.T) {
	tsv := strings.Join([]string{
		"0.0.0.0\t0.255.255.255\t0\tNone\tNot routed",
		"1.0.0.0\t1.0.0.255\t13335\tUS\tCLOUDFLARENET",
		"2.0.0.0\t2.255.255.255\t0\tNone\tNot routed",
	}, "\n")

	owners, err := asnowner.Parse(strings.NewReader(tsv))
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}

	if len(owners) != 1 || owners[0].ASN != 13335 {
		t.Errorf("got %+v, want only AS13335", owners)
	}
}

// A third-party file fetched over the network. One bad line must not cost the other
// half million: the alternative is the panel losing every name over an upstream typo.
func TestParseSkipsMalformedLinesAndKeepsTheRest(t *testing.T) {
	tsv := strings.Join([]string{
		"1.0.0.0\t1.0.0.255\t13335\tUS\tCLOUDFLARENET",
		"this line has no tabs at all",
		"2.0.0.0\t2.0.0.255\tnot-a-number\tUS\tBROKEN",
		"3.0.0.0\t3.0.0.255\t8866", // truncated: too few columns
		"4.0.0.0\t4.0.0.255\t15169\tUS\t",
		"5.0.0.0\t5.0.0.255\t29244\tBG\tBTC-NET",
	}, "\n")

	owners, err := asnowner.Parse(strings.NewReader(tsv))
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}

	if len(owners) != 2 {
		t.Fatalf("got %d owners, want 2 (the two well-formed lines): %+v", len(owners), owners)
	}
	if owners[1].ASN != 29244 || owners[1].Name != "BTC-NET" {
		t.Errorf("the line after the malformed ones was lost: %+v", owners)
	}
}

// A name may legitimately contain spaces and punctuation. Splitting on tabs rather than
// on whitespace is what keeps it whole.
func TestParseKeepsMultiWordNames(t *testing.T) {
	tsv := "8.8.8.0\t8.8.8.255\t15169\tUS\tGOOGLE, LLC"

	owners, err := asnowner.Parse(strings.NewReader(tsv))
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	if len(owners) != 1 || owners[0].Name != "GOOGLE, LLC" {
		t.Errorf("got %+v, want the name kept whole", owners)
	}
}

func TestParseGzipReadsThePublishedForm(t *testing.T) {
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	if _, err := gz.Write([]byte("1.0.0.0\t1.0.0.255\t13335\tUS\tCLOUDFLARENET\n")); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	if err := gz.Close(); err != nil {
		t.Fatalf("close fixture: %v", err)
	}

	owners, err := asnowner.ParseGzip(&buf)
	if err != nil {
		t.Fatalf("ParseGzip() error = %v", err)
	}
	if len(owners) != 1 || owners[0].ASN != 13335 {
		t.Errorf("got %+v, want AS13335", owners)
	}
}

func TestParseGzipRejectsSomethingThatIsNotGzip(t *testing.T) {
	if _, err := asnowner.ParseGzip(strings.NewReader("plain text, not gzip")); err == nil {
		t.Error("ParseGzip() accepted a non-gzip body")
	}
}

// An empty file is not an error to PARSE, but it must be visibly empty so the caller can
// refuse to replace a good table with nothing. See Refresh.
func TestParseAcceptsAnEmptyFileAsEmpty(t *testing.T) {
	owners, err := asnowner.Parse(strings.NewReader(""))
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	if len(owners) != 0 {
		t.Errorf("got %+v, want nothing", owners)
	}
}
