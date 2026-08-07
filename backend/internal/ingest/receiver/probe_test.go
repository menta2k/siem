package receiver

import (
	"bytes"
	"compress/gzip"
	"strings"
	"testing"
)

func gzipped(t *testing.T, s string) []byte {
	t.Helper()

	var buf bytes.Buffer
	w := gzip.NewWriter(&buf)
	if _, err := w.Write([]byte(s)); err != nil {
		t.Fatalf("gzip write: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("gzip close: %v", err)
	}
	return buf.Bytes()
}

// The exact payload Cloudflare uploads to validate a Logpush destination.
func TestTheCloudflareValidationUploadIsRecognised(t *testing.T) {
	if !isDestinationProbe(gzipped(t, `{"content":"tests"}`)) {
		t.Error("the gzipped Cloudflare validation payload was not recognised; Logpush " +
			"cannot create a job against a destination that does not acknowledge it")
	}
}

// Cloudflare documents the payload as gzipped, but an uncompressed one must not be
// mistaken for data either.
func TestAnUncompressedProbeIsRecognised(t *testing.T) {
	if !isDestinationProbe([]byte(`{"content":"tests"}`)) {
		t.Error("an uncompressed validation payload was not recognised")
	}
}

func TestWhitespaceAndOrderingDoNotMatter(t *testing.T) {
	for _, body := range []string{
		"  {\"content\":\"tests\"}\n",
		"{ \"content\" : \"tests\" }",
	} {
		if !isDestinationProbe([]byte(body)) {
			t.Errorf("probe %q was not recognised", body)
		}
	}
}

// THE IMPORTANT DIRECTION. Anything that is not the probe must fall through to normal
// ingestion — a real delivery silently answered "ok" would be acknowledged and then
// dropped, which is the one failure the 202 contract exists to prevent.
func TestRealDeliveriesAreNotMistakenForProbes(t *testing.T) {
	cases := map[string]string{
		"a cloudflare log line": `{"RayID":"abc","EdgeStartTimestamp":"2026-08-07T00:00:00Z"}`,
		"an ndjson batch":       "{\"RayID\":\"a\"}\n{\"RayID\":\"b\"}",
		"a json array":          `[{"RayID":"a"}]`,
		"content but not tests": `{"content":"something else"}`,
		"content as a number":   `{"content":123}`,
		"empty object":          `{}`,
		"not json at all":       `plain text`,
	}

	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			if isDestinationProbe([]byte(body)) {
				t.Error("a real delivery was treated as a validation probe; it would be " +
					"acknowledged and never ingested")
			}
			if isDestinationProbe(gzipped(t, body)) {
				t.Error("a real gzipped delivery was treated as a validation probe")
			}
		})
	}
}

// A large body is a delivery by definition, and must not be decompressed twice just to
// discover that.
func TestALargeBodyIsNeverAProbe(t *testing.T) {
	big := `{"content":"tests"}` + strings.Repeat(" ", probeMaxBytes)

	if isDestinationProbe([]byte(big)) {
		t.Error("an oversized body was treated as a validation probe")
	}
}

// A gzip bomb must not be expanded without bound: this runs before the delivery has
// been shown to be trustworthy.
func TestProbeDecompressionIsBounded(t *testing.T) {
	bomb := gzipped(t, strings.Repeat("A", 10<<20))

	// Under the size gate this never even reaches the decompressor, but the bound is
	// asserted here so the gate and the limit cannot drift apart unnoticed.
	if isDestinationProbe(bomb) {
		t.Error("a gzip bomb was treated as a validation probe")
	}
	if out, ok := gunzipProbe(bomb); ok && len(out) > probeMaxBytes {
		t.Errorf("decompressed %d bytes, want at most %d", len(out), probeMaxBytes)
	}
}
