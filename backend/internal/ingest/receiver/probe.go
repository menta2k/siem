package receiver

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"io"
)

// probeMaxBytes bounds how much of a body is examined when deciding whether it is a
// validation probe. The payload vendors send is a few dozen bytes; anything larger is a
// real delivery and must not be decompressed twice just to find that out.
const probeMaxBytes = 1 << 10

// isDestinationProbe reports whether a body is a vendor's destination-validation upload
// rather than log data.
//
// Cloudflare will not save a Logpush job until it has proved the destination works, and
// it proves it by uploading a gzipped `test.txt.gz` whose content is `{"content":"tests"}`.
// That is not a log record: fed to the adapter it parses as one unrecognisable event, is
// rejected, and the delivery answers 207 Multi-Status. Cloudflare reads anything other
// than a clean success as a broken destination, so the job still cannot be created — and
// the feed acquires a permanent rejected event describing a delivery that never happened.
//
// Recognising the probe and answering 200 keeps both halves honest: the vendor gets the
// unambiguous success it is asking for, and `rejected_events` continues to mean "a real
// delivery the platform could not parse".
func isDestinationProbe(body []byte) bool {
	if len(body) > probeMaxBytes {
		return false
	}

	payload := body
	if decompressed, ok := gunzipProbe(body); ok {
		payload = decompressed
	}

	// Matched on structure rather than on the exact bytes, so whitespace or key ordering
	// from a future vendor build does not turn a probe back into a rejected event.
	var probe struct {
		Content *string `json:"content"`
	}
	if err := json.Unmarshal(bytes.TrimSpace(payload), &probe); err != nil {
		return false
	}
	return probe.Content != nil && *probe.Content == "tests"
}

// gunzipProbe decompresses a small gzip body, reporting whether it was gzip at all.
func gunzipProbe(body []byte) ([]byte, bool) {
	reader, err := gzip.NewReader(bytes.NewReader(body))
	if err != nil {
		return nil, false
	}
	defer func() { _ = reader.Close() }()

	// Bounded: a small gzip body can decompress to an enormous one, and this runs before
	// the delivery is known to be trustworthy.
	decompressed, err := io.ReadAll(io.LimitReader(reader, probeMaxBytes))
	if err != nil {
		return nil, false
	}
	return decompressed, true
}
