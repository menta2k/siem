package f5

import "testing"

// The production failure, end to end: an ASM Field-Value line must normalize rather than
// be rejected for a timestamp it plainly contains.
func TestASMLineNormalizesEndToEnd(t *testing.T) {
	a := New()

	format, ok := a.Detect([]byte(asmLine))
	if !ok {
		t.Fatal("Detect did not recognise a real ASM line")
	}

	records, err := a.Parse([]byte(asmLine), format)
	if err != nil || len(records) != 1 {
		t.Fatalf("Parse: %v (%d records)", err, len(records))
	}

	event, err := a.Normalize(records[0])
	if err != nil {
		t.Fatalf("Normalize rejected a real ASM line: %v", err)
	}

	if event.RequestHost != "shop.example.com" {
		t.Errorf("RequestHost = %q — without it F5 cannot join other vendors on hostname",
			event.RequestHost)
	}
	if event.VendorRequestID != "1827399125" {
		t.Errorf("VendorRequestID = %q, want the support_id", event.VendorRequestID)
	}
	if event.EventTime.IsZero() {
		t.Error("EventTime is zero — this is the exact production rejection")
	}
	t.Logf("normalized: host=%s path=%s verdict=%s time=%s",
		event.RequestHost, event.RequestPath, event.Verdict, event.EventTime)
}
