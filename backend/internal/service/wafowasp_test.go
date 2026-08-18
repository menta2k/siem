package service

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	pb "github.com/menta2k/siem/api/gen/siem/v1"
	"github.com/menta2k/siem/internal/crs"
	chdata "github.com/menta2k/siem/internal/data/clickhouse"
	"github.com/menta2k/siem/internal/vendors"
	"github.com/menta2k/siem/internal/vendors/cloudflare"
	"github.com/menta2k/siem/internal/vendors/f5"
)

// recordingPayloads answers with one payload and remembers how it was asked.
type recordingPayloads struct {
	payload string
	err     error

	gotEventID string
	gotHint    chdata.RawPayloadHint
}

func (p *recordingPayloads) GetRawPayload(
	_ context.Context, eventID string, hint chdata.RawPayloadHint,
) (chdata.RawPayload, error) {
	p.gotEventID, p.gotHint = eventID, hint
	if p.err != nil {
		return chdata.RawPayload{}, p.err
	}
	return chdata.RawPayload{
		Payload: []byte(p.payload), Format: "syslog", Vendor: vendors.F5,
	}, nil
}

// An F5 syslog line whose transcript carries an unmistakable SQL injection in a form field.
func owaspPayload() string {
	// support_id is what identifies the line as F5's at all; without it the adapter does
	// not recognize the payload and there is nothing to evaluate.
	return `<130>Aug 17 22:54:31 host ASM:policy_name="/Common/p",request_status="blocked",` +
		`support_id="2773644994017383095",date_time="2026-08-17 22:54:31",` +
		`method="POST",uri="/js_file.php",` +
		`request="POST /js_file.php HTTP/1.1\r\nHost: www.jobs.bg\r\n` +
		`content-type: multipart/form-data; boundary=----B\r\ncontent-length: 90000\r\n\r\n` +
		`------B\r\nContent-Disposition: form-data; name=%22q%22\r\n\r\n` +
		`1' UNION SELECT password FROM users--\r\n"`
}

func owaspService(
	t *testing.T, evaluator OwaspEvaluator, payloads RawPayloadReader,
) *WAFMigrationService {
	t.Helper()

	registry, err := vendors.NewRegistry(cloudflare.New(), f5.New())
	if err != nil {
		t.Fatalf("vendor registry: %v", err)
	}
	service := migrationService(&stubMigrationReader{}, nil).
		WithEvaluator(nil, payloads, registry)
	if evaluator != nil {
		service = service.WithOwasp(evaluator)
	}
	return service
}

func owaspRequest() *pb.WafOwaspRequest {
	return &pb.WafOwaspRequest{
		EventId:      "f5-event",
		ReceivedAt:   timestamppb.New(migrationNow),
		SourceVendor: vendors.F5,
	}
}

// THE QUESTION THE PANEL EXISTS FOR. Cloudflare says "949110: Inbound Anomaly Score
// Exceeded" and stops, which names the decision and hides the reasoning. This has to come
// back with the rules that built the score and what each one added.
func TestTheContributingOwaspRulesAreNamed(t *testing.T) {
	payloads := &recordingPayloads{payload: owaspPayload()}
	service := owaspService(t, crs.NewLazy(crs.Options{Threshold: 15}), payloads)

	result, err := service.ExplainOwasp(context.Background(), owaspRequest())
	if err != nil {
		t.Fatalf("ExplainOwasp: %v", err)
	}
	if !result.GetAvailable() {
		t.Fatalf("no reading was produced: %s", result.GetError())
	}

	var sqli, scored int
	for _, match := range result.GetMatched() {
		if match.GetCategory() == "attack-sqli" {
			sqli++
		}
		if match.GetScore() > 0 {
			scored++
		}
	}
	if sqli == 0 {
		t.Errorf("the injection in a form field was not attributed: %+v", result.GetMatched())
	}
	if scored == 0 {
		t.Error("no rule reported what it added, so the total cannot be explained")
	}
	if result.GetBlockingScore() == 0 {
		t.Error("the score that drives the decision came back as zero")
	}
	if !result.GetWouldBlock() {
		t.Errorf("score %d against threshold %d was not reported as blocking",
			result.GetBlockingScore(), result.GetThreshold())
	}
}

// THE NUMBER THAT KEEPS A CLEAN RESULT HONEST. F5 keeps a couple of kilobytes of a request
// that declared 90,000, and every OWASP hit on this deployment is an upload. Without the
// two byte counts on the wire, "nothing matched" reads as "this request is clean" when it
// means the deciding bytes were never captured.
func TestHowMuchOfTheBodyWasReadTravelsToTheClient(t *testing.T) {
	service := owaspService(t, crs.NewLazy(crs.Options{}),
		&recordingPayloads{payload: owaspPayload()})

	result, err := service.ExplainOwasp(context.Background(), owaspRequest())
	if err != nil {
		t.Fatalf("ExplainOwasp: %v", err)
	}

	if result.GetBodyDeclared() != 90000 {
		t.Errorf("declared body = %d, want the 90000 the request claimed",
			result.GetBodyDeclared())
	}
	if result.GetBodyEvaluated() == 0 || result.GetBodyEvaluated() >= result.GetBodyDeclared() {
		t.Errorf("evaluated %d of %d body bytes, which cannot be right for a truncated log",
			result.GetBodyEvaluated(), result.GetBodyDeclared())
	}
	if !result.GetBodyTruncated() || len(result.GetNotes()) == 0 {
		t.Error("nothing on the wire says the reading was made on a prefix")
	}
}

// THE LOOKUP THAT DECIDES WHETHER THIS ANSWERS AT ALL. raw_events is partitioned by arrival
// and sorted by delivering vendor; an id on its own reads every partition — measured at 50
// million rows — and the panel times out. Both hints have to reach the reader.
func TestThePayloadLookupIsGivenWhatItNeedsToSeek(t *testing.T) {
	payloads := &recordingPayloads{payload: owaspPayload()}
	service := owaspService(t, crs.NewLazy(crs.Options{}), payloads)

	if _, err := service.ExplainOwasp(context.Background(), owaspRequest()); err != nil {
		t.Fatalf("ExplainOwasp: %v", err)
	}

	if payloads.gotEventID != "f5-event" {
		t.Errorf("looked up %q", payloads.gotEventID)
	}
	if payloads.gotHint.SourceVendor != vendors.F5 {
		t.Errorf("delivering vendor = %q, without which the query cannot seek",
			payloads.gotHint.SourceVendor)
	}
	if !payloads.gotHint.ReceivedAt.Equal(migrationNow) {
		t.Errorf("arrival time = %v, without which the query cannot prune partitions",
			payloads.gotHint.ReceivedAt)
	}
}

// A request that has aged out is NOT a request with no findings. Reporting an empty rule
// list would hand back a clean bill of health for something nobody looked at.
func TestAnExpiredRequestIsRefusedRatherThanReportedClean(t *testing.T) {
	service := owaspService(t, crs.NewLazy(crs.Options{}),
		&recordingPayloads{err: errors.New("no payload")})

	result, err := service.ExplainOwasp(context.Background(), owaspRequest())
	if err != nil {
		t.Fatalf("ExplainOwasp: %v", err)
	}

	if result.GetAvailable() {
		t.Error("a request with no stored payload was reported as evaluated")
	}
	if !strings.Contains(result.GetError(), "retained") {
		t.Errorf("error = %q, want it to say the request is no longer retained",
			result.GetError())
	}
	if len(result.GetMatched()) != 0 {
		t.Error("an unanswerable question came back with findings")
	}
}

// A deployment with no rule engine is a configuration, not a fault, and the panel says so
// rather than failing in a way that suggests the request was the problem.
func TestWithoutAnEngineThePanelExplainsItself(t *testing.T) {
	service := owaspService(t, nil, &recordingPayloads{payload: owaspPayload()})

	result, err := service.ExplainOwasp(context.Background(), owaspRequest())
	if err != nil {
		t.Fatalf("ExplainOwasp: %v", err)
	}
	if result.GetAvailable() || !strings.Contains(result.GetError(), "configured") {
		t.Errorf("result = %+v, want a stated absence", result)
	}
}

// A payload that holds no transcript cannot be evaluated, and must not be reported as a
// request that matched nothing.
func TestAPayloadWithoutTheRequestIsRefused(t *testing.T) {
	service := owaspService(t, crs.NewLazy(crs.Options{}), &recordingPayloads{
		payload: `<130>Aug 17 22:54:31 host ASM:policy_name="/Common/p",` +
			`request_status="blocked",support_id="2773644994017383095",` +
			`date_time="2026-08-17 22:54:31",method="POST",uri="/js_file.php"`,
	})

	result, err := service.ExplainOwasp(context.Background(), owaspRequest())
	if err != nil {
		t.Fatalf("ExplainOwasp: %v", err)
	}
	if result.GetAvailable() {
		t.Error("a payload with no request transcript produced a reading")
	}
}

func TestAnEventIdIsRequired(t *testing.T) {
	service := owaspService(t, crs.NewLazy(crs.Options{}), &recordingPayloads{})

	_, err := service.ExplainOwasp(context.Background(), &pb.WafOwaspRequest{
		ReceivedAt: timestamppb.New(time.Now()),
	})
	if err == nil {
		t.Error("a request naming no event was accepted")
	}
}
