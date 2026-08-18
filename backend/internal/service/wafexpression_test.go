package service

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	pb "github.com/menta2k/siem/api/gen/siem/v1"
	chdata "github.com/menta2k/siem/internal/data/clickhouse"
	"github.com/menta2k/siem/internal/vendors"
	"github.com/menta2k/siem/internal/vendors/cloudflare"
	"github.com/menta2k/siem/internal/vendors/f5"
	"github.com/menta2k/siem/internal/wirefilter"
)

// stubEvaluator stands in for the sidecar, recording what it was asked.
type stubEvaluator struct {
	configured bool
	result     wirefilter.Result
	err        error

	gotExpression string
	gotRequests   []wirefilter.Request
}

func (s *stubEvaluator) Configured() bool { return s.configured }

func (s *stubEvaluator) Evaluate(
	_ context.Context, expression string, requests []wirefilter.Request,
) (wirefilter.Result, error) {
	s.gotExpression, s.gotRequests = expression, requests
	return s.result, s.err
}

// stubPayloads returns a transcript per event, or nothing for an event whose payload has
// aged out.
type stubPayloads struct{ byEvent map[string]string }

func (s stubPayloads) GetRawPayload(
	_ context.Context, eventID string, _ chdata.RawPayloadHint,
) (chdata.RawPayload, error) {
	payload, ok := s.byEvent[eventID]
	if !ok {
		return chdata.RawPayload{}, errors.New("no payload")
	}
	return chdata.RawPayload{Payload: []byte(payload), Format: "syslog", Vendor: vendors.F5}, nil
}

// An F5 syslog line carrying the transcript, which is what the extractor reads.
func f5Payload(filename string) string {
	return `<130>Aug 17 22:54:31 host ASM:policy_name="/Common/p",request_status="blocked",` +
		`method="POST",uri="/js_file.php",` +
		`request="POST /js_file.php HTTP/1.1\r\nHost: www.jobs.bg\r\n\r\n` +
		`Content-Disposition: form-data; name=%22file%22; filename=%22` + filename + `%22\r\n"`
}

func expressionService(
	t *testing.T, evaluator ExpressionEvaluator, payloads RawPayloadReader,
	samples []chdata.WAFMigrationSample,
) *WAFMigrationService {
	t.Helper()

	registry, err := vendors.NewRegistry(cloudflare.New(), f5.New())
	if err != nil {
		t.Fatalf("vendor registry: %v", err)
	}
	reader := &stubMigrationReader{samples: samples}
	return migrationService(reader, nil).WithEvaluator(evaluator, payloads, registry)
}

func expressionRequest() *pb.WafExpressionRequest {
	return &pb.WafExpressionRequest{
		TimeRange:  migrationRange(),
		Violation:  "Attack signature detected",
		Expression: `http.request.body.raw matches "(?i)filename=\"[^\"]*\.html?\""`,
	}
}

func sample(eventID string) chdata.WAFMigrationSample {
	return chdata.WAFMigrationSample{
		F5EventID:     eventID,
		EventTime:     migrationNow,
		ReceivedAt:    migrationNow.Add(time.Second),
		SourceVendor:  vendors.F5,
		RequestHost:   "www.jobs.bg",
		RequestPath:   "/js_file.php",
		RequestMethod: "POST",
	}
}

// THE POINT OF THE FEATURE. The transcript reaches the evaluator with F5's escaping undone,
// because a multipart body is nothing but quotes and an expression matching a filename would
// otherwise never match — reporting that a correct rule does not work.
func TestTheEvaluatorReceivesTheDecodedRequest(t *testing.T) {
	evaluator := &stubEvaluator{
		configured: true,
		result: wirefilter.Result{
			Valid:    true,
			Outcomes: []wirefilter.Outcome{{ID: "e1", Matched: true}},
		},
	}
	svc := expressionService(t, evaluator,
		stubPayloads{byEvent: map[string]string{"e1": f5Payload("test.html")}},
		[]chdata.WAFMigrationSample{sample("e1")})

	result, err := svc.EvaluateExpression(context.Background(), expressionRequest())
	if err != nil {
		t.Fatalf("EvaluateExpression: %v", err)
	}

	if len(evaluator.gotRequests) != 1 {
		t.Fatalf("sent %d requests, want 1", len(evaluator.gotRequests))
	}
	sent := evaluator.gotRequests[0]
	if sent.Fields["http.request.uri.path"] != "/js_file.php" {
		t.Errorf("path = %q", sent.Fields["http.request.uri.path"])
	}
	if !sent.BodyTruncated {
		t.Error("the body must be marked truncated: F5 keeps only a prefix")
	}
	if result.GetTested() != 1 || result.GetMatched() != 1 {
		t.Errorf("tested/matched = %d/%d, want 1/1", result.GetTested(), result.GetMatched())
	}
}

// A sample whose payload has aged out is DROPPED, not sent with an empty body. A body
// expression would miss it, and that miss would read as evidence about the rule when it is
// really evidence about retention.
func TestSamplesWithoutATranscriptAreNotTested(t *testing.T) {
	evaluator := &stubEvaluator{configured: true, result: wirefilter.Result{Valid: true}}
	svc := expressionService(t, evaluator,
		stubPayloads{byEvent: map[string]string{"kept": f5Payload("test.html")}},
		[]chdata.WAFMigrationSample{sample("kept"), sample("expired")})

	if _, err := svc.EvaluateExpression(context.Background(), expressionRequest()); err != nil {
		t.Fatalf("EvaluateExpression: %v", err)
	}

	if len(evaluator.gotRequests) != 1 || evaluator.gotRequests[0].ID != "kept" {
		t.Errorf("sent %+v, want only the request whose transcript survived",
			evaluator.gotRequests)
	}
}

// A refused expression carries no counts. "0 of 20 matched" beside the reason would read as
// a result, when the question was never asked.
func TestARefusedExpressionReportsNoCounts(t *testing.T) {
	evaluator := &stubEvaluator{
		configured: true,
		result: wirefilter.Result{
			Valid:             false,
			Error:             "unknown field",
			UnavailableFields: []string{"cf.bot_management.score"},
		},
	}
	svc := expressionService(t, evaluator,
		stubPayloads{byEvent: map[string]string{"e1": f5Payload("test.html")}},
		[]chdata.WAFMigrationSample{sample("e1")})

	result, err := svc.EvaluateExpression(context.Background(), expressionRequest())
	if err != nil {
		t.Fatalf("EvaluateExpression: %v", err)
	}

	if result.GetValid() {
		t.Error("a refused expression must not be reported as valid")
	}
	if result.GetTested() != 0 || len(result.GetOutcomes()) != 0 {
		t.Error("a refused expression must carry no verdicts")
	}
	if len(result.GetUnavailableFields()) != 1 {
		t.Error("the unavailable field must be named for the reader")
	}
}

// A qualified miss is counted apart, so "3 of 20" is never read as more certain than it is.
func TestUncertainMissesAreCountedApart(t *testing.T) {
	evaluator := &stubEvaluator{
		configured: true,
		result: wirefilter.Result{Valid: true, Outcomes: []wirefilter.Outcome{
			{ID: "e1", Matched: true},
			{ID: "e2", Matched: false, Caveat: "only part of the body was captured"},
		}},
	}
	svc := expressionService(t, evaluator, stubPayloads{byEvent: map[string]string{
		"e1": f5Payload("a.html"), "e2": f5Payload("b.pdf"),
	}}, []chdata.WAFMigrationSample{sample("e1"), sample("e2")})

	result, err := svc.EvaluateExpression(context.Background(), expressionRequest())
	if err != nil {
		t.Fatalf("EvaluateExpression: %v", err)
	}

	if result.GetTested() != 2 || result.GetMatched() != 1 || result.GetUncertain() != 1 {
		t.Errorf("tested/matched/uncertain = %d/%d/%d, want 2/1/1",
			result.GetTested(), result.GetMatched(), result.GetUncertain())
	}
}

// A deployment without an evaluator is a configuration, not a fault, and the reason has to
// say so — failing plainly would suggest the expression was the problem.
func TestWithoutAnEvaluatorTheTestIsRefusedWithAReason(t *testing.T) {
	svc := expressionService(t, &stubEvaluator{configured: false},
		stubPayloads{}, []chdata.WAFMigrationSample{sample("e1")})

	_, err := svc.EvaluateExpression(context.Background(), expressionRequest())
	if err == nil {
		t.Fatal("a missing evaluator must be reported")
	}
	if !strings.Contains(err.Error(), "evaluator") {
		t.Errorf("error = %v, want it to name the missing evaluator", err)
	}
}

// An empty expression, or a group that identifies nothing, is rejected before any work.
func TestTheRequestIsValidatedFirst(t *testing.T) {
	svc := expressionService(t, &stubEvaluator{configured: true},
		stubPayloads{}, nil)

	if _, err := svc.EvaluateExpression(context.Background(), &pb.WafExpressionRequest{
		TimeRange: migrationRange(), Violation: "x",
	}); err == nil {
		t.Error("an empty expression was accepted")
	}
	if _, err := svc.EvaluateExpression(context.Background(), &pb.WafExpressionRequest{
		TimeRange: migrationRange(), Expression: "http.host eq \"x\"",
	}); err == nil {
		t.Error("a request identifying no group was accepted")
	}
}

// No requests is not a failed test: the group's evidence has aged out, or the range holds
// none. The expression has not been judged, and saying "0 matched" would claim it was.
func TestAnEmptyGroupIsNotAVerdict(t *testing.T) {
	evaluator := &stubEvaluator{configured: true}
	svc := expressionService(t, evaluator, stubPayloads{}, nil)

	result, err := svc.EvaluateExpression(context.Background(), expressionRequest())
	if err != nil {
		t.Fatalf("EvaluateExpression: %v", err)
	}
	if !result.GetValid() || result.GetTested() != 0 {
		t.Errorf("result = %+v, want a valid, untested answer", result)
	}
	if evaluator.gotExpression != "" {
		t.Error("the evaluator was called with nothing to evaluate")
	}
}
