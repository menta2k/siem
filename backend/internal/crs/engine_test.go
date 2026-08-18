package crs

import (
	"strings"
	"sync"
	"testing"
)

// The rule set is expensive to load, so the whole file shares one engine.
var (
	shared     *Engine
	sharedOnce sync.Once
)

func engine(t *testing.T) *Engine {
	t.Helper()
	sharedOnce.Do(func() {
		built, err := New(Options{})
		if err != nil {
			t.Fatalf("load CRS: %v", err)
		}
		shared = built
	})
	if shared == nil {
		t.Fatal("the rule set failed to load")
	}
	return shared
}

func ids(result Result) map[int]Match {
	byID := make(map[int]Match, len(result.Matched))
	for _, match := range result.Matched {
		byID[match.ID] = match
	}
	return byID
}

// THE QUESTION THIS EXISTS TO ANSWER. Cloudflare reports 949110 — "inbound anomaly score
// exceeded" — and nothing else, so an operator can see that the OWASP ruleset blocked a
// request but not which of its rules decided that. The whole point is to name the
// contributors and what each one added.
func TestTheContributingRulesAreNamedNotJustTheBlockingDecision(t *testing.T) {
	result, err := engine(t).Evaluate(Request{
		Method:  "GET",
		URI:     "/search.php?q=1%27%20UNION%20SELECT%20username,password%20FROM%20users--",
		Proto:   "HTTP/1.1",
		Headers: [][2]string{{"Host", "www.jobs.bg"}, {"User-Agent", "curl/8.4.0"}},
	})
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}

	byID := ids(result)
	if _, found := byID[949110]; !found {
		t.Fatalf("the blocking rule did not fire on a plain UNION SELECT: %+v", result.Matched)
	}

	var sqli []int
	for id, match := range byID {
		if match.Category == "attack-sqli" {
			sqli = append(sqli, id)
		}
	}
	if len(sqli) == 0 {
		t.Errorf("949110 was reported with no contributing rule to explain it: %+v", byID)
	}
	if result.BlockingScore < result.Threshold {
		t.Errorf("score %d is below the threshold %d yet the request was blocked",
			result.BlockingScore, result.Threshold)
	}
	if !result.WouldBlock {
		t.Error("a request over the threshold was not reported as blocked")
	}
}

// THE SHAPE THE TRAFFIC ACTUALLY TAKES. Every OWASP hit on this deployment is a multipart
// upload, and F5's transcript always cuts one off mid-file. The parts that DID survive still
// have to be evaluated — otherwise the tool would answer "clean" for every upload, which is
// the one answer it must never give by accident.
func TestTheSurvivingPartsOfATruncatedUploadAreStillEvaluated(t *testing.T) {
	request, ok := ParseTranscript(
		`POST /js_file.php HTTP/1.1\r\nHost: www.jobs.bg\r\n` +
			`content-type: multipart/form-data; boundary=----B\r\n` +
			`content-length: 90000\r\n\r\n` +
			`------B\r\nContent-Disposition: form-data; name=%22q%22\r\n\r\n` +
			`1' UNION SELECT password FROM users--\r\n` +
			`------B\r\nContent-Disposition: form-data; name=%22file%22; ` +
			`filename=%22a.jpg%22\r\n\r\n`)
	if !ok {
		t.Fatal("the transcript did not parse")
	}

	result, err := engine(t).Evaluate(request)
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}

	byID := ids(result)
	if _, found := byID[942100]; !found {
		t.Errorf("the SQLi in a surviving form field was missed: %+v", result.Matched)
	}
	if _, found := byID[949110]; !found {
		t.Error("the score was exceeded but the blocking rule was not reported")
	}
	if result.BodyDeclared != 90000 || result.BodyEvaluated >= result.BodyDeclared {
		t.Errorf("evaluated %d of %d declared body bytes; the gap is what makes a miss "+
			"inconclusive and it has to be reported",
			result.BodyEvaluated, result.BodyDeclared)
	}
	if len(result.Notes) == 0 {
		t.Error("nothing told the reader how little of the body was seen")
	}
}

// The score is the number the decision is actually made on, so it has to come back — and
// per rule, because "40 out of 40" over five rules is a different finding from one rule
// carrying it alone.
func TestEachRuleReportsWhatItAddedToTheScore(t *testing.T) {
	result, err := engine(t).Evaluate(Request{
		Method:  "GET",
		URI:     "/?q=%3Cscript%3Ealert(1)%3C/script%3E",
		Headers: [][2]string{{"Host", "www.jobs.bg"}},
	})
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}

	var scored int
	for _, match := range result.Matched {
		if match.ID != 949110 && match.Score > 0 {
			scored++
		}
	}
	if scored == 0 {
		t.Errorf("no rule reported a score, so the total cannot be explained: %+v", result.Matched)
	}
	if result.BlockingScore == 0 {
		t.Error("an XSS payload scored nothing")
	}
}

// A request nobody would block must come back clean. Without this the tool would look
// useful while agreeing with everything.
func TestAnOrdinaryRequestMatchesNothing(t *testing.T) {
	result, err := engine(t).Evaluate(Request{
		Method: "GET",
		URI:    "/js_file_list.php?subm=1",
		Headers: [][2]string{
			{"Host", "www.jobs.bg"},
			{"User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)"},
			{"Accept", "text/html,application/xhtml+xml"},
			{"Accept-Language", "en-GB,en;q=0.9"},
		},
	})
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}

	if result.WouldBlock {
		t.Errorf("an ordinary browser request would be blocked: %+v", result.Matched)
	}
	if result.BlockingScore >= result.Threshold {
		t.Errorf("score %d on an ordinary request", result.BlockingScore)
	}
}

// The paranoia level is the single knob that most changes what CRS says, and Cloudflare
// exposes it too — so a reading is only comparable to their deployment if this is settable.
func TestTheParanoiaLevelChangesWhatIsEvaluated(t *testing.T) {
	strict, err := New(Options{ParanoiaLevel: 4})
	if err != nil {
		t.Fatalf("load CRS at PL4: %v", err)
	}

	request := Request{
		Method:  "GET",
		URI:     "/index.php?redirect=http://example.com/",
		Headers: [][2]string{{"Host", "www.jobs.bg"}},
	}

	relaxed, err := engine(t).Evaluate(request)
	if err != nil {
		t.Fatalf("Evaluate at PL1: %v", err)
	}
	paranoid, err := strict.Evaluate(request)
	if err != nil {
		t.Fatalf("Evaluate at PL4: %v", err)
	}

	if paranoid.ParanoiaLevel != 4 {
		t.Errorf("paranoia level = %d, want 4", paranoid.ParanoiaLevel)
	}
	if paranoid.BlockingScore <= relaxed.BlockingScore {
		t.Errorf("PL4 scored %d and PL1 scored %d: the level had no effect",
			paranoid.BlockingScore, relaxed.BlockingScore)
	}
}

// THE CAVEAT THAT KEEPS THIS HONEST. F5 keeps a prefix of the body, so a body rule that did
// not fire has not cleared the request — it was never shown the bytes. A result that hid
// that would be worse than no result.
func TestATruncatedBodyIsDeclaredNotAssumedComplete(t *testing.T) {
	request, ok := ParseTranscript(
		`POST /js_file.php HTTP/1.1\r\nHost: www.jobs.bg\r\n` +
			`Content-Type: multipart/form-data; boundary=----X\r\n\r\n` +
			`------X\r\nContent-Disposition: form-data; name=%22file%22; ` +
			`filename=%22shell.html%22\r\n`)
	if !ok {
		t.Fatal("the transcript did not parse")
	}

	result, err := engine(t).Evaluate(request)
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}

	if !result.BodyTruncated {
		t.Error("a body known to be a prefix was not declared truncated")
	}
	if len(result.Notes) == 0 {
		t.Error("nothing warned the reader that a miss on the body proves nothing")
	}
	for _, match := range result.Matched {
		if bodyErrorRules[match.ID] && !match.Artifact {
			t.Errorf("rule %d fired on how the body was captured but is not marked an "+
				"artifact", match.ID)
		}
	}
}

// A request needs at least a method and a target; evaluating half of one would report a
// clean result for a request that was never assessed.
func TestAnIncompleteRequestIsRefused(t *testing.T) {
	if _, err := engine(t).Evaluate(Request{Method: "GET"}); err == nil {
		t.Error("a request with no URI was evaluated")
	}
}

// The engine is shared across evaluations, and Coraza reports matches through one
// WAF-wide callback — so without keying by transaction, one request's rules would show up
// in another's answer.
func TestConcurrentEvaluationsDoNotMixResults(t *testing.T) {
	shared := engine(t)
	clean := Request{Method: "GET", URI: "/about.php", Headers: [][2]string{{"Host", "x"}}}
	attack := Request{Method: "GET", URI: "/?q=1%27%20OR%20%271%27%3D%271", Headers: clean.Headers}

	var wg sync.WaitGroup
	errs := make(chan string, 32)
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			request, wantMatches := clean, false
			if i%2 == 1 {
				request, wantMatches = attack, true
			}
			result, err := shared.Evaluate(request)
			if err != nil {
				errs <- err.Error()
				return
			}
			if got := len(result.Matched) > 0; got != wantMatches {
				errs <- "a request was answered with another request's rules"
			}
		}(i)
	}
	wg.Wait()
	close(errs)
	for message := range errs {
		t.Error(message)
	}
}

func TestParseTranscriptRestoresTheRequestFromF5sEscaping(t *testing.T) {
	request, ok := ParseTranscript(
		`POST /js_file.php?subm=1 HTTP/1.1\r\nHost: app2.jobs.bg\r\n` +
			`Cookie: a=b\r\n\r\nname=%22x%22`)
	if !ok {
		t.Fatal("the transcript did not parse")
	}

	if request.Method != "POST" || request.URI != "/js_file.php?subm=1" {
		t.Errorf("request line = %q %q", request.Method, request.URI)
	}
	if len(request.Headers) != 2 || request.Headers[0][0] != "Host" {
		t.Errorf("headers = %v", request.Headers)
	}
	if !strings.Contains(string(request.Body), `name="x"`) {
		t.Errorf("body = %q, want F5's escaping undone", request.Body)
	}
}
