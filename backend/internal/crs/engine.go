// Package crs evaluates a captured request against the OWASP Core Rule Set.
//
// The migration keeps asking one question the platform could not answer: Cloudflare's
// OWASP managed ruleset IS the CRS, so when F5 blocks something Cloudflare let through,
// would turning the managed ruleset on have caught it — and on which rule? Until now that
// was answered by deploying a rule and waiting a day.
//
// This runs the real CRS, in process, against the request as F5 recorded it, and reports
// every rule that fires with the score it contributes. It answers "what would match", not
// "what should you do": the anomaly score and the threshold are both reported so the
// reader can see how close a decision was rather than being handed a verdict.
//
// Two honesty constraints shape everything here:
//
//   - The engine runs in DETECTION mode even though the question is about blocking. In
//     blocking mode the first disruptive rule ends the transaction and the later phases
//     never run, so the reader would be shown one rule out of the several that matched.
//     "Would block" is derived from the score instead.
//   - F5 keeps a bounded prefix of the body. Every result says so, because a body rule
//     that did not fire may simply never have been shown the bytes that would have fired
//     it, and a clean "no match" would send someone off to trust a rule that does not work.
package crs

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync"

	coreruleset "github.com/corazawaf/coraza-coreruleset/v4"
	"github.com/corazawaf/coraza/v3"
	"github.com/corazawaf/coraza/v3/types"
)

// The knobs that change what CRS decides, with CRS's own defaults.
const (
	// DefaultParanoiaLevel matches CRS out of the box, and Cloudflare's OWASP ruleset
	// default. Higher levels add rules that catch more and cost more false positives.
	DefaultParanoiaLevel = 1
	// DefaultThreshold is CRS's inbound anomaly threshold: 5 is one critical rule.
	DefaultThreshold = 5
	maxParanoiaLevel = 4
)

// reportRuleID carries the transaction's scores back out through the only channel the
// public API offers — a rule that matches on purpose in the logging phase, with the scores
// macro-expanded into its message. It is stripped from the matches before they are shown.
const reportRuleID = 8000100

// Options configures an engine. The zero value is CRS's own defaults.
type Options struct {
	// ParanoiaLevel selects how much of CRS is in force, 1 to 4.
	ParanoiaLevel int
	// Threshold is the inbound anomaly score at which CRS decides to block.
	Threshold int
}

func (o Options) withDefaults() Options {
	if o.ParanoiaLevel < 1 || o.ParanoiaLevel > maxParanoiaLevel {
		o.ParanoiaLevel = DefaultParanoiaLevel
	}
	if o.Threshold < 1 {
		o.Threshold = DefaultThreshold
	}
	return o
}

// Engine is a loaded CRS, reusable across requests.
//
// Loading the rule set parses several thousand rules and takes on the order of a second,
// so this is built once and shared. It is safe for concurrent use.
type Engine struct {
	waf  coraza.WAF
	opts Options

	// Coraza reports matches through a WAF-wide callback, so concurrent evaluations land
	// in the same place and have to be sorted back out by transaction id.
	mu      sync.Mutex
	matches map[string][]types.MatchedRule
}

// New loads the Core Rule Set.
func New(opts Options) (*Engine, error) {
	engine := &Engine{
		opts:    opts.withDefaults(),
		matches: make(map[string][]types.MatchedRule),
	}

	waf, err := coraza.NewWAF(coraza.NewWAFConfig().
		WithRootFS(coreruleset.FS).
		WithErrorCallback(engine.record).
		WithDirectives(directives(engine.opts)))
	if err != nil {
		return nil, fmt.Errorf("load the core rule set: %w", err)
	}

	engine.waf = waf
	return engine, nil
}

// ParanoiaLevel reports the level this engine was built with.
func (e *Engine) ParanoiaLevel() int { return e.opts.ParanoiaLevel }

// directives assembles the configuration CRS expects, in the order it expects it.
//
// The overrides sit between the setup file and the rules on purpose: CRS applies its own
// defaults in rule 901, and rules run in the order they are defined, so anything set after
// the rule set is loaded is set too late to be read.
func directives(opts Options) string {
	return strings.Join([]string{
		"Include @coraza.conf-recommended",
		// Detection, not blocking — see the package comment: blocking would hide every
		// rule that comes after the first disruptive one.
		"SecRuleEngine DetectionOnly",
		"SecRequestBodyAccess On",
		// ProcessPartial rather than Reject: the body is a prefix already, and refusing
		// to look at it would turn a partial answer into no answer.
		"SecRequestBodyLimitAction ProcessPartial",
		"Include @crs-setup.conf.example",
		fmt.Sprintf(
			`SecAction "id:900000,phase:1,nolog,pass,t:none,setvar:tx.blocking_paranoia_level=%d"`,
			opts.ParanoiaLevel),
		fmt.Sprintf(
			`SecAction "id:900110,phase:1,nolog,pass,t:none,`+
				`setvar:tx.inbound_anomaly_score_threshold=%d"`,
			opts.Threshold),
		"Include @owasp_crs/*.conf",
		fmt.Sprintf(
			`SecAction "id:%d,phase:5,pass,log,noauditlog,`+
				`msg:'blocking=%%{tx.blocking_inbound_anomaly_score} `+
				`detection=%%{tx.detection_inbound_anomaly_score}'"`,
			reportRuleID),
	}, "\n")
}

// record collects one matched rule. Coraza calls this from the transaction's goroutine.
func (e *Engine) record(rule types.MatchedRule) {
	e.mu.Lock()
	defer e.mu.Unlock()
	id := rule.TransactionID()
	e.matches[id] = append(e.matches[id], rule)
}

// take removes and returns everything recorded for one transaction.
func (e *Engine) take(id string) []types.MatchedRule {
	e.mu.Lock()
	defer e.mu.Unlock()
	matched := e.matches[id]
	delete(e.matches, id)
	return matched
}

// Evaluate runs the rule set against one captured request.
func (e *Engine) Evaluate(request Request) (Result, error) {
	if request.Method == "" || request.URI == "" {
		return Result{}, errors.New("a request needs at least a method and a URI")
	}

	tx := e.waf.NewTransaction()
	id := tx.ID()
	defer func() {
		// ProcessLogging runs phase 5, which is where the score is reported back.
		tx.ProcessLogging()
		_ = tx.Close()
	}()

	if request.ClientIP != "" {
		tx.ProcessConnection(request.ClientIP, 0, "", 0)
	}
	tx.ProcessURI(request.URI, request.Method, protoOf(request))
	for _, header := range request.Headers {
		tx.AddRequestHeader(header[0], header[1])
	}
	tx.ProcessRequestHeaders()

	notes := []string{}
	if len(request.Body) > 0 {
		if _, _, err := tx.WriteRequestBody(request.Body); err != nil {
			return Result{}, fmt.Errorf("write the captured body: %w", err)
		}
	}
	if _, err := tx.ProcessRequestBody(); err != nil {
		// Not fatal, and not silent either: a body the parser could not follow is the
		// normal outcome for a transcript that stops mid-upload, and the reader has to
		// know the body rules were not really given a chance.
		notes = append(notes, "the captured body could not be fully parsed: "+err.Error())
	}

	// Phase 5 has to run before the matches are read, since that is what reports the
	// score; the deferred Close would run it too late.
	tx.ProcessLogging()

	return e.result(e.take(id), request, notes), nil
}

// protoOf keeps CRS's protocol rules honest about what the transcript actually held.
func protoOf(request Request) string {
	if request.Proto == "" {
		return "HTTP/1.1"
	}
	return request.Proto
}

// result turns Coraza's matches into the reading, pulling the scores out of the report rule.
func (e *Engine) result(matched []types.MatchedRule, request Request, notes []string) Result {
	out := Result{
		Threshold:     e.opts.Threshold,
		ParanoiaLevel: e.opts.ParanoiaLevel,
		BodyTruncated: request.BodyTruncated,
		BodyEvaluated: len(request.Body),
		BodyDeclared:  request.BodyDeclared,
		Notes:         notes,
		Matched:       make([]Match, 0, len(matched)),
	}

	for _, rule := range matched {
		meta := rule.Rule()
		if meta.ID() == reportRuleID {
			out.BlockingScore, out.DetectionScore = scores(rule.Message())
			continue
		}

		out.Matched = append(out.Matched, Match{
			ID:       meta.ID(),
			Message:  rule.Message(),
			Data:     rule.Data(),
			Severity: meta.Severity().String(),
			Phase:    int(meta.Phase()),
			Tags:     meta.Tags(),
			Category: category(meta.Tags()),
			Score:    contributed(meta.Raw()),
			Artifact: bodyErrorRules[meta.ID()],
			File:     meta.File(),
			Line:     meta.Line(),
		})
	}

	out.WouldBlock = out.BlockingScore >= out.Threshold
	out.Notes = append(out.Notes, bodyNote(request)...)
	return out
}

// bodyNote says how much of the body was really evaluated.
//
// This is the difference that explains most disagreements with the edge: Cloudflare reads
// the whole upload, the log kept the first couple of kilobytes, and a body rule that fires
// there fires on nothing here. Stating the two numbers is the only thing that stops "no
// rule matched" from being read as "this request is clean".
func bodyNote(request Request) []string {
	switch {
	case request.BodyDeclared > len(request.Body):
		return []string{fmt.Sprintf(
			"only %d of the %d body bytes the request declared were captured, so the body "+
				"rules were barely evaluated — the edge saw the rest",
			len(request.Body), request.BodyDeclared)}
	case request.BodyTruncated && len(request.Body) > 0:
		return []string{"the body may be a prefix, so a rule that did not fire on it has " +
			"not been answered"}
	default:
		return nil
	}
}

// scores reads the two totals out of the report rule's expanded message.
func scores(message string) (blocking, detection int) {
	for _, part := range strings.Fields(message) {
		name, value, found := strings.Cut(part, "=")
		if !found {
			continue
		}
		number, err := strconv.Atoi(value)
		if err != nil {
			continue
		}
		switch name {
		case "blocking":
			blocking = number
		case "detection":
			detection = number
		}
	}
	return blocking, detection
}

// The anomaly score a CRS rule adds is written into the rule text as a setvar, in terms of
// a named severity — "+%{tx.critical_anomaly_score}" — so it is read from there rather than
// inferred from the severity, which is set independently and does occasionally differ.
var anomalyScores = map[string]int{
	"critical": 5,
	"error":    4,
	"warning":  3,
	"notice":   2,
}

// contributed reports what one rule adds to the inbound anomaly score.
func contributed(raw string) int {
	for name, score := range anomalyScores {
		if strings.Contains(raw, "tx."+name+"_anomaly_score") {
			return score
		}
	}
	return 0
}
