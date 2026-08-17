package service

import (
	"context"
	"errors"
	"testing"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	pb "github.com/menta2k/siem/api/gen/siem/v1"
	chdata "github.com/menta2k/siem/internal/data/clickhouse"
	"github.com/menta2k/siem/internal/query"
)

// stubMigrationReader records what the service asked for and returns what it is told to.
type stubMigrationReader struct {
	uncovered   []chdata.WAFUncoveredGroup
	rules       []chdata.WAFRuleAgreement
	samples     []chdata.WAFMigrationSample
	observed    []string
	observedErr error

	gotFilter     chdata.WAFMigrationFilter
	gotReadings   []string
	gotCandidates []string
	gotSelector   chdata.WAFMigrationSelector
	gotLimit      int
}

func (s *stubMigrationReader) Uncovered(
	_ context.Context, q chdata.DashboardQuery, filter chdata.WAFMigrationFilter,
) ([]chdata.WAFUncoveredGroup, error) {
	s.gotFilter, s.gotLimit = filter, q.Limit
	return s.uncovered, nil
}

func (s *stubMigrationReader) RuleAgreement(
	_ context.Context, q chdata.DashboardQuery, filter chdata.WAFMigrationFilter,
	readings, monitoredRuleIDs []string,
) ([]chdata.WAFRuleAgreement, error) {
	s.gotFilter, s.gotReadings, s.gotLimit = filter, readings, q.Limit
	s.gotCandidates = monitoredRuleIDs
	return s.rules, nil
}

// stubMonitored stands in for the rule table's view of which rules do not enforce.
type stubMonitored struct {
	actions map[string]string
	err     error
}

func (s stubMonitored) MonitoredRules(context.Context) (map[string]string, error) {
	return s.actions, s.err
}

// defaultMonitored covers the rules the fixtures below use.
func defaultMonitored() stubMonitored {
	return stubMonitored{actions: map[string]string{
		"23548ee2b36547a1be09bb2c0550c529": "log",
		"abc":                              "simulate",
	}}
}

func (s *stubMigrationReader) ObservedMonitoredRules(
	_ context.Context, _ chdata.DashboardQuery,
) ([]string, error) {
	return s.observed, s.observedErr
}

func (s *stubMigrationReader) Samples(
	_ context.Context, sel chdata.WAFMigrationSelector, q chdata.DashboardQuery,
) ([]chdata.WAFMigrationSample, error) {
	s.gotSelector, s.gotLimit = sel, q.Limit
	return s.samples, nil
}

// stubRuleNamer stands in for the Cloudflare rule resolver.
type stubRuleNamer struct{ names map[string]string }

func (s stubRuleNamer) Describe(_ context.Context, _ []string) map[string]string {
	return s.names
}

var migrationNow = time.Date(2026, 8, 16, 12, 0, 0, 0, time.UTC)

func migrationService(reader WAFMigrationReader, namer RuleNamer) *WAFMigrationService {
	return migrationServiceWith(reader, namer, defaultMonitored())
}

func migrationServiceWith(
	reader WAFMigrationReader, namer RuleNamer, monitored MonitoredRuleSource,
) *WAFMigrationService {
	s := NewWAFMigrationService(reader, query.DefaultLimits(), namer, monitored)
	s.now = func() time.Time { return migrationNow }
	return s
}

func migrationRange() *pb.TimeRange {
	return &pb.TimeRange{
		From: timestamppb.New(migrationNow.Add(-24 * time.Hour)),
		To:   timestamppb.New(migrationNow),
	}
}

// An unbounded scan is rejected here exactly as everywhere else. A panel that offers a
// control producing a guaranteed error teaches analysts the tool is broken.
func TestMigrationRequiresATimeRange(t *testing.T) {
	svc := migrationService(&stubMigrationReader{}, nil)

	if _, err := svc.GetUncovered(context.Background(), &pb.WafMigrationRequest{}); err == nil {
		t.Error("uncovered accepted a request with no time range")
	}
	if _, err := svc.GetReadyToEnforce(
		context.Background(), &pb.WafMigrationRequest{}); err == nil {
		t.Error("ready accepted a request with no time range")
	}
}

func TestUncoveredCarriesEveryCountThrough(t *testing.T) {
	reader := &stubMigrationReader{uncovered: []chdata.WAFUncoveredGroup{{
		Violation:             "Illegal file type",
		RequestHost:           "www.jobs.bg",
		RequestMethod:         "GET",
		Requests:              84,
		Paths:                 60,
		Clients:               67,
		CloudflareAllowlisted: 1,
		FirstSeen:             migrationNow.Add(-20 * time.Hour),
		LastSeen:              migrationNow,
	}}}

	panel, err := migrationService(reader, nil).GetUncovered(
		context.Background(), &pb.WafMigrationRequest{TimeRange: migrationRange()})
	if err != nil {
		t.Fatalf("GetUncovered: %v", err)
	}

	if len(panel.GetGroups()) != 1 {
		t.Fatalf("groups = %d, want 1", len(panel.GetGroups()))
	}
	g := panel.GetGroups()[0]
	if g.GetViolation() != "Illegal file type" || g.GetRequests() != 84 {
		t.Errorf("group = %q/%d, want the violation and count as read", g.GetViolation(), g.GetRequests())
	}
	// The one that is easy to drop and changes the action entirely: an exemption already
	// in place means a new detection rule behind it would do nothing.
	if g.GetCloudflareAllowlisted() != 1 {
		t.Errorf("allowlisted = %d, want 1", g.GetCloudflareAllowlisted())
	}
}

// The host filter is what makes a migration runnable site by site, and it has to reach
// storage rather than be applied to the response.
func TestMigrationPassesTheHostFilterToStorage(t *testing.T) {
	reader := &stubMigrationReader{}
	_, err := migrationService(reader, nil).GetUncovered(
		context.Background(), &pb.WafMigrationRequest{
			TimeRange: migrationRange(), RequestHost: "api.jobs.bg", Limit: 25,
		})
	if err != nil {
		t.Fatalf("GetUncovered: %v", err)
	}

	if reader.gotFilter.RequestHost != "api.jobs.bg" {
		t.Errorf("host filter = %q, want it passed through to storage", reader.gotFilter.RequestHost)
	}
	if reader.gotLimit != 25 {
		t.Errorf("limit = %d, want 25", reader.gotLimit)
	}
}

// The two rule stages read the SAME measurement from opposite ends. Which readings each
// asks for is the whole difference between them, and getting it wrong would show a rule
// as ready to enforce on the false-positive screen.
func TestRuleStagesAskForOppositeReadings(t *testing.T) {
	reader := &stubMigrationReader{}
	svc := migrationService(reader, nil)
	req := &pb.WafMigrationRequest{TimeRange: migrationRange()}

	if _, err := svc.GetReadyToEnforce(context.Background(), req); err != nil {
		t.Fatalf("GetReadyToEnforce: %v", err)
	}
	// Disputed rides along with ready: a rule the vendors half agree on is the case that
	// most needs a person, and it would otherwise appear on no screen at all.
	if len(reader.gotReadings) != 2 ||
		reader.gotReadings[0] != chdata.ReadingReady ||
		reader.gotReadings[1] != chdata.ReadingDisputed {
		t.Errorf("ready stage asked for %v, want ready and disputed", reader.gotReadings)
	}

	if _, err := svc.GetFalsePositives(context.Background(), req); err != nil {
		t.Fatalf("GetFalsePositives: %v", err)
	}
	if len(reader.gotReadings) != 1 || reader.gotReadings[0] != chdata.ReadingFalsePositive {
		t.Errorf("false-positive stage asked for %v, want false_positive alone", reader.gotReadings)
	}
}

// The three F5 counts are the finding. Merging any two of them would make a rule read as
// ready to enforce, or as a false positive, on evidence that says neither.
func TestAgreementKeepsTheThreeF5CountsApart(t *testing.T) {
	reader := &stubMigrationReader{rules: []chdata.WAFRuleAgreement{{
		RuleID:     "23548ee2b36547a1be09bb2c0550c529",
		Action:     "monitored",
		Correlated: 147,
		F5Blocked:  140,
		F5Flagged:  4,
		F5Allowed:  3,
		Hosts:      2,
		Reading:    chdata.ReadingReady,
	}}}
	namer := stubRuleNamer{names: map[string]string{
		"23548ee2b36547a1be09bb2c0550c529": "Block WordPress probes",
	}}

	panel, err := migrationService(reader, namer).GetReadyToEnforce(
		context.Background(), &pb.WafMigrationRequest{TimeRange: migrationRange()})
	if err != nil {
		t.Fatalf("GetReadyToEnforce: %v", err)
	}

	r := panel.GetRules()[0]
	if r.GetF5Blocked() != 140 || r.GetF5Flagged() != 4 || r.GetF5Allowed() != 3 {
		t.Errorf("counts = %d/%d/%d, want 140/4/3 kept separate",
			r.GetF5Blocked(), r.GetF5Flagged(), r.GetF5Allowed())
	}
	if r.GetCorrelated() != 147 {
		t.Errorf("correlated = %d, want the denominator carried through", r.GetCorrelated())
	}
	// A bare id is unreadable in a decision this consequential.
	if r.GetRuleDescription() != "Block WordPress probes" {
		t.Errorf("description = %q, want the rule named", r.GetRuleDescription())
	}
}

// A deployment with no Cloudflare token has no namer. That is a degraded display, not an
// error, and it must not panic.
func TestAgreementWithoutANamerReturnsBareIDs(t *testing.T) {
	reader := &stubMigrationReader{rules: []chdata.WAFRuleAgreement{{RuleID: "abc"}}}

	panel, err := migrationService(reader, nil).GetFalsePositives(
		context.Background(), &pb.WafMigrationRequest{TimeRange: migrationRange()})
	if err != nil {
		t.Fatalf("GetFalsePositives: %v", err)
	}
	if panel.GetRules()[0].GetRuleDescription() != "" {
		t.Error("a rule was described without a resolver")
	}
}

// Without a key this is "every correlated request in the range", which is a search — and
// the search page already does that better.
func TestSamplesRequireAGroupKey(t *testing.T) {
	svc := migrationService(&stubMigrationReader{}, nil)

	_, err := svc.GetMigrationSamples(context.Background(),
		&pb.WafMigrationSampleRequest{TimeRange: migrationRange()})
	if err == nil {
		t.Error("samples were returned for no group at all")
	}
}

// An unrecognised verdict would return nothing, which reads as "no such traffic" rather
// than "that is not a verdict".
func TestSamplesRejectAnUnknownVerdict(t *testing.T) {
	svc := migrationService(&stubMigrationReader{}, nil)

	_, err := svc.GetMigrationSamples(context.Background(), &pb.WafMigrationSampleRequest{
		TimeRange: migrationRange(), RuleId: "abc", F5Verdict: "challenged",
	})
	if err == nil {
		t.Error("an F5 verdict F5 never reports was accepted")
	}

	// The Cloudflare side is validated the same way, for the same reason: an
	// unrecognised value returns nothing, which reads as "no such traffic".
	if _, err := svc.GetMigrationSamples(context.Background(),
		&pb.WafMigrationSampleRequest{
			TimeRange: migrationRange(), RuleId: "abc", CloudflareVerdict: "nonsense",
		}); err == nil {
		t.Error("an unknown Cloudflare verdict was accepted")
	}

	for _, verdict := range []string{"blocked", "monitored", "allowed", ""} {
		if _, err := svc.GetMigrationSamples(context.Background(),
			&pb.WafMigrationSampleRequest{
				TimeRange: migrationRange(), RuleId: "abc", F5Verdict: verdict,
			}); err != nil {
			t.Errorf("verdict %q was rejected: %v", verdict, err)
		}
	}
}

func TestSamplesCarryBothVendorsAndEveryViolation(t *testing.T) {
	reader := &stubMigrationReader{samples: []chdata.WAFMigrationSample{{
		CorrelationID:     "3066ba52-59c3-4e23-ba98-b194b3978126",
		F5EventID:         "f5-event",
		CloudflareEventID: "cf-event",
		EventTime:         migrationNow,
		RequestHost:       "www.jobs.bg",
		RequestPath:       "/306d8a667e8d58.webp",
		F5Verdict:         "blocked",
		F5Violations: []string{
			"Illegal request length", "Illegal URL length", "Illegal file type",
		},
		CloudflareVerdict: "allowed",
		AttackScore:       93,
	}}}

	panel, err := migrationService(reader, nil).GetMigrationSamples(
		context.Background(), &pb.WafMigrationSampleRequest{
			TimeRange: migrationRange(), Violation: "Illegal file type",
			RequestHost: "www.jobs.bg", RequestMethod: "GET", F5Verdict: "blocked",
			CloudflareVerdict: "allowed",
		})
	if err != nil {
		t.Fatalf("GetMigrationSamples: %v", err)
	}

	// Every part of the row that was clicked has to reach storage, or the samples belong
	// to a different group than the counts did.
	want := chdata.WAFMigrationSelector{
		Violation: "Illegal file type", RequestHost: "www.jobs.bg",
		RequestMethod: "GET", F5Verdict: "blocked", CloudflareVerdict: "allowed",
	}
	if reader.gotSelector != want {
		t.Errorf("selector = %+v, want %+v", reader.gotSelector, want)
	}

	s := panel.GetSamples()[0]
	if s.GetF5EventId() != "f5-event" || s.GetCloudflareEventId() != "cf-event" {
		t.Error("both vendor event ids must survive, so either can be opened")
	}
	// A request that tripped three violations is a different case from one that tripped
	// the grouped one alone.
	if len(s.GetF5Violations()) != 3 {
		t.Errorf("violations = %v, want all three", s.GetF5Violations())
	}
	if s.GetAttackScore() != 93 {
		t.Errorf("attack score = %d, want 93", s.GetAttackScore())
	}
}

// A zero address rendered as "::" reads as a real one.
func TestSamplesOmitAnAbsentClientAddress(t *testing.T) {
	reader := &stubMigrationReader{samples: []chdata.WAFMigrationSample{{F5EventID: "e"}}}

	panel, err := migrationService(reader, nil).GetMigrationSamples(
		context.Background(), &pb.WafMigrationSampleRequest{
			TimeRange: migrationRange(), RuleId: "abc",
		})
	if err != nil {
		t.Fatalf("GetMigrationSamples: %v", err)
	}
	if panel.GetSamples()[0].GetClientIp() != "" {
		t.Errorf("client ip = %q, want empty", panel.GetSamples()[0].GetClientIp())
	}
}

// THE BUG THIS PINS. Which rules are migration candidates comes from the rule TABLE, not
// from what happened on a request. A rule in log mode does not decide anything — a later
// skip does — so reading candidacy off the request hid every rule the stage measures.
func TestAgreementTakesCandidatesFromTheRuleTable(t *testing.T) {
	reader := &stubMigrationReader{}
	svc := migrationServiceWith(reader, nil, stubMonitored{actions: map[string]string{
		"rule-b": "log",
		"rule-a": "simulate",
	}})

	if _, err := svc.GetReadyToEnforce(context.Background(),
		&pb.WafMigrationRequest{TimeRange: migrationRange()}); err != nil {
		t.Fatalf("GetReadyToEnforce: %v", err)
	}

	// Sorted, so the same request produces the same query — a slow one stays reproducible
	// and ClickHouse can reuse its cache.
	want := []string{"rule-a", "rule-b"}
	if len(reader.gotCandidates) != 2 ||
		reader.gotCandidates[0] != want[0] || reader.gotCandidates[1] != want[1] {
		t.Errorf("candidates = %v, want %v in order", reader.gotCandidates, want)
	}
}

// The panel reports the rule's CONFIGURED action. Reporting what happened on the requests
// would say `skip` for a rule that only ever logged.
func TestAgreementReportsTheConfiguredAction(t *testing.T) {
	reader := &stubMigrationReader{rules: []chdata.WAFRuleAgreement{{
		RuleID: "abc", Correlated: 40, F5Blocked: 38, Reading: chdata.ReadingReady,
	}}}

	panel, err := migrationService(reader, nil).GetReadyToEnforce(
		context.Background(), &pb.WafMigrationRequest{TimeRange: migrationRange()})
	if err != nil {
		t.Fatalf("GetReadyToEnforce: %v", err)
	}
	if got := panel.GetRules()[0].GetAction(); got != "simulate" {
		t.Errorf("action = %q, want the rule's own configured action", got)
	}
}

// A deployment with no Cloudflare token cannot know which rules are in log mode. An empty
// stage is the honest answer; listing every rule that ever matched would fill the worklist
// with work already finished.
func TestAgreementWithoutAnyMonitoredRulesIsEmpty(t *testing.T) {
	reader := &stubMigrationReader{rules: []chdata.WAFRuleAgreement{{RuleID: "abc"}}}

	for name, monitored := range map[string]MonitoredRuleSource{
		"no source configured": nil,
		"none in log mode":     stubMonitored{actions: map[string]string{}},
	} {
		t.Run(name, func(t *testing.T) {
			svc := migrationServiceWith(reader, nil, monitored)
			panel, err := svc.GetFalsePositives(context.Background(),
				&pb.WafMigrationRequest{TimeRange: migrationRange()})
			if err != nil {
				t.Fatalf("GetFalsePositives: %v", err)
			}
			if len(panel.GetRules()) != 0 {
				t.Errorf("rules = %d, want none", len(panel.GetRules()))
			}
		})
	}
}

// A rule table that cannot be read is an error, not an empty stage: silently showing
// nothing would read as "no rules are waiting to be migrated".
func TestAgreementSurfacesARuleTableFailure(t *testing.T) {
	svc := migrationServiceWith(&stubMigrationReader{}, nil,
		stubMonitored{err: errors.New("clickhouse unavailable")})

	if _, err := svc.GetReadyToEnforce(context.Background(),
		&pb.WafMigrationRequest{TimeRange: migrationRange()}); err == nil {
		t.Error("a failure reading the rule table was reported as an empty stage")
	}
}

// THE OTHER HALF OF CANDIDACY. A managed rule's stored action is its own default, while the
// action that runs comes from a ruleset override — OWASP 949110 reads as `block` in the rule
// table and fires as `log` in production, six times in twenty minutes with F5 on the same
// requests. Reading candidacy from the table alone would hide exactly those, which is this
// change's own blind spot merely moved.
func TestAgreementUnionsConfiguredAndObservedCandidates(t *testing.T) {
	reader := &stubMigrationReader{
		observed: []string{"managed-override", "", "configured-rule"},
		rules: []chdata.WAFRuleAgreement{
			{RuleID: "managed-override", Correlated: 20, F5Blocked: 19},
		},
	}
	svc := migrationServiceWith(reader, nil, stubMonitored{actions: map[string]string{
		"configured-rule": "log",
	}})

	panel, err := svc.GetReadyToEnforce(context.Background(),
		&pb.WafMigrationRequest{TimeRange: migrationRange()})
	if err != nil {
		t.Fatalf("GetReadyToEnforce: %v", err)
	}

	// Both sources, deduplicated, empty ids dropped, sorted for a reproducible query.
	want := []string{"configured-rule", "managed-override"}
	if len(reader.gotCandidates) != 2 ||
		reader.gotCandidates[0] != want[0] || reader.gotCandidates[1] != want[1] {
		t.Errorf("candidates = %v, want %v", reader.gotCandidates, want)
	}

	// A rule known only from the requests has no configured action to report. Blank would
	// read as "no action", so it says how it was found instead.
	if got := panel.GetRules()[0].GetAction(); got != chdata.ActionObservedMonitored {
		t.Errorf("action = %q, want it labelled as observed", got)
	}
}

// Reading the requests for observed candidates can fail on its own, and that is an error
// rather than an empty stage: silently showing nothing reads as "nothing to migrate".
func TestAgreementSurfacesAnObservedLookupFailure(t *testing.T) {
	reader := &stubMigrationReader{observedErr: errors.New("clickhouse unavailable")}
	svc := migrationServiceWith(reader, nil, defaultMonitored())

	if _, err := svc.GetReadyToEnforce(context.Background(),
		&pb.WafMigrationRequest{TimeRange: migrationRange()}); err == nil {
		t.Error("a failure reading observed candidates was reported as an empty stage")
	}
}
