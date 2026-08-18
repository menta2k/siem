package service

import (
	"context"
	"math"
	"time"

	"github.com/google/uuid"
	"google.golang.org/protobuf/types/known/timestamppb"

	pb "github.com/menta2k/siem/api/gen/siem/v1"
	chdata "github.com/menta2k/siem/internal/data/clickhouse"
	mw "github.com/menta2k/siem/internal/middleware"
	"github.com/menta2k/siem/internal/query"
	"github.com/menta2k/siem/internal/vendors"
)

// PanelReader is the rollup surface the dashboards read.
type PanelReader interface {
	VendorVolume(ctx context.Context, q chdata.DashboardQuery) ([]chdata.VolumePoint, error)
	VerdictMix(ctx context.Context, q chdata.DashboardQuery) ([]chdata.VerdictPoint, error)
	TopRules(ctx context.Context, q chdata.DashboardQuery) ([]chdata.RuleCount, error)
	TopSources(ctx context.Context, q chdata.DashboardQuery) ([]chdata.SourceCount, error)
	TopASNs(ctx context.Context, q chdata.DashboardQuery) ([]chdata.ASNCount, error)
	Disagreements(ctx context.Context, q chdata.DashboardQuery) ([]chdata.DisagreementPoint, error)
}

// StorageReader reports what the platform has written to disk.
type StorageReader interface {
	Read(ctx context.Context) (chdata.Storage, error)
}

// FeedHealthReader supplies the health tiles.
type FeedHealthReader interface {
	ListFeedHealth(ctx context.Context) (map[uuid.UUID]chdata.FeedHealth, error)
}

// CorrelationHealthReader reports whether correlation is still running.
type CorrelationHealthReader interface {
	GetCorrelationHealth(ctx context.Context) (chdata.CorrelationHealth, error)
}

// DashboardsService implements the Dashboards proto service.
type DashboardsService struct {
	panels  PanelReader
	feeds   *chdata.FeedRepo
	health  FeedHealthReader
	limits  query.Limits
	storage StorageReader
	// rules names the WAF rule the top-rules panel ranks.
	rules RuleNamer
	// networks names the ASNs the source panels rank. Optional: nil where the lookup is
	// disabled, in which case the panels show bare numbers.
	networks NetworkNamer
	// correlation reports the pipeline's own health. Optional: nil on a deployment
	// whose processor predates the health table, where the panel reports that it has
	// nothing to say rather than failing the page.
	correlation CorrelationHealthReader
	now         func() time.Time
}

// NewDashboardsService constructs the service.
func NewDashboardsService(
	panels PanelReader, feeds *chdata.FeedRepo, health FeedHealthReader,
	limits query.Limits, networks NetworkNamer, storage StorageReader, rules RuleNamer,
	correlation CorrelationHealthReader,
) *DashboardsService {
	return &DashboardsService{
		panels: panels, feeds: feeds, health: health, limits: limits,
		networks: networks, storage: storage, rules: rules,
		correlation: correlation, now: time.Now,
	}
}

// GetStorage reports disk headroom and how long it lasts at the measured write rate.
//
// Takes no time range, unlike every other panel here, and ignores the one it is sent:
// this describes what is on disk NOW. A range would suggest the answer could be asked
// about last week, which the parts on disk cannot say — they hold what survived
// retention, not what once existed.
func (s *DashboardsService) GetStorage(
	ctx context.Context, _ *pb.DashboardRequest,
) (*pb.StoragePanel, error) {
	ctx, cancel := s.limits.WithTimeout(ctx)
	defer cancel()

	storage, err := s.storage.Read(ctx)
	if err != nil {
		return nil, query.TranslateError(err)
	}

	projection := project(storage, s.now())

	out := &pb.StoragePanel{
		DiskTotalBytes: storage.DiskTotalBytes,
		DiskFreeBytes:  storage.DiskFreeBytes,
		DatabaseBytes:  storage.DatabaseBytes,
		BytesPerDay:    projection.BytesPerDay,
		MeasuredDays:   clampToUint32(projection.MeasuredDays),
		DaysRemaining:  projection.DaysRemaining,
		Steady:         projection.Steady,
		Tables:         make([]*pb.TableSize, 0, len(storage.Tables)),
	}
	for _, table := range storage.Tables {
		out.Tables = append(out.Tables, &pb.TableSize{
			Table: table.Table, Bytes: table.Bytes, Rows: table.Rows,
		})
	}
	return out, nil
}

// GetOverview returns volume and verdict mix for the shared range.
func (s *DashboardsService) GetOverview(
	ctx context.Context, req *pb.DashboardRequest,
) (*pb.OverviewPanel, error) {
	q, err := s.dashboardQuery(req)
	if err != nil {
		return nil, err
	}

	ctx, cancel := s.limits.WithTimeout(ctx)
	defer cancel()

	volume, err := s.panels.VendorVolume(ctx, q)
	if err != nil {
		return nil, query.TranslateError(err)
	}
	verdicts, err := s.panels.VerdictMix(ctx, q)
	if err != nil {
		return nil, query.TranslateError(err)
	}

	out := &pb.OverviewPanel{
		Volume:   make([]*pb.VolumePoint, 0, len(volume)),
		Verdicts: make([]*pb.VerdictPoint, 0, len(verdicts)),
	}
	for _, p := range volume {
		out.Volume = append(out.Volume, &pb.VolumePoint{
			Bucket: timestamppb.New(p.Bucket),
			Vendor: vendorToProto(p.Vendor),
			Events: p.Events,
		})
		// Summed server-side so the headline figure and the series cannot disagree.
		// Leaving the client to re-sum invites two numbers on one screen that differ.
		out.TotalEvents += p.Events
	}
	for _, p := range verdicts {
		out.Verdicts = append(out.Verdicts, &pb.VerdictPoint{
			Bucket:  timestamppb.New(p.Bucket),
			Vendor:  vendorToProto(p.Vendor),
			Verdict: verdictToProto(p.Verdict),
			Events:  p.Events,
		})
		switch p.Verdict {
		case vendors.VerdictBlocked, vendors.VerdictRateLimited:
			out.TotalBlocked += p.Events
		case vendors.VerdictChallenged:
			out.TotalChallenged += p.Events
		}
	}
	return out, nil
}

// GetRules returns the most frequently triggered rules.
func (s *DashboardsService) GetRules(
	ctx context.Context, req *pb.DashboardRequest,
) (*pb.RulesPanel, error) {
	q, err := s.dashboardQuery(req)
	if err != nil {
		return nil, err
	}

	ctx, cancel := s.limits.WithTimeout(ctx)
	defer cancel()

	rules, err := s.panels.TopRules(ctx, q)
	if err != nil {
		return nil, query.TranslateError(err)
	}

	out := &pb.RulesPanel{Rules: make([]*pb.RuleCount, 0, len(rules))}
	for _, r := range rules {
		out.Rules = append(out.Rules, &pb.RuleCount{
			Vendor: vendorToProto(r.Vendor), RuleId: r.RuleID, Events: r.Events,
		})
	}
	// A ranking of opaque ids is the least useful form of a top-ten list.
	describeRuleCounts(ctx, s.rules, out.Rules)
	return out, nil
}

// GetSources returns the busiest client addresses.
func (s *DashboardsService) GetSources(
	ctx context.Context, req *pb.DashboardRequest,
) (*pb.SourcesPanel, error) {
	q, err := s.dashboardQuery(req)
	if err != nil {
		return nil, err
	}

	ctx, cancel := s.limits.WithTimeout(ctx)
	defer cancel()

	sources, err := s.panels.TopSources(ctx, q)
	if err != nil {
		return nil, query.TranslateError(err)
	}
	// Fetched alongside the addresses because they answer the same question at two
	// scales, and a distributed source is invisible at the address scale.
	asns, err := s.panels.TopASNs(ctx, q)
	if err != nil {
		return nil, query.TranslateError(err)
	}

	out := &pb.SourcesPanel{
		Sources: make([]*pb.SourceCount, 0, len(sources)),
		Asns:    make([]*pb.AsnCount, 0, len(asns)),
	}
	for _, s := range sources {
		source := &pb.SourceCount{
			Country: s.Country, Asn: s.ASN, Events: s.Events, Blocked: s.Blocked,
		}
		if s.ClientIP != nil {
			source.ClientIp = s.ClientIP.String()
		}
		out.Sources = append(out.Sources, source)
	}
	for _, a := range asns {
		out.Asns = append(out.Asns, &pb.AsnCount{
			Asn: a.ASN, Country: a.Country, Events: a.Events,
			Blocked: a.Blocked, Clients: a.Clients,
		})
	}

	// Both tables name their networks from ONE lookup. The two panels rank the same
	// traffic at different scales, so they overlap heavily — resolving them separately
	// would ask for most of the same numbers twice.
	s.nameNetworks(ctx, out)
	return out, nil
}

// nameNetworks fills in the owner name on both source panels.
func (s *DashboardsService) nameNetworks(ctx context.Context, panel *pb.SourcesPanel) {
	if s.networks == nil {
		return
	}

	asns := make([]uint32, 0, len(panel.GetSources())+len(panel.GetAsns()))
	for _, source := range panel.GetSources() {
		if source.GetAsn() != 0 {
			asns = append(asns, source.GetAsn())
		}
	}
	for _, network := range panel.GetAsns() {
		asns = append(asns, network.GetAsn())
	}
	if len(asns) == 0 {
		return
	}

	names := s.networks.Names(ctx, asns)
	for _, source := range panel.GetSources() {
		source.AsnOwner = names[source.GetAsn()]
	}
	for _, network := range panel.GetAsns() {
		network.Owner = names[network.GetAsn()]
	}
}

// clampToUint32 saturates rather than wrapping. The count is a day tally that cannot
// realistically overflow, but a conversion that CAN wrap is worth closing rather than
// arguing about: a negative or enormous "measured days" would make the panel's caveat
// read as its headline.
func clampToUint32(n int) uint32 {
	switch {
	case n < 0:
		return 0
	case n > math.MaxUint32:
		return math.MaxUint32
	default:
		return uint32(n)
	}
}

// GetDisagreements returns the disagreement rate and breakdown.
func (s *DashboardsService) GetDisagreements(
	ctx context.Context, req *pb.DashboardRequest,
) (*pb.DisagreementsPanel, error) {
	q, err := s.dashboardQuery(req)
	if err != nil {
		return nil, err
	}

	ctx, cancel := s.limits.WithTimeout(ctx)
	defer cancel()

	points, err := s.panels.Disagreements(ctx, q)
	if err != nil {
		return nil, query.TranslateError(err)
	}

	out := &pb.DisagreementsPanel{Points: make([]*pb.DisagreementPoint, 0, len(points))}
	seenTotals := map[int64]uint64{}
	for _, p := range points {
		out.Points = append(out.Points, &pb.DisagreementPoint{
			Bucket:  timestamppb.New(p.Bucket),
			Kind:    disagreementToProto(p.Kind),
			Records: p.Records,
			Total:   p.Total,
		})
		out.TotalDisagreements += p.Records
		// The denominator is per BUCKET and repeats across that bucket's kinds. Summing
		// it directly would multiply the total by the number of kinds present and make
		// the disagreement rate look several times smaller than it is.
		seenTotals[p.Bucket.Unix()] = max(seenTotals[p.Bucket.Unix()], p.Total)
	}
	for _, total := range seenTotals {
		out.TotalRecords += total
	}
	return out, nil
}

// GetFeedHealthPanel returns the per-feed health tiles.
func (s *DashboardsService) GetFeedHealthPanel(
	ctx context.Context, _ *pb.DashboardRequest,
) (*pb.FeedHealthPanel, error) {
	feeds, err := s.feeds.List(ctx)
	if err != nil {
		return nil, mw.Internal().WithCause(err)
	}

	health, err := s.health.ListFeedHealth(ctx)
	if err != nil {
		return nil, mw.Internal().WithCause(err)
	}

	out := &pb.FeedHealthPanel{Feeds: make([]*pb.FeedHealth, 0, len(feeds))}
	for _, feed := range feeds {
		out.Feeds = append(out.Feeds, toHealthProto(feed.ID, health[feed.ID]))
	}
	return out, nil
}

// dashboardQuery validates the shared range and interval.
func (s *DashboardsService) dashboardQuery(
	req *pb.DashboardRequest,
) (chdata.DashboardQuery, error) {
	r := req.GetTimeRange()
	if r == nil {
		return chdata.DashboardQuery{}, mw.TimeRangeRequired()
	}

	var from, to time.Time
	if r.GetFrom() != nil {
		from = r.GetFrom().AsTime()
	}
	if r.GetTo() != nil {
		to = r.GetTo().AsTime()
	}

	rng, err := s.limits.Range(from, to, s.now())
	if err != nil {
		return chdata.DashboardQuery{}, err
	}

	interval, err := intervalFromProto(req.GetInterval())
	if err != nil {
		return chdata.DashboardQuery{}, err
	}

	return chdata.DashboardQuery{
		Range: rng, Interval: interval, Limit: int(req.GetLimit()),
	}, nil
}

// intervalFromProto maps the enum to a bucket width.
//
// Unspecified defaults rather than failing: a client that omits the interval wants a
// chart, not an error, and every panel then agrees on the same default.
func intervalFromProto(interval pb.BucketInterval) (chdata.Interval, error) {
	switch interval {
	case pb.BucketInterval_BUCKET_INTERVAL_5M:
		return chdata.Interval5m, nil
	case pb.BucketInterval_BUCKET_INTERVAL_1H, pb.BucketInterval_BUCKET_INTERVAL_UNSPECIFIED:
		return chdata.Interval1h, nil
	case pb.BucketInterval_BUCKET_INTERVAL_1D:
		return chdata.Interval1d, nil
	default:
		return "", mw.ValidationFailed("unsupported dashboard interval")
	}
}

// GetCorrelationHealth reports whether the correlation pipeline is still running.
//
// Takes no time range and ignores the one it is sent, like GetStorage: the question is
// "is this working NOW", and a range would suggest it could be asked about last week —
// which the counters can answer but nobody needs, and which would let a stale range
// hide a live outage behind a healthy afternoon.
func (s *DashboardsService) GetCorrelationHealth(
	ctx context.Context, _ *pb.DashboardRequest,
) (*pb.CorrelationHealth, error) {
	if s.correlation == nil {
		// Nothing has ever written the table. Reported as idle with an empty window
		// rather than as an error, because a page that fails to load says far less
		// than a panel that says it does not know yet.
		return &pb.CorrelationHealth{Status: string(chdata.CorrelationIdle)}, nil
	}

	ctx, cancel := s.limits.WithTimeout(ctx)
	defer cancel()

	health, err := s.correlation.GetCorrelationHealth(ctx)
	if err != nil {
		return nil, query.TranslateError(err)
	}
	return toCorrelationHealthProto(health), nil
}

// toCorrelationHealthProto maps the read model, deriving the status on the SERVER.
//
// The console could compute it from the counters it is sent, and then two places would
// decide what "losing data" means and drift apart the first time one of them was
// edited.
func toCorrelationHealthProto(health chdata.CorrelationHealth) *pb.CorrelationHealth {
	out := &pb.CorrelationHealth{
		Status:              string(health.Status()),
		EventsFiled:         health.EventsFiled,
		WindowsClosed:       health.WindowsClosed,
		RecordsEmitted:      health.RecordsEmitted,
		WindowsDroppedEmpty: health.WindowsDroppedEmpty,
		CloseFailures:       health.CloseFailures,
		WindowsDue:          health.WindowsDue,
		ClaimLagMs:          uint64(health.ClaimLag.Milliseconds()),  //nolint:gosec // non-negative
		WindowTtlMs:         uint64(health.WindowTTL.Milliseconds()), //nolint:gosec // non-negative
	}
	if !health.Since.IsZero() {
		out.Since = timestamppb.New(health.Since)
	}
	// Left unset when nothing has ever been emitted, so the console can say "never"
	// rather than rendering the zero time as 1970.
	if !health.LastRecordAt.IsZero() {
		out.LastRecordAt = timestamppb.New(health.LastRecordAt)
	}
	return out
}
