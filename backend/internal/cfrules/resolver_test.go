package cfrules_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/menta2k/siem/internal/cfrules"
	"github.com/menta2k/siem/internal/tenancy"
)

var (
	tenantA = uuid.MustParse("00000000-0000-4000-8000-00000000000a")
	tenantB = uuid.MustParse("00000000-0000-4000-8000-00000000000b")
)

// stubDescriptions answers per tenant, so a cross-tenant leak is detectable rather than
// merely assumed absent.
type stubDescriptions struct {
	byTenant map[uuid.UUID]map[string]string
	calls    int
	err      error
}

func (s *stubDescriptions) DescriptionsFor(
	ctx context.Context, ruleIDs []string,
) (map[string]string, error) {
	s.calls++
	if s.err != nil {
		return nil, s.err
	}

	tenantID, err := tenancy.MustID(ctx)
	if err != nil {
		return nil, err
	}

	out := map[string]string{}
	for _, id := range ruleIDs {
		if name, ok := s.byTenant[tenantID][id]; ok {
			out[id] = name
		}
	}
	return out, nil
}

func ctxFor(tenantID uuid.UUID) context.Context {
	return tenancy.WithTenant(context.Background(), tenancy.Tenant{ID: tenantID, Name: "t"})
}

func TestDescribeNamesWhatItCan(t *testing.T) {
	reader := &stubDescriptions{byTenant: map[uuid.UUID]map[string]string{
		tenantA: {"r1": "SQLi - Body detection"},
	}}
	resolver := cfrules.NewResolver(reader, time.Minute)

	names := resolver.Describe(ctxFor(tenantA), []string{
		"r1",
		"unknown",
	})

	if names["r1"] != "SQLi - Body detection" {
		t.Errorf("names = %+v", names)
	}
	if _, present := names["unknown"]; present {
		t.Errorf("an unknown rule was reported as named: %+v", names)
	}
}

// THE PROPERTY THAT MATTERS. These are one customer's WAF rule names held in a process
// shared by every customer, and every customer is deployed the SAME managed rule ids —
// so a cache keyed on the id alone would hand tenant A's description to tenant B.
func TestTheCacheIsScopedToATenant(t *testing.T) {
	reader := &stubDescriptions{byTenant: map[uuid.UUID]map[string]string{
		tenantA: {"r1": "Tenant A rule"},
		tenantB: {"r1": "Tenant B rule"},
	}}
	resolver := cfrules.NewResolver(reader, time.Minute)

	first := resolver.Describe(ctxFor(tenantA), []string{"r1"})
	second := resolver.Describe(ctxFor(tenantB), []string{"r1"})

	if first["r1"] != "Tenant A rule" {
		t.Errorf("tenant A got %+v", first)
	}
	if second["r1"] != "Tenant B rule" {
		t.Errorf("tenant B got %+v — the cache served another tenant's name", second)
	}
}

// A request with no tenant cannot be answered safely, so it is answered with nothing
// rather than with an unscoped lookup.
func TestDescribeRefusesWithoutATenant(t *testing.T) {
	reader := &stubDescriptions{}
	resolver := cfrules.NewResolver(reader, time.Minute)

	names := resolver.Describe(context.Background(), []string{"r1"})

	if len(names) != 0 {
		t.Errorf("names = %+v, want nothing", names)
	}
	if reader.calls != 0 {
		t.Error("an unscoped lookup reached storage")
	}
}

func TestDescribeAsksStorageOncePerRule(t *testing.T) {
	reader := &stubDescriptions{byTenant: map[uuid.UUID]map[string]string{
		tenantA: {"r1": "SQLi"},
	}}
	resolver := cfrules.NewResolver(reader, time.Minute)
	ctx := ctxFor(tenantA)

	resolver.Describe(ctx, []string{
		"r1", "r1", "r1",
	})
	resolver.Describe(ctx, []string{"r1"})

	if reader.calls != 1 {
		t.Errorf("storage was asked %d times, want 1", reader.calls)
	}
}

// A rule deleted from Cloudflare since the event was logged will never resolve. Without
// caching the miss, every page view asks again for exactly those ids.
func TestDescribeCachesAMiss(t *testing.T) {
	reader := &stubDescriptions{byTenant: map[uuid.UUID]map[string]string{}}
	resolver := cfrules.NewResolver(reader, time.Minute)
	ctx := ctxFor(tenantA)

	resolver.Describe(ctx, []string{"gone"})
	resolver.Describe(ctx, []string{"gone"})

	if reader.calls != 1 {
		t.Errorf("an unresolvable rule was looked up %d times, want 1", reader.calls)
	}
}

// Names are decoration: a storage failure costs the label, never the page.
func TestDescribeDegradesOnFailure(t *testing.T) {
	reader := &stubDescriptions{err: errors.New("clickhouse unreachable")}
	resolver := cfrules.NewResolver(reader, time.Minute)

	names := resolver.Describe(ctxFor(tenantA), []string{"r1"})

	if len(names) != 0 {
		t.Errorf("names = %+v, want nothing rather than an error", names)
	}
}

func TestDescribeIgnoresEmptyIDs(t *testing.T) {
	reader := &stubDescriptions{byTenant: map[uuid.UUID]map[string]string{}}
	resolver := cfrules.NewResolver(reader, time.Minute)

	resolver.Describe(ctxFor(tenantA), []string{""})

	if reader.calls != 0 {
		t.Errorf("an incomplete key reached storage")
	}
}

func TestNilResolverNamesNothing(t *testing.T) {
	var resolver *cfrules.Resolver

	if names := resolver.Describe(ctxFor(tenantA), []string{"r"}); len(names) != 0 {
		t.Errorf("names = %+v, want nothing", names)
	}
}
