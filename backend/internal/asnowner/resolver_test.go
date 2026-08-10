package asnowner_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/menta2k/siem/internal/asnowner"
)

// stubReader counts lookups so the tests can assert on what reached storage.
type stubReader struct {
	names map[uint32]string
	calls int
	asked [][]uint32
	err   error
}

func (s *stubReader) NamesFor(_ context.Context, asns []uint32) (map[uint32]string, error) {
	s.calls++
	s.asked = append(s.asked, asns)
	if s.err != nil {
		return nil, s.err
	}

	out := map[uint32]string{}
	for _, asn := range asns {
		if name, ok := s.names[asn]; ok {
			out[asn] = name
		}
	}
	return out, nil
}

func TestResolverNamesWhatItCan(t *testing.T) {
	reader := &stubReader{names: map[uint32]string{8866: "VIVACOM-AS", 13335: "CLOUDFLARENET"}}
	resolver := asnowner.NewResolver(reader, time.Hour)

	names := resolver.Names(context.Background(), []uint32{8866, 13335, 64512})

	if names[8866] != "VIVACOM-AS" || names[13335] != "CLOUDFLARENET" {
		t.Errorf("names = %+v, want both known networks", names)
	}
	// Unknown networks are absent rather than present-and-empty, so a caller can test
	// for the name without also testing for the empty string.
	if _, present := names[64512]; present {
		t.Errorf("an unknown ASN was reported as named: %+v", names)
	}
}

// A panel repeats the same network across rows, and a page is loaded repeatedly. Both
// must cost one lookup.
func TestResolverAsksStorageOncePerNetwork(t *testing.T) {
	reader := &stubReader{names: map[uint32]string{8866: "VIVACOM-AS"}}
	resolver := asnowner.NewResolver(reader, time.Hour)
	ctx := context.Background()

	resolver.Names(ctx, []uint32{8866, 8866, 8866})
	resolver.Names(ctx, []uint32{8866})
	resolver.Name(ctx, 8866)

	if reader.calls != 1 {
		t.Errorf("storage was asked %d times, want 1: %v", reader.calls, reader.asked)
	}
	if len(reader.asked[0]) != 1 {
		t.Errorf("the repeated ASN was requested %d times in one call", len(reader.asked[0]))
	}
}

// Most unnamed networks stay unnamed. Without caching the miss, every page view
// re-queries for exactly the ASNs that will never resolve.
func TestResolverCachesAMissToo(t *testing.T) {
	reader := &stubReader{names: map[uint32]string{}}
	resolver := asnowner.NewResolver(reader, time.Hour)
	ctx := context.Background()

	resolver.Names(ctx, []uint32{64512})
	resolver.Names(ctx, []uint32{64512})

	if reader.calls != 1 {
		t.Errorf("an unresolvable ASN was looked up %d times, want 1", reader.calls)
	}
}

// Names are decoration. A storage failure must cost the label, never the panel.
func TestResolverDegradesToNoNameOnFailure(t *testing.T) {
	reader := &stubReader{err: errors.New("clickhouse unreachable")}
	resolver := asnowner.NewResolver(reader, time.Hour)

	names := resolver.Names(context.Background(), []uint32{8866})

	if len(names) != 0 {
		t.Errorf("names = %+v, want nothing rather than an error", names)
	}
	if got := resolver.Name(context.Background(), 8866); got != "" {
		t.Errorf("Name() = %q, want empty", got)
	}
}

// AS 0 means "no vendor reported a network". It is not a network to look up.
func TestResolverIgnoresTheZeroASN(t *testing.T) {
	reader := &stubReader{names: map[uint32]string{}}
	resolver := asnowner.NewResolver(reader, time.Hour)
	ctx := context.Background()

	if got := resolver.Name(ctx, 0); got != "" {
		t.Errorf("Name(0) = %q, want empty", got)
	}
	resolver.Names(ctx, []uint32{0})

	if reader.calls != 0 {
		t.Errorf("AS0 reached storage %d times", reader.calls)
	}
}

func TestResolverRefetchesOnceTheEntryHasAged(t *testing.T) {
	reader := &stubReader{names: map[uint32]string{8866: "VIVACOM-AS"}}
	// A TTL short enough to expire within the test, exercising the same path an hour
	// would in production.
	resolver := asnowner.NewResolver(reader, time.Millisecond)
	ctx := context.Background()

	resolver.Names(ctx, []uint32{8866})
	time.Sleep(5 * time.Millisecond)
	resolver.Names(ctx, []uint32{8866})

	if reader.calls != 2 {
		t.Errorf("storage was asked %d times, want 2 — the entry should have aged out",
			reader.calls)
	}
}

// The read paths hold a resolver that a deployment may have switched off, so the nil
// case has to be a no-op rather than a panic on the request path.
func TestNilResolverNamesNothing(t *testing.T) {
	var resolver *asnowner.Resolver

	if names := resolver.Names(context.Background(), []uint32{8866}); len(names) != 0 {
		t.Errorf("names = %+v, want nothing", names)
	}
}
