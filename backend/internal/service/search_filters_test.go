package service

import (
	"strings"
	"testing"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"

	pb "github.com/menta2k/siem/api/gen/siem/v1"
)

// THE BUG THIS CLASS OF TEST EXISTS FOR. The search service filtered on
// `vendor_event_id`, the console offered it as a field, and the query builder's allowlist
// did not contain it — so every search by an F5 support id failed outright with "unknown
// filter field". A rejected filter fails the whole query rather than being dropped, which
// is the right behaviour and makes the omission total: the feature simply did not work.
//
// The field list is discovered by REFLECTION over the proto rather than written out here.
// A hand-written list would have to be updated by the same person who forgets the
// allowlist, and would have been missing vendor_event_id for exactly the same reason.

// populate fills every scalar field of a filter message with a plausible value, so the
// conditions builder is exercised on all of them at once.
func populate(msg proto.Message) {
	m := msg.ProtoReflect()
	fields := m.Descriptor().Fields()

	for i := 0; i < fields.Len(); i++ {
		f := fields.Get(i)
		switch {
		case f.IsList():
			// Enum lists are the vendor and verdict filters; one member is enough to
			// make the builder render them.
			if f.Kind() == protoreflect.EnumKind {
				list := m.Mutable(f).List()
				list.Append(protoreflect.ValueOfEnum(1))
			}
		case f.Kind() == protoreflect.StringKind:
			m.Set(f, protoreflect.ValueOfString("x"))
		case f.Kind() == protoreflect.Uint32Kind:
			m.Set(f, protoreflect.ValueOfUint32(1))
		case f.Kind() == protoreflect.FloatKind:
			m.Set(f, protoreflect.ValueOfFloat32(1))
		case f.Kind() == protoreflect.BoolKind:
			m.Set(f, protoreflect.ValueOfBool(true))
		}
	}
}

// Every field the events filter carries must resolve to a column. One that does not
// breaks the entire search, not just itself.
func TestEveryEventFilterFieldResolves(t *testing.T) {
	filters := &pb.EventFilters{}
	populate(filters)

	if _, _, err := eventConditions(filters); err != nil {
		t.Fatalf("a populated event filter was rejected: %v\n"+
			"a field the service filters on is missing from query.EventsTable.Columns", err)
	}
}

// The correlated surface has its own table and its own allowlist, so it can drift the
// same way independently. It did not here — identifiers reach it through a separate fixed
// set in EventIDsFor — but nothing except this test would say so.
func TestEveryCorrelatedFilterFieldResolves(t *testing.T) {
	filters := &pb.CorrelatedFilters{}
	populate(filters)

	if _, _, err := correlatedConditions(filters, []string{"event-1"}); err != nil {
		t.Fatalf("a populated correlated filter was rejected: %v\n"+
			"a field the service filters on is missing from query.CorrelatedTable.Columns", err)
	}
}

// The identifier that started it: F5's support_id, which is what a user quotes when they
// report being blocked, and which the console links to from the correlation timeline.
func TestSearchAcceptsAnF5SupportID(t *testing.T) {
	_, args, err := eventConditions(&pb.EventFilters{
		VendorEventId: "2773644994033316544",
	})
	if err != nil {
		t.Fatalf("search by support id was rejected: %v", err)
	}

	var bound bool
	for _, arg := range args {
		if s, ok := arg.(string); ok && s == "2773644994033316544" {
			bound = true
		}
	}
	if !bound {
		t.Error("the support id never reached the query arguments")
	}
}

// The two vendor identifiers mean different things and both have to be filterable:
// vendor_request_id is the id SHARED between vendors, vendor_event_id is the vendor's own
// reference. Resolving one to the other's column would answer a different question.
func TestVendorIdentifiersAreDistinct(t *testing.T) {
	sql, _, err := eventConditions(&pb.EventFilters{
		VendorRequestId: "ray-1",
		VendorEventId:   "support-1",
	})
	if err != nil {
		t.Fatalf("eventConditions: %v", err)
	}

	if !strings.Contains(sql, "vendor_request_id") || !strings.Contains(sql, "vendor_event_id") {
		t.Errorf("both identifiers must appear in the SQL, got: %s", sql)
	}
}
