package service

import (
	"context"

	pb "github.com/menta2k/siem/api/gen/siem/v1"
	"github.com/menta2k/siem/internal/asnowner"
)

// NetworkNamer resolves AS numbers to the networks that own them.
//
// An interface rather than the concrete resolver so a service can be constructed
// without one — a deployment with the lookup disabled passes nil, and every call below
// degrades to leaving the name empty.
type NetworkNamer interface {
	Names(ctx context.Context, asns []uint32) map[uint32]string
}

// Compile-time proof that the resolver satisfies what the services need.
var _ NetworkNamer = (*asnowner.Resolver)(nil)

// nameClients fills in the owner name on every client block of one response.
//
// Done as a PASS OVER THE BUILT RESPONSE rather than inside each builder, for two
// reasons. The builders are pure projections with no context to pass a lookup through,
// and a whole page of results resolves in ONE call here — the same network appears on
// most rows of a search, and resolving per row would turn one query into fifty.
func nameClients(ctx context.Context, namer NetworkNamer, clients ...*pb.ClientInfo) {
	if namer == nil || len(clients) == 0 {
		return
	}

	asns := make([]uint32, 0, len(clients))
	for _, client := range clients {
		if client.GetAsn() != 0 {
			asns = append(asns, client.GetAsn())
		}
	}
	if len(asns) == 0 {
		return
	}

	names := namer.Names(ctx, asns)
	for _, client := range clients {
		if name, ok := names[client.GetAsn()]; ok {
			client.AsnOwner = name
		}
	}
}

// clientsOf collects the client blocks of a page of event summaries.
func clientsOf(items []*pb.EventSummary) []*pb.ClientInfo {
	clients := make([]*pb.ClientInfo, 0, len(items))
	for _, item := range items {
		if item.GetClient() != nil {
			clients = append(clients, item.Client)
		}
	}
	return clients
}

// correlatedClientsOf collects the client blocks of a page of correlated records.
//
// The same page appears from two entry points — the correlated search and the plain
// listing — and both name their networks from one lookup.
func correlatedClientsOf(items []*pb.CorrelatedRequest) []*pb.ClientInfo {
	clients := make([]*pb.ClientInfo, 0, len(items))
	for _, item := range items {
		if item.GetClient() != nil {
			clients = append(clients, item.Client)
		}
	}
	return clients
}
