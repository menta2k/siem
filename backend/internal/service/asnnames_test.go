package service

import (
	"context"
	"testing"

	pb "github.com/menta2k/siem/api/gen/siem/v1"
)

// stubNamer records what it was asked, so a test can assert that one page costs one
// lookup rather than one per row.
type stubNamer struct {
	names map[uint32]string
	calls int
	asked []uint32
}

func (s *stubNamer) Names(_ context.Context, asns []uint32) map[uint32]string {
	s.calls++
	s.asked = append(s.asked, asns...)

	out := map[uint32]string{}
	for _, asn := range asns {
		if name, ok := s.names[asn]; ok {
			out[asn] = name
		}
	}
	return out
}

func TestNameClientsLabelsWhatItCanAndLeavesTheRest(t *testing.T) {
	namer := &stubNamer{names: map[uint32]string{8866: "VIVACOM-AS"}}
	clients := []*pb.ClientInfo{
		{Asn: 8866},
		{Asn: 64512}, // not in the published table
		{Asn: 0},     // no vendor reported a network
	}

	nameClients(context.Background(), namer, clients...)

	if clients[0].GetAsnOwner() != "VIVACOM-AS" {
		t.Errorf("asn_owner = %q, want VIVACOM-AS", clients[0].GetAsnOwner())
	}
	if clients[1].GetAsnOwner() != "" {
		t.Errorf("an unlisted network was named %q", clients[1].GetAsnOwner())
	}
	if clients[2].GetAsnOwner() != "" {
		t.Errorf("AS0 was named %q", clients[2].GetAsnOwner())
	}
}

// A page of results is dominated by a handful of networks. Resolving per row would turn
// one query into one per result.
func TestNameClientsResolvesAWholePageInOneLookup(t *testing.T) {
	namer := &stubNamer{names: map[uint32]string{8866: "VIVACOM-AS"}}
	clients := make([]*pb.ClientInfo, 0, 50)
	for range 50 {
		clients = append(clients, &pb.ClientInfo{Asn: 8866})
	}

	nameClients(context.Background(), namer, clients...)

	if namer.calls != 1 {
		t.Errorf("the namer was called %d times for one page, want 1", namer.calls)
	}
	for i, client := range clients {
		if client.GetAsnOwner() != "VIVACOM-AS" {
			t.Fatalf("row %d was left unnamed", i)
		}
	}
}

// A deployment may run with the lookup switched off entirely. That must cost the label,
// not the response.
func TestNameClientsIsANoOpWithoutANamer(t *testing.T) {
	clients := []*pb.ClientInfo{{Asn: 8866}}

	nameClients(context.Background(), nil, clients...)

	if clients[0].GetAsnOwner() != "" {
		t.Errorf("asn_owner = %q, want empty", clients[0].GetAsnOwner())
	}
}

// Nothing to resolve must not reach storage at all.
func TestNameClientsSkipsStorageWhenNoRowHasANetwork(t *testing.T) {
	namer := &stubNamer{names: map[uint32]string{}}

	nameClients(context.Background(), namer, &pb.ClientInfo{Asn: 0}, &pb.ClientInfo{})

	if namer.calls != 0 {
		t.Errorf("the namer was called %d times with nothing to name", namer.calls)
	}
}
