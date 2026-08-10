// Package asnowner resolves an AS number to the network that owns it.
//
// An ASN identifies a network without naming it. "AS8866" is not something an analyst
// can act on; "AS8866 VIVACOM-AS" says whether the traffic came from a residential ISP
// or a hosting provider, which is usually the whole question when a network appears at
// the top of a panel with a high block rate.
//
// The data comes from iptoasn.com, published under PDDL v1.0 (public domain) and rebuilt
// hourly from the RIR allocations. Only the AS number and its description are kept: the
// events already carry the ASN, so the address ranges have nothing to contribute here.
package asnowner

import (
	"bufio"
	"compress/gzip"
	"fmt"
	"io"
	"strconv"
	"strings"
)

// Owner is one network's registry entry.
type Owner struct {
	ASN uint32
	// Name is the AS description verbatim, e.g. "VIVACOM-AS".
	Name string
	// Country is where the AS is REGISTERED, which is not where its traffic comes from.
	// A carrier registered in the US routes traffic from everywhere.
	Country string
}

// Limits bound what a download may cost before it is abandoned.
//
// Both are needed, and the second is the one that matters: gzip expands, so a small
// response can decompress into an unbounded stream. The published file is ~5 MB
// compressed and ~130 MB expanded, and these leave room for it to grow several times
// over while still refusing something that never ends.
const (
	MaxCompressedBytes   = 64 << 20  // 64 MiB
	MaxDecompressedBytes = 512 << 20 // 512 MiB
)

// notRouted marks ranges the registry knows about but nobody announces. They carry AS 0
// and a placeholder description, and keeping them would put a meaningless "Not routed"
// entry in the table for an ASN no event can ever report.
const notRouted = "Not routed"

// Parse reads the iptoasn TSV and returns one entry per AS number.
//
// The published format is five tab-separated columns:
//
//	range_start  range_end  as_number  country_code  as_description
//
// The file is ADDRESS RANGES, so one AS appears on many lines — around 500,000 lines
// reduce to roughly 90,000 networks. The first description for an AS wins; they are
// identical across that AS's ranges in practice, and picking a later one would make the
// result depend on file order for no benefit.
//
// A malformed line is SKIPPED rather than failing the import. This is a third-party file
// fetched over the network: refusing the whole 500,000-line download because one line
// gained a column would mean the panel loses every name over a single upstream typo.
func Parse(r io.Reader) ([]Owner, error) {
	scanner := bufio.NewScanner(io.LimitReader(r, MaxDecompressedBytes))
	// The default 64 KiB token limit is ample for a five-column line, but a truncated
	// download can present the tail as one enormous line; this caps that explicitly.
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)

	seen := make(map[uint32]struct{}, 128_000)
	owners := make([]Owner, 0, 128_000)

	for scanner.Scan() {
		owner, ok := parseLine(scanner.Text())
		if !ok {
			continue
		}
		if _, duplicate := seen[owner.ASN]; duplicate {
			continue
		}
		seen[owner.ASN] = struct{}{}
		owners = append(owners, owner)
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read asn table: %w", err)
	}
	return owners, nil
}

// parseLine turns one TSV line into an entry, reporting whether it is usable.
func parseLine(line string) (Owner, bool) {
	fields := strings.Split(line, "\t")
	if len(fields) < 5 {
		return Owner{}, false
	}

	number, err := strconv.ParseUint(strings.TrimSpace(fields[2]), 10, 32)
	if err != nil || number == 0 {
		return Owner{}, false
	}

	name := strings.TrimSpace(fields[4])
	if name == "" || name == notRouted {
		return Owner{}, false
	}

	return Owner{
		ASN:     uint32(number),
		Name:    name,
		Country: strings.ToUpper(strings.TrimSpace(fields[3])),
	}, true
}

// ParseGzip decompresses the published file and parses it.
func ParseGzip(r io.Reader) ([]Owner, error) {
	gz, err := gzip.NewReader(io.LimitReader(r, MaxCompressedBytes))
	if err != nil {
		return nil, fmt.Errorf("open gzip stream: %w", err)
	}
	defer func() { _ = gz.Close() }()

	return Parse(gz)
}
