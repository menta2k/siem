// Command gen builds the embedded BIG-IP ASM catalogue from a pair of iControl REST
// dumps.
//
// The dumps are what a BIG-IP returns verbatim:
//
//	curl -sku admin: 'https://<bigip>/mgmt/tm/asm/violations'            > violations.json
//	curl -sku admin: 'https://<bigip>/mgmt/tm/asm/signatures?$top=10000' > signatures.json
//
// They are NOT committed. Together they are 22 MiB of which the platform displays a
// tenth: every signature carries a dozen matchesWithin* booleans, a systems array and
// two self-links that exist to serve the BIG-IP's own UI. Trimming to the displayed
// fields and gzipping takes the pair to ~270 KiB, which is small enough to embed and
// therefore small enough to need no migration, no import step and no way to be missing
// in one environment and present in another.
//
// Run it from the repository root:
//
//	go run ./internal/f5catalog/gen \
//	  -violations violations.json -signatures signatures.json \
//	  -out internal/f5catalog/catalog.json.gz
package main

import (
	"compress/gzip"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/menta2k/siem/internal/f5catalog"
)

// bigipViolations is the shape of the violations dump, narrowed to what is read.
type bigipViolations struct {
	Items []struct {
		Name        string `json:"name"`
		Title       string `json:"title"`
		Severity    string `json:"severity"`
		Description string `json:"description"`
		Risk        string `json:"risk"`
		Examples    string `json:"examples"`
		Type        string `json:"type"`
		AttackType  struct {
			Name string `json:"name"`
		} `json:"attackTypeReference"`
	} `json:"items"`
}

// bigipSignatures is the shape of the signatures dump, narrowed to what is read.
type bigipSignatures struct {
	Items []struct {
		SignatureID   uint64 `json:"signatureId"`
		Name          string `json:"name"`
		Description   string `json:"description"`
		Accuracy      string `json:"accuracy"`
		Risk          string `json:"risk"`
		SignatureType string `json:"signatureType"`
		HasCVE        bool   `json:"hasCve"`
		IsUserDefined bool   `json:"isUserDefined"`
		AttackType    struct {
			Name string `json:"name"`
		} `json:"attackTypeReference"`
		References []struct {
			Value string `json:"value"`
			Type  string `json:"type"`
		} `json:"references"`
	} `json:"items"`
}

func main() {
	violationsPath := flag.String("violations", "violations.json", "BIG-IP violations dump")
	signaturesPath := flag.String("signatures", "signatures.json", "BIG-IP signatures dump")
	outPath := flag.String("out", "internal/f5catalog/catalog.json.gz", "embedded catalogue")
	flag.Parse()

	catalog, err := build(*violationsPath, *signaturesPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "build catalogue: %v\n", err)
		os.Exit(1)
	}
	if err := write(*outPath, catalog); err != nil {
		fmt.Fprintf(os.Stderr, "write catalogue: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("wrote %s: %d violations, %d signatures\n",
		*outPath, len(catalog.Violations), len(catalog.Signatures))
}

func build(violationsPath, signaturesPath string) (f5catalog.Catalog, error) {
	var violations bigipViolations
	if err := readJSON(violationsPath, &violations); err != nil {
		return f5catalog.Catalog{}, err
	}
	var signatures bigipSignatures
	if err := readJSON(signaturesPath, &signatures); err != nil {
		return f5catalog.Catalog{}, err
	}

	catalog := f5catalog.Catalog{
		Violations: toViolations(violations),
		Signatures: toSignatures(signatures),
	}

	// Sorted so the generated file is byte-identical for identical input. A generator
	// whose output depends on map iteration order produces a diff on every run and
	// teaches reviewers to skip it.
	sort.Slice(catalog.Violations, func(i, j int) bool {
		return catalog.Violations[i].Title < catalog.Violations[j].Title
	})
	sort.Slice(catalog.Signatures, func(i, j int) bool {
		return catalog.Signatures[i].ID < catalog.Signatures[j].ID
	})

	return catalog, nil
}

func toViolations(dump bigipViolations) []f5catalog.Violation {
	out := make([]f5catalog.Violation, 0, len(dump.Items))
	for _, v := range dump.Items {
		// The TITLE is the join key, because that is what ASM writes into the
		// violations field of a log record — "Illegal file type", not VIOL_FILETYPE.
		// A violation with no title cannot be matched to anything and is dropped.
		if v.Title == "" {
			continue
		}
		out = append(out, f5catalog.Violation{
			Name:        v.Name,
			Title:       v.Title,
			Severity:    v.Severity,
			AttackType:  v.AttackType.Name,
			Type:        v.Type,
			Description: clean(v.Description),
			Risk:        clean(v.Risk),
			Examples:    clean(v.Examples),
		})
	}
	return out
}

func toSignatures(dump bigipSignatures) []f5catalog.Signature {
	out := make([]f5catalog.Signature, 0, len(dump.Items))
	for _, s := range dump.Items {
		if s.SignatureID == 0 {
			continue
		}
		sig := f5catalog.Signature{
			ID:          s.SignatureID,
			Name:        s.Name,
			Accuracy:    s.Accuracy,
			Risk:        s.Risk,
			Type:        s.SignatureType,
			AttackType:  s.AttackType.Name,
			UserDefined: s.IsUserDefined,
			Description: clean(s.Description),
		}
		sig.CVEs, sig.References = splitReferences(s.References)
		out = append(out, sig)
	}
	return out
}

// splitReferences separates CVEs from everything else, because a CVE is what an analyst
// pivots on into every other tool they own while a vendor blog post is context.
func splitReferences(refs []struct {
	Value string `json:"value"`
	Type  string `json:"type"`
}) (cves, others []string) {
	for _, ref := range refs {
		switch {
		case ref.Value == "":
		case strings.EqualFold(ref.Type, "cve"):
			cves = append(cves, ref.Value)
		default:
			others = append(others, ref.Value)
		}
	}
	return cves, others
}

func readJSON(path string, into any) error {
	body, err := os.ReadFile(path) //nolint:gosec // operator-supplied path, run by hand
	if err != nil {
		return fmt.Errorf("read %s: %w", path, err)
	}
	if err := json.Unmarshal(body, into); err != nil {
		return fmt.Errorf("parse %s: %w", path, err)
	}
	return nil
}

func write(path string, catalog f5catalog.Catalog) error {
	file, err := os.Create(path) //nolint:gosec // operator-supplied path, run by hand
	if err != nil {
		return err
	}
	defer func() { _ = file.Close() }()

	// Best compression: this runs by hand and the result is committed, so the tradeoff
	// is entirely one-sided.
	zw, err := gzip.NewWriterLevel(file, gzip.BestCompression)
	if err != nil {
		return err
	}
	if err := json.NewEncoder(zw).Encode(catalog); err != nil {
		return err
	}
	return zw.Close()
}

// clean normalises the whitespace BIG-IP embeds in its prose. The descriptions arrive
// with trailing newlines and hard-wrapped sections; leaving them raw makes the UI
// render ragged blocks with blank lines in the middle of a sentence.
func clean(s string) string {
	return strings.TrimSpace(strings.ReplaceAll(s, "\r\n", "\n"))
}
