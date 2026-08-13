package service

import (
	pb "github.com/menta2k/siem/api/gen/siem/v1"
	chdata "github.com/menta2k/siem/internal/data/clickhouse"
	"github.com/menta2k/siem/internal/f5catalog"
	"github.com/menta2k/siem/internal/vendors"
)

// asmFindings explains a BIG-IP block, resolved against the embedded ASM catalogue.
//
// Built from two different places on purpose, because ASM reports the two halves
// differently. The violations are already on the normalized row — the adapter maps the
// `violations` field onto RuleIDs — while the signature ids only ever existed inside the
// payload, so they come from the vendor fields rebuilt beside them. Reading violations
// back out of the rebuilt fields instead would make the panel depend on the raw payload
// still existing, and it expires on its own TTL while the row survives.
//
// Returns nil rather than an empty message when there is nothing to say, so a client can
// branch on presence instead of on vendor.
func asmFindings(event chdata.NormalizedEvent, vendorFields map[string]string) *pb.AsmFindings {
	if event.Vendor != vendors.F5 {
		return nil
	}

	violations := f5catalog.DescribeViolations(event.RuleIDs)
	signatures := f5catalog.DescribeSignatures(vendorFields["sig_ids"])
	if len(violations) == 0 && len(signatures) == 0 {
		return nil
	}

	findings := &pb.AsmFindings{
		Violations: make([]*pb.AsmViolation, 0, len(violations)),
		Signatures: make([]*pb.AsmSignature, 0, len(signatures)),
		// Carried through as reported rather than parsed into a number: ASM writes "N/A"
		// as readily as "4", and a zero would claim the request scored nothing.
		ViolationRating: notApplicableToEmpty(vendorFields["violation_rating"]),
	}

	for _, v := range violations {
		findings.Violations = append(findings.Violations, &pb.AsmViolation{
			Title:       v.Title,
			Name:        v.Name,
			Severity:    v.Severity,
			AttackType:  v.AttackType,
			Description: v.Description,
			Risk:        v.Risk,
			Examples:    v.Examples,
		})
	}
	for _, s := range signatures {
		findings.Signatures = append(findings.Signatures, &pb.AsmSignature{
			Id:          s.ID,
			Name:        s.Name,
			Accuracy:    s.Accuracy,
			Risk:        s.Risk,
			AttackType:  s.AttackType,
			Description: s.Description,
			Cves:        s.CVEs,
			References:  s.References,
			UserDefined: s.UserDefined,
		})
	}
	return findings
}

// notApplicableToEmpty collapses ASM's placeholder to an absent value, so the UI can
// test for emptiness rather than knowing that "N/A" means nothing.
func notApplicableToEmpty(value string) string {
	if value == "N/A" {
		return ""
	}
	return value
}
