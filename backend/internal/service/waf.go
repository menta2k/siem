package service

import (
	pb "github.com/menta2k/siem/api/gen/siem/v1"
	chdata "github.com/menta2k/siem/internal/data/clickhouse"
)

// toWafDetail projects a row's WAF columns onto the wire type.
//
// Returns nil when the vendor reported nothing, so a client tests for presence rather
// than for a struct of zeroes. That matters more than usual here: 0 means NOT SCORED,
// and on this inverted scale a zero-valued struct would render as the most dangerous
// request in the result.
func toWafDetail(e chdata.EventSearchResult) *pb.WafDetail {
	if e.WAFAttackScore == 0 && e.WAFAction == "" && e.WAFSource == "" {
		return nil
	}
	return &pb.WafDetail{
		AttackScore: uint32(e.WAFAttackScore),
		SqliScore:   uint32(e.WAFSQLiScore),
		XssScore:    uint32(e.WAFXSSScore),
		RceScore:    uint32(e.WAFRCEScore),
		Action:      e.WAFAction,
		Source:      e.WAFSource,
	}
}
