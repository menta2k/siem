//go:build integration

package integration

import (
	"os"
	"testing"

	"github.com/menta2k/siem/test/support"
)

// TestMain starts ClickHouse, Redis, and Redpanda ONCE for the whole package and
// tears them down at the end.
//
// Each test still gets its own tenant, which is what keeps them isolated: tenant
// scoping is a physical property of every table's sort key, so two tests sharing a
// server cannot see each other's rows.
func TestMain(m *testing.M) {
	os.Exit(support.RunSuite(m))
}
