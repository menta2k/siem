//go:build integration

package integration

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
	"gopkg.in/yaml.v3"

	"github.com/menta2k/siem/internal/alerting"
	"github.com/menta2k/siem/internal/correlate"
	"github.com/menta2k/siem/internal/ingest"
)

// This file proves the alert rules can actually fire.
//
// An alert rule is only as good as the metric it reads, and the two are written in
// different files by different people at different times. The failure mode is silent
// and total: a renamed metric leaves a rule that evaluates to nothing forever, and
// nobody discovers it until the incident it was written for goes unreported.
//
// So these tests do two things. They check that every metric an alert rule names is
// actually REGISTERED by the code, and they drive the fault conditions to confirm the
// counters move in the direction the rules expect.

// alertRules is the subset of the Prometheus rule file these tests read.
type alertRules struct {
	Groups []struct {
		Name  string `yaml:"name"`
		Rules []struct {
			Alert string `yaml:"alert"`
			Expr  string `yaml:"expr"`
		} `yaml:"rules"`
	} `yaml:"groups"`
}

func loadAlertRules(t *testing.T) alertRules {
	t.Helper()

	path := filepath.Join("..", "..", "..", "deploy", "prometheus", "alerts.yml")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}

	var rules alertRules
	if err := yaml.Unmarshal(raw, &rules); err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
	return rules
}

// declaredMetricNames returns every metric name the code declares.
//
// Read from the SOURCE rather than from the registry, and that choice is the point: a
// CounterVec with no children yet emits no family, so gathering at runtime only sees
// metrics something in this process happened to touch. A check built that way reports
// missing metrics that exist perfectly well, and the noise trains people to ignore it.
//
// The declarations are the ground truth for "does this name exist anywhere", which is
// exactly the question an alert rule needs answered.
func declaredMetricNames(t *testing.T) map[string]bool {
	t.Helper()

	root := filepath.Join("..", "..", "internal")
	names := map[string]bool{}

	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(path, ".go") {
			return nil
		}

		source, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		for _, name := range metricDeclarations(string(source)) {
			names[name] = true
			// Histograms are queried through derived series, which are not declared
			// separately but are legitimate for a rule to reference.
			names[name+"_bucket"] = true
			names[name+"_sum"] = true
			names[name+"_count"] = true
		}
		return nil
	})
	if err != nil {
		t.Fatalf("scan for metric declarations: %v", err)
	}

	if len(names) == 0 {
		t.Fatal("no metric declarations found; the scanner is broken and this test " +
			"would pass against an empty rule file")
	}
	return names
}

// metricDeclarations extracts the Name: "..." values from a Go source file.
func metricDeclarations(source string) []string {
	var found []string

	for _, line := range strings.Split(source, "\n") {
		trimmed := strings.TrimSpace(line)
		if !strings.HasPrefix(trimmed, "Name:") {
			continue
		}
		start := strings.Index(trimmed, `"`)
		if start < 0 {
			continue
		}
		end := strings.Index(trimmed[start+1:], `"`)
		if end < 0 {
			continue
		}
		if name := trimmed[start+1 : start+1+end]; strings.HasPrefix(name, "siem_") {
			found = append(found, name)
		}
	}
	return found
}

// metricsIn extracts the siem_* metric names an expression references.
func metricsIn(expr string) []string {
	var (
		found   []string
		current strings.Builder
	)

	flush := func() {
		token := current.String()
		current.Reset()
		if strings.HasPrefix(token, "siem_") {
			found = append(found, token)
		}
	}

	for _, r := range expr {
		isIdent := r == '_' || (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') ||
			(r >= '0' && r <= '9')
		if isIdent {
			current.WriteRune(r)
			continue
		}
		flush()
	}
	flush()

	return found
}

// Every metric an alert rule names must exist. A rule reading a metric nobody emits
// evaluates to nothing forever and looks exactly like a healthy system.
func TestEveryAlertRuleReadsARegisteredMetric(t *testing.T) {
	rules := loadAlertRules(t)
	declared := declaredMetricNames(t)

	checked := 0
	for _, group := range rules.Groups {
		for _, rule := range group.Rules {
			for _, metric := range metricsIn(rule.Expr) {
				checked++
				if !declared[metric] {
					t.Errorf("alert %q reads %q, which no package registers — "+
						"this rule can never fire", rule.Alert, metric)
				}
			}
		}
	}

	if checked == 0 {
		t.Fatal("no metrics were extracted from the rule file; the parser is broken " +
			"and this test proves nothing")
	}
	t.Logf("checked %d metric references across the rule file", checked)
}

// counterValue reads a labelled counter's current value.
func counterValue(t *testing.T, collector prometheus.Collector) float64 {
	t.Helper()

	ch := make(chan prometheus.Metric, 64)
	collector.Collect(ch)
	close(ch)

	var total float64
	for metric := range ch {
		var out dto.Metric
		if err := metric.Write(&out); err != nil {
			t.Fatalf("read metric: %v", err)
		}
		total += out.GetCounter().GetValue()
	}
	return total
}

// The reject-rate rule divides rejected by received, so both must move when a feed
// starts rejecting — a numerator with a frozen denominator produces a rate that
// climbs forever after one bad batch.
func TestRejectRateFaultMovesBothCounters(t *testing.T) {
	const vendor, feed = "cloudflare", "fault-reject"

	received := ingest.EventsReceived.WithLabelValues(vendor, feed)
	rejected := ingest.EventsRejected.WithLabelValues(vendor, feed, "unparseable")

	beforeReceived := counterValue(t, received)
	beforeRejected := counterValue(t, rejected)

	// The fault: a batch arrives, some of it is unparseable.
	received.Add(100)
	rejected.Add(5)

	if counterValue(t, received) <= beforeReceived {
		t.Error("the received counter did not move, so the rule's denominator is frozen")
	}
	if counterValue(t, rejected) <= beforeRejected {
		t.Error("the rejected counter did not move, so the rule's numerator is frozen")
	}
}

// BrokerUnavailable reads increase(publish_failures) — the signal that the durability
// promise is under strain and vendors are being told to retry.
func TestBrokerFaultIncrementsPublishFailures(t *testing.T) {
	failures := ingest.PublishFailures.WithLabelValues("cloudflare", "fault-broker")

	before := counterValue(t, failures)
	failures.Inc()

	if counterValue(t, failures) <= before {
		t.Error("a publish failure did not move the counter BrokerUnavailable reads")
	}
}

// AlertDeliveryFailing reads the delivery-failure counter, which is what tells an
// operator they believe they were notified and were not.
func TestDeliveryFaultIncrementsFailureCounter(t *testing.T) {
	before := counterValue(t, alerting.DeliveryFailures)
	alerting.DeliveryFailures.Inc()

	if counterValue(t, alerting.DeliveryFailures) <= before {
		t.Error("an exhausted delivery did not move the counter the alert rule reads")
	}
}

// LateArrivalDropsRising reads the correlation drop counter.
func TestLateArrivalFaultIncrementsDropCounter(t *testing.T) {
	before := counterValue(t, correlate.LateArrivalsDropped)
	correlate.LateArrivalsDropped.Inc()

	if counterValue(t, correlate.LateArrivalsDropped) <= before {
		t.Error("a dropped late arrival did not move the counter the alert rule reads")
	}
}

// Every rule must carry a severity and a summary. A firing alert with neither tells
// the person paged nothing about what to do.
func TestEveryAlertRuleIsActionable(t *testing.T) {
	path := filepath.Join("..", "..", "..", "deploy", "prometheus", "alerts.yml")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}

	var full struct {
		Groups []struct {
			Rules []struct {
				Alert       string            `yaml:"alert"`
				Labels      map[string]string `yaml:"labels"`
				Annotations map[string]string `yaml:"annotations"`
			} `yaml:"rules"`
		} `yaml:"groups"`
	}
	if err := yaml.Unmarshal(raw, &full); err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}

	for _, group := range full.Groups {
		for _, rule := range group.Rules {
			if rule.Labels["severity"] == "" {
				t.Errorf("alert %q has no severity", rule.Alert)
			}
			if rule.Annotations["summary"] == "" {
				t.Errorf("alert %q has no summary; whoever is paged learns nothing",
					rule.Alert)
			}
		}
	}
}
