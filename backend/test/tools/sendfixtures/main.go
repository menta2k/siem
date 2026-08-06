// Command sendfixtures posts synthetic vendor logs at a feed.
//
// Used throughout quickstart.md to put believable traffic into a running stack. It
// speaks each vendor's REAL wire format rather than the platform's internal one, so it
// exercises the adapters and the ingest contract instead of bypassing them — a fixture
// tool that posts already-normalized events proves nothing about the pipeline.
//
//	go run ./test/tools/sendfixtures --vendor=cloudflare --count=10000 --feed=$FEED_ID
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"time"
)

func main() {
	var (
		vendor    = flag.String("vendor", "cloudflare", "cloudflare | f5 | datadome")
		feedID    = flag.String("feed", "", "feed id to deliver to")
		token     = flag.String("token", "", "feed ingest token")
		endpoint  = flag.String("endpoint", "http://localhost:8001", "ingest base URL")
		count     = flag.Int("count", 100, "events to send")
		batchSize = flag.Int("batch", 500, "events per request")
		rate      = flag.Int("rate", 0, "events per second; 0 sends as fast as possible")
		// The seed drives the whole sequence, so running all three vendors with the
		// SAME seed makes them describe the same requests — which is what the
		// correlation scenarios need. Different seeds produce unrelated traffic that
		// will not join, and that is a useful case to be able to generate too.
		seed = flag.Int64("seed", 1, "fixture seed; the same seed correlates across vendors")
	)
	flag.Parse()

	if *feedID == "" {
		log.Fatal("--feed is required")
	}
	if *batchSize <= 0 {
		*batchSize = 500
	}

	gen := newGenerator(*seed)
	sent := 0
	started := time.Now()

	limiter := newLimiter(*rate)

	for sent < *count {
		size := min(*batchSize, *count-sent)

		body, contentType, err := gen.batch(*vendor, size)
		if err != nil {
			log.Fatalf("build %s batch: %v", *vendor, err)
		}

		if err := post(*endpoint, *vendor, *feedID, *token, contentType, body); err != nil {
			log.Fatalf("deliver batch: %v", err)
		}

		sent += size
		limiter.wait(size)

		if sent%5000 == 0 || sent == *count {
			elapsed := time.Since(started).Seconds()
			log.Printf("sent %d/%d (%.0f eps)", sent, *count, float64(sent)/elapsed)
		}
	}

	log.Printf("done: %d events in %s", sent, time.Since(started).Round(time.Millisecond))
}

// post delivers one batch to the ingest endpoint.
func post(endpoint, vendor, feedID, token, contentType string, body []byte) error {
	url := fmt.Sprintf("%s/ingest/v1/%s/%s",
		strings.TrimSuffix(endpoint, "/"), vendor, feedID)

	req, err := http.NewRequestWithContext(
		context.Background(), http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", contentType)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}

	resp, err := (&http.Client{Timeout: 30 * time.Second}).Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()

	preview, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<10))

	// 202 is the ONLY success. A 503 means the broker refused the write and the
	// platform is asking for a retry — treating it as success here would make the tool
	// report traffic it never actually delivered.
	if resp.StatusCode != http.StatusAccepted {
		return fmt.Errorf("ingest returned %d: %s",
			resp.StatusCode, strings.TrimSpace(string(preview)))
	}
	return nil
}

// limiter paces sending to a target rate.
type limiter struct {
	perSecond int
	window    time.Time
	inWindow  int
}

func newLimiter(perSecond int) *limiter {
	return &limiter{perSecond: perSecond, window: time.Now()}
}

func (l *limiter) wait(n int) {
	if l.perSecond <= 0 {
		return
	}

	l.inWindow += n
	if l.inWindow < l.perSecond {
		return
	}

	if remaining := time.Second - time.Since(l.window); remaining > 0 {
		time.Sleep(remaining)
	}
	l.window, l.inWindow = time.Now(), 0
}

// generator produces vendor-native fixture records.
type generator struct {
	seed    int64
	counter int
}

func newGenerator(seed int64) *generator {
	return &generator{seed: seed}
}

// requestShape is one synthetic request, shared across vendors when correlatable.
type requestShape struct {
	id     string
	ip     string
	host   string
	path   string
	method string
	at     time.Time
	block  bool
}

func (g *generator) next() requestShape {
	g.counter++

	// Derived from the seed and counter rather than from a random source, so two runs
	// with the same seed produce the same traffic and a failure can be reproduced.
	n := int(g.seed) + g.counter

	return requestShape{
		id:     fmt.Sprintf("fixture-%d-%d", g.seed, g.counter),
		ip:     fmt.Sprintf("203.0.113.%d", n%254+1),
		host:   []string{"shop.example.com", "api.example.com"}[n%2],
		path:   fmt.Sprintf("/checkout/%d", n%50),
		method: []string{"GET", "POST"}[n%2],
		at:     time.Now().UTC().Add(-time.Duration(n%60) * time.Second),
		// Roughly one in seven blocked, which is enough for a disagreement to appear
		// without making blocked traffic the norm.
		block: n%7 == 0,
	}
}

func (g *generator) batch(vendor string, size int) ([]byte, string, error) {
	switch vendor {
	case "cloudflare":
		return g.cloudflare(size)
	case "f5":
		return g.f5(size)
	case "datadome":
		return g.datadome(size)
	default:
		return nil, "", fmt.Errorf("unsupported vendor %q", vendor)
	}
}

// cloudflare emits NDJSON, which is what Logpush delivers.
func (g *generator) cloudflare(size int) ([]byte, string, error) {
	var buf bytes.Buffer

	for range size {
		shape := g.next()
		action := "allow"
		if shape.block {
			action = "block"
		}

		record := map[string]any{
			"RayID":                  shape.id,
			"EdgeStartTimestamp":     shape.at.Format(time.RFC3339Nano),
			"ClientIP":               shape.ip,
			"ClientRequestHost":      shape.host,
			"ClientRequestPath":      shape.path,
			"ClientRequestMethod":    shape.method,
			"ClientRequestUserAgent": "Mozilla/5.0 (fixture)",
			"EdgeResponseStatus":     200,
			"SecurityAction":         action,
			"ClientCountry":          "de",
			"BotScore":               30,
			"WAFRuleID":              "",
		}
		if shape.block {
			record["EdgeResponseStatus"] = 403
			record["WAFRuleID"] = "waf-sqli"
		}

		encoded, err := json.Marshal(record)
		if err != nil {
			return nil, "", err
		}
		buf.Write(encoded)
		buf.WriteByte('\n')
	}
	return buf.Bytes(), "application/x-ndjson", nil
}

// f5 emits a JSON array of ASM-style records.
func (g *generator) f5(size int) ([]byte, string, error) {
	records := make([]map[string]any, 0, size)

	for range size {
		shape := g.next()
		status := "passed"
		if shape.block {
			status = "blocked"
		}

		record := map[string]any{
			"support_id":     shape.id,
			"date_time":      shape.at.Format("2006-01-02 15:04:05"),
			"ip_client":      shape.ip,
			"host":           shape.host,
			"uri":            shape.path,
			"method":         shape.method,
			"request_status": status,
			"policy_name":    "prod_waf_policy",
			"geo_location":   "DE",
			"virtual_server": "/Common/vs_shop_https",
			"response_code":  200,
		}
		if shape.block {
			record["response_code"] = 403
			record["attack_type"] = "SQL-Injection"
		}
		records = append(records, record)
	}

	encoded, err := json.Marshal(records)
	return encoded, "application/json", err
}

// datadome emits a JSON array of bot-defence events.
func (g *generator) datadome(size int) ([]byte, string, error) {
	records := make([]map[string]any, 0, size)

	for range size {
		shape := g.next()
		action := "ALLOW"
		score := 20
		if shape.block {
			action, score = "BLOCK", 95
		}

		records = append(records, map[string]any{
			"requestid": shape.id,
			"timestamp": shape.at.UnixMilli(),
			"ip":        shape.ip,
			"host":      shape.host,
			"uri":       shape.path,
			"method":    shape.method,
			"action":    action,
			"score":     score,
			"country":   "DE",
			"useragent": "Mozilla/5.0 (fixture)",
		})
	}

	encoded, err := json.Marshal(records)
	return encoded, "application/json", err
}
