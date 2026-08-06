// Command webhookecho is a local receiver for alert webhooks.
//
// It exists so an operator can answer "is the platform actually sending, and is it
// signing correctly" without standing up a real receiver — and so the delivery path
// can be validated end to end during development, where the usual failure is silent:
// the alert says delivered and nothing ever arrived.
//
// It VERIFIES the signature using the same code the sender signs with. A verifier
// written separately would drift from the sender and start accepting deliveries the
// real receiver rejects, which is worse than not checking at all.
//
//	go run ./test/tools/webhookecho --addr :9099 --secret hunter2
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/menta2k/siem/internal/alerting"
)

// maxBody bounds what is read from a delivery. A tool used against a live system must
// not be trivially exhaustible by whatever is pointed at it.
const maxBody = 1 << 20

// maxSkew is how stale a signed timestamp may be.
//
// The signature covers the timestamp precisely so a replay can be rejected; without a
// skew check the signature proves authenticity but not freshness, and a captured
// delivery stays valid forever.
const maxSkew = 5 * time.Minute

func main() {
	addr := flag.String("addr", ":9099", "address to listen on")
	secret := flag.String("secret", "", "signing secret; signature checks are skipped when empty")
	failFirst := flag.Int("fail-first", 0, "reject the first N deliveries, to exercise retry")
	flag.Parse()

	received := 0

	mux := http.NewServeMux()
	mux.HandleFunc("POST /", func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(io.LimitReader(r.Body, maxBody))
		if err != nil {
			http.Error(w, "could not read the body", http.StatusBadRequest)
			return
		}

		received++
		if received <= *failFirst {
			log.Printf("delivery %d: rejected deliberately (--fail-first=%d)",
				received, *failFirst)
			http.Error(w, "deliberate failure", http.StatusInternalServerError)
			return
		}

		if *secret != "" {
			if err := verify(r, body, *secret); err != nil {
				log.Printf("delivery %d: REJECTED — %v", received, err)
				http.Error(w, err.Error(), http.StatusUnauthorized)
				return
			}
		}

		report(received, body, *secret != "")
		w.WriteHeader(http.StatusNoContent)
	})

	server := &http.Server{
		Addr:              *addr,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
	}

	log.Printf("listening on %s (signature checks: %v)", *addr, *secret != "")
	if err := server.ListenAndServe(); err != nil {
		log.Printf("server stopped: %v", err)
		os.Exit(1)
	}
}

// verify checks the delivery's signature and freshness.
func verify(r *http.Request, body []byte, secret string) error {
	timestamp := r.Header.Get("X-Siem-Timestamp")
	signature := r.Header.Get("X-Siem-Signature")

	if timestamp == "" || signature == "" {
		return fmt.Errorf("the delivery is unsigned")
	}

	seconds, err := strconv.ParseInt(timestamp, 10, 64)
	if err != nil {
		return fmt.Errorf("the timestamp is not a unix time")
	}
	if age := time.Since(time.Unix(seconds, 0)); age > maxSkew || age < -maxSkew {
		return fmt.Errorf("the timestamp is %s out of date, which is a replay", age.Round(time.Second))
	}

	if !alerting.Verify(secret, timestamp, body, signature) {
		return fmt.Errorf("the signature does not match")
	}
	return nil
}

// report prints the delivery in a form an operator can read at a glance.
func report(n int, body []byte, verified bool) {
	var payload alerting.Payload
	if err := json.Unmarshal(body, &payload); err != nil {
		log.Printf("delivery %d: accepted but unparseable: %v", n, err)
		return
	}

	status := "unverified"
	if verified {
		status = "signature ok"
	}

	log.Printf("delivery %d (%s): rule=%q severity=%s observed=%.2f threshold=%.2f group=%v",
		n, status, payload.RuleName, payload.Severity,
		payload.ObservedValue, payload.Threshold, payload.GroupValues)

	for _, url := range payload.EvidenceURLs {
		log.Printf("  evidence: %s", url)
	}
}
