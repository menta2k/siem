package alerting

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"

	chdata "github.com/menta2k/siem/internal/data/clickhouse"
)

// Delivery limits.
const (
	// MaxAttempts bounds retries. Beyond this the alert is marked failed and left
	// visible in the console: retrying forever hides a broken endpoint behind a queue
	// that only grows.
	MaxAttempts = 5
	// BaseBackoff is the first retry delay; each attempt doubles it.
	BaseBackoff = 2 * time.Second
	// MaxBackoff caps the growth so a long outage does not push the next attempt days out.
	MaxBackoff = 5 * time.Minute
	// DeliveryTimeout bounds one attempt. A receiver that accepts the connection and
	// never responds would otherwise hold a worker indefinitely.
	DeliveryTimeout = 10 * time.Second
	// MaxResponseBytes bounds what is read back for the error message. A hostile or
	// broken receiver must not be able to stream gigabytes into an error field.
	MaxResponseBytes = 4 << 10
)

// Payload is the JSON body delivered to a webhook.
//
// A stable, documented shape: receivers build automation on it, so field names here
// are a contract as much as the OpenAPI surface is.
type Payload struct {
	AlertID       string            `json:"alert_id"`
	RuleID        string            `json:"rule_id"`
	RuleName      string            `json:"rule_name"`
	TenantID      string            `json:"tenant_id"`
	Severity      string            `json:"severity"`
	FiredAt       time.Time         `json:"fired_at"`
	GroupValues   map[string]string `json:"group_values,omitempty"`
	ObservedValue float64           `json:"observed_value"`
	Threshold     float64           `json:"threshold"`
	// EvidenceURLs are deep links into the console, so the first click from a chat
	// message lands on the evidence rather than on a dashboard.
	EvidenceURLs []string `json:"evidence_urls,omitempty"`
}

// SecretResolver reads a webhook signing key from the secret manager.
type SecretResolver interface {
	Resolve(ctx context.Context, ref string) (string, error)
}

// Webhook delivers alerts to a tenant's endpoint.
type Webhook struct {
	client     *http.Client
	secrets    SecretResolver
	consoleURL string
	// allowPrivateTargets permits loopback and private addresses.
	//
	// OFF by default and never enabled in production. It exists because the local
	// validation path — the webhookecho tool, the integration suite — necessarily
	// points at 127.0.0.1, and a protection with no supported way to develop against
	// it gets disabled wholesale by the first person who needs to.
	allowPrivateTargets bool
}

// Option configures the deliverer.
type Option func(*Webhook)

// AllowPrivateTargets permits delivery to loopback and private addresses.
//
// For local development and tests ONLY. Enabling it in a deployment turns the
// alerting worker into a proxy for reaching internal services.
func AllowPrivateTargets() Option {
	return func(w *Webhook) { w.allowPrivateTargets = true }
}

// NewWebhook constructs the deliverer.
func NewWebhook(secrets SecretResolver, consoleURL string, opts ...Option) *Webhook {
	w := &Webhook{
		client: &http.Client{
			Timeout: DeliveryTimeout,
			// Redirects are NOT followed. A webhook URL is tenant-supplied, and
			// following a redirect would let a tenant point at a benign host that
			// bounces the signed request to an internal address.
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
		secrets:    secrets,
		consoleURL: strings.TrimSuffix(consoleURL, "/"),
	}
	for _, opt := range opts {
		opt(w)
	}
	return w
}

// Backoff returns the delay before a given attempt number, starting at 1.
func Backoff(attempt int) time.Duration {
	if attempt < 1 {
		attempt = 1
	}
	delay := BaseBackoff << (attempt - 1)
	if delay > MaxBackoff || delay <= 0 {
		return MaxBackoff
	}
	return delay
}

// Deliver posts one alert and reports the outcome.
//
// Returns the updated notify fields rather than writing them, so the caller decides
// when the alert row is versioned — a delivery attempt and a state change are separate
// facts and combining them would make a retry look like a triage action.
func (w *Webhook) Deliver(
	ctx context.Context, rule chdata.AlertRule, alert chdata.Alert,
) (status string, attempts uint8, lastErr string) {
	attempts = alert.NotifyAttempts + 1

	if strings.TrimSpace(rule.WebhookURL) == "" {
		// No endpoint configured is not a failure: the alert still exists and is
		// visible in the console, which is the primary channel.
		return chdata.NotifyDelivered, alert.NotifyAttempts, ""
	}

	if err := validateWebhookURL(rule.WebhookURL, w.allowPrivateTargets); err != nil {
		// A rejected URL will never succeed, so it fails immediately rather than
		// consuming five attempts to reach the same conclusion.
		return chdata.NotifyFailed, attempts, err.Error()
	}

	body, err := json.Marshal(w.payload(rule, alert))
	if err != nil {
		return chdata.NotifyFailed, attempts, "the alert payload could not be encoded"
	}

	secret := ""
	if rule.WebhookSecretRef != "" {
		secret, err = w.secrets.Resolve(ctx, rule.WebhookSecretRef)
		if err != nil {
			return chdata.NotifyFailed, attempts, "the webhook signing key is unavailable"
		}
	}

	if err := w.post(ctx, rule.WebhookURL, body, secret); err != nil {
		if attempts >= MaxAttempts {
			return chdata.NotifyFailed, attempts, err.Error()
		}
		// Still pending: the worker will retry after the backoff.
		return chdata.NotifyPending, attempts, err.Error()
	}
	return chdata.NotifyDelivered, attempts, ""
}

func (w *Webhook) post(ctx context.Context, endpoint string, body []byte, secret string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("build webhook request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "siem-alerting/1")

	if secret != "" {
		timestamp := strconv.FormatInt(time.Now().UTC().Unix(), 10)
		req.Header.Set("X-Siem-Timestamp", timestamp)
		// The timestamp is signed ALONGSIDE the body, not just sent beside it. Signing
		// the body alone lets an observer replay a valid delivery indefinitely; with
		// the timestamp inside the MAC the receiver can reject anything stale.
		req.Header.Set("X-Siem-Signature", Sign(secret, timestamp, body))
	}

	resp, err := w.client.Do(req)
	if err != nil {
		return fmt.Errorf("webhook request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	// Read and discard the body so the connection can be reused, bounded so a hostile
	// receiver cannot stream unbounded data into this process.
	preview, _ := io.ReadAll(io.LimitReader(resp.Body, MaxResponseBytes))

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("webhook returned %d: %s",
			resp.StatusCode, strings.TrimSpace(string(preview)))
	}
	return nil
}

// Sign computes the delivery signature.
//
// Exported so the echo tool and the receiving side verify with the same code — a
// signature scheme documented in prose and implemented twice is a scheme that diverges.
func Sign(secret, timestamp string, body []byte) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(timestamp))
	mac.Write([]byte("."))
	mac.Write(body)
	return "sha256=" + hex.EncodeToString(mac.Sum(nil))
}

// Verify checks a delivery signature in constant time.
func Verify(secret, timestamp string, body []byte, signature string) bool {
	expected := Sign(secret, timestamp, body)
	// hmac.Equal rather than ==: a byte-by-byte comparison leaks the position of the
	// first mismatch through timing, which is enough to forge a signature offline.
	return hmac.Equal([]byte(expected), []byte(signature))
}

func (w *Webhook) payload(rule chdata.AlertRule, alert chdata.Alert) Payload {
	payload := Payload{
		AlertID:       alert.ID.String(),
		RuleID:        alert.RuleID.String(),
		RuleName:      rule.Name,
		TenantID:      alert.TenantID.String(),
		Severity:      alert.Severity,
		FiredAt:       alert.FiredAt.UTC(),
		GroupValues:   alert.GroupValues,
		ObservedValue: alert.ObservedValue,
		Threshold:     alert.Threshold,
	}

	for _, id := range alert.EvidenceCorrelationIDs {
		payload.EvidenceURLs = append(payload.EvidenceURLs,
			fmt.Sprintf("%s/correlated/%s", w.consoleURL, id))
	}
	return payload
}

// validateWebhookURL rejects endpoints the platform must not call.
//
// This is SSRF protection, and it is the reason a webhook URL cannot simply be handed
// to http.Post. The URL is supplied by a tenant and the request originates inside the
// cluster, so an unchecked endpoint turns the alerting worker into a proxy for
// reaching the metadata service, ClickHouse, or any internal address.
func validateWebhookURL(raw string, allowPrivate bool) error {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return fmt.Errorf("the webhook URL could not be parsed")
	}

	if parsed.Scheme != "https" && parsed.Scheme != "http" {
		return fmt.Errorf("the webhook URL must be http or https")
	}
	if parsed.Host == "" {
		return fmt.Errorf("the webhook URL has no host")
	}

	// The metadata address is blocked even when private targets are allowed: no
	// development workflow needs it, and it is the single most valuable SSRF target.
	host := parsed.Hostname()
	if ip := net.ParseIP(host); ip != nil && ip.Equal(metadataAddress) {
		return fmt.Errorf("the webhook URL points at the metadata service")
	}
	if allowPrivate {
		return nil
	}
	if isBlockedHost(host) {
		return fmt.Errorf("the webhook URL points at a non-routable address")
	}
	return nil
}

// isBlockedHost reports whether a host is one the platform refuses to call.
//
// Literal addresses are checked directly. A HOSTNAME is not resolved here: resolution
// at validation time is a TOCTOU window — DNS can return a public address now and a
// private one when the request is made — so the deployment is expected to run this
// worker behind an egress policy. Blocking the literal forms removes the trivial case
// without pretending to solve the general one.
func isBlockedHost(host string) bool {
	if strings.EqualFold(host, "localhost") || strings.HasSuffix(host, ".localhost") {
		return true
	}

	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}
	return ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() ||
		ip.IsLinkLocalMulticast() || ip.IsUnspecified() ||
		ip.Equal(metadataAddress)
}

// metadataAddress is the cloud instance-metadata endpoint: neither private nor
// loopback, and the single most valuable SSRF target in any hosted deployment.
var metadataAddress = net.IPv4(169, 254, 169, 254)

// EvidenceURL builds a console deep link for one correlated record.
func EvidenceURL(consoleURL string, id uuid.UUID) string {
	return fmt.Sprintf("%s/correlated/%s", strings.TrimSuffix(consoleURL, "/"), id)
}
