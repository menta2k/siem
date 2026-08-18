// Command crs-eval reports which OWASP Core Rule Set rules a captured request matches.
//
// Cloudflare's OWASP managed ruleset reports the decision — 949110, "inbound anomaly score
// exceeded" — and not the rules that added up to it. This runs the same rule set locally
// against the request F5 recorded, and prints the contributors with what each one scored.
//
// Read an F5 syslog payload on stdin:
//
//	crs-eval < payload.log
//	crs-eval -raw < transcript.txt        # already just the HTTP request
//	crs-eval -pl 2 -threshold 40 -json < payload.log
//
// The threshold is settable because Cloudflare's own is: their OWASP ruleset offers Low,
// Medium and High, and the numbers behind them are not CRS's default of 5.
package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"

	"encoding/json"

	"github.com/menta2k/siem/internal/crs"
	"github.com/menta2k/siem/internal/vendors/f5"
)

func main() {
	paranoia := flag.Int("pl", crs.DefaultParanoiaLevel, "CRS paranoia level, 1 to 4")
	threshold := flag.Int("threshold", crs.DefaultThreshold,
		"inbound anomaly score at which the request is blocked")
	raw := flag.Bool("raw", false,
		"the input is the HTTP request itself, not an F5 syslog payload")
	asJSON := flag.Bool("json", false, "print the result as JSON")
	file := flag.String("file", "", "read the payload from this file instead of stdin")
	flag.Parse()

	if err := run(*paranoia, *threshold, *raw, *asJSON, *file); err != nil {
		fmt.Fprintln(os.Stderr, "crs-eval:", err)
		os.Exit(1)
	}
}

func run(paranoia, threshold int, raw, asJSON bool, file string) error {
	payload, err := input(file)
	if err != nil {
		return err
	}

	transcript := string(payload)
	if !raw {
		if transcript, err = f5Transcript(payload); err != nil {
			return err
		}
	}

	request, ok := crs.ParseTranscript(transcript)
	if !ok {
		return fmt.Errorf("the payload holds no request that could be parsed")
	}

	engine, err := crs.New(crs.Options{ParanoiaLevel: paranoia, Threshold: threshold})
	if err != nil {
		return err
	}
	result, err := engine.Evaluate(request)
	if err != nil {
		return err
	}

	if asJSON {
		encoder := json.NewEncoder(os.Stdout)
		encoder.SetIndent("", "  ")
		return encoder.Encode(result)
	}

	_, err = io.WriteString(os.Stdout, report(request, result))
	return err
}

func input(file string) ([]byte, error) {
	if file != "" {
		// The path comes from the operator running the command, on their own machine and
		// with their own permissions; there is no privilege here to escalate.
		return os.ReadFile(file) //nolint:gosec // an operator naming their own file
	}
	return io.ReadAll(os.Stdin)
}

// f5Transcript pulls the logged request out of an F5 syslog payload, using the same adapter
// the ingest pipeline uses so this cannot drift from what the platform stored.
func f5Transcript(payload []byte) (string, error) {
	adapter := f5.New()
	format, ok := adapter.Detect(payload)
	if !ok {
		return "", fmt.Errorf("this does not look like an F5 payload; try -raw")
	}
	records, err := adapter.Parse(payload, format)
	if err != nil || len(records) == 0 {
		return "", fmt.Errorf("parse the F5 payload: %w", err)
	}
	event, err := adapter.Normalize(records[0])
	if err != nil {
		return "", fmt.Errorf("normalize the F5 record: %w", err)
	}

	transcript := event.RawExtra["request"]
	if transcript == "" {
		return "", fmt.Errorf("the payload carries no request transcript")
	}
	return transcript, nil
}

// report renders the reading the way the question is asked: the decision first, then the
// rules that produced it, largest contribution first.
//
// Built as a string and written once, so a broken pipe is one error to handle rather than
// twenty writes that each quietly returned one.
func report(request crs.Request, result crs.Result) string {
	var out strings.Builder

	fmt.Fprintf(&out, "%s %s\n", request.Method, request.URI)
	fmt.Fprintf(&out, "paranoia level %d, threshold %d, %d headers, %s\n\n",
		result.ParanoiaLevel, result.Threshold, len(request.Headers), bodyLine(result))

	decision := "would NOT be blocked"
	if result.WouldBlock {
		decision = "would be BLOCKED"
	}
	fmt.Fprintf(&out, "score %d of %d — %s\n", result.BlockingScore, result.Threshold, decision)
	if result.DetectionScore > result.BlockingScore {
		fmt.Fprintf(&out, "  (%d at higher paranoia levels, which do not decide here)\n",
			result.DetectionScore)
	}
	out.WriteString("\n")

	if len(result.Matched) == 0 {
		out.WriteString("no rule matched\n")
	}
	for _, match := range byContribution(result.Matched) {
		score := "   "
		if match.Score > 0 {
			score = fmt.Sprintf("+%-2d", match.Score)
		}
		note := ""
		if match.Artifact {
			note = "  [artifact of the captured body, not of the request]"
		}
		fmt.Fprintf(&out, "%s %-7d %-16s %s%s\n",
			score, match.ID, match.Category, firstLine(match.Message), note)
		if match.Data != "" {
			fmt.Fprintf(&out, "            %s\n", firstLine(match.Data))
		}
	}

	for _, note := range result.Notes {
		fmt.Fprintf(&out, "\nnote: %s\n", note)
	}
	return out.String()
}

// byContribution orders the rules by what each added to the score.
func byContribution(matched []crs.Match) []crs.Match {
	ordered := append([]crs.Match(nil), matched...)
	sort.SliceStable(ordered, func(i, j int) bool {
		if ordered[i].Score != ordered[j].Score {
			return ordered[i].Score > ordered[j].Score
		}
		return ordered[i].ID < ordered[j].ID
	})
	return ordered
}

// bodyLine says how much body the reading actually had to work with.
func bodyLine(result crs.Result) string {
	if result.BodyDeclared > 0 {
		return fmt.Sprintf("%d of %d body bytes captured",
			result.BodyEvaluated, result.BodyDeclared)
	}
	return fmt.Sprintf("%d body bytes captured", result.BodyEvaluated)
}

func firstLine(text string) string {
	if index := strings.IndexAny(text, "\r\n"); index >= 0 {
		return text[:index]
	}
	return text
}
