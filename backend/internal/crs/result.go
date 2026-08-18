package crs

import "strings"

// What a CRS evaluation says, in the terms the migration cares about.

// Match is one CRS rule that fired.
type Match struct {
	ID       int      `json:"id"`
	Message  string   `json:"message,omitempty"`
	Data     string   `json:"data,omitempty"`
	Severity string   `json:"severity,omitempty"`
	Phase    int      `json:"phase"`
	Tags     []string `json:"tags,omitempty"`
	// Category is the attack class CRS itself assigns, read off the tags rather than
	// guessed from the rule number: "attack-sqli", "attack-protocol", and so on.
	Category string `json:"category,omitempty"`
	// Score is what this rule contributed to the inbound anomaly score, when it says so.
	Score int `json:"score,omitempty"`
	// Artifact marks a rule that fired because of how the request was CAPTURED rather
	// than because of the request. A body cut off mid-multipart trips CRS's body-error
	// rules every time, and reporting that as a finding would send someone chasing a
	// request that was never malformed on the wire.
	Artifact bool   `json:"artifact,omitempty"`
	File     string `json:"-"`
	Line     int    `json:"-"`
}

// Result is the whole reading for one request.
type Result struct {
	Matched []Match `json:"matched"`
	// BlockingScore is the score CRS accumulated at or below the active paranoia level —
	// the one compared against the threshold. DetectionScore includes the higher
	// paranoia levels, which are evaluated but do not decide.
	BlockingScore  int `json:"blockingScore"`
	DetectionScore int `json:"detectionScore"`
	Threshold      int `json:"threshold"`
	ParanoiaLevel  int `json:"paranoiaLevel"`
	// WouldBlock is derived from the score, not from an interruption: the engine runs in
	// detection mode on purpose, so that a phase-1 block does not hide the phase-2 rules
	// the reader asked about.
	WouldBlock bool `json:"wouldBlock"`
	// BodyTruncated qualifies every negative in this result. F5 keeps a prefix of the
	// body, so a body rule that did not fire may simply not have been shown the bytes.
	BodyTruncated bool `json:"bodyTruncated"`
	// How much of the body was actually evaluated, against how much the request declared.
	// A reading over 900 of 124,129 bytes is not a reading about the body at all, and
	// these two numbers are the only thing that says so.
	BodyEvaluated int `json:"bodyEvaluated"`
	BodyDeclared  int `json:"bodyDeclared,omitempty"`
	// Notes are caveats about the evaluation itself, in the reader's language.
	Notes []string `json:"notes,omitempty"`
}

// crsTagPrefix marks the tags CRS uses to classify an attack.
const crsTagPrefix = "attack-"

// category picks the attack class out of a rule's tags.
func category(tags []string) string {
	for _, tag := range tags {
		if strings.HasPrefix(tag, crsTagPrefix) {
			return tag
		}
	}
	return ""
}

// bodyErrorRules fire on how the request reached us, not on what it contained.
//
// 200002 is a body Coraza could not parse and 200004 a multipart boundary it could not
// follow — both are the expected consequence of evaluating a transcript that stops in the
// middle of an upload.
var bodyErrorRules = map[int]bool{200002: true, 200003: true, 200004: true}
