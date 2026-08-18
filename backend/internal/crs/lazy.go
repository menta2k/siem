package crs

import "sync"

// Deferring the cost of loading the rule set until something asks for it.
//
// Loading CRS parses several thousand rules and takes on the order of a second. Doing that
// at start-up would charge every deployment for a feature most requests never use, and
// would turn a bad rule set into a service that will not boot. Doing it on first use makes
// a failure local to the one panel that needs it.

// Lazy loads the rule set on first use and reuses it afterwards.
type Lazy struct {
	opts   Options
	once   sync.Once
	engine *Engine
	err    error
}

// NewLazy returns an engine that will load when it is first needed.
func NewLazy(opts Options) *Lazy { return &Lazy{opts: opts} }

// Evaluate loads the rule set if it is not loaded, then runs it.
//
// A load failure is returned to every caller, not retried per request: rebuilding a rule
// set that failed to parse would fail the same way each time, slowly.
func (l *Lazy) Evaluate(request Request) (Result, error) {
	l.once.Do(func() { l.engine, l.err = New(l.opts) })
	if l.err != nil {
		return Result{}, l.err
	}
	return l.engine.Evaluate(request)
}
