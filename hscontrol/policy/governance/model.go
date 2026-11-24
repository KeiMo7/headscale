package governance

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
)

// Action tokens understood by the governance layer. "accept" is an alias for
// allow so legacy wording remains natural.
const (
	ActionAllow = "allow"
	ActionDeny  = "deny"
	ActionLog   = "log"

	actionAccept = "accept"
)

// PortRange is an inclusive TCP/UDP port interval.
type PortRange struct {
	First uint16 `json:"first"`
	Last  uint16 `json:"last"`
}

// SinglePort returns a one-port range.
func SinglePort(port uint16) PortRange {
	return PortRange{First: port, Last: port}
}

// AllPorts returns the complete legal port interval.
func AllPorts() PortRange {
	return PortRange{First: 0, Last: 65535}
}

// Contains reports whether port is in the inclusive range.
func (r PortRange) Contains(port uint16) bool {
	return r.First <= port && port <= r.Last
}

// Count returns the number of ports in the inclusive range.
func (r PortRange) Count() int {
	return int(r.Last) - int(r.First) + 1
}

func (r PortRange) String() string {
	if r.First == r.Last {
		return strconv.Itoa(int(r.First))
	}

	return strconv.Itoa(int(r.First)) + "-" + strconv.Itoa(int(r.Last))
}

// UnmarshalJSON accepts 443, "443", "8000-8100" and {"first":..,"last":..}.
func (r *PortRange) UnmarshalJSON(b []byte) error {
	b = bytes.TrimSpace(b)

	if len(b) > 0 && b[0] == '{' {
		type rawRange PortRange

		var raw rawRange
		if err := json.Unmarshal(b, &raw); err != nil {
			return err
		}

		if raw.First > raw.Last {
			return fmt.Errorf("port range %d-%d is reversed", raw.First, raw.Last)
		}

		*r = PortRange(raw)

		return nil
	}

	var v any
	if err := json.Unmarshal(b, &v); err != nil {
		return err
	}

	switch x := v.(type) {
	case float64:
		if x < 0 || x > 65535 || x != float64(int(x)) {
			return fmt.Errorf("port %v is outside 0-65535", x)
		}

		p := uint16(x)
		*r = SinglePort(p)

		return nil
	case string:
		parsed, err := ParsePortRange(x)
		if err != nil {
			return err
		}

		*r = parsed

		return nil
	default:
		return fmt.Errorf("port must be number, string or range object")
	}
}

// ParsePortRange parses "443" or "8000-8100".
func ParsePortRange(s string) (PortRange, error) {
	s = strings.TrimSpace(s)

	if before, after, ok := strings.Cut(s, "-"); ok {
		first, err := parsePortNumber(strings.TrimSpace(before))
		if err != nil {
			return PortRange{}, err
		}

		last, err := parsePortNumber(strings.TrimSpace(after))
		if err != nil {
			return PortRange{}, err
		}

		if first > last {
			return PortRange{}, fmt.Errorf("port range %s is reversed", s)
		}

		return PortRange{First: first, Last: last}, nil
	}

	p, err := parsePortNumber(s)
	if err != nil {
		return PortRange{}, err
	}

	return SinglePort(p), nil
}

func parsePortNumber(s string) (uint16, error) {
	n, err := strconv.Atoi(s)
	if err != nil || n < 0 || n > 65535 {
		return 0, fmt.Errorf("port %q is outside 0-65535", s)
	}

	return uint16(n), nil
}

// Rule is the additive action/priority model. A rule may both allow and
// record by setting Actions to ["allow","log"] (or Log to true).
type Rule struct {
	ID       string   `json:"id,omitempty"`
	Priority int      `json:"priority,omitempty"`
	Actions  []string `json:"actions,omitempty"`

	// Action is the singular convenience form. "accept" remains accepted.
	Action string `json:"action,omitempty"`

	// Log attaches the built-in log marker without changing the verdict.
	Log bool `json:"log,omitempty"`

	// Markers are stable record tags. They never alter the allow-list.
	Markers []string `json:"markers,omitempty"`

	Sources      []string    `json:"src,omitempty"`
	Source       []string    `json:"sources,omitempty"`
	Destinations []string    `json:"dst,omitempty"`
	Destination  []string    `json:"destinations,omitempty"`
	Ports        []PortRange `json:"ports,omitempty"`
	Protocols    []string    `json:"protocols,omitempty"`
	Protocol     []string    `json:"proto,omitempty"`

	// TieBreaker is optional operator-controlled stable ordering material for
	// equal-priority rules. It is never derived from input array position.
	TieBreaker string `json:"tie_breaker,omitempty"`
}

// Policy is the governance document. It can be supplied on its own or under
// the "governance" key of a legacy Headscale policy.
type Policy struct {
	Version string `json:"version,omitempty"`
	Rules   []Rule `json:"rules"`

	// RejectEqualPriorityConflicts makes an overlapping allow/deny tie a
	// write error. When false the compiler still resolves ties deterministically
	// using deny precedence and stable IDs.
	RejectEqualPriorityConflicts *bool `json:"reject_equal_priority_conflicts,omitempty"`
}

// ParsePolicy parses a standalone governance document.
func ParsePolicy(b []byte) (*Policy, error) {
	var p Policy
	if err := json.Unmarshal(b, &p); err != nil {
		if strings.Contains(err.Error(), "outside 0-65535") ||
			strings.Contains(err.Error(), "port range") {
			return nil, &ValidationError{Issues: []Issue{{
				Class:   ClassPortOutOfRange,
				Code:    ReasonPortOutOfRange,
				Field:   "ports",
				Message: "port is outside the legal 0-65535 range",
			}}}
		}

		return nil, &ValidationError{Issues: []Issue{{
			Class:   ClassInvalidPolicy,
			Code:    ReasonInvalidPolicy,
			Message: "governance policy is not valid JSON",
		}}}
	}

	return &p, nil
}

func (p *Policy) strictConflicts() bool {
	return p == nil || p.RejectEqualPriorityConflicts == nil || *p.RejectEqualPriorityConflicts
}

func (r Rule) sourceRefs() []string {
	return append(append([]string{}, r.Sources...), r.Source...)
}

func (r Rule) destinationRefs() []string {
	return append(append([]string{}, r.Destinations...), r.Destination...)
}

func (r Rule) protocolNames() []string {
	out := append(append([]string{}, r.Protocols...), r.Protocol...)
	if len(out) == 0 {
		return []string{"tcp"}
	}

	return out
}

func normalizeAction(a string) (string, bool) {
	switch strings.ToLower(strings.TrimSpace(a)) {
	case ActionAllow, actionAccept:
		return ActionAllow, true
	case ActionDeny:
		return ActionDeny, true
	case ActionLog, "record":
		return ActionLog, true
	default:
		return "", false
	}
}
