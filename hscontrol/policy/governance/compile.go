package governance

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"slices"
	"strings"

	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/rs/zerolog/log"
	"tailscale.com/tailcfg"
)

var protocolNumbers = map[string]int{
	"tcp":    6,
	"udp":    17,
	"icmp":   1,
	"icmpv6": 58,
}

// CompiledRule is a validated rule with identities resolved to node IDs.
type CompiledRule struct {
	Rule     Rule
	Index    int
	ID       string
	Priority int
	Allow    bool
	Deny     bool
	Log      bool
	Markers  []string

	SourceIDs map[types.NodeID]struct{}
	TargetIDs map[types.NodeID]struct{}

	PortRanges []PortRange
	Protocols  map[int]struct{}
	Dormant    bool
}

func (r CompiledRule) matchesTuple(src, dst types.NodeID, proto int, port uint16) bool {
	if !idSetHas(r.SourceIDs, src) || !idSetHas(r.TargetIDs, dst) {
		return false
	}

	if _, ok := r.Protocols[proto]; !ok {
		return false
	}

	if len(r.PortRanges) == 0 {
		return true
	}

	return slices.ContainsFunc(r.PortRanges, func(pr PortRange) bool { return pr.Contains(port) })
}

func idSetHas(set map[types.NodeID]struct{}, id types.NodeID) bool {
	if set == nil {
		return false
	}

	_, ok := set[id]

	return ok
}

// Compilation is the immutable single authority.
type Compilation struct {
	Version      uint64
	SnapshotHash string
	Snapshot     *Snapshot

	Rules []CompiledRule

	// Filters are the allow-only wire rules derived from Decide. They contain
	// no governance-specific fields because tailcfg.FilterRule has none.
	Filters map[types.NodeID][]tailcfg.FilterRule

	pairFingerprints map[Pair]string
}

// Compile validates and compiles a policy against snap. Unknown actions and
// undefined identities are rejected; no state is mutated.
func Compile(p *Policy, snap *Snapshot) (*Compilation, error) {
	return compile(p, snap, false)
}

// CompileForReload compiles a stored policy after an identity deletion. A
// reference that is no longer defined makes only that rule dormant instead of
// taking the controller down.
func CompileForReload(p *Policy, snap *Snapshot) (*Compilation, []Issue) {
	c, err := compile(p, snap, true)
	if err != nil {
		// Reload must remain available even for a stored document that can no
		// longer compile. Return an empty default-deny compilation rather than
		// panicking; the issues are observable and the previous atomic pointer
		// remains in the service until this candidate is explicitly installed.
		log.Error().Err(err).Msg("governance reload compilation failed; keeping previous compilation")

		return &Compilation{Snapshot: snap, SnapshotHash: snap.Hash, Filters: map[types.NodeID][]tailcfg.FilterRule{}}, nil
	}

	var dormant []Issue

	for _, r := range c.Rules {
		if r.Dormant {
			dormant = append(dormant, Issue{
				Class:   ClassUndefinedIdentity,
				Code:    ReasonDormantUndefinedIdentity,
				RuleID:  r.ID,
				Message: "rule is dormant because a referenced identity is no longer defined",
			})
		}
	}

	return c, dormant
}

func compile(p *Policy, snap *Snapshot, allowDormant bool) (*Compilation, error) {
	if p == nil {
		p = &Policy{}
	}

	if snap == nil {
		snap = NewSnapshot(nil)
	}

	var issues []Issue

	rules := make([]CompiledRule, 0, len(p.Rules))

	for i, raw := range p.Rules {
		cr := CompiledRule{
			Rule:       raw,
			Index:      i,
			Priority:   raw.Priority,
			Markers:    slices.Clone(raw.Markers),
			SourceIDs:  map[types.NodeID]struct{}{},
			TargetIDs:  map[types.NodeID]struct{}{},
			Protocols:  map[int]struct{}{},
			PortRanges: slices.Clone(raw.Ports),
		}

		cr.ID = raw.ID
		if cr.ID == "" {
			cr.ID = stableRuleID(raw)
		}

		actionTokens := slices.Clone(raw.Actions)
		if raw.Action != "" {
			actionTokens = append(actionTokens, raw.Action)
		}

		if raw.Log {
			actionTokens = append(actionTokens, ActionLog)
		}

		for _, token := range actionTokens {
			normalized, ok := normalizeAction(token)
			if !ok {
				issues = append(issues, Issue{
					Class: ClassInvalidAction, Code: ReasonInvalidAction, RuleID: cr.ID,
					Field: "action", Message: "unknown policy action",
				})

				continue
			}

			switch normalized {
			case ActionAllow:
				cr.Allow = true
			case ActionDeny:
				cr.Deny = true
			case ActionLog:
				cr.Log = true
				cr.Markers = append(cr.Markers, "log")
			}
		}

		if cr.Allow && cr.Deny {
			issues = append(issues, Issue{
				Class: ClassInvalidAction, Code: ReasonInvalidAction, RuleID: cr.ID,
				Field: "actions", Message: "a rule cannot both allow and deny",
			})
		}

		if !cr.Allow && !cr.Deny {
			issues = append(issues, Issue{
				Class: ClassInvalidAction, Code: ReasonInvalidAction, RuleID: cr.ID,
				Field: "actions", Message: "rule must declare allow or deny",
			})
		}

		if len(raw.sourceRefs()) == 0 || len(raw.destinationRefs()) == 0 {
			issues = append(issues, Issue{
				Class: ClassInvalidPolicy, Code: ReasonInvalidPolicy, RuleID: cr.ID,
				Message: "rule must declare source and destination identities",
			})
		}

		for _, name := range raw.protocolNames() {
			num, ok := protocolNumbers[strings.ToLower(strings.TrimSpace(name))]
			if !ok {
				issues = append(issues, Issue{
					Class: ClassInvalidPolicy, Code: ReasonInvalidPolicy, RuleID: cr.ID,
					Field: "protocols", Message: "unknown protocol",
				})

				continue
			}

			cr.Protocols[num] = struct{}{}
		}

		missing := false

		for _, ref := range raw.sourceRefs() {
			ids, err := snap.Resolve(ref)
			if err != nil {
				issues = append(issues, Issue{
					Class: ClassUndefinedIdentity, Code: ReasonUndefinedIdentity,
					RuleID: cr.ID, Field: "src", Message: "identity reference cannot be resolved",
				})
				missing = true

				continue
			}

			if len(ids) == 0 {
				issues = append(issues, Issue{
					Class: ClassUndefinedIdentity, Code: ReasonUndefinedIdentity,
					RuleID: cr.ID, Field: "src", Message: "source identity is not defined",
				})
				missing = true

				continue
			}

			for _, id := range ids {
				cr.SourceIDs[id.NodeID] = struct{}{}
			}
		}

		for _, ref := range raw.destinationRefs() {
			ids, err := snap.Resolve(ref)
			if err != nil || len(ids) == 0 {
				issues = append(issues, Issue{
					Class: ClassUndefinedIdentity, Code: ReasonUndefinedIdentity,
					RuleID: cr.ID, Field: "dst", Message: "destination identity is not defined",
				})
				missing = true

				continue
			}

			for _, id := range ids {
				cr.TargetIDs[id.NodeID] = struct{}{}
			}
		}

		if missing && allowDormant {
			cr.Dormant = true
			// A dormant rule must not participate in decisions or conflicts.
			cr.SourceIDs = map[types.NodeID]struct{}{}
			cr.TargetIDs = map[types.NodeID]struct{}{}
		}

		rules = append(rules, cr)
	}

	if len(issues) == 0 || allowDormant {
		if conflictIssues := detectConflicts(p, rules); len(conflictIssues) > 0 {
			if p.strictConflicts() && !allowDormant {
				issues = append(issues, conflictIssues...)
			}
		}
	}

	if len(issues) > 0 {
		if allowDormant {
			issues = slices.DeleteFunc(issues, func(issue Issue) bool {
				return issue.Class == ClassUndefinedIdentity
			})
		}

		if len(issues) > 0 {
			return nil, &ValidationError{Issues: issues}
		}
	}

	sortCompiledRules(rules)

	c := &Compilation{
		Snapshot:     snap,
		SnapshotHash: snap.Hash,
		Rules:        rules,
		Filters:      map[types.NodeID][]tailcfg.FilterRule{},
	}

	c.buildFilters()

	return c, nil
}

func stableRuleID(r Rule) string {
	b, _ := json.Marshal(struct {
		Priority int         `json:"priority"`
		Actions  []string    `json:"actions"`
		Action   string      `json:"action"`
		Log      bool        `json:"log"`
		Markers  []string    `json:"markers"`
		Src      []string    `json:"src"`
		Dst      []string    `json:"dst"`
		Ports    []PortRange `json:"ports"`
		Proto    []string    `json:"proto"`
	}{
		Priority: r.Priority, Actions: r.Actions, Action: r.Action, Log: r.Log,
		Markers: r.Markers, Src: r.sourceRefs(), Dst: r.destinationRefs(),
		Ports: r.Ports, Proto: r.protocolNames(),
	})
	sum := sha256.Sum256(b)

	return "rule-" + hex.EncodeToString(sum[:])[:12]
}

func sortCompiledRules(rules []CompiledRule) {
	slices.SortFunc(rules, func(a, b CompiledRule) int {
		if a.Priority != b.Priority {
			// Higher numeric priority wins.
			return b.Priority - a.Priority
		}

		// Deny precedes allow at equal priority.
		if a.Deny != b.Deny {
			if a.Deny {
				return -1
			}

			return 1
		}

		if a.Rule.TieBreaker != b.Rule.TieBreaker {
			return strings.Compare(a.Rule.TieBreaker, b.Rule.TieBreaker)
		}

		if a.ID != b.ID {
			return strings.Compare(a.ID, b.ID)
		}

		return a.Index - b.Index
	})
}

func detectConflicts(p *Policy, rules []CompiledRule) []Issue {
	var issues []Issue

	active := slices.DeleteFunc(slices.Clone(rules), func(r CompiledRule) bool { return r.Dormant })

	for i := 0; i < len(active); i++ {
		for j := i + 1; j < len(active); j++ {
			a, b := active[i], active[j]
			if a.Priority != b.Priority || a.Allow == b.Allow && a.Deny == b.Deny {
				continue
			}

			if !setsOverlap(a.SourceIDs, b.SourceIDs) || !setsOverlap(a.TargetIDs, b.TargetIDs) {
				continue
			}

			if !portRangesOverlap(a.PortRanges, b.PortRanges) || !protoSetsOverlap(a.Protocols, b.Protocols) {
				continue
			}

			// Explicit distinct tie breakers/IDs make the tie total and
			// reproducible; equal stable keys make it genuinely unorderable.
			keyA := orderingKey(a)
			keyB := orderingKey(b)
			if keyA != keyB && !p.strictConflicts() {
				continue
			}

			issues = append(issues, Issue{
				Class: ClassConflict, Code: ReasonEqualPriorityConflict,
				RuleID: a.ID, Rules: []string{a.ID, b.ID},
				Message: "equal-priority allow and deny rules conflict",
			})
		}
	}

	return issues
}

func orderingKey(r CompiledRule) string {
	if r.Rule.TieBreaker != "" {
		return r.Rule.TieBreaker
	}

	return r.ID
}

func setsOverlap(a, b map[types.NodeID]struct{}) bool {
	small, large := a, b
	if len(small) > len(large) {
		small, large = b, a
	}

	for id := range small {
		if _, ok := large[id]; ok {
			return true
		}
	}

	return false
}

func portRangesOverlap(a, b []PortRange) bool {
	if len(a) == 0 || len(b) == 0 {
		return true
	}

	return slices.ContainsFunc(a, func(x PortRange) bool {
		return slices.ContainsFunc(b, func(y PortRange) bool {
			return x.First <= y.Last && y.First <= x.Last
		})
	})
}

func protoSetsOverlap(a, b map[int]struct{}) bool {
	if len(a) == 0 || len(b) == 0 {
		return true
	}

	for p := range a {
		if _, ok := b[p]; ok {
			return true
		}
	}

	return false
}
