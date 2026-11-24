package governance

import (
	"slices"
	"strings"

	"github.com/juanfont/headscale/hscontrol/types"
)

type outcome struct {
	decision Decision
	code     ReasonCode
	ruleID   string
	markers  string
}

func outcomeOf(c *Compilation, src, dst types.NodeID, proto int, port uint16) outcome {
	d, code, rule := c.decide(src, dst, proto, port)

	markers := slices.Clone(rule.Markers)
	slices.Sort(markers)

	return outcome{
		decision: d,
		code:     code,
		ruleID:   rule.ID,
		markers:  strings.Join(markers, ","),
	}
}

// Diff calculates the deterministic source/target/port change set between two
// compilations. Identity snapshots are expected to be the same for an
// incremental commit; callers degrade to full recompute otherwise.
func Diff(old, next *Compilation) []PortChange {
	if next == nil {
		return nil
	}

	idSet := map[types.NodeID]struct{}{}
	for id := range next.Snapshot.Identities {
		idSet[id] = struct{}{}
	}

	if old != nil && old.Snapshot != nil {
		for id := range old.Snapshot.Identities {
			idSet[id] = struct{}{}
		}
	}

	ids := make([]types.NodeID, 0, len(idSet))
	for id := range idSet {
		ids = append(ids, id)
	}

	slices.Sort(ids)

	var changes []PortChange

	for _, src := range ids {
		for _, dst := range ids {
			if src == dst {
				continue
			}

			for _, proto := range []int{6, 17} {
				segments := unionAtomicRanges(old, next, src, dst, proto)
				protoName := protocolName(proto)

				for _, pr := range segments {
					newOut := outcomeOf(next, src, dst, proto, pr.First)

					var oldOut outcome
					if old != nil {
						oldOut = outcomeOf(old, src, dst, proto, pr.First)
					} else {
						oldOut = outcome{decision: DecisionDeny, code: ReasonDefaultDenyNoSourceCoverage}
					}

					if outcomesEqual(oldOut, newOut) {
						continue
					}

					kind := "marked"
					before, after := oldOut.decision, newOut.decision

					switch {
					case oldOut.decision != DecisionAllow && newOut.decision == DecisionAllow:
						kind = "added"
					case oldOut.decision == DecisionAllow && newOut.decision != DecisionAllow:
						kind = "removed"
					case oldOut.decision != newOut.decision:
						kind = "changed"
					}

					var markers []string
					if newOut.ruleID != "" {
						for _, r := range next.Rules {
							if r.ID == newOut.ruleID {
								markers = slices.Clone(r.Markers)
								break
							}
						}
					}

					changes = append(changes, PortChange{
						Source: src, Target: dst, Protocol: protoName, Ports: pr,
						Kind: kind, Before: before, After: after,
						Code: newOut.code, RuleID: newOut.ruleID, Markers: markers,
					})
				}
			}
		}
	}

	return mergeAdjacentChanges(changes)
}

func outcomesEqual(a, b outcome) bool {
	// Rule identity/provenance can move during an equivalent rewrite. The
	// effective change set cares about verdict, stable reason and markers, not
	// the internal ID of an equivalent rule.
	return a.decision == b.decision &&
		a.code == b.code &&
		a.markers == b.markers
}

func unionAtomicRanges(old, next *Compilation, src, dst types.NodeID, proto int) []PortRange {
	points := map[int]struct{}{0: {}, 65536: {}}

	add := func(c *Compilation) {
		if c == nil {
			return
		}

		for _, r := range c.Rules {
			if r.Dormant || !r.matchesIdentityProto(src, dst, proto) {
				continue
			}

			for _, pr := range r.PortRanges {
				points[int(pr.First)] = struct{}{}
				points[int(pr.Last)+1] = struct{}{}
			}
		}
	}

	add(old)
	add(next)

	ordered := make([]int, 0, len(points))
	for p := range points {
		ordered = append(ordered, p)
	}

	slices.Sort(ordered)

	out := make([]PortRange, 0, len(ordered)-1)

	for i := 0; i+1 < len(ordered); i++ {
		start, end := ordered[i], ordered[i+1]-1
		if start < 0 || end > 65535 || start > end {
			continue
		}

		out = append(out, PortRange{First: uint16(start), Last: uint16(end)})
	}

	return out
}

func (c *Compilation) atomicRanges(src, dst types.NodeID, proto int) []PortRange {
	return unionAtomicRanges(nil, c, src, dst, proto)
}

func mergeAdjacentChanges(in []PortChange) []PortChange {
	if len(in) == 0 {
		return nil
	}

	out := make([]PortChange, 0, len(in))

	for _, ch := range in {
		if n := len(out); n > 0 {
			last := &out[n-1]
			if last.Source == ch.Source && last.Target == ch.Target &&
				last.Protocol == ch.Protocol && last.Kind == ch.Kind &&
				last.Code == ch.Code && last.RuleID == ch.RuleID &&
				slices.Equal(last.Markers, ch.Markers) &&
				last.Ports.Last+1 == ch.Ports.First {
				last.Ports.Last = ch.Ports.Last
				continue
			}
		}

		out = append(out, ch)
	}

	return out
}
