package governance

import (
	"fmt"
	"slices"
	"strings"

	"github.com/juanfont/headscale/hscontrol/types"
	"tailscale.com/tailcfg"
)

// ExplainRequest identifies one principal/principal/port tuple.
type ExplainRequest struct {
	SourceNode types.NodeID `json:"source_node_id,omitempty"`
	SourceRef  string       `json:"source_ref,omitempty"`
	TargetNode types.NodeID `json:"target_node_id,omitempty"`
	TargetRef  string       `json:"target_ref,omitempty"`
	Protocol   string       `json:"protocol,omitempty"`
	Port       int          `json:"port,omitempty"`
}

// Coverage reports which selector dimension first failed to cover a tuple.
type Coverage struct {
	SourceCovered bool `json:"source_covered"`
	TargetCovered bool `json:"target_covered"`
	PortCovered   bool `json:"port_covered"`
}

// Explanation is the stable, safe decision trace.
type Explanation struct {
	Decision    Decision    `json:"decision"`
	Code        ReasonCode  `json:"code"`
	Message     string      `json:"message"`
	RuleID      string      `json:"rule_id,omitempty"`
	RuleIDs     []string    `json:"rule_ids,omitempty"`
	Markers     []string    `json:"markers,omitempty"`
	Priority    int         `json:"priority,omitempty"`
	DefaultDeny bool        `json:"default_deny,omitempty"`
	Coverage    Coverage    `json:"coverage"`
	Source      *Resolution `json:"source,omitempty"`
	Target      *Resolution `json:"target,omitempty"`
}

// Explain resolves identities and returns the same verdict used to derive
// FilterRulesForNode.
func (c *Compilation) Explain(req ExplainRequest) (*Explanation, error) {
	if c == nil {
		return nil, &IdentityError{Class: ClassIdentityUnknown, Code: ReasonIdentityUnknown}
	}

	protoName := req.Protocol
	if protoName == "" {
		protoName = "tcp"
	}

	proto, ok := protocolNumbers[strings.ToLower(protoName)]
	if !ok {
		return nil, &ValidationError{Issues: []Issue{{
			Class: ClassInvalidPolicy, Code: ReasonInvalidPolicy, Field: "protocol",
			Message: "unknown protocol",
		}}}
	}

	if req.Port < 0 || req.Port > 65535 {
		return nil, &ValidationError{Issues: []Issue{{
			Class: ClassPortOutOfRange, Code: ReasonPortOutOfRange, Field: "port",
			Message: "port is outside 0-65535",
		}}}
	}

	srcRes, err := c.Snapshot.ResolveForExplanation(req.SourceNode, req.SourceRef)
	if err != nil {
		return nil, err
	}

	dstRes, err := c.Snapshot.ResolveForExplanation(req.TargetNode, req.TargetRef)
	if err != nil {
		return nil, err
	}

	port := uint16(req.Port)
	src, dst := srcRes.Identity.NodeID, dstRes.Identity.NodeID

	ex := &Explanation{Source: srcRes, Target: dstRes}

	var matches []CompiledRule

	for _, rule := range c.Rules {
		if rule.Dormant {
			continue
		}

		if rule.matchesTuple(src, dst, proto, port) {
			matches = append(matches, rule)
			ex.RuleIDs = append(ex.RuleIDs, rule.ID)
		}
	}

	if len(matches) > 0 {
		winner := matches[0] // Rules are deterministically sorted.
		ex.RuleID = winner.ID
		ex.Priority = winner.Priority
		ex.Markers = slices.Clone(winner.Markers)

		switch {
		case winner.Deny:
			ex.Decision = DecisionDeny
			ex.Code = ReasonDenyRule
			ex.Message = safeMessage(ReasonDenyRule)
		default:
			ex.Decision = DecisionAllow
			ex.Code = ReasonAllowRule
			ex.Message = safeMessage(ReasonAllowRule)
		}

		if winner.Log || len(winner.Markers) > 0 {
			ex.Markers = append(ex.Markers, winner.Markers...)
			ex.Markers = slices.Compact(slices.Sorted(slices.Values(ex.Markers)))
		}

		return ex, nil
	}

	ex.Decision = DecisionDeny
	ex.DefaultDeny = true
	ex.Coverage = c.coverage(src, dst, proto, port)

	switch {
	case !ex.Coverage.SourceCovered:
		ex.Code = ReasonDefaultDenyNoSourceCoverage
	case !ex.Coverage.TargetCovered:
		ex.Code = ReasonDefaultDenyNoTargetCoverage
	default:
		ex.Code = ReasonDefaultDenyNoPortCoverage
	}

	ex.Message = safeMessage(ex.Code)

	return ex, nil
}

func (c *Compilation) coverage(src, dst types.NodeID, proto int, port uint16) Coverage {
	var cov Coverage

	sourceMatched := slices.ContainsFunc(c.Rules, func(r CompiledRule) bool {
		return !r.Dormant && idSetHas(r.SourceIDs, src)
	})
	cov.SourceCovered = sourceMatched

	if !sourceMatched {
		return cov
	}

	targetMatched := slices.ContainsFunc(c.Rules, func(r CompiledRule) bool {
		return !r.Dormant && idSetHas(r.SourceIDs, src) && idSetHas(r.TargetIDs, dst)
	})
	cov.TargetCovered = targetMatched

	if !targetMatched {
		return cov
	}

	cov.PortCovered = slices.ContainsFunc(c.Rules, func(r CompiledRule) bool {
		_, protoOK := r.Protocols[proto]

		return !r.Dormant &&
			idSetHas(r.SourceIDs, src) &&
			idSetHas(r.TargetIDs, dst) &&
			protoOK &&
			(len(r.PortRanges) == 0 || slices.ContainsFunc(r.PortRanges, func(pr PortRange) bool {
				return pr.Contains(port)
			}))
	})

	return cov
}

func safeMessage(code ReasonCode) string {
	switch code {
	case ReasonAllowRule:
		return "allowed by a compiled policy rule"
	case ReasonDenyRule:
		return "denied by a compiled policy rule"
	case ReasonDefaultDenyNoSourceCoverage:
		return "default deny: no rule source covers this identity"
	case ReasonDefaultDenyNoTargetCoverage:
		return "default deny: no rule destination covers this identity"
	case ReasonDefaultDenyNoPortCoverage:
		return "default deny: no rule covers this protocol and port"
	case ReasonIdentityUnknown:
		return "identity could not be resolved"
	case ReasonIdentityDeleted:
		return "identity is deleted"
	case ReasonIdentityUnassigned:
		return "identity has no group or tag assignment"
	default:
		return "policy decision unavailable"
	}
}

func (c *Compilation) decide(src, dst types.NodeID, proto int, port uint16) (Decision, ReasonCode, CompiledRule) {
	ex, err := c.Explain(ExplainRequest{
		SourceNode: src, TargetNode: dst, Protocol: protocolName(proto), Port: int(port),
	})
	if err != nil {
		return DecisionDeny, ReasonIdentityUnknown, CompiledRule{}
	}

	var rule CompiledRule
	if ex.RuleID != "" {
		for _, r := range c.Rules {
			if r.ID == ex.RuleID {
				rule = r
				break
			}
		}
	}

	return ex.Decision, ex.Code, rule
}

func protocolName(num int) string {
	for name, n := range protocolNumbers {
		if n == num {
			return name
		}
	}

	return ""
}

// FilterRulesForNode returns the derived allow-list for the inbound destination
// node. A present but empty slice enforces default deny.
func (s *Service) FilterRulesForNode(nodeID types.NodeID) ([]tailcfg.FilterRule, bool) {
	if s == nil {
		return nil, false
	}

	c := s.current.Load()
	if c == nil {
		return nil, false
	}

	return c.Filters[nodeID], true
}

func (c *Compilation) buildFilters() {
	if c.Snapshot == nil {
		return
	}

	nodeIDs := make([]types.NodeID, 0, len(c.Snapshot.Identities))
	for id, ident := range c.Snapshot.Identities {
		if !ident.Deleted {
			nodeIDs = append(nodeIDs, id)
		}
	}

	slices.Sort(nodeIDs)

	c.pairFingerprints = map[Pair]string{}

	for _, dst := range nodeIDs {
		var rules []tailcfg.FilterRule

		for _, src := range nodeIDs {
			if src == dst {
				continue
			}

			srcIdent := c.Snapshot.Identities[src]
			srcIPs := identityIPStrings(srcIdent)
			if len(srcIPs) == 0 {
				continue
			}

			for _, proto := range []int{6, 17} {
				allowed := c.allowedRanges(src, dst, proto)
				if len(allowed) == 0 {
					continue
				}

				dsts := make([]tailcfg.NetPortRange, 0, len(allowed))
				for _, pr := range allowed {
					dsts = append(dsts, tailcfg.NetPortRange{
						IP:    "*",
						Ports: tailcfg.PortRange{First: pr.First, Last: pr.Last},
					})
				}

				rules = append(rules, tailcfg.FilterRule{
					SrcIPs:   srcIPs,
					IPProto:  []int{proto},
					DstPorts: dsts,
				})

				pair := Pair{Source: src, Target: dst}
				c.pairFingerprints[pair] = c.fingerprintRanges(proto, allowed)
			}
		}

		slices.SortFunc(rules, compareFilterRule)
		c.Filters[dst] = rules
	}
}

func identityIPStrings(id Identity) []string {
	out := make([]string, 0, len(id.Addresses))
	for _, addr := range id.Addresses {
		out = append(out, addr.String())
	}

	slices.Sort(out)

	return slices.Compact(out)
}

func compareFilterRule(a, b tailcfg.FilterRule) int {
	if x := slices.Compare(a.IPProto, b.IPProto); x != 0 {
		return x
	}

	return strings.Compare(strings.Join(a.SrcIPs, ","), strings.Join(b.SrcIPs, ","))
}

func (c *Compilation) allowedRanges(src, dst types.NodeID, proto int) []PortRange {
	breakpoints := map[int]struct{}{0: {}, 65536: {}}

	for _, r := range c.Rules {
		if r.Dormant || !r.matchesIdentityProto(src, dst, proto) {
			continue
		}

		for _, pr := range r.PortRanges {
			breakpoints[int(pr.First)] = struct{}{}
			breakpoints[int(pr.Last)+1] = struct{}{}
		}
	}

	points := make([]int, 0, len(breakpoints))
	for p := range breakpoints {
		points = append(points, p)
	}

	slices.Sort(points)

	var allowed []PortRange

	for i := 0; i+1 < len(points); i++ {
		start, end := points[i], points[i+1]-1
		if start < 0 || end > 65535 || start > end {
			continue
		}

		decision, _, _ := c.decide(src, dst, proto, uint16(start))
		if decision != DecisionAllow {
			continue
		}

		r := PortRange{First: uint16(start), Last: uint16(end)}
		if n := len(allowed); n > 0 && allowed[n-1].Last+1 == r.First {
			allowed[n-1].Last = r.Last
		} else {
			allowed = append(allowed, r)
		}
	}

	return allowed
}

func (r CompiledRule) matchesIdentityProto(src, dst types.NodeID, proto int) bool {
	return idSetHas(r.SourceIDs, src) && idSetHas(r.TargetIDs, dst) && func() bool {
		_, ok := r.Protocols[proto]
		return ok
	}()
}

func (c *Compilation) fingerprintRanges(proto int, ranges []PortRange) string {
	parts := []string{fmt.Sprintf("proto=%d", proto)}
	for _, r := range ranges {
		parts = append(parts, r.String())
	}

	return strings.Join(parts, ";")
}

// PairFingerprint returns the deterministic effective port fingerprint for a
// directed pair.
func (c *Compilation) PairFingerprint(p Pair) string {
	if c == nil || c.pairFingerprints == nil {
		return ""
	}

	return c.pairFingerprints[p]
}
