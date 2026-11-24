package state

import (
	"bytes"
	stdjson "encoding/json"
	"fmt"
	"net/netip"

	"github.com/juanfont/headscale/hscontrol/policy/governance"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/juanfont/headscale/hscontrol/types/change"
	"github.com/rs/zerolog/log"
	"github.com/tailscale/hujson"
)

// Governance exposes the additive explanation/recomputation service.
func (s *State) Governance() *governance.Service { return s.governance }

// PreviewGovernancePolicy extracts and trials the governance section without
// storing or installing it.
func (s *State) PreviewGovernancePolicy(pol []byte) (
	*governance.Policy,
	*governance.Compilation,
	*governance.TrialReport,
	error,
) {
	doc, ok, err := extractGovernanceDocument(pol)
	if err != nil {
		return nil, nil, nil, invalidPolicyError{reason: err}
	}

	if !ok {
		return nil, nil, nil, nil //nolint:nilnil // no governance section
	}

	snap, err := s.governanceSnapshot()
	if err != nil {
		return nil, nil, nil, err
	}

	return s.governance.PreviewDocument(doc, snap)
}

// UpdatePolicyWithReport is [State.UpdatePolicy] plus the structured
// governance change report for callers that need counts and reason codes.
func (s *State) UpdatePolicyWithReport(pol []byte) (
	*types.Policy,
	*governance.CommitReport,
	[]change.Change,
	error,
) {
	stored, changes, err := s.UpdatePolicy(pol)
	if err != nil {
		return stored, nil, changes, err
	}

	return stored, s.governance.LastCommitReport(), changes, nil
}

// ExplainGovernance explains a tuple using the current atomic compilation.
func (s *State) ExplainGovernance(req governance.ExplainRequest) (*governance.Explanation, error) {
	c := s.governance.Current()
	if c == nil {
		return nil, &governance.ValidationError{Issues: []governance.Issue{{
			Class:   governance.ClassInvalidPolicy,
			Code:    governance.ReasonInvalidPolicy,
			Message: "governance policy is not active",
		}}}
	}

	return c.Explain(req)
}

// governanceSnapshot builds the current identity/node universe used for
// trial compilation and explanation.
func (s *State) governanceSnapshot() (*governance.Snapshot, error) {
	users, err := s.ListAllUsers()
	if err != nil {
		return nil, fmt.Errorf("loading users for governance: %w", err)
	}

	userByID := make(map[types.UserID]types.User, len(users))
	for _, u := range users {
		userByID[types.UserID(u.ID)] = u
	}

	nodes := s.ListNodes()
	ids := make([]governance.Identity, 0, nodes.Len())

	for _, node := range nodes.All() {
		uid := node.TypedUserID()

		var userName, email string

		if u, ok := userByID[uid]; ok {
			userName = u.Name
			email = u.Email
		}

		var tags []string

		for _, tag := range node.Tags().All() {
			tags = append(tags, tag)
		}

		var addrs []netip.Addr

		addrs = append(addrs, node.IPs()...)

		ids = append(ids, governance.Identity{
			NodeID:     node.ID(),
			StableID:   string(node.ID().StableID()),
			Name:       node.Hostname(),
			UserID:     uid,
			UserName:   userName,
			Email:      email,
			Tags:       tags,
			Tagged:     node.IsTagged(),
			Unassigned: len(tags) == 0,
			Addresses:  addrs,
		})
	}

	return governance.NewSnapshot(ids), nil
}

// ValidateGovernancePolicy strictly validates and tries only the governance
// section embedded in pol. It does not mutate live state.
func (s *State) ValidateGovernancePolicy(pol []byte) error {
	doc, ok, err := extractGovernanceDocument(pol)
	if err != nil {
		return invalidPolicyError{reason: err}
	}

	if !ok {
		return nil
	}

	snap, err := s.governanceSnapshot()
	if err != nil {
		return err
	}

	_, _, _, err = s.governance.PreviewDocument(doc, snap)
	if err != nil {
		return invalidPolicyError{reason: err}
	}

	return nil
}

func (s *State) applyGovernancePolicyLocked(pol []byte) *governance.CommitReport {
	s.lastGovernanceReport = nil

	doc, ok, err := extractGovernanceDocument(pol)
	if err != nil {
		log.Warn().Err(err).Msg("could not extract governance document")
		return nil
	}

	if !ok {
		s.governance.Reset()
		return nil
	}

	snap, err := s.governanceSnapshot()
	if err != nil {
		log.Error().Err(err).Msg("could not build governance snapshot")
		return nil
	}

	report, dormant, err := s.governance.ReloadDocument(doc, snap)
	if err != nil {
		log.Error().Err(err).Msg("governance reload failed; keeping previous compilation")
		return nil
	}

	if len(dormant) > 0 {
		log.Warn().Int("rules", len(dormant)).Msg("governance rules are dormant because identities are missing")
	}

	s.lastGovernanceReport = report

	return report
}

// InvalidateSSHCheckAuthPairs removes only confirmed SSH authorizations for
// the supplied directed node pairs and returns how many entries were removed.
func (s *State) InvalidateSSHCheckAuthPairs(pairs ...governance.Pair) int {
	if len(pairs) == 0 {
		return 0
	}

	wanted := make(map[sshCheckPair]struct{}, len(pairs))
	for _, p := range pairs {
		wanted[sshCheckPair{Src: p.Source, Dst: p.Target}] = struct{}{}
	}

	s.sshCheckMu.Lock()
	defer s.sshCheckMu.Unlock()

	removed := 0

	for pair := range s.sshCheckAuth {
		if _, ok := wanted[pair]; ok {
			delete(s.sshCheckAuth, pair)
			removed++
		}
	}

	return removed
}

// invalidateGovernanceAuth reevaluates stored SSH confirmations against the
// new compilation. In incremental mode only changed pairs are touched. Full
// recompute mode checks every stored pair but still deletes only entries the
// new policy no longer authorizes.
func (s *State) invalidateGovernanceAuth(report *governance.CommitReport) int {
	if report == nil {
		return 0
	}

	if report.RecomputeMode == "incremental" && !report.Degraded {
		return s.InvalidateSSHCheckAuthPairs(report.ChangedPairs...)
	}

	c := s.governance.Current()
	if c == nil {
		return s.ClearSSHCheckAuthCounted()
	}

	s.sshCheckMu.Lock()
	defer s.sshCheckMu.Unlock()

	removed := 0

	for pair := range s.sshCheckAuth {
		ex, explainErr := c.Explain(governance.ExplainRequest{
			SourceNode: pair.Src, TargetNode: pair.Dst, Protocol: "tcp", Port: 22,
		})
		if explainErr != nil || ex == nil || ex.Decision == governance.DecisionDeny {
			delete(s.sshCheckAuth, pair)
			removed++
		}
	}

	return removed
}

// ClearSSHCheckAuthCounted is the counted form of ClearSSHCheckAuth.
func (s *State) ClearSSHCheckAuthCounted() int {
	s.sshCheckMu.Lock()
	defer s.sshCheckMu.Unlock()

	n := len(s.sshCheckAuth)
	s.sshCheckAuth = make(map[sshCheckPair]sshCheckAuthRecord)

	return n
}

func extractGovernanceDocument(pol []byte) ([]byte, bool, error) {
	if len(bytes.TrimSpace(pol)) == 0 {
		return nil, false, nil
	}

	ast, err := hujson.Parse(bytes.Clone(pol))
	if err != nil {
		return nil, false, fmt.Errorf("parsing policy HuJSON: %w", err)
	}

	ast.Standardize()

	var envelope struct {
		Governance stdjson.RawMessage `json:"governance"`
	}

	if err := stdjson.Unmarshal(ast.Pack(), &envelope); err != nil {
		return nil, false, fmt.Errorf("decoding governance section: %w", err)
	}

	if len(bytes.TrimSpace(envelope.Governance)) == 0 ||
		bytes.Equal(bytes.TrimSpace(envelope.Governance), []byte("null")) {
		return nil, false, nil
	}

	return envelope.Governance, true, nil
}
