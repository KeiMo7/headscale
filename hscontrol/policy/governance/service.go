package governance

import (
	"slices"
	"sync"
	"sync/atomic"

	"github.com/juanfont/headscale/hscontrol/types"
)

// PortChange is one changed source/target/port coordinate or contiguous range
// of coordinates. Code is always populated, including for deny and marked
// changes.
type PortChange struct {
	Source   types.NodeID `json:"source"`
	Target   types.NodeID `json:"target"`
	Protocol string       `json:"protocol"`
	Ports    PortRange    `json:"ports"`
	Kind     string       `json:"kind"` // added | removed

	Before Decision `json:"before"`
	After  Decision `json:"after"`

	Code    ReasonCode `json:"reason_code"`
	RuleID  string     `json:"rule_id,omitempty"`
	Markers []string   `json:"markers,omitempty"`
}

// Count is the number of individual port coordinates in the change.
func (c PortChange) Count() int { return c.Ports.Count() }

// CommitReport describes a committed candidate and its incremental effect.
type CommitReport struct {
	Version         uint64 `json:"version"`
	PreviousVersion uint64 `json:"previous_version"`

	// RecomputeMode is "incremental" or "full".
	RecomputeMode string     `json:"recompute_mode"`
	Degraded      bool       `json:"degraded,omitempty"`
	DegradeReason ReasonCode `json:"degrade_reason,omitempty"`

	Changes      []PortChange `json:"changes"`
	ChangeCount  int          `json:"change_count"`
	ChangedPairs []Pair       `json:"changed_pairs"`

	// AffectedNodes contains both endpoints of changed coordinates.
	AffectedNodes []types.NodeID `json:"affected_nodes"`
	// RefreshNodes are inbound filter owners; today that is destination nodes.
	RefreshNodes []types.NodeID `json:"refresh_nodes"`

	AffectedNodeCount         int `json:"affected_node_count"`
	InvalidatedAuthorizations int `json:"invalidated_authorizations"`

	DormantRules []Issue `json:"dormant_rules,omitempty"`

	PairRecomputeCounts map[Pair]uint64 `json:"-"`
	PairVersions        map[Pair]uint64 `json:"-"`
}

// TrialReport is the non-mutating result of trying a compilation against the
// current identity snapshot.
type TrialReport struct {
	Pairs        int `json:"pairs"`
	Checks       int `json:"checks"`
	Allows       int `json:"allows"`
	Denies       int `json:"denies"`
	DormantRules int `json:"dormant_rules"`
}

// Service owns the atomic current compilation and per-pair recompute state.
type Service struct {
	mu      sync.Mutex
	current atomic.Pointer[Compilation]
	version uint64

	pairVersion map[Pair]uint64
	pairCounts  map[Pair]uint64

	fullRecomputes     atomic.Uint64
	degradedRecomputes atomic.Uint64

	lastReport *CommitReport
}

// NewService creates an empty governance service.
func NewService() *Service {
	return &Service{
		pairVersion: map[Pair]uint64{},
		pairCounts:  map[Pair]uint64{},
	}
}

// Current returns the immutable compilation. Readers must not mutate it.
func (s *Service) Current() *Compilation { return s.current.Load() }

// Version returns the committed governance version.
func (s *Service) Version() uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.version
}

// LastCommitReport returns the most recent commit report.
func (s *Service) LastCommitReport() *CommitReport {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.lastReport
}

// PairVersion returns the version at which this pair last changed. An
// unchanged pair keeps its previous value across unrelated commits.
func (s *Service) PairVersion(p Pair) uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.pairVersion[p]
}

// RecomputeCount returns how many incremental recomputes affected this pair.
func (s *Service) RecomputeCount(p Pair) uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.pairCounts[p]
}

// FullRecomputeCount counts initial/full recomputes.
func (s *Service) FullRecomputeCount() uint64 { return s.fullRecomputes.Load() }

// DegradedRecomputeCount counts identity-snapshot fallback full recomputes.
func (s *Service) DegradedRecomputeCount() uint64 { return s.degradedRecomputes.Load() }

// PreviewDocument parses, validates, compiles and tries a candidate without
// installing it or advancing the version.
func (s *Service) PreviewDocument(b []byte, snap *Snapshot) (*Policy, *Compilation, *TrialReport, error) {
	pol, err := ParsePolicy(b)
	if err != nil {
		return nil, nil, nil, err
	}

	c, err := Compile(pol, snap)
	if err != nil {
		return pol, nil, nil, err
	}

	trial := Trial(c)

	return pol, c, &trial, nil
}

// Trial evaluates representative port segments for every active node pair.
func Trial(c *Compilation) TrialReport {
	var out TrialReport
	if c == nil || c.Snapshot == nil {
		return out
	}

	ids := make([]types.NodeID, 0, len(c.Snapshot.Identities))
	for id, ident := range c.Snapshot.Identities {
		if !ident.Deleted {
			ids = append(ids, id)
		}
	}

	slices.Sort(ids)

	for _, r := range c.Rules {
		if r.Dormant {
			out.DormantRules++
		}
	}

	for _, src := range ids {
		for _, dst := range ids {
			if src == dst {
				continue
			}

			out.Pairs++

			for _, proto := range []int{6, 17} {
				ranges := c.atomicRanges(src, dst, proto)
				for _, pr := range ranges {
					out.Checks++

					decision, _, _ := c.decide(src, dst, proto, pr.First)
					switch decision {
					case DecisionAllow:
						out.Allows++
					default:
						out.Denies++
					}
				}
			}
		}
	}

	return out
}

// CommitDocument validates and atomically installs a candidate. Invalid input
// returns before the current pointer, version or pair counters are touched.
func (s *Service) CommitDocument(b []byte, snap *Snapshot) (*CommitReport, error) {
	pol, err := ParsePolicy(b)
	if err != nil {
		return nil, err
	}

	c, err := Compile(pol, snap)
	if err != nil {
		return nil, err
	}

	return s.install(c, nil), nil
}

// ReloadDocument installs stored bytes, tolerating references made dormant by
// identity deletion. It is used by process/policy reload paths.
func (s *Service) ReloadDocument(b []byte, snap *Snapshot) (*CommitReport, []Issue, error) {
	pol, err := ParsePolicy(b)
	if err != nil {
		return nil, nil, err
	}

	c, dormant := CompileForReload(pol, snap)
	report := s.install(c, dormant)

	return report, dormant, nil
}

// Reset removes governance enforcement, for legacy policies without a
// governance document.
func (s *Service) Reset() {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.current.Store(nil)
	s.lastReport = nil
}

func (s *Service) install(c *Compilation, dormant []Issue) *CommitReport {
	s.mu.Lock()
	defer s.mu.Unlock()

	old := s.current.Load()
	previousVersion := s.version

	s.version++
	c.Version = s.version

	report := &CommitReport{
		Version:         c.Version,
		PreviousVersion: previousVersion,
		DormantRules:    dormant,
	}

	switch {
	case old == nil:
		report.RecomputeMode = "full"
		report.DegradeReason = ReasonFullRecomputeNoPrevious
		s.fullRecomputes.Add(1)
	case old.SnapshotHash != c.SnapshotHash:
		report.RecomputeMode = "full"
		report.Degraded = true
		report.DegradeReason = ReasonFullRecomputeSnapshotChanged
		s.fullRecomputes.Add(1)
		s.degradedRecomputes.Add(1)

		report.Changes = Diff(old, c)
	default:
		report.RecomputeMode = "incremental"
		report.Changes = Diff(old, c)
	}

	report.ChangeCount = 0
	pairSet := map[Pair]struct{}{}
	nodeSet := map[types.NodeID]struct{}{}
	refreshSet := map[types.NodeID]struct{}{}

	for _, change := range report.Changes {
		report.ChangeCount += change.Count()
		p := Pair{Source: change.Source, Target: change.Target}
		pairSet[p] = struct{}{}
		nodeSet[change.Source] = struct{}{}
		nodeSet[change.Target] = struct{}{}
		refreshSet[change.Target] = struct{}{}
	}

	// On a full recompute, every active destination filter is re-rendered,
	// including nodes whose effective list is empty/default-deny.
	if report.RecomputeMode == "full" && c.Snapshot != nil {
		for id, ident := range c.Snapshot.Identities {
			if ident.Deleted {
				continue
			}

			nodeSet[id] = struct{}{}
			refreshSet[id] = struct{}{}
		}

		for p := range c.pairFingerprints {
			pairSet[p] = struct{}{}
			nodeSet[p.Source] = struct{}{}
			nodeSet[p.Target] = struct{}{}
		}
	}

	report.ChangedPairs = sortedPairSet(pairSet)
	report.AffectedNodes = sortedNodeSet(nodeSet)
	report.RefreshNodes = sortedNodeSet(refreshSet)
	report.AffectedNodeCount = len(report.AffectedNodes)

	if s.pairVersion == nil {
		s.pairVersion = map[Pair]uint64{}
	}

	if s.pairCounts == nil {
		s.pairCounts = map[Pair]uint64{}
	}

	report.PairVersions = map[Pair]uint64{}
	report.PairRecomputeCounts = map[Pair]uint64{}

	for p := range pairSet {
		s.pairCounts[p]++
		s.pairVersion[p] = c.Version
	}

	// Populate read-only snapshots for callers/tests. Unchanged pairs are
	// present with their prior values when known.
	for p, v := range s.pairVersion {
		report.PairVersions[p] = v
		report.PairRecomputeCounts[p] = s.pairCounts[p]
	}

	s.lastReport = report
	s.current.Store(c)

	return report
}

func sortedPairSet(in map[Pair]struct{}) []Pair {
	out := make([]Pair, 0, len(in))
	for p := range in {
		out = append(out, p)
	}

	slices.SortFunc(out, func(a, b Pair) int {
		if a.Source != b.Source {
			return int(a.Source - b.Source)
		}

		return int(a.Target - b.Target)
	})

	return out
}

func sortedNodeSet(in map[types.NodeID]struct{}) []types.NodeID {
	out := make([]types.NodeID, 0, len(in))
	for id := range in {
		out = append(out, id)
	}

	slices.Sort(out)

	return out
}
