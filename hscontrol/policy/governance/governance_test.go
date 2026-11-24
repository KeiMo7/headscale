package governance_test

import (
	"testing"

	"github.com/juanfont/headscale/hscontrol/policy/governance"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"net/netip"
)

func testSnapshot() *governance.Snapshot {
	snap := governance.NewSnapshot([]governance.Identity{
		{
			NodeID: 1, Name: "alice", UserID: 101, UserName: "alice",
			Groups:    []string{"group:eng"},
			Addresses: []netip.Addr{netip.MustParseAddr("100.64.0.1")},
		},
		{
			NodeID: 2, Name: "bob", UserID: 102, UserName: "bob",
			Tags:      []string{"tag:web"},
			Tagged:    true,
			Addresses: []netip.Addr{netip.MustParseAddr("100.64.0.2")},
		},
		{
			NodeID: 3, Name: "carol", UserID: 103, UserName: "carol",
			Unassigned: true,
			Addresses:  []netip.Addr{netip.MustParseAddr("100.64.0.3")},
		},
		{
			NodeID: 4, Name: "dave", UserID: 104, UserName: "dave",
			Groups:    []string{"group:sales"},
			Addresses: []netip.Addr{netip.MustParseAddr("100.64.0.4")},
		},
		{
			NodeID: 99, Name: "gone", Deleted: true,
		},
	})

	return snap
}

func TestExplainTableDrivenReasonCodes(t *testing.T) {
	t.Parallel()

	snap := testSnapshot()

	allowLogPolicy := &governance.Policy{Rules: []governance.Rule{{
		ID: "allow-log", Priority: 100, Actions: []string{"allow", "log"},
		Markers: []string{"audit"}, Sources: []string{"group:eng"},
		Destinations: []string{"tag:web"}, Ports: []governance.PortRange{governance.SinglePort(443)},
	}}}

	comp, err := governance.Compile(allowLogPolicy, snap)
	require.NoError(t, err)

	tests := []struct {
		name         string
		req          governance.ExplainRequest
		wantDecision governance.Decision
		wantCode     governance.ReasonCode
		wantClass    governance.ErrorClass
		wantErr      bool
	}{
		{
			name: "allow and record combination",
			req: governance.ExplainRequest{
				SourceNode: 1, TargetNode: 2, Port: 443,
			},
			wantDecision: governance.DecisionAllow,
			wantCode:     governance.ReasonAllowRule,
		},
		{
			name: "default deny source side",
			req: governance.ExplainRequest{
				SourceNode: 4, TargetNode: 2, Port: 443,
			},
			wantDecision: governance.DecisionDeny,
			wantCode:     governance.ReasonDefaultDenyNoSourceCoverage,
		},
		{
			name: "default deny target side",
			req: governance.ExplainRequest{
				SourceNode: 1, TargetNode: 3, Port: 443,
			},
			wantDecision: governance.DecisionDeny,
			wantCode:     governance.ReasonDefaultDenyNoTargetCoverage,
		},
		{
			name: "default deny port side",
			req: governance.ExplainRequest{
				SourceNode: 1, TargetNode: 2, Port: 80,
			},
			wantDecision: governance.DecisionDeny,
			wantCode:     governance.ReasonDefaultDenyNoPortCoverage,
		},
		{
			name: "unknown node identity is not a deny",
			req: governance.ExplainRequest{
				SourceNode: 1, TargetNode: 404, Port: 443,
			},
			wantErr:   true,
			wantClass: governance.ClassIdentityUnknown,
		},
		{
			name: "deleted identity is unknown",
			req: governance.ExplainRequest{
				SourceNode: 1, TargetNode: 99, Port: 443,
			},
			wantErr:   true,
			wantClass: governance.ClassIdentityUnknown,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			ex, err := comp.Explain(tt.req)
			if tt.wantErr {
				require.Error(t, err)
				assert.True(t, governance.IsClass(err, tt.wantClass), "error %v should class %s", err, tt.wantClass)
				assert.Nil(t, ex)
				return
			}

			require.NoError(t, err)
			require.NotNil(t, ex)
			assert.Equal(t, tt.wantDecision, ex.Decision)
			assert.Equal(t, tt.wantCode, ex.Code)
			assert.NotEmpty(t, ex.Message)
			assert.NotContains(t, ex.Message, "100.64.")
		})
	}

	t.Run("unassigned identity unknown", func(t *testing.T) {
		t.Parallel()

		strictSnap := testSnapshot()
		strictSnap.RequireAssignment = true
		strictComp, err := governance.Compile(allowLogPolicy, strictSnap)
		require.NoError(t, err)

		_, err = strictComp.Explain(governance.ExplainRequest{SourceNode: 1, TargetNode: 3, Port: 443})
		require.Error(t, err)
		assert.True(t, governance.IsClass(err, governance.ClassIdentityUnknown))
	})
}

func TestPriorityDenyAndConflict(t *testing.T) {
	t.Parallel()

	snap := testSnapshot()

	t.Run("higher priority deny wins deterministically", func(t *testing.T) {
		t.Parallel()

		pol := &governance.Policy{Rules: []governance.Rule{
			{ID: "allow-low", Priority: 10, Actions: []string{"allow"}, Sources: []string{"*"}, Destinations: []string{"*"}, Ports: []governance.PortRange{governance.AllPorts()}},
			{ID: "deny-high", Priority: 100, Actions: []string{"deny"}, Markers: []string{"audit"}, Sources: []string{"user:alice"}, Destinations: []string{"tag:web"}, Ports: []governance.PortRange{governance.SinglePort(22)}},
		}}

		comp, err := governance.Compile(pol, snap)
		require.NoError(t, err)

		ex, err := comp.Explain(governance.ExplainRequest{SourceNode: 1, TargetNode: 2, Port: 22})
		require.NoError(t, err)
		assert.Equal(t, governance.DecisionDeny, ex.Decision)
		assert.Equal(t, "deny-high", ex.RuleID)
		assert.Equal(t, governance.ReasonDenyRule, ex.Code)
		assert.Contains(t, ex.Markers, "audit")

		ex80, err := comp.Explain(governance.ExplainRequest{SourceNode: 1, TargetNode: 2, Port: 80})
		require.NoError(t, err)
		assert.Equal(t, governance.DecisionAllow, ex80.Decision)
	})

	t.Run("equal priority conflict rejected with both rules", func(t *testing.T) {
		t.Parallel()

		pol := &governance.Policy{Rules: []governance.Rule{
			{ID: "a", Priority: 50, Actions: []string{"allow"}, Sources: []string{"user:101"}, Destinations: []string{"user:102"}, Ports: []governance.PortRange{governance.SinglePort(22)}},
			{ID: "b", Priority: 50, Actions: []string{"deny"}, Sources: []string{"user:alice"}, Destinations: []string{"tag:web"}, Ports: []governance.PortRange{governance.SinglePort(22)}},
		}}

		_, err := governance.Compile(pol, snap)
		require.Error(t, err)
		assert.True(t, governance.IsClass(err, governance.ClassConflict))

		var ve *governance.ValidationError
		require.ErrorAs(t, err, &ve)
		require.NotEmpty(t, ve.Issues)
		assert.Equal(t, governance.ReasonEqualPriorityConflict, ve.Issues[0].Code)
		assert.ElementsMatch(t, []string{"a", "b"}, ve.Issues[0].Rules)
	})

	t.Run("non-strict equal tie is reproducible deny", func(t *testing.T) {
		t.Parallel()

		nonStrict := false
		pol := &governance.Policy{RejectEqualPriorityConflicts: &nonStrict, Rules: []governance.Rule{
			{ID: "allow-tie", Priority: 50, Actions: []string{"allow"}, Sources: []string{"*"}, Destinations: []string{"*"}, Ports: []governance.PortRange{governance.SinglePort(22)}},
			{ID: "deny-tie", Priority: 50, Actions: []string{"deny"}, Sources: []string{"*"}, Destinations: []string{"*"}, Ports: []governance.PortRange{governance.SinglePort(22)}},
		}}

		comp1, err := governance.Compile(pol, snap)
		require.NoError(t, err)

		comp2, err := governance.Compile(pol, snap)
		require.NoError(t, err)

		ex1, err := comp1.Explain(governance.ExplainRequest{SourceNode: 1, TargetNode: 2, Port: 22})
		require.NoError(t, err)

		ex2, err := comp2.Explain(governance.ExplainRequest{SourceNode: 1, TargetNode: 2, Port: 22})
		require.NoError(t, err)

		assert.Equal(t, governance.DecisionDeny, ex1.Decision)
		assert.Equal(t, "deny-tie", ex1.RuleID)
		assert.Equal(t, ex1.RuleID, ex2.RuleID)
	})
}

func TestInvalidInputClassification(t *testing.T) {
	t.Parallel()

	snap := testSnapshot()

	tests := []struct {
		name       string
		policyJSON string
		wantClass  governance.ErrorClass
	}{
		{
			name:       "unknown action",
			policyJSON: `{"rules":[{"id":"x","actions":["drop"],"src":["*"],"dst":["*"],"ports":[80]}]}`,
			wantClass:  governance.ClassInvalidAction,
		},
		{
			name:       "undefined identity",
			policyJSON: `{"rules":[{"id":"x","actions":["allow"],"src":["user:nobody"],"dst":["tag:web"],"ports":[80]}]}`,
			wantClass:  governance.ClassUndefinedIdentity,
		},
		{
			name:       "port out of range",
			policyJSON: `{"rules":[{"id":"x","actions":["allow"],"src":["*"],"dst":["*"],"ports":[70000]}]}`,
			wantClass:  governance.ClassPortOutOfRange,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			svc := governance.NewService()
			_, _, _, err := svc.PreviewDocument([]byte(tt.policyJSON), snap)
			require.Error(t, err)
			assert.True(t, governance.IsClass(err, tt.wantClass), "err=%v", err)
		})
	}
}

func TestIncrementalOnlyAffectedPairRecomputes(t *testing.T) {
	t.Parallel()

	snap := testSnapshot()
	svc := governance.NewService()

	v1 := []byte(`{"rules":[
		{"id":"alice-bob","priority":100,"actions":["allow"],"src":["user:101"],"dst":["user:102"],"ports":[80,443]},
		{"id":"alice-carol","priority":100,"actions":["allow"],"src":["user:101"],"dst":["user:103"],"ports":["1-65535"]}
	]}`)

	r1, err := svc.CommitDocument(v1, snap)
	require.NoError(t, err)
	require.Equal(t, "full", r1.RecomputeMode)

	ab := governance.Pair{Source: types.NodeID(1), Target: types.NodeID(2)}
	ac := governance.Pair{Source: types.NodeID(1), Target: types.NodeID(3)}

	acVersionBefore := svc.PairVersion(ac)
	acCountBefore := svc.RecomputeCount(ac)
	abVersionBefore := svc.PairVersion(ab)

	v2 := []byte(`{"rules":[
		{"id":"alice-bob-443","priority":100,"actions":["allow"],"src":["user:101"],"dst":["user:102"],"ports":[443]},
		{"id":"alice-bob-deny-80","priority":200,"actions":["deny","log"],"markers":["http-blocked"],"src":["user:101"],"dst":["user:102"],"ports":[80]},
		{"id":"alice-carol","priority":100,"actions":["allow"],"src":["user:101"],"dst":["user:103"],"ports":["1-65535"]}
	]}`)

	r2, err := svc.CommitDocument(v2, snap)
	require.NoError(t, err)
	assert.Equal(t, "incremental", r2.RecomputeMode)
	assert.Equal(t, uint64(2), r2.Version)

	assert.Equal(t, acVersionBefore, svc.PairVersion(ac), "unaffected pair version unchanged")
	assert.Equal(t, acCountBefore, svc.RecomputeCount(ac), "unaffected pair recompute count unchanged")
	assert.Equal(t, r1.Version, acVersionBefore)
	assert.Equal(t, uint64(1), acCountBefore)

	assert.Equal(t, r2.Version, svc.PairVersion(ab))
	assert.Greater(t, svc.PairVersion(ab), abVersionBefore)
	assert.Equal(t, uint64(2), svc.RecomputeCount(ab))

	require.Len(t, r2.ChangedPairs, 1)
	assert.Equal(t, ab, r2.ChangedPairs[0])
	assert.Equal(t, 1, r2.ChangeCount)
	assert.ElementsMatch(t, []types.NodeID{1, 2}, r2.AffectedNodes)
	assert.Equal(t, []types.NodeID{2}, r2.RefreshNodes)
	require.NotEmpty(t, r2.Changes)

	change := r2.Changes[0]
	assert.Equal(t, uint16(80), change.Ports.First)
	assert.Equal(t, governance.DecisionAllow, change.Before)
	assert.Equal(t, governance.DecisionDeny, change.After)
	assert.Equal(t, governance.ReasonDenyRule, change.Code)
	assert.Equal(t, "alice-bob-deny-80", change.RuleID)
	assert.Contains(t, change.Markers, "http-blocked")

	rules, active := svc.FilterRulesForNode(2)
	require.True(t, active)
	require.NotEmpty(t, rules)

	var ports []uint16
	for _, rule := range rules {
		for _, d := range rule.DstPorts {
			if d.Ports.First == d.Ports.Last {
				ports = append(ports, d.Ports.First)
			}
		}
	}

	assert.Contains(t, ports, uint16(443))
	assert.NotContains(t, ports, uint16(80))
}

func TestFailedCommitDoesNotAdvanceVersion(t *testing.T) {
	t.Parallel()

	snap := testSnapshot()
	svc := governance.NewService()

	good := []byte(`{"rules":[{"id":"good","actions":["allow"],"src":["*"],"dst":["*"],"ports":[443]}]}`)
	r1, err := svc.CommitDocument(good, snap)
	require.NoError(t, err)

	bad := []byte(`{"rules":[{"id":"bad","actions":["teleport"],"src":["*"],"dst":["*"],"ports":[443]}]}`)
	_, err = svc.CommitDocument(bad, snap)
	require.Error(t, err)

	assert.Equal(t, r1.Version, svc.Version())
	assert.Equal(t, r1.Version, svc.Current().Version)

	ex, err := svc.Current().Explain(governance.ExplainRequest{SourceNode: 1, TargetNode: 2, Port: 443})
	require.NoError(t, err)
	assert.Equal(t, "good", ex.RuleID)
}

func TestSnapshotChangeFallsBackToObservableFullRecompute(t *testing.T) {
	t.Parallel()

	snap1 := testSnapshot()
	svc := governance.NewService()
	doc := []byte(`{"rules":[{"id":"allow","actions":["allow"],"src":["*"],"dst":["*"],"ports":[443]}]}`)

	first, err := svc.CommitDocument(doc, snap1)
	require.NoError(t, err)
	require.Equal(t, "full", first.RecomputeMode)
	require.False(t, first.Degraded)

	snap2 := testSnapshot()
	snap2.Identities[1] = func() governance.Identity {
		id := snap2.Identities[1]
		id.Addresses = append(id.Addresses, netip.MustParseAddr("100.64.0.250"))
		return id
	}()
	snap2.RecalculateHash()

	second, err := svc.CommitDocument(doc, snap2)
	require.NoError(t, err)
	require.Equal(t, "full", second.RecomputeMode)
	require.True(t, second.Degraded)
	assert.Equal(t, governance.ReasonFullRecomputeSnapshotChanged, second.DegradeReason)
	assert.Equal(t, uint64(1), svc.DegradedRecomputeCount())
	assert.Greater(t, svc.FullRecomputeCount(), uint64(1))
}

func TestReloadMissingIdentityMakesRuleDormant(t *testing.T) {
	t.Parallel()

	snap := testSnapshot()
	doc := &governance.Policy{Rules: []governance.Rule{{
		ID: "deleted-group-rule", Actions: []string{"deny"},
		Sources: []string{"group:deleted"}, Destinations: []string{"tag:web"},
		Ports: []governance.PortRange{governance.SinglePort(22)},
	}}}

	comp, dormant := governance.CompileForReload(doc, snap)
	require.NotNil(t, comp)
	require.Len(t, dormant, 1)
	assert.Equal(t, governance.ReasonDormantUndefinedIdentity, dormant[0].Code)
	require.Len(t, comp.Rules, 1)
	assert.True(t, comp.Rules[0].Dormant)

	ex, err := comp.Explain(governance.ExplainRequest{SourceNode: 1, TargetNode: 2, Port: 22})
	require.NoError(t, err)
	assert.True(t, ex.DefaultDeny)
	assert.NotEqual(t, "deleted-group-rule", ex.RuleID)
}
