package servertest_test

import (
	"fmt"
	"testing"
	"time"

	"github.com/juanfont/headscale/hscontrol/policy/governance"
	"github.com/juanfont/headscale/hscontrol/servertest"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/stretchr/testify/require"
	"go4.org/netipx"
	"tailscale.com/types/logger"
	"tailscale.com/types/netmap"
	"tailscale.com/wgengine/filter"
)

func governancePolicyV1(alice, bob, carol uint) []byte {
	return fmt.Appendf(nil, `{
		"acls": [{"action":"accept","src":["*"],"dst":["*:*"]}],
		"governance": {"rules": [
			{"id":"alice-to-bob-web","priority":100,"actions":["allow"],"src":["user:%d"],"dst":["user:%d"],"ports":[80,443]},
			{"id":"alice-to-carol-all","priority":100,"actions":["allow"],"src":["user:%d"],"dst":["user:%d"],"ports":["0-65535"]}
		]}
	}`, alice, bob, alice, carol)
}

func governancePolicyV2(alice, bob, carol uint) []byte {
	return fmt.Appendf(nil, `{
		"acls": [{"action":"accept","src":["*"],"dst":["*:*"]}],
		"governance": {"rules": [
			{"id":"alice-to-bob-https","priority":100,"actions":["allow","log"],"markers":["web-audit"],"src":["user:%d"],"dst":["user:%d"],"ports":[443]},
			{"id":"alice-to-bob-http-deny","priority":200,"actions":["deny","log"],"markers":["http-blocked"],"src":["user:%d"],"dst":["user:%d"],"ports":[80]},
			{"id":"alice-to-carol-all","priority":100,"actions":["allow"],"src":["user:%d"],"dst":["user:%d"],"ports":["0-65535"]}
		]}
	}`, alice, bob, alice, bob, alice, carol)
}

func TestGovernanceTightenIncrementalAuthAndAtomicity(t *testing.T) {
	t.Parallel()

	srv := servertest.NewServer(t)
	st := srv.State()

	aliceUser := srv.CreateUser(t, "gov-alice")
	bobUser := srv.CreateUser(t, "gov-bob")
	carolUser := srv.CreateUser(t, "gov-carol")

	alice := servertest.NewClient(t, srv, "gov-alice-node", servertest.WithUser(aliceUser))
	bob := servertest.NewClient(t, srv, "gov-bob-node", servertest.WithUser(bobUser))
	carol := servertest.NewClient(t, srv, "gov-carol-node", servertest.WithUser(carolUser))

	alice.WaitForPeers(t, 2, 15*time.Second)
	bob.WaitForPeers(t, 2, 15*time.Second)
	carol.WaitForPeers(t, 2, 15*time.Second)

	policyV1 := governancePolicyV1(aliceUser.ID, bobUser.ID, carolUser.ID)
	_, changes, err := st.UpdatePolicy(policyV1)
	require.NoError(t, err)
	srv.App.Change(changes...)

	aliceID := types.NodeID(alice.Netmap().SelfNode.ID())
	bobID := types.NodeID(bob.Netmap().SelfNode.ID())
	carolID := types.NodeID(carol.Netmap().SelfNode.ID())

	ab := governance.Pair{Source: aliceID, Target: bobID}
	ac := governance.Pair{Source: aliceID, Target: carolID}

	waitTCPPort := func(dst *servertest.TestClient, port uint16, want filter.Response) {
		t.Helper()

		dst.WaitForCondition(t, fmt.Sprintf("tcp/%d=%v", port, want), 15*time.Second,
			func(nm *netmap.NetworkMap) bool {
				return filterHasVerdict(t, alice, port, want, nm)
			})
	}

	waitTCPPort(bob, 80, filter.Accept)
	waitTCPPort(bob, 443, filter.Accept)
	waitTCPPort(carol, 443, filter.Accept)

	// Long-lived SSH/check confirmations are keyed by node pair.
	st.SetLastSSHAuth(aliceID, bobID)
	st.SetLastSSHAuth(aliceID, carolID)
	_, bobAuth := st.GetLastSSHAuth(aliceID, bobID)
	_, carolAuth := st.GetLastSSHAuth(aliceID, carolID)
	require.True(t, bobAuth)
	require.True(t, carolAuth)

	acVersionBefore := st.Governance().PairVersion(ac)
	acCountBefore := st.Governance().RecomputeCount(ac)
	carolRulesBefore, carolGoverned := st.Governance().FilterRulesForNode(carolID)
	require.True(t, carolGoverned)

	policyV2 := governancePolicyV2(aliceUser.ID, bobUser.ID, carolUser.ID)
	stored, report, changes, err := st.UpdatePolicyWithReport(policyV2)
	require.NoError(t, err)
	require.NotNil(t, stored)
	require.NotNil(t, report)
	require.Equal(t, "incremental", report.RecomputeMode)
	// One port loses access (80); 443 stays allowed but gains record markers.
	require.Equal(t, 2, report.ChangeCount)
	require.Equal(t, []governance.Pair{ab}, report.ChangedPairs)
	require.Equal(t, []types.NodeID{bobID}, report.RefreshNodes)
	require.Equal(t, 1, report.InvalidatedAuthorizations)
	require.Len(t, changes, 1, "only Bob's inbound filter should be refreshed")
	require.Equal(t, bobID, changes[0].TargetNode)
	require.True(t, changes[0].IncludePolicy)
	require.False(t, changes[0].RequiresRuntimePeerComputation)

	srv.App.Change(changes...)

	waitTCPPort(bob, 443, filter.Accept)
	waitTCPPort(bob, 80, filter.Drop)

	// The removed Bob confirmation is gone; the unrelated Carol one survives.
	_, bobAuth = st.GetLastSSHAuth(aliceID, bobID)
	_, carolAuth = st.GetLastSSHAuth(aliceID, carolID)
	require.False(t, bobAuth, "removed authorization must require confirmation again")
	require.True(t, carolAuth, "unrelated authorization must not be cleared")

	require.Equal(t, acVersionBefore, st.Governance().PairVersion(ac))
	require.Equal(t, acCountBefore, st.Governance().RecomputeCount(ac))

	// The change is targeted at Bob. Carol's pair counters do not move and
	// her compiled allow-list stays byte-equivalent.
	carolRulesAfter, _ := st.Governance().FilterRulesForNode(carolID)
	require.Equal(t, carolRulesBefore, carolRulesAfter,
		"unaffected node's compiled allow-list must not change")
	waitTCPPort(carol, 443, filter.Accept)

	ex, err := st.Governance().Current().Explain(governance.ExplainRequest{
		SourceNode: aliceID, TargetNode: bobID, Protocol: "tcp", Port: 80,
	})
	require.NoError(t, err)
	require.Equal(t, governance.DecisionDeny, ex.Decision)
	require.Equal(t, governance.ReasonDenyRule, ex.Code)
	require.Equal(t, "alice-to-bob-http-deny", ex.RuleID)
	require.Contains(t, ex.Markers, "http-blocked")

	// Atomic rejection: illegal action must not move DB policy, version,
	// explanation or delivered filter.
	liveBefore, err := st.GetPolicy()
	require.NoError(t, err)

	bad := []byte(fmt.Sprintf(`{
		"acls": [{"action":"accept","src":["*"],"dst":["*:*"]}],
		"governance": {"rules":[{"id":"bad-action","actions":["defenestrate"],"src":["user:%d"],"dst":["user:%d"],"ports":[22]}]}
	}`, aliceUser.ID, bobUser.ID))

	_, _, err = st.UpdatePolicy(bad)
	require.Error(t, err)
	require.True(t, governance.IsClass(err, governance.ClassInvalidAction), "err=%v", err)

	liveAfter, err := st.GetPolicy()
	require.NoError(t, err)
	require.Equal(t, liveBefore.Data, liveAfter.Data)
	require.Equal(t, report.Version, st.Governance().Version())

	exAfter, err := st.Governance().Current().Explain(governance.ExplainRequest{
		SourceNode: aliceID, TargetNode: bobID, Protocol: "tcp", Port: 80,
	})
	require.NoError(t, err)
	require.Equal(t, "alice-to-bob-http-deny", exAfter.RuleID)

	bob.WaitForCondition(t, "atomic old filter still drops tcp/80", 5*time.Second,
		func(nm *netmap.NetworkMap) bool {
			return filterHasVerdict(t, alice, 80, filter.Drop, nm)
		})
}

func filterHasVerdict(
	t *testing.T,
	alice *servertest.TestClient,
	port uint16,
	want filter.Response,
	nm *netmap.NetworkMap,
) bool {
	t.Helper()

	if nm == nil || len(nm.PacketFilter) == 0 || !nm.SelfNode.Valid() {
		return false
	}

	var localBuilder netipx.IPSetBuilder
	for _, prefix := range nm.SelfNode.Addresses().All() {
		localBuilder.AddPrefix(prefix)
	}

	local, err := localBuilder.IPSet()
	if err != nil {
		return false
	}

	f := filter.New(nm.PacketFilter, nil, local, nil, nil, logger.Discard)

	aliceNode := alice.Netmap().SelfNode
	if !aliceNode.Valid() {
		return false
	}

	for family := range aliceNode.Addresses().Len() {
		src := aliceNode.Addresses().At(family).Addr()
		dst := nm.SelfNode.Addresses().At(family).Addr()

		if !src.IsValid() || !dst.IsValid() {
			continue
		}

		if got := f.CheckTCP(src, dst, port); got != want {
			return false
		}
	}

	return true
}
