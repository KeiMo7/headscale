package governance

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"slices"
	"strconv"
	"strings"

	"github.com/juanfont/headscale/hscontrol/types"
	"net/netip"
)

// Identity is the resolved directory information for one node.
type Identity struct {
	NodeID   types.NodeID `json:"node_id"`
	StableID string       `json:"stable_id,omitempty"`
	Name     string       `json:"name,omitempty"`

	UserID   types.UserID `json:"user_id,omitempty"`
	UserName string       `json:"user_name,omitempty"`
	Email    string       `json:"email,omitempty"`

	Groups []string `json:"groups,omitempty"`
	Tags   []string `json:"tags,omitempty"`

	// Tagged is authoritative ownership information. A tagged node may still
	// carry UserID as creator, so callers must not infer user ownership from
	// a nonzero UserID alone.
	Tagged bool `json:"tagged"`

	// Unassigned marks a principal that exists in the directory but belongs
	// to neither a group nor a tag. Explanation treats that as unknown when
	// RequireAssignment is set.
	Unassigned bool `json:"unassigned,omitempty"`
	Deleted    bool `json:"deleted,omitempty"`

	// Addresses are needed to derive wire rules but are never serialized into
	// an explanation: denial reasons must not disclose peer addresses.
	Addresses []netip.Addr `json:"-"`
}

// Pair is a directed source -> target node pair.
type Pair struct {
	Source types.NodeID `json:"source"`
	Target types.NodeID `json:"target"`
}

// String renders a stable safe identifier. It contains only numeric IDs.
func (p Pair) String() string {
	return strconv.FormatUint(p.Source.Uint64(), 10) + "->" + strconv.FormatUint(p.Target.Uint64(), 10)
}

// Snapshot is the immutable identity/node universe a candidate is tried
// against.
type Snapshot struct {
	Identities map[types.NodeID]Identity `json:"identities"`
	Hash       string                    `json:"hash"`

	// RequireAssignment makes an existing but group/tag-less identity unknown
	// to Explain. It does not affect rule compilation against explicit user
	// selectors.
	RequireAssignment bool `json:"-"`
}

// NewSnapshot builds a deterministic snapshot and calculates its hash.
func NewSnapshot(ids []Identity) *Snapshot {
	s := &Snapshot{Identities: make(map[types.NodeID]Identity, len(ids))}

	for _, id := range ids {
		s.Identities[id.NodeID] = id
	}

	s.Hash = s.calculateHash()

	return s
}

// RecalculateHash recomputes the deterministic snapshot hash after a test or
// adapter has modified an identity in place.
func (s *Snapshot) RecalculateHash() {
	s.Hash = s.calculateHash()
}

func (s *Snapshot) calculateHash() string {
	ids := make([]types.NodeID, 0, len(s.Identities))
	for id := range s.Identities {
		ids = append(ids, id)
	}

	slices.Sort(ids)

	h := sha256.New()

	for _, nodeID := range ids {
		id := s.Identities[nodeID]
		fmt.Fprintf(h, "node=%d stable=%s name=%s user=%d/%s/%s tagged=%t deleted=%t unassigned=%t\n",
			id.NodeID, id.StableID, id.Name, id.UserID, id.UserName, id.Email,
			id.Tagged, id.Deleted, id.Unassigned)

		groups := slices.Clone(id.Groups)
		tags := slices.Clone(id.Tags)
		addrs := make([]string, 0, len(id.Addresses))
		for _, a := range id.Addresses {
			addrs = append(addrs, a.String())
		}

		slices.Sort(groups)
		slices.Sort(tags)
		slices.Sort(addrs)

		fmt.Fprintf(h, "groups=%s tags=%s addrs=%s\n",
			strings.Join(groups, ","), strings.Join(tags, ","), strings.Join(addrs, ","))
	}

	return hex.EncodeToString(h.Sum(nil))[:16]
}

// Node returns an active identity by ID.
func (s *Snapshot) Node(id types.NodeID) (Identity, bool) {
	if s == nil {
		return Identity{}, false
	}

	ident, ok := s.Identities[id]
	if !ok || ident.Deleted {
		return Identity{}, false
	}

	return ident, true
}

// Resolve turns a policy reference into active identities. An empty result
// with a nil error means the reference is syntactically valid but undefined.
func (s *Snapshot) Resolve(ref string) ([]Identity, error) {
	ref = strings.TrimSpace(ref)
	if ref == "" {
		return nil, nil
	}

	if ref == "*" {
		out := make([]Identity, 0, len(s.Identities))
		for _, id := range s.Identities {
			if !id.Deleted {
				out = append(out, id)
			}
		}

		slices.SortFunc(out, func(a, b Identity) int { return int(a.NodeID - b.NodeID) })

		return out, nil
	}

	prefix, value, hasPrefix := strings.Cut(ref, ":")
	if !hasPrefix {
		// Bare values are accepted as user names for ergonomic table tests.
		prefix, value = "user", ref
	}

	var out []Identity

	for _, id := range s.Identities {
		if id.Deleted {
			continue
		}

		matched := false

		switch prefix {
		case "node":
			matched = matchNodeRef(id, value)
		case "user":
			matched = matchUserRef(id, value)
		case "group":
			want := ref
			if !strings.HasPrefix(value, "group:") {
				want = "group:" + value
			}

			matched = slices.Contains(id.Groups, want) || slices.Contains(id.Groups, value)
		case "tag":
			want := ref
			if !strings.HasPrefix(value, "tag:") {
				want = "tag:" + value
			}

			matched = slices.Contains(id.Tags, want) || slices.Contains(id.Tags, value)
		default:
			return nil, fmt.Errorf("unsupported identity reference %q", ref)
		}

		if matched {
			out = append(out, id)
		}
	}

	slices.SortFunc(out, func(a, b Identity) int { return int(a.NodeID - b.NodeID) })

	return out, nil
}

func matchNodeRef(id Identity, value string) bool {
	if n, err := strconv.ParseUint(value, 10, 64); err == nil && types.NodeID(n) == id.NodeID {
		return true
	}

	return id.Name == value || id.StableID == value
}

func matchUserRef(id Identity, value string) bool {
	if n, err := strconv.ParseUint(value, 10, 64); err == nil && types.UserID(n) == id.UserID {
		return true
	}

	return id.UserName == value || id.Email == value ||
		strings.EqualFold(id.Email, value) ||
		strings.EqualFold(id.UserName, value)
}

// TraceStep records one stage of identity resolution.
type TraceStep struct {
	Dimension string     `json:"dimension"`
	Input     string     `json:"input,omitempty"`
	Resolved  []string   `json:"resolved,omitempty"`
	Matched   bool       `json:"matched"`
	Code      ReasonCode `json:"code,omitempty"`
	Detail    string     `json:"detail,omitempty"`
}

// Resolution is an explained identity plus its trace.
type Resolution struct {
	Identity Identity    `json:"identity"`
	Steps    []TraceStep `json:"steps"`
}

// ResolveForExplanation resolves a node ID/reference and records the user,
// group, tag and ownership stages. Deleted or unassigned principals return an
// [IdentityError], never a deny decision.
func (s *Snapshot) ResolveForExplanation(nodeID types.NodeID, ref string) (*Resolution, error) {
	steps := []TraceStep{{Dimension: "node", Input: chooseRef(nodeID, ref)}}

	var ident Identity

	var found bool

	if nodeID != 0 {
		ident, found = s.Identities[nodeID]
		if !found {
			steps[0].Matched = false
			steps[0].Code = ReasonIdentityUnknown

			return nil, &IdentityError{Class: ClassIdentityUnknown, Code: ReasonIdentityUnknown}
		}

		steps[0].Matched = true
		steps[0].Resolved = []string{ident.Name, ident.NodeID.String()}
	} else {
		ids, err := s.Resolve(ref)
		if err != nil || len(ids) == 0 {
			steps[0].Matched = false
			steps[0].Code = ReasonIdentityUnknown

			code := ReasonIdentityUnknown
			if err == nil {
				// Distinguish a known deleted record when the snapshot retains it.
				for _, candidate := range s.Identities {
					if refMatchesIdentityRef(candidate, ref) && candidate.Deleted {
						code = ReasonIdentityDeleted
						ident = candidate

						break
					}
				}
			}

			return nil, &IdentityError{Class: ClassIdentityUnknown, Code: code, Ref: ref}
		}

		ident = ids[0]
		found = true
		steps[0].Matched = true
		steps[0].Resolved = []string{ident.Name, ident.NodeID.String()}
	}

	if ident.Deleted {
		return nil, &IdentityError{Class: ClassIdentityUnknown, Code: ReasonIdentityDeleted, Ref: ref}
	}

	userStep := TraceStep{Dimension: "user", Matched: ident.UserID != 0 || ident.UserName != ""}
	if ident.UserID != 0 {
		userStep.Resolved = append(userStep.Resolved, "id:"+strconv.FormatUint(uint64(ident.UserID), 10))
	}

	if ident.UserName != "" {
		userStep.Resolved = append(userStep.Resolved, ident.UserName)
	}

	if ident.Email != "" {
		userStep.Resolved = append(userStep.Resolved, ident.Email)
	}

	groupStep := TraceStep{Dimension: "group", Resolved: slices.Clone(ident.Groups), Matched: len(ident.Groups) > 0}
	if !groupStep.Matched {
		groupStep.Code = ReasonIdentityUnassigned
	}

	tagStep := TraceStep{Dimension: "tag", Resolved: slices.Clone(ident.Tags), Matched: len(ident.Tags) > 0}
	if !tagStep.Matched {
		tagStep.Code = ReasonIdentityUnassigned
	}

	owner := "user-owned"
	if ident.Tagged {
		owner = "tagged"
	}

	ownerStep := TraceStep{
		Dimension: "node_ownership",
		Resolved:  []string{owner},
		Matched:   true,
		Detail:    "tag ownership is authoritative; UserID may be creator-only",
	}
	if ident.Tagged && len(ident.Tags) > 0 {
		ownerStep.Resolved = append(ownerStep.Resolved, ident.Tags...)
	} else if ident.UserID != 0 {
		ownerStep.Resolved = append(ownerStep.Resolved, "user:"+strconv.FormatUint(uint64(ident.UserID), 10))
	}

	steps = append(steps, userStep, groupStep, tagStep, ownerStep)

	if s != nil && s.RequireAssignment && ident.Unassigned {
		return nil, &IdentityError{Class: ClassIdentityUnknown, Code: ReasonIdentityUnassigned, Ref: ref}
	}

	_ = found

	return &Resolution{Identity: ident, Steps: steps}, nil
}

func chooseRef(id types.NodeID, ref string) string {
	if ref != "" {
		return ref
	}

	return "node:" + id.String()
}

func refMatchesIdentityRef(id Identity, ref string) bool {
	ids, err := NewSnapshot([]Identity{id}).Resolve(ref)
	return err == nil && len(ids) == 1
}
