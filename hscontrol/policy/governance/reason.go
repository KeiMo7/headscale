// Package governance is the single compiled authority for allow/deny
// decisions, explanations, trial writes and incremental policy recomputation.
//
// It is deliberately additive: policies without a governance document do not
// enter this layer and continue to use the legacy policy compiler unchanged.
// The immutable [Compilation] produced by a commit is the only thing used to
// explain a tuple and to derive the allow-list sent to nodes.
package governance

import "errors"

// ReasonCode is a stable, machine-readable explanation identifier. Reason
// codes are part of the operational contract and must not be renamed.
type ReasonCode string

const (
	ReasonAllowRule ReasonCode = "POLICY_ALLOW_RULE"
	ReasonDenyRule  ReasonCode = "POLICY_DENY_RULE"
	ReasonLogMarker ReasonCode = "POLICY_LOG_MARKER"

	ReasonDefaultDenyNoSourceCoverage ReasonCode = "DEFAULT_DENY_NO_SOURCE_COVERAGE"
	ReasonDefaultDenyNoTargetCoverage ReasonCode = "DEFAULT_DENY_NO_TARGET_COVERAGE"
	ReasonDefaultDenyNoPortCoverage   ReasonCode = "DEFAULT_DENY_NO_PORT_COVERAGE"

	ReasonIdentityUnknown       ReasonCode = "IDENTITY_UNKNOWN"
	ReasonIdentityDeleted       ReasonCode = "IDENTITY_DELETED"
	ReasonIdentityUnassigned    ReasonCode = "IDENTITY_UNASSIGNED"
	ReasonInvalidAction         ReasonCode = "INVALID_ACTION"
	ReasonUndefinedIdentity     ReasonCode = "UNDEFINED_IDENTITY"
	ReasonPortOutOfRange        ReasonCode = "PORT_OUT_OF_RANGE"
	ReasonInvalidPolicy         ReasonCode = "INVALID_POLICY"
	ReasonEqualPriorityConflict ReasonCode = "EQUAL_PRIORITY_CONFLICT"

	ReasonFullRecomputeNoPrevious      ReasonCode = "FULL_RECOMPUTE_NO_PREVIOUS_COMPILATION"
	ReasonFullRecomputeSnapshotChanged ReasonCode = "FULL_RECOMPUTE_SNAPSHOT_CHANGED"

	ReasonDormantUndefinedIdentity ReasonCode = "RULE_DORMANT_UNDEFINED_IDENTITY"
)

// Decision is the deterministic verdict for one source/target/port tuple.
type Decision string

const (
	DecisionAllow   Decision = "allow"
	DecisionDeny    Decision = "deny"
	DecisionUnknown Decision = "unknown"
)

// ErrorClass separates syntax/reference rejection from a legal deny verdict.
type ErrorClass string

const (
	ClassInvalidAction     ErrorClass = "invalid_action"
	ClassUndefinedIdentity ErrorClass = "undefined_identity"
	ClassPortOutOfRange    ErrorClass = "port_out_of_range"
	ClassConflict          ErrorClass = "conflict"
	ClassInvalidPolicy     ErrorClass = "invalid_policy"
	ClassIdentityUnknown   ErrorClass = "identity_unknown"
)

// Issue is one safe, locatable policy problem. Message never contains peer
// addresses, tokens or keys.
type Issue struct {
	Class   ErrorClass `json:"class"`
	Code    ReasonCode `json:"code"`
	Message string     `json:"message"`
	RuleID  string     `json:"rule_id,omitempty"`
	Field   string     `json:"field,omitempty"`
	Rules   []string   `json:"rules,omitempty"`
}

// ValidationError aggregates all reject-worthy policy issues.
type ValidationError struct {
	Issues []Issue `json:"issues"`
}

func (e *ValidationError) Error() string {
	if e == nil || len(e.Issues) == 0 {
		return "governance policy invalid"
	}

	msg := "governance policy rejected"
	for i, issue := range e.Issues {
		if i == 0 {
			msg += ": " + issue.Message
		}
	}

	return msg
}

func (e *ValidationError) Unwrap() []error {
	return nil
}

// IdentityError means the principal could not be resolved. It is distinct
// from a resolved identity that policy evaluates to deny.
type IdentityError struct {
	Class ErrorClass
	Code  ReasonCode
	Ref   string
}

func (e *IdentityError) Error() string {
	switch e.Code {
	case ReasonIdentityDeleted:
		return "governance identity has been deleted"
	case ReasonIdentityUnassigned:
		return "governance identity is not assigned to a group or tag"
	default:
		return "governance identity is unknown"
	}
}

// IsClass reports whether err contains an issue in class c.
func IsClass(err error, c ErrorClass) bool {
	var ve *ValidationError
	if errors.As(err, &ve) {
		for _, issue := range ve.Issues {
			if issue.Class == c {
				return true
			}
		}

		return false
	}

	var ie *IdentityError
	if errors.As(err, &ie) {
		return ie.Class == c
	}

	return false
}
