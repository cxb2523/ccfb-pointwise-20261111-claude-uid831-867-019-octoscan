package rules

import (
	"regexp"
	"strings"

	"github.com/rhysd/actionlint"
)

// usesKind classifies a "uses:" specification after splitting it. A single bool
// cannot tell a shortened commit SHA (7 to 39 hex chars) apart from a tag, so
// the classification has to carry the kind.
type usesKind int

const (
	// usesKindLocal covers "./" local references and specifications without any
	// ref to check. They are allowed both at step and job level and never report.
	usesKindLocal usesKind = iota
	// usesKindDocker covers "docker://" references, including image digests whose
	// "@" must not be interpreted as a ref separator.
	usesKindDocker
	// usesKindPinned is a full length, 40 lowercase hex characters, commit SHA.
	usesKindPinned
	// usesKindShortSHA is a 7 to 39 lowercase hex characters commit SHA. It looks
	// immutable but is still mutable, hence its own reporting wording.
	usesKindShortSHA
	// usesKindTag covers every other ref: tags and branches are merged together.
	usesKindTag
)

var (
	// only 40 lowercase hex characters are considered an immutable commit SHA
	pinnedSHARegexp = regexp.MustCompile(`^[0-9a-f]{40}$`)
	// 7 to 39 lowercase hex characters: a shortened commit SHA
	shortSHARegexp = regexp.MustCompile(`^[0-9a-f]{7,39}$`)
)

// splitUsesRef is the single splitting function shared by step actions and
// reusable workflow calls. It returns the kind of the specification, its ref
// part and the byte offset of the ref relative to the node position reported by
// actionlint.
//
// The split order is constrained by the inputs:
//   - "docker://image@sha256:..." carries its own "@", the scheme has to be
//     recognized first or the 64 characters digest would be classified as a tag.
//   - "./" local references have no "@": strings.LastIndexByte returns -1 and
//     must short-circuit, otherwise -1 pollutes the offset.
//   - repository references are split on the LAST "@", so "release/v2" style
//     refs keep their "/".
//   - actionlint points quoted scalar nodes at the opening quote while plain
//     scalars point at their first character. The offset is computed on the
//     decoded value and then bumped by one for quoted nodes, otherwise the
//     underline would start one column before the ref.
func splitUsesRef(uses *actionlint.String) (kind usesKind, ref string, offset int) {
	spec := uses.Value

	if strings.HasPrefix(spec, "docker://") {
		return usesKindDocker, "", 0
	}

	if strings.HasPrefix(spec, "./") {
		return usesKindLocal, "", 0
	}

	idx := strings.LastIndexByte(spec, '@')
	if idx == -1 {
		// no ref at all, nothing to underline: skip instead of computing an
		// offset from a negative index
		return usesKindLocal, "", 0
	}

	ref = spec[idx+1:]
	offset = idx + 1 // first ref character, relative to the decoded value
	if uses.Quoted {
		// the node position includes the opening quote
		offset++
	}

	switch {
	case pinnedSHARegexp.MatchString(ref):
		kind = usesKindPinned
	case shortSHARegexp.MatchString(ref):
		kind = usesKindShortSHA
	default:
		kind = usesKindTag
	}

	return kind, ref, offset
}

type RuleUnpinnedAction struct {
	actionlint.RuleBase
	filterTriggers []string
	skip           bool
}

// NewRuleUnpinnedAction creates new RuleUnpinnedAction instance.
func NewRuleUnpinnedAction(filterTriggers []string) *RuleUnpinnedAction {
	return &RuleUnpinnedAction{
		RuleBase: actionlint.NewRuleBase(
			"unpinned-action",
			"Check for actions and reusable workflows that are not pinned to a full length commit SHA.",
		),
		filterTriggers: filterTriggers,
		skip:           false,
	}
}

func (rule *RuleUnpinnedAction) VisitWorkflowPre(n *actionlint.Workflow) error {
	// check on event and set skip if needed
	rule.skip = skipAnalysis(n, rule.filterTriggers)

	return nil
}

// VisitJobPre handles reusable workflow calls at job level, which go through
// the same splitting function as step actions.
func (rule *RuleUnpinnedAction) VisitJobPre(j *actionlint.Job) error {
	if rule.skip || j.WorkflowCall == nil {
		return nil
	}

	rule.checkUses(j.WorkflowCall.Uses)

	return nil
}

// VisitStep is callback when visiting Step node.
func (rule *RuleUnpinnedAction) VisitStep(n *actionlint.Step) error {
	if rule.skip {
		return nil
	}

	e, ok := n.Exec.(*actionlint.ExecAction)
	if !ok || e.Uses == nil {
		return nil
	}

	rule.checkUses(e.Uses)

	return nil
}

func (rule *RuleUnpinnedAction) checkUses(uses *actionlint.String) {
	if uses.ContainsExpression() {
		// Cannot parse specification made with interpolation. Give up
		return
	}

	kind, ref, offset := splitUsesRef(uses)
	pos := &actionlint.Pos{Line: uses.Pos.Line, Col: uses.Pos.Col + offset}

	switch kind {
	case usesKindShortSHA:
		rule.Errorf(
			pos,
			"%q is pinned to the shortened commit SHA %q, only the full length 40 hex characters SHA is immutable.",
			uses.Value,
			ref,
		)
	case usesKindTag:
		rule.Errorf(
			pos,
			"%q is not pinned to a full length commit SHA, %q is a mutable tag or branch.",
			uses.Value,
			ref,
		)
	}
}
