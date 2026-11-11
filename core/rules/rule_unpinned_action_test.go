package rules

import (
	"os"
	"strings"
	"testing"

	"github.com/rhysd/actionlint"
)

const (
	hex40 = "0123456789abcdef0123456789abcdef01234567"
	hex39 = "0123456789abcdef0123456789abcdef0123456"
	hex64 = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
)

func TestUnpinnedActionSplitUsesRef(t *testing.T) {
	tests := []struct {
		name   string
		spec   string
		quoted bool
		kind   usesKind
		ref    string
		offset int
	}{
		{
			name:   "quoted tag step",
			spec:   "actions/checkout@v4",
			quoted: true,
			kind:   usesKindTag,
			ref:    "v4",
			offset: len("actions/checkout@") + 1, // +1 for the opening quote
		},
		{
			name:   "plain tag step",
			spec:   "octo/release@2",
			kind:   usesKindTag,
			ref:    "2",
			offset: len("octo/release@"), // split on the last "@"
		},
		{
			name:   "ref containing a slash keeps the last at split",
			spec:   "octo/repo/.github/workflows/wf.yml@release/v2",
			kind:   usesKindTag,
			ref:    "release/v2",
			offset: len("octo/repo/.github/workflows/wf.yml@"),
		},
		{
			name:   "shortened 7 hex SHA",
			spec:   "octo/action@abcdef7",
			kind:   usesKindShortSHA,
			ref:    "abcdef7",
			offset: len("octo/action@"),
		},
		{
			name:   "shortened 39 hex SHA",
			spec:   "octo/action@" + hex39,
			kind:   usesKindShortSHA,
			ref:    hex39,
			offset: len("octo/action@"),
		},
		{
			name:   "full length 40 lowercase hex SHA is pinned",
			spec:   "octo/action@" + hex40,
			kind:   usesKindPinned,
			ref:    hex40,
			offset: len("octo/action@"),
		},
		{
			name:   "uppercase 40 hex SHA is not pinned",
			spec:   "octo/action@0123456789ABCDEF0123456789ABCDEF01234567",
			kind:   usesKindTag,
			ref:    "0123456789ABCDEF0123456789ABCDEF01234567",
			offset: len("octo/action@"),
		},
		{
			name: "local reference has no at sign and must not pollute the offset",
			spec: "./.github/workflows/reusable.yml",
			kind: usesKindLocal,
		},
		{
			name: "job level local reference",
			spec: "./local/action",
			kind: usesKindLocal,
		},
		{
			name: "docker digest at sign belongs to the scheme",
			spec: "docker://alpine@sha256:" + hex64,
			kind: usesKindDocker,
		},
		{
			name: "docker image without digest",
			spec: "docker://alpine:3.20",
			kind: usesKindDocker,
		},
		{
			name: "spec without any ref",
			spec: "octo/action",
			kind: usesKindLocal,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			kind, ref, offset := splitUsesRef(&actionlint.String{Value: tc.spec, Quoted: tc.quoted})
			if kind != tc.kind {
				t.Fatalf("kind: want %d, got %d", tc.kind, kind)
			}
			if ref != tc.ref {
				t.Fatalf("ref: want %q, got %q", tc.ref, ref)
			}
			if offset != tc.offset {
				t.Fatalf("offset: want %d, got %d", tc.offset, offset)
			}
		})
	}
}

func TestUnpinnedActionRuleOnTestdata(t *testing.T) {
	src, err := os.ReadFile("../../testdata/unpinned-actions.yml")
	if err != nil {
		t.Fatal(err)
	}

	workflow, parseErrs := actionlint.Parse(src)
	if len(parseErrs) != 0 {
		t.Fatalf("unexpected parse errors: %v", parseErrs)
	}

	rule := NewRuleUnpinnedAction(nil)
	visitor := actionlint.NewVisitor()
	visitor.AddPass(rule)

	if err := visitor.Visit(workflow); err != nil {
		t.Fatal(err)
	}

	errs := rule.Errs()
	if len(errs) != 3 {
		t.Fatalf("want exactly 3 findings, got %d: %v", len(errs), errs)
	}

	// ref -> expected wording, the three refs that must be reported
	wantWording := map[string]string{
		"v4":      "mutable tag or branch",
		"2":       "mutable tag or branch",
		"abcdef7": "shortened commit SHA",
	}

	lines := strings.Split(string(src), "\n")

	for _, e := range errs {
		if e.Kind != "unpinned-action" {
			t.Fatalf("unexpected rule kind %q", e.Kind)
		}

		fields := e.GetTemplateFields(src)
		line := lines[e.Line-1]

		// the ref starts right after the last "@" on the source line
		at := strings.LastIndexByte(line, '@')
		if at < 0 {
			t.Fatalf("no \"@\" on line %q", line)
		}
		refStart := at + 1 // 0-based column of the first ref character

		if fields.Column != refStart+1 {
			t.Fatalf("underline start: want column %d, got %d on line %q", refStart+1, fields.Column, line)
		}

		// actionlint renders the indicator until the next whitespace, so a quoted
		// scalar additionally covers the closing quote; cut at it and keep the
		// ref characters only
		ref := firstToken(line[refStart:])
		wording, ok := wantWording[ref]
		if !ok {
			t.Fatalf("unexpected reported ref %q on line %q", ref, line)
		}
		if fields.EndColumn < fields.Column+len(ref)-1 {
			t.Fatalf("underline does not cover the whole ref %q: column %d, end %d", ref, fields.Column, fields.EndColumn)
		}
		if !strings.Contains(e.Message, wording) {
			t.Fatalf("message %q does not contain %q", e.Message, wording)
		}

		delete(wantWording, ref)
	}

	if len(wantWording) != 0 {
		t.Fatalf("missing findings for refs %v", wantWording)
	}
}

// firstToken cuts the indicator span at the first whitespace or closing quote,
// leaving exactly the ref characters.
func firstToken(s string) string {
	for i, r := range s {
		if r == ' ' || r == '\t' || r == '"' || r == '\'' || r == '\r' {
			return s[:i]
		}
	}
	return s
}
