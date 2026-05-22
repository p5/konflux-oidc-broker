package token

import (
	"strings"
	"testing"
	"testing/quick"

	"github.com/p5/konflux-oidc-broker/internal/metadata"
)

func TestBuildSubClaim(t *testing.T) {
	tests := []struct {
		name     string
		meta     metadata.PipelineRunMeta
		expected string
	}{
		{
			name: "all fields populated",
			meta: metadata.PipelineRunMeta{
				Namespace: "my-ns", Application: "my-app", Component: "api",
				PipelineType: "build", PipelineName: "docker-build",
				TaskName: "buildah", TargetBranch: "main",
			},
			expected: "v1:ns:my-ns:app:my-app:component:api:type:build:pipeline:docker-build:task:buildah:ref:main",
		},
		{
			name: "empty optional fields",
			meta: metadata.PipelineRunMeta{
				Namespace: "ns", Application: "app", Component: "comp",
			},
			expected: "v1:ns:ns:app:app:component:comp:type::pipeline::task::ref:",
		},
		{
			name: "ref with slash",
			meta: metadata.PipelineRunMeta{
				Namespace: "ns", Application: "app", Component: "comp",
				PipelineType: "build", PipelineName: "build",
				TaskName: "push", TargetBranch: "feature/login",
			},
			expected: "v1:ns:ns:app:app:component:comp:type:build:pipeline:build:task:push:ref:feature/login",
		},
		{
			name: "ref with multiple slashes",
			meta: metadata.PipelineRunMeta{
				Namespace: "ns", Application: "app", Component: "comp",
				PipelineType: "build", PipelineName: "build",
				TaskName: "push", TargetBranch: "refs/heads/release/1.0",
			},
			expected: "v1:ns:ns:app:app:component:comp:type:build:pipeline:build:task:push:ref:refs/heads/release/1.0",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sub, err := BuildSubClaim(&tt.meta)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if sub != tt.expected {
				t.Errorf("got %q, want %q", sub, tt.expected)
			}
		})
	}
}

func TestBuildSubClaimRejectsColonInValues(t *testing.T) {
	fields := []struct {
		name  string
		apply func(*metadata.PipelineRunMeta)
	}{
		{"application", func(m *metadata.PipelineRunMeta) { m.Application = "evil:app" }},
		{"component", func(m *metadata.PipelineRunMeta) { m.Component = "evil:comp" }},
		{"pipelineType", func(m *metadata.PipelineRunMeta) { m.PipelineType = "evil:type" }},
		{"pipelineName", func(m *metadata.PipelineRunMeta) { m.PipelineName = "evil:pipe" }},
		{"taskName", func(m *metadata.PipelineRunMeta) { m.TaskName = "evil:task" }},
		{"targetBranch", func(m *metadata.PipelineRunMeta) { m.TargetBranch = "evil:ref" }},
		{"commitSHA", func(m *metadata.PipelineRunMeta) { m.CommitSHA = "evil:sha" }},
	}

	for _, f := range fields {
		t.Run(f.name, func(t *testing.T) {
			meta := metadata.PipelineRunMeta{Namespace: "ns", Application: "app", Component: "comp"}
			f.apply(&meta)
			_, err := BuildSubClaim(&meta)
			if err == nil {
				t.Error("expected error for colon in value, got nil")
			}
		})
	}
}

func TestBuildSubClaimVersionPrefix(t *testing.T) {
	meta := metadata.PipelineRunMeta{Namespace: "ns", Application: "app", Component: "comp"}
	sub, err := BuildSubClaim(&meta)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(sub, "v1:") {
		t.Errorf("sub should start with 'v1:', got %q", sub)
	}
}

func TestBuildSubClaimFieldOrder(t *testing.T) {
	meta := metadata.PipelineRunMeta{
		Namespace: "ns", Application: "app", Component: "comp",
		PipelineType: "build", PipelineName: "pipe", TaskName: "task", TargetBranch: "main",
	}
	sub, _ := BuildSubClaim(&meta)

	fields := []string{"ns:", "app:", "component:", "type:", "pipeline:", "task:", "ref:"}
	lastIdx := -1
	for _, f := range fields {
		idx := strings.Index(sub, f)
		if idx == -1 {
			t.Errorf("field %q not found in sub %q", f, sub)
			continue
		}
		if idx <= lastIdx {
			t.Errorf("field %q at index %d is out of order", f, idx)
		}
		lastIdx = idx
	}
}

func TestBuildSubClaimIsIdempotent(t *testing.T) {
	f := func(app, comp, ref string) bool {
		if strings.Contains(app, ":") || strings.Contains(comp, ":") || strings.Contains(ref, ":") {
			return true
		}
		meta := metadata.PipelineRunMeta{Namespace: "ns", Application: app, Component: comp, TargetBranch: ref}
		sub1, err1 := BuildSubClaim(&meta)
		sub2, err2 := BuildSubClaim(&meta)
		if err1 != nil || err2 != nil {
			return err1 != nil && err2 != nil
		}
		return sub1 == sub2
	}
	if err := quick.Check(f, nil); err != nil {
		t.Error(err)
	}
}

func FuzzBuildSubClaimNoColonInjection(f *testing.F) {
	f.Add("app", "comp", "build", "pipe", "task", "main")
	f.Add("my-app", "my-comp", "test", "docker-build", "buildah", "feature/login")
	f.Add("", "", "", "", "", "")

	f.Fuzz(func(t *testing.T, app, comp, ptype, pipe, task, ref string) {
		meta := metadata.PipelineRunMeta{
			Namespace: "ns", Application: app, Component: comp,
			PipelineType: ptype, PipelineName: pipe, TaskName: task, TargetBranch: ref,
		}
		sub, err := BuildSubClaim(&meta)
		if err != nil {
			if !strings.Contains(err.Error(), "delimiter") {
				t.Errorf("unexpected error: %v", err)
			}
			return
		}
		if !strings.HasPrefix(sub, "v1:") {
			t.Errorf("missing version prefix: %q", sub)
		}
	})
}
