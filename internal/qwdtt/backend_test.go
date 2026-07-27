package qwdtt

import (
	"context"
	"testing"
)

type fakeRunner struct{ calls int }

func (f *fakeRunner) Run(context.Context, string, ...string) error { f.calls++; return nil }

func TestBackendDryRun(t *testing.T) {
	runner := &fakeRunner{}
	err := (Backend{Runner: runner, DryRun: true}).Apply(context.Background(), RoutingConfig{Mode: RouteAll}, "10.66.66.2/32", "10.66.66.1")
	if err != nil {
		t.Fatal(err)
	}
	if runner.calls != 0 {
		t.Fatalf("dry run executed %d commands", runner.calls)
	}
}
