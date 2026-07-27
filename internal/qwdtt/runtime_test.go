package qwdtt

import (
	"path/filepath"
	"testing"
)

func TestRuntimeUpdateKeepsDisabledState(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "config.json")
	cfg := validTestConfig()
	rt := NewRuntime(&cfg, path, NewLogBook())

	next := cfg
	next.Enabled = false
	next.Server.PublicHost = "updated.example"
	if err := rt.Update(next); err != nil {
		t.Fatal(err)
	}
	if rt.Running() {
		t.Fatal("disabled configuration started the transport")
	}
	got := rt.Config()
	if got.Enabled || got.Server.PublicHost != next.Server.PublicHost {
		t.Fatalf("unexpected runtime config: %#v", got)
	}
}

func validTestConfig() Config {
	return Config{
		Mode:    ModeServer,
		DataDir: ".",
		Server: ServerConfig{
			PublicHost: "example.test",
			Password:   "secret",
			Network:    "10.66.66.0/24",
		},
		Routing: RoutingConfig{Mode: RouteAll},
	}
}
