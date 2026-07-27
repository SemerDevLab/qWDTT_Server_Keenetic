package qwdtt

import (
	"context"
	"errors"
	"strings"
	"testing"
)

type recordingRunner struct {
	commands []string
}

func (r *recordingRunner) Run(_ context.Context, name string, args ...string) error {
	r.commands = append(r.commands, name+" "+strings.Join(args, " "))
	for _, arg := range args {
		if arg == "-C" {
			return errors.New("not found")
		}
	}
	return nil
}

func TestEnsureProfileAccessPoliciesFiltersOnlyInternetProfiles(t *testing.T) {
	t.Parallel()

	runner := &recordingRunner{}
	profiles := []ConnectionProfile{
		{ID: "full", Enabled: true, ClientIP: "10.66.66.2", AccessMode: RouteAll},
		{ID: "internet", Enabled: true, ClientIP: "10.66.66.3", AccessMode: RouteInternet},
		{ID: "disabled", Enabled: false, ClientIP: "10.66.66.4", AccessMode: RouteInternet},
	}
	if err := EnsureProfileAccessPolicies(context.Background(), runner, profiles); err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(runner.commands, "\n")
	if !strings.Contains(joined, "-s 10.66.66.3/32 -d 192.168.0.0/16 -j REJECT") {
		t.Fatalf("Internet-only profile rule missing:\n%s", joined)
	}
	dnsRule := "-s 10.66.66.3/32 -p udp --dport 53 -j ACCEPT"
	rejectRule := "-s 10.66.66.3/32 -d 192.168.0.0/16 -j REJECT"
	if dnsAt, rejectAt := strings.Index(joined, dnsRule), strings.Index(joined, rejectRule); dnsAt < 0 || rejectAt < 0 || dnsAt > rejectAt {
		t.Fatalf("DNS exception must precede private-network rejection:\n%s", joined)
	}
	if strings.Contains(joined, "10.66.66.2/32") || strings.Contains(joined, "10.66.66.4/32") {
		t.Fatalf("unexpected rule for full or disabled profile:\n%s", joined)
	}
	if strings.Contains(joined, "-s 10.66.66.3/32 -d 10.0.0.0/8 -j REJECT") {
		t.Fatalf("profile policy blocked the qWDTT 10.x tunnel network:\n%s", joined)
	}
	if !strings.Contains(joined, "-I FORWARD 1 -i wdtt0 -j QWDTT_PROFILE_FWD") {
		t.Fatalf("profile chain is not placed before general forwarding:\n%s", joined)
	}
}
