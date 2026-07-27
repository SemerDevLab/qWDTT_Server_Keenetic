package qwdtt

import "testing"

func TestBuildRulesAll(t *testing.T) {
	rules, err := BuildRules(RoutingConfig{Mode: RouteAll, Interface: "wdtt0"})
	if err != nil || len(rules) != 1 || rules[0].Target != "0.0.0.0/0" {
		t.Fatalf("unexpected rules: %#v, %v", rules, err)
	}
}

func TestBuildRulesSelectiveDeduplicates(t *testing.T) {
	rules, err := BuildRules(RoutingConfig{Mode: RouteSelective, Clients: []string{"192.168.1.20", "192.168.1.20"}, Networks: []string{"192.168.2.0/24"}})
	if err != nil || len(rules) != 2 {
		t.Fatalf("unexpected rules: %#v, %v", rules, err)
	}
}

func TestBuildRulesRejectsProtectedNetwork(t *testing.T) {
	if _, err := BuildRules(RoutingConfig{Mode: RouteSelective, Networks: []string{"127.0.0.0/8"}}); err == nil {
		t.Fatal("expected protected network error")
	}
}
