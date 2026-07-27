package qwdtt

import (
	"fmt"
	"net"
	"sort"
	"strings"
)

// Rule is a platform-neutral routing operation. Keenetic integration can
// translate these operations to ip rule/ip route or the native router API.
type Rule struct {
	Kind   string
	Target string
	Device string
}

// BuildRules creates deterministic rules for the selected routing policy.
func BuildRules(cfg RoutingConfig) ([]Rule, error) {
	device := strings.TrimSpace(cfg.Interface)
	if device == "" {
		device = "wdtt0"
	}
	if cfg.Mode != RouteAll && cfg.Mode != RouteInternet && cfg.Mode != RouteSelective {
		return nil, fmt.Errorf("unsupported routing mode %q", cfg.Mode)
	}
	seen := make(map[string]bool)
	var rules []Rule
	add := func(kind, target string) error {
		if isProtectedNetwork(target) {
			return fmt.Errorf("refusing to route protected network %s", target)
		}
		key := kind + ":" + target
		if !seen[key] {
			seen[key] = true
			rules = append(rules, Rule{Kind: kind, Target: target, Device: device})
		}
		return nil
	}
	if cfg.Mode == RouteAll || cfg.Mode == RouteInternet {
		if err := add("default", "0.0.0.0/0"); err != nil {
			return nil, err
		}
	} else {
		for _, value := range append(append([]string{}, cfg.Clients...), cfg.Networks...) {
			network, err := normalizeNetwork(value)
			if err != nil {
				return nil, err
			}
			if err := add("network", network); err != nil {
				return nil, err
			}
		}
		if len(rules) == 0 {
			return nil, fmt.Errorf("selective routing has no targets")
		}
	}
	sort.Slice(rules, func(i, j int) bool { return rules[i].Target < rules[j].Target })
	return rules, nil
}

func normalizeNetwork(value string) (string, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return "", fmt.Errorf("empty routing target")
	}
	if ip := net.ParseIP(value); ip != nil {
		bits := 128
		if ip.To4() != nil {
			ip = ip.To4()
			bits = 32
		}
		return (&net.IPNet{IP: ip, Mask: net.CIDRMask(bits, bits)}).String(), nil
	}
	_, network, err := net.ParseCIDR(value)
	if err != nil {
		return "", fmt.Errorf("invalid routing target %q: %w", value, err)
	}
	return network.String(), nil
}

func isProtectedNetwork(value string) bool {
	_, network, err := net.ParseCIDR(value)
	if err != nil {
		return false
	}
	protected := []string{"127.0.0.0/8", "169.254.0.0/16", "224.0.0.0/4", "255.255.255.255/32"}
	for _, raw := range protected {
		_, reserved, _ := net.ParseCIDR(raw)
		// A broad route such as 0.0.0.0/0 is allowed; only reject a
		// target whose network address lies inside a protected range.
		if reserved.Contains(network.IP) {
			return true
		}
	}
	return false
}
