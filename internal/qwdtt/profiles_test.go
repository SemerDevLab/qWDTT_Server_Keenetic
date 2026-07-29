package qwdtt

import (
	"strings"
	"testing"
)

func TestNormalizeProfilesMigratesLegacyServer(t *testing.T) {
	t.Parallel()

	cfg := validTestConfig()
	cfg.Server.DTLSPort = 56000
	cfg.Server.VKHash = "legacy-hash"
	cfg.NormalizeProfiles()

	if len(cfg.Server.Profiles) != 1 {
		t.Fatalf("got %d profiles, want 1", len(cfg.Server.Profiles))
	}
	profile := cfg.Server.Profiles[0]
	if profile.ID != "default" || profile.ClientIP != "10.66.66.2" || profile.VKHash != "legacy-hash" || profile.DTLSPort != 56000 || !profile.Enabled {
		t.Fatalf("unexpected migrated profile: %#v", profile)
	}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestNormalizeProfilesPreservesExplicitEmptyList(t *testing.T) {
	t.Parallel()

	cfg := validTestConfig()
	cfg.Server.Profiles = []ConnectionProfile{}
	cfg.NormalizeProfiles()
	if cfg.Server.Profiles == nil || len(cfg.Server.Profiles) != 0 {
		t.Fatalf("explicit empty profile list was not preserved: %#v", cfg.Server.Profiles)
	}
}

func TestProfilesRejectDuplicateAddress(t *testing.T) {
	t.Parallel()

	cfg := validTestConfig()
	cfg.Server.Profiles = []ConnectionProfile{
		{ID: "one", Name: "One", Enabled: true, ClientIP: "10.66.66.2", DTLSPort: 56000, AccessMode: RouteAll},
		{ID: "two", Name: "Two", Enabled: true, ClientIP: "10.66.66.2", DTLSPort: 56001, AccessMode: RouteInternet},
	}
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "duplicate profile clientIP") {
		t.Fatalf("expected duplicate IP error, got %v", err)
	}

}

func TestProfileLinksContainOwnPortAndHash(t *testing.T) {
	t.Parallel()

	cfg := validTestConfig()
	cfg.Server.PublicHost = "vpn.example"
	cfg.Server.Password = "shared-pass"
	cfg.Server.DTLSPort = 56000
	profile := ConnectionProfile{ID: "phone", Name: "Телефон", Enabled: true, ClientIP: "10.66.66.2", VKHash: "phone-hash", DTLSPort: 56123}

	qwdttLink := cfg.ProfileQWDTTLink(profile)
	if !strings.Contains(qwdttLink, "vpn.example%3A56000") || !strings.Contains(qwdttLink, "hashes=phone-hash") {
		t.Fatalf("unexpected qWDTT profile link: %s", qwdttLink)
	}
	legacyLink := cfg.ProfileLegacyLink(profile)
	if !strings.Contains(legacyLink, "vpn.example:56000:") || !strings.HasSuffix(legacyLink, ":phone-hash") {
		t.Fatalf("unexpected legacy profile link: %s", legacyLink)
	}
}

func TestProfileLinkSupportsMultipleHashesAndWorkers(t *testing.T) {
	cfg := validTestConfig()
	profile := ConnectionProfile{ID: "phone", VKHashes: []string{"one", "two"}, Workers: 54}
	link := cfg.ProfileQWDTTLink(profile)
	if !strings.Contains(link, "hashes=one%2Ctwo") || !strings.Contains(link, "workers=54") {
		t.Fatalf("unexpected multi-hash qWDTT link: %s", link)
	}
}

func TestNormalizeVKHashesLimitsAndDeduplicates(t *testing.T) {
	got := normalizeVKHashes([]string{"one, two", "two", "three", "four", "five"}, "")
	if strings.Join(got, ",") != "one,two,three,four" {
		t.Fatalf("unexpected hashes: %#v", got)
	}
}

func TestNormalizeVKHashFromFullLink(t *testing.T) {
	if got := normalizeVKHash("https://vk.ru/call/join/8Trt578L7Q22ZY4iWImAkUYk3NNAPwTVT1-Jxtxi3Wo"); got != "8Trt578L7Q22ZY4iWImAkUYk3NNAPwTVT1-Jxtxi3Wo" {
		t.Fatalf("unexpected VK hash: %q", got)
	}
}

func TestProfilePasswordsSelectProfilesOnSharedPort(t *testing.T) {
	t.Parallel()

	cfg := validTestConfig()
	cfg.Server.Password = "shared-secret"
	first := ConnectionProfile{ID: "phone"}
	second := ConnectionProfile{ID: "laptop"}
	if cfg.profilePassword(first) == cfg.profilePassword(second) {
		t.Fatal("different profiles received the same transport selector")
	}
	if got := cfg.profilePassword(ConnectionProfile{ID: "default"}); got != cfg.Server.Password {
		t.Fatalf("legacy default profile password changed: %q", got)
	}
}

func TestNormalizeProfilesAssignsAddressesByOrder(t *testing.T) {
	t.Parallel()

	cfg := validTestConfig()
	cfg.Server.Profiles = []ConnectionProfile{
		{ID: "one", Name: "One", Enabled: true, ClientIP: "192.0.2.99", DTLSPort: 1},
		{ID: "two", Name: "Two", Enabled: true, ClientIP: "192.0.2.100", DTLSPort: 2},
	}
	cfg.Server.DTLSPort = 56000
	cfg.NormalizeProfiles()
	if cfg.Server.Profiles[0].ClientIP != "10.66.66.2" || cfg.Server.Profiles[1].ClientIP != "10.66.66.3" {
		t.Fatalf("unexpected automatic addresses: %#v", cfg.Server.Profiles)
	}
	for _, profile := range cfg.Server.Profiles {
		if profile.DTLSPort != 56000 {
			t.Fatalf("profile did not inherit shared DTLS port: %#v", profile)
		}
	}
}
