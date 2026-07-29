package qwdtt

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"net/url"
	"strings"
)

func (c Config) ClientLink() string {
	// The official qWDTT client currently consumes the original wdtt:// URI.
	// Keep this as the canonical client link; the qwdtt://config form is kept
	// separately for diagnostics/compatibility with newer clients.
	return c.LegacyLink()
}

// QWDTTLink is the newer query-style URI, if a client explicitly supports it.
func (c Config) QWDTTLink() string {
	return c.ProfileQWDTTLink(c.defaultProfile())
}

func (c Config) ProfileQWDTTLink(profile ConnectionProfile) string {
	s := c.Server
	vpnPort := s.VPNPort
	if vpnPort == 0 {
		vpnPort = 9000
	}
	name := profile.Name
	if name == "" {
		name = "qWDTT server"
	}
	port := s.DTLSPort
	if port == 0 {
		port = 56000
	}
	workers := profile.Workers
	if workers == 0 {
		workers = 9
	}
	return "qwdtt://config?name=" + url.QueryEscape(name) + "&peer=" + url.QueryEscape(normalizePublicHost(s.PublicHost)+":"+intString(port)) + "&hashes=" + url.QueryEscape(strings.Join(profileHashes(profile), ",")) + "&workers=" + intString(workers) + "&port=" + intString(vpnPort) + "&pass=" + url.QueryEscape(c.profilePassword(profile))
}

// LegacyLink is the URI consumed by the original qWDTT/WDTT clients.
func (c Config) LegacyLink() string {
	return c.ProfileLegacyLink(c.defaultProfile())
}

func (c Config) ProfileLegacyLink(profile ConnectionProfile) string {
	s := c.Server
	dtlsPort, wgPort := s.DTLSPort, s.WGPort
	vpnPort := s.VPNPort
	if dtlsPort == 0 {
		dtlsPort = 56000
	}
	if wgPort == 0 {
		wgPort = 56001
	}
	if vpnPort == 0 {
		vpnPort = 9000
	}
	return "wdtt://" + normalizePublicHost(s.PublicHost) + ":" + intString(dtlsPort) + ":" + intString(wgPort) + ":" + intString(vpnPort) + ":" + url.PathEscape(c.profilePassword(profile)) + ":" + url.PathEscape(strings.Join(profileHashes(profile), ","))
}

func (c Config) profilePassword(profile ConnectionProfile) string {
	// Preserve links produced by pre-profile releases for the migrated default
	// profile. Other profiles receive deterministic, non-reversible selectors.
	if profile.ID == "default" {
		return c.Server.Password
	}
	mac := hmac.New(sha256.New, []byte(c.Server.Password))
	_, _ = mac.Write([]byte("qwdtt-profile\x00" + profile.ID))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil)[:18])
}

func (c Config) ProfileByID(id string) (ConnectionProfile, bool) {
	for _, profile := range c.Server.Profiles {
		if profile.ID == id {
			return profile, true
		}
	}
	return ConnectionProfile{}, false
}

func (c Config) defaultProfile() ConnectionProfile {
	for _, profile := range c.Server.Profiles {
		if profile.Enabled {
			return profile
		}
	}
	if len(c.Server.Profiles) > 0 {
		return c.Server.Profiles[0]
	}
	return ConnectionProfile{ID: "default", Name: "qWDTT server", Enabled: true, VKHash: c.Server.VKHash, DTLSPort: c.Server.DTLSPort}
}

func normalizePublicHost(host string) string {
	host = strings.TrimSpace(host)
	host = strings.TrimPrefix(host, "https://")
	host = strings.TrimPrefix(host, "http://")
	host = strings.TrimRight(host, "/")
	if i := strings.IndexByte(host, '/'); i >= 0 {
		host = host[:i]
	}
	return host
}

func normalizeVKHash(value string) string {
	value = strings.TrimSpace(value)
	marker := "/call/join/"
	if index := strings.Index(strings.ToLower(value), marker); index >= 0 {
		value = value[index+len(marker):]
	}
	value = strings.Trim(value, "/")
	if index := strings.IndexAny(value, "/?#"); index >= 0 {
		value = value[:index]
	}
	return strings.TrimSpace(value)
}

func normalizeVKHashes(values []string, legacy string) []string {
	if len(values) == 0 && strings.TrimSpace(legacy) != "" {
		values = []string{legacy}
	}
	out := make([]string, 0, len(values))
	seen := make(map[string]bool)
	for _, value := range values {
		for _, part := range strings.Split(value, ",") {
			hash := normalizeVKHash(part)
			if hash == "" || seen[hash] {
				continue
			}
			seen[hash] = true
			out = append(out, hash)
		}
	}
	if len(out) > 4 {
		out = out[:4]
	}
	return out
}

func profileHashes(profile ConnectionProfile) []string {
	return normalizeVKHashes(profile.VKHashes, profile.VKHash)
}

func intString(v int) string {
	if v == 0 {
		return "0"
	}
	out := ""
	for v > 0 {
		out = string(byte('0'+v%10)) + out
		v /= 10
	}
	return out
}
