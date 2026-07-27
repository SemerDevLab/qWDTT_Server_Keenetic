package qwdtt

import "testing"

func TestTransportRestartRequiredIgnoresLinkAndPolicyFields(t *testing.T) {
	t.Parallel()

	previous := Config{
		Enabled: true,
		Mode:    ModeServer,
		DataDir: "/opt/etc/qwdtt",
		Server: ServerConfig{
			ListenAddr: "0.0.0.0:56000",
			DTLSPort:   56000,
			WGPort:     56001,
			Password:   "secret",
			Network:    "10.66.66.0/24",
			PublicHost: "old.example",
			Profiles: []ConnectionProfile{{
				ID: "phone", Name: "Phone", Enabled: true, ClientIP: "10.66.66.2", VKHash: "old", AccessMode: RouteAll,
			}},
		},
		Routing: RoutingConfig{WAN: "ppp0"},
	}
	next := previous
	next.Server.PublicHost = "new.example"
	next.Server.Profiles = append([]ConnectionProfile(nil), previous.Server.Profiles...)
	next.Server.Profiles[0].Name = "New name"
	next.Server.Profiles[0].VKHash = "new"
	next.Server.Profiles[0].AccessMode = RouteInternet

	if transportRestartRequired(previous, next) {
		t.Fatal("link and access-policy edits should not restart active transport")
	}
}

func TestTransportRestartRequiredForListenerAndProfileSet(t *testing.T) {
	t.Parallel()

	base := Config{
		Enabled: true,
		Mode:    ModeServer,
		DataDir: "/opt/etc/qwdtt",
		Server: ServerConfig{
			ListenAddr: "0.0.0.0:56000", DTLSPort: 56000, WGPort: 56001,
			Password: "secret", Network: "10.66.66.0/24",
			Profiles: []ConnectionProfile{{ID: "phone", Enabled: true, ClientIP: "10.66.66.2"}},
		},
		Routing: RoutingConfig{WAN: "ppp0"},
	}
	changedPort := base
	changedPort.Server.DTLSPort++
	if !transportRestartRequired(base, changedPort) {
		t.Fatal("DTLS port change must restart transport")
	}
	addedProfile := base
	addedProfile.Server.Profiles = append(append([]ConnectionProfile(nil), base.Server.Profiles...), ConnectionProfile{ID: "tablet", Enabled: true, ClientIP: "10.66.66.3"})
	if !transportRestartRequired(base, addedProfile) {
		t.Fatal("profile set change must restart transport")
	}
	disabledProfile := base
	disabledProfile.Server.Profiles = append([]ConnectionProfile(nil), base.Server.Profiles...)
	disabledProfile.Server.Profiles[0].Enabled = false
	if !transportRestartRequired(base, disabledProfile) {
		t.Fatal("enabling or disabling a profile must restart transport")
	}
}
