package qwdtt

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"io"
	"net/http"
	"os"
	"os/exec"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"
)

const githubRepository = "SemerDevLab/qWDTT_Server_Keenetic"
const githubReleasesURL = "https://api.github.com/repos/" + githubRepository + "/releases?per_page=100"
const githubReleasePageURL = "https://github.com/" + githubRepository + "/releases"

var releaseAssetPattern = regexp.MustCompile(`^qwdtt_([0-9]+(?:\.[0-9]+)*)-([0-9]+)_([^/]+)-kn\.ipk$`)

type githubRelease struct {
	TagName    string        `json:"tag_name"`
	Draft      bool          `json:"draft"`
	Prerelease bool          `json:"prerelease"`
	Assets     []githubAsset `json:"assets"`
}

type githubAsset struct {
	Name               string `json:"name"`
	BrowserDownloadURL string `json:"browser_download_url"`
	Size               int64  `json:"size"`
}

type UpdateInfo struct {
	Current      string `json:"current"`
	Latest       string `json:"latest"`
	Available    bool   `json:"available"`
	Architecture string `json:"architecture"`
	Asset        string `json:"asset"`
	Status       string `json:"status,omitempty"`
	Error        string `json:"error,omitempty"`
	DownloadURL  string `json:"-"`
}

type updateState struct {
	mu   sync.Mutex
	info UpdateInfo
}

func (s *updateState) get() UpdateInfo {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.info
}

func (s *updateState) set(info UpdateInfo) {
	s.mu.Lock()
	s.info = info
	s.mu.Unlock()
}

func packageArchitecture() string {
	if output, err := exec.Command("uname", "-m").Output(); err == nil {
		switch strings.ToLower(strings.TrimSpace(string(output))) {
		case "mips", "mipsel", "mipsle":
			return "mipsel-3.4"
		case "armv7l", "armv6l", "arm":
			return "armv7-3.2"
		case "aarch64", "arm64":
			return "aarch64-3.10"
		}
	}
	switch runtime.GOARCH {
	case "mipsle":
		return "mipsel-3.4"
	case "arm":
		return "armv7-3.2"
	case "arm64":
		return "aarch64-3.10"
	default:
		return ""
	}
}

func parseReleaseVersion(value string) (string, int, bool) {
	parts := strings.Split(strings.TrimPrefix(strings.TrimSpace(value), "v"), "-")
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return "", 0, false
	}
	if _, err := strconv.Atoi(parts[1]); err != nil {
		return "", 0, false
	}
	for _, part := range strings.Split(parts[0], ".") {
		if _, err := strconv.Atoi(part); err != nil {
			return "", 0, false
		}
	}
	return parts[0], mustAtoi(parts[1]), true
}

func mustAtoi(value string) int {
	parsed, _ := strconv.Atoi(value)
	return parsed
}

func compareReleaseVersions(left, right string) int {
	leftVersion, leftRelease, leftOK := parseReleaseVersion(left)
	rightVersion, rightRelease, rightOK := parseReleaseVersion(right)
	if !leftOK || !rightOK {
		return strings.Compare(left, right)
	}
	leftParts := strings.Split(leftVersion, ".")
	rightParts := strings.Split(rightVersion, ".")
	for index := 0; index < 3; index++ {
		leftPart, rightPart := 0, 0
		if index < len(leftParts) {
			leftPart = mustAtoi(leftParts[index])
		}
		if index < len(rightParts) {
			rightPart = mustAtoi(rightParts[index])
		}
		if leftPart != rightPart {
			if leftPart < rightPart {
				return -1
			}
			return 1
		}
	}
	if leftRelease < rightRelease {
		return -1
	}
	if leftRelease > rightRelease {
		return 1
	}
	return 0
}

func checkForUpdate(ctx context.Context, logs *LogBook) (UpdateInfo, error) {
	info := UpdateInfo{Current: ServerVersion(), Architecture: packageArchitecture(), Status: "idle"}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, githubReleasesURL, nil)
	if err != nil {
		if logs != nil {
			logs.Add("ERROR", "update check request creation failed: %v", err)
		}
		return info, err
	}
	request.Header.Set("Accept", "application/vnd.github+json")
	request.Header.Set("User-Agent", "qWDTT-Control/"+ServerVersion())
	client := &http.Client{Timeout: 20 * time.Second}
	response, err := client.Do(request)
	if err != nil {
		if logs != nil {
			logs.Add("ERROR", "update check request failed: %v", err)
		}
		return info, fmt.Errorf("GitHub Releases: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		// GitHub returns 404 when there is no release marked as the latest one
		// (for example, when assets were published under a named release). The
		// releases page still contains the downloadable IPK assets in that case.
		if response.StatusCode == http.StatusForbidden || response.StatusCode == http.StatusNotFound {
			return checkReleasePage(ctx, info, logs)
		}
		if logs != nil {
			logs.Add("ERROR", "update check GitHub returned HTTP %d", response.StatusCode)
		}
		return info, fmt.Errorf("GitHub Releases returned HTTP %d", response.StatusCode)
	}
	var releases []githubRelease
	if err := json.NewDecoder(io.LimitReader(response.Body, 2<<20)).Decode(&releases); err != nil {
		if logs != nil {
			logs.Add("ERROR", "update check response parse failed: %v", err)
		}
		return info, fmt.Errorf("parse GitHub releases: %w", err)
	}
	architecture := info.Architecture
	if architecture == "" {
		if logs != nil {
			logs.Add("ERROR", "update check failed: unsupported router architecture")
		}
		return info, errors.New("unsupported router architecture")
	}
	for _, release := range releases {
		if release.Draft || release.Prerelease {
			continue
		}
		for _, asset := range release.Assets {
			match := releaseAssetPattern.FindStringSubmatch(asset.Name)
			if len(match) != 4 || match[3] != architecture {
				continue
			}
			candidate := match[1] + "-" + match[2]
			if info.Latest == "" || compareReleaseVersions(info.Latest, candidate) < 0 {
				info.Latest = candidate
				info.Asset = asset.Name
				info.DownloadURL = asset.BrowserDownloadURL
			}
		}
	}
	if info.Latest == "" {
		if logs != nil {
			logs.Add("ERROR", "update check found no IPK for architecture %s", architecture)
		}
		return info, fmt.Errorf("releases have no IPK for architecture %s", architecture)
	}
	info.Available = info.Current == "dev" || compareReleaseVersions(info.Current, info.Latest) < 0
	return info, nil
}

func checkReleasePage(ctx context.Context, info UpdateInfo, logs *LogBook) (UpdateInfo, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, githubReleasePageURL, nil)
	if err != nil {
		if logs != nil {
			logs.Add("ERROR", "update release page request creation failed: %v", err)
		}
		return info, err
	}
	request.Header.Set("User-Agent", "qWDTT-Control/"+ServerVersion())
	response, err := (&http.Client{Timeout: 20 * time.Second}).Do(request)
	if err != nil {
		if logs != nil {
			logs.Add("ERROR", "update release page request failed: %v", err)
		}
		return info, fmt.Errorf("GitHub Releases page: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		if logs != nil {
			logs.Add("ERROR", "update release page returned HTTP %d", response.StatusCode)
		}
		return info, fmt.Errorf("GitHub Releases page returned HTTP %d", response.StatusCode)
	}
	page, err := io.ReadAll(io.LimitReader(response.Body, 8<<20))
	if err != nil {
		if logs != nil {
			logs.Add("ERROR", "read GitHub Releases page failed: %v", err)
		}
		return info, fmt.Errorf("read GitHub Releases page: %w", err)
	}
	architecture := info.Architecture
	assetLinkPattern := regexp.MustCompile(`releases/download/([^/]+)/([^"'<>&? ]+\.ipk)`)
	for _, match := range assetLinkPattern.FindAllStringSubmatch(html.UnescapeString(string(page)), -1) {
		if len(match) != 3 || !strings.HasSuffix(match[2], "_"+architecture+"-kn.ipk") {
			continue
		}
		assetMatch := releaseAssetPattern.FindStringSubmatch(match[2])
		if len(assetMatch) != 4 {
			continue
		}
		candidate := assetMatch[1] + "-" + assetMatch[2]
		if info.Latest == "" || compareReleaseVersions(info.Latest, candidate) < 0 {
			info.Latest = candidate
			info.Asset = match[2]
			info.DownloadURL = "https://github.com/" + githubRepository + "/releases/download/" + match[1] + "/" + match[2]
		}
	}
	if info.Latest == "" {
		if logs != nil {
			logs.Add("ERROR", "update release page found no IPK for architecture %s", architecture)
		}
		return info, fmt.Errorf("release page has no IPK for architecture %s", architecture)
	}
	info.Available = info.Current == "dev" || compareReleaseVersions(info.Current, info.Latest) < 0
	return info, nil
}

func installUpdate(ctx context.Context, info UpdateInfo) error {
	if !info.Available || info.Asset == "" {
		return errors.New("no update is available")
	}
	if info.DownloadURL == "" {
		return errors.New("update download URL is missing")
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, info.DownloadURL, nil)
	if err != nil {
		return err
	}
	request.Header.Set("User-Agent", "qWDTT-Control/"+ServerVersion())
	client := &http.Client{Timeout: 10 * time.Minute}
	response, err := client.Do(request)
	if err != nil {
		return fmt.Errorf("download update: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("download update returned HTTP %d", response.StatusCode)
	}
	if response.ContentLength > 256<<20 {
		return errors.New("update package is too large")
	}
	if err := os.MkdirAll("/opt/tmp", 0755); err != nil {
		return fmt.Errorf("create update directory: %w", err)
	}
	temporary, err := os.CreateTemp("/opt/tmp", "qwdtt-update-*.ipk")
	if err != nil {
		return fmt.Errorf("create update file: %w", err)
	}
	path := temporary.Name()
	defer func() {
		if path != "" {
			_ = os.Remove(path)
		}
	}()
	if err := temporary.Chmod(0600); err != nil {
		_ = temporary.Close()
		return err
	}
	if _, err := io.Copy(temporary, io.LimitReader(response.Body, 256<<20)); err != nil {
		_ = temporary.Close()
		return fmt.Errorf("save update: %w", err)
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	runner, err := os.CreateTemp("/opt/tmp", "qwdtt-update-runner-*.sh")
	if err != nil {
		return fmt.Errorf("create update runner: %w", err)
	}
	runnerPath := runner.Name()
	logPath := "/opt/tmp/qwdtt-update.log"
	script := fmt.Sprintf(`#!/bin/sh
IPK=%q
LOG=%q
OPKG=/opt/bin/opkg
INIT=/opt/etc/init.d/S99qwdtt
sleep 3
echo "qWDTT update started $(date)" > "$LOG"
if [ ! -x "$OPKG" ]; then OPKG=opkg; fi
"$OPKG" install "$IPK" >> "$LOG" 2>&1
STATUS=$?
if [ "$STATUS" -eq 0 ]; then
    sleep 2
    if ! pidof qwdtt >/dev/null 2>&1; then
        "$INIT" start >> "$LOG" 2>&1 || STATUS=$?
    fi
fi
rm -f "$IPK" "$0"
exit "$STATUS"
`, path, logPath)
	if _, err := runner.WriteString(script); err != nil {
		_ = runner.Close()
		_ = os.Remove(runnerPath)
		return fmt.Errorf("write update runner: %w", err)
	}
	if err := runner.Chmod(0700); err != nil {
		_ = runner.Close()
		_ = os.Remove(runnerPath)
		return err
	}
	if err := runner.Close(); err != nil {
		_ = os.Remove(runnerPath)
		return err
	}
	command := exec.Command("/bin/sh", runnerPath)
	command.Stdin = nil
	command.Stdout = io.Discard
	command.Stderr = io.Discard
	if err := command.Start(); err != nil {
		_ = os.Remove(runnerPath)
		return fmt.Errorf("start detached update runner: %w", err)
	}
	// The runner owns both files from this point. It removes them after opkg
	// finishes, even though preinst stops the qWDTT process that launched it.
	path = ""
	return nil
}

func attachUpdateEndpoints(m *http.ServeMux, logs *LogBook) {
	state := &updateState{info: UpdateInfo{Current: ServerVersion(), Architecture: packageArchitecture(), Status: "idle"}}
	m.HandleFunc("GET /api/qwdtt/update/check", func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 25*time.Second)
		defer cancel()
		info, err := checkForUpdate(ctx, logs)
		if err != nil {
			if logs != nil {
				logs.Add("ERROR", "update check finished with error: %v", err)
			}
			info.Error = err.Error()
			info.Status = "error"
			state.set(info)
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		state.set(info)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(info)
	})
	m.HandleFunc("GET /api/qwdtt/update/status", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(state.get())
	})
	m.HandleFunc("POST /api/qwdtt/update/install", func(w http.ResponseWriter, r *http.Request) {
		info := state.get()
		if !info.Available {
			http.Error(w, "no checked update is available", http.StatusBadRequest)
			return
		}
		state.mu.Lock()
		if state.info.Status == "installing" {
			state.mu.Unlock()
			http.Error(w, "update is already installing", http.StatusConflict)
			return
		}
		state.info.Status = "installing"
		state.mu.Unlock()
		go func(info UpdateInfo) {
			ctx, cancel := context.WithTimeout(context.Background(), 12*time.Minute)
			defer cancel()
			if err := installUpdate(ctx, info); err != nil {
				info.Status = "error"
				info.Error = err.Error()
				info.Available = true
			} else {
				info.Status = "installing"
				info.Available = false
			}
			state.set(info)
		}(info)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusAccepted)
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "installing", "version": info.Latest})
	})
}
