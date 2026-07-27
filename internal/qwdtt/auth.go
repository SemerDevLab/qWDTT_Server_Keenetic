package qwdtt

import (
	"bytes"
	"context"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

var errInvalidWebCredentials = errors.New("invalid Keenetic credentials")

type webAuth struct {
	mu       sync.Mutex
	sessions map[string]time.Time
}

func newWebAuth() *webAuth { return &webAuth{sessions: make(map[string]time.Time)} }

func (a *webAuth) valid(r *http.Request) bool {
	c, err := r.Cookie("qwdtt_session")
	if err != nil {
		return false
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	expires, ok := a.sessions[c.Value]
	if !ok || time.Now().After(expires) {
		delete(a.sessions, c.Value)
		return false
	}
	return true
}

func (a *webAuth) create() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return ""
	}
	token := fmt.Sprintf("%x", sha256.Sum256(b))
	a.mu.Lock()
	now := time.Now()
	for existing, expires := range a.sessions {
		if now.After(expires) {
			delete(a.sessions, existing)
		}
	}
	a.sessions[token] = now.Add(7 * 24 * time.Hour)
	a.mu.Unlock()
	return token
}

func authenticateKeenetic(ctx context.Context, login, password string) error {
	login = strings.TrimSpace(login)
	if login == "" || password == "" {
		return errInvalidWebCredentials
	}
	host := "192.168.1.1"
	if iface, err := net.InterfaceByName("br0"); err == nil {
		if addrs, err := iface.Addrs(); err == nil {
			for _, addr := range addrs {
				if n, ok := addr.(*net.IPNet); ok && n.IP.To4() != nil {
					host = n.IP.To4().String()
					break
				}
			}
		}
	}
	client := &http.Client{Timeout: 10 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	url := "http://" + host + "/auth"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusOK {
		return nil
	}
	if resp.StatusCode != http.StatusUnauthorized {
		return errInvalidWebCredentials
	}
	challenge, realm := resp.Header.Get("X-NDM-Challenge"), resp.Header.Get("X-NDM-Realm")
	if challenge == "" || realm == "" {
		return errInvalidWebCredentials
	}
	md := md5.Sum([]byte(login + ":" + realm + ":" + password))
	sha := sha256.Sum256([]byte(challenge + hex.EncodeToString(md[:])))
	body, _ := json.Marshal(map[string]string{"login": login, "password": hex.EncodeToString(sha[:])})
	req, err = http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	for _, c := range resp.Cookies() {
		req.AddCookie(c)
	}
	resp, err = client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusUnauthorized {
		return errInvalidWebCredentials
	}
	if resp.StatusCode != http.StatusOK {
		return errInvalidWebCredentials
	}
	return nil
}
