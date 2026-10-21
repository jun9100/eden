// SPDX-FileCopyrightText: Copyright 2026 Eden Emulator Project
// SPDX-License-Identifier: GPL-3.0-or-later

package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	sessionCookie   = "eden_syncd_session"
	sessionLifetime = 7 * 24 * time.Hour
	// Mutating dashboard requests must carry this header. Browsers cannot attach custom headers to
	// cross-site requests without a CORS preflight, which this service never grants.
	csrfHeader = "X-Eden-Admin"

	loginFailureLimit  = 8
	loginFailureWindow = 10 * time.Minute
)

type loginFailures struct {
	count int
	start time.Time
}

type loginLimiter struct {
	mu       sync.Mutex
	failures map[string]loginFailures
}

func (l *loginLimiter) blocked(address string, now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	entry, ok := l.failures[address]
	if !ok {
		return false
	}
	if now.Sub(entry.start) > loginFailureWindow {
		delete(l.failures, address)
		return false
	}
	return entry.count >= loginFailureLimit
}

func (l *loginLimiter) fail(address string, now time.Time) {
	l.mu.Lock()
	defer l.mu.Unlock()
	for key, entry := range l.failures {
		if now.Sub(entry.start) > loginFailureWindow {
			delete(l.failures, key)
		}
	}
	entry, ok := l.failures[address]
	if !ok {
		entry.start = now
	}
	entry.count++
	l.failures[address] = entry
}

func (l *loginLimiter) reset(address string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.failures, address)
}

func (s *server) sessionSignature(expires int64) string {
	mac := hmac.New(sha256.New, []byte(s.adminToken))
	mac.Write([]byte("eden-syncd session v1:" + strconv.FormatInt(expires, 10)))
	return hex.EncodeToString(mac.Sum(nil))
}

func (s *server) newSessionValue(now time.Time) (string, time.Time) {
	expires := now.Add(sessionLifetime)
	unix := expires.Unix()
	return strconv.FormatInt(unix, 10) + "." + s.sessionSignature(unix), expires
}

func (s *server) validSession(value string, now time.Time) bool {
	encodedExpiry, signature, ok := strings.Cut(value, ".")
	if !ok {
		return false
	}
	expires, err := strconv.ParseInt(encodedExpiry, 10, 64)
	if err != nil || now.Unix() >= expires {
		return false
	}
	return hmac.Equal([]byte(signature), []byte(s.sessionSignature(expires)))
}

func (s *server) adminTokenMatches(candidate string) bool {
	return subtle.ConstantTimeCompare([]byte(candidate), []byte(s.adminToken)) == 1
}

// adminAuthenticated accepts either the dashboard session cookie or HTTP Basic Auth whose
// password is the administrator token (useful for scripts and Prometheus).
func (s *server) adminAuthenticated(r *http.Request) bool {
	if cookie, err := r.Cookie(sessionCookie); err == nil && s.validSession(cookie.Value, time.Now()) {
		return true
	}
	if _, password, ok := r.BasicAuth(); ok && s.adminTokenMatches(password) {
		return true
	}
	return false
}

func (s *server) requireAdmin(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if s.adminToken == "" {
			http.NotFound(w, r)
			return
		}
		if !s.adminAuthenticated(r) {
			writeError(w, http.StatusUnauthorized, "administrator authentication required")
			return
		}
		next(w, r)
	}
}

// requireAdminWrite additionally requires the anti-CSRF header for state-changing requests.
func (s *server) requireAdminWrite(next http.HandlerFunc) http.HandlerFunc {
	return s.requireAdmin(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get(csrfHeader) != "1" {
			writeError(w, http.StatusForbidden, "missing "+csrfHeader+" header")
			return
		}
		next(w, r)
	})
}

func requestIsSecure(r *http.Request) bool {
	return r.TLS != nil || strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https")
}

func (s *server) handleLogin(w http.ResponseWriter, r *http.Request) {
	if s.adminToken == "" {
		http.NotFound(w, r)
		return
	}
	if r.Header.Get(csrfHeader) != "1" {
		writeError(w, http.StatusForbidden, "missing "+csrfHeader+" header")
		return
	}
	now := time.Now()
	address := remoteHost(r)
	if s.logins.blocked(address, now) {
		writeError(w, http.StatusTooManyRequests, "too many failed attempts, try again later")
		return
	}
	var request struct {
		Token string `json:"token"`
	}
	if !decodeAdminJSON(w, r, &request) {
		return
	}
	if !s.adminTokenMatches(request.Token) {
		s.logins.fail(address, now)
		writeError(w, http.StatusUnauthorized, "invalid administrator token")
		return
	}
	s.logins.reset(address)
	value, expires := s.newSessionValue(now)
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookie,
		Value:    value,
		Path:     "/",
		Expires:  expires,
		HttpOnly: true,
		Secure:   requestIsSecure(r),
		SameSite: http.SameSiteStrictMode,
	})
	writeJSON(w, http.StatusOK, map[string]any{"authenticated": true, "expires_at": expires.UTC()})
}

func (s *server) handleLogout(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookie,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   requestIsSecure(r),
		SameSite: http.SameSiteStrictMode,
	})
	w.WriteHeader(http.StatusNoContent)
}

func (s *server) handleSession(w http.ResponseWriter, r *http.Request) {
	if s.adminToken == "" {
		http.NotFound(w, r)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"authenticated": s.adminAuthenticated(r), "version": version})
}
