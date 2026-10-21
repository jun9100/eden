// SPDX-FileCopyrightText: Copyright 2026 Eden Emulator Project
// SPDX-License-Identifier: GPL-3.0-or-later

package main

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	defaultMaxObjectBytes int64 = 512 * 1024 * 1024
	maxMetadataBytes            = 64 * 1024
	onlineWindow                = 90 * time.Second
)

// version is overridden at build time with -ldflags "-X main.version=...".
var version = "dev"

type server struct {
	dataDir        string
	token          string
	adminToken     string
	maxObjectBytes int64
	startedAt      time.Time

	mu        sync.Mutex
	state     serverState
	dashboard dashboardState
	settings  serverSettings
	events    []event

	verifying sync.Mutex
	logins    loginLimiter
	requests  atomic.Int64
}

type serverOptions struct {
	adminToken string
	settings   serverSettings
}

func newServer(dataDir, token string, maxObjectBytes int64, adminTokens ...string) (*server, error) {
	options := serverOptions{}
	if len(adminTokens) > 0 {
		options.adminToken = adminTokens[0]
	}
	return newServerWithOptions(dataDir, token, maxObjectBytes, options)
}

func newServerWithOptions(dataDir, token string, maxObjectBytes int64, options serverOptions) (*server, error) {
	if token == "" {
		return nil, errors.New("EDEN_SYNCD_TOKEN or --token is required")
	}
	if options.adminToken != "" && options.adminToken == token {
		slog.Error("administrator dashboard disabled: EDEN_SYNCD_ADMIN_TOKEN must differ from EDEN_SYNCD_TOKEN")
		options.adminToken = ""
	}
	if maxObjectBytes <= 0 {
		return nil, errors.New("max object size must be positive")
	}
	if !options.settings.Retention.valid() {
		return nil, errors.New("invalid retention policy")
	}
	if err := os.MkdirAll(filepath.Join(dataDir, "objects"), 0o700); err != nil {
		return nil, fmt.Errorf("create data directory: %w", err)
	}

	s := &server{
		dataDir:        dataDir,
		token:          token,
		adminToken:     options.adminToken,
		maxObjectBytes: maxObjectBytes,
		startedAt:      time.Now().UTC(),
		state:          serverState{Scopes: make(map[string]scope)},
		dashboard: dashboardState{
			Scopes:  make(map[string]scopeMetadata),
			Devices: make(map[string]deviceInfo),
		},
		logins: loginLimiter{failures: make(map[string]loginFailures)},
	}
	if err := s.loadState(); err != nil {
		return nil, err
	}
	if err := s.loadDashboard(); err != nil {
		return nil, err
	}
	if err := s.loadSettings(options.settings); err != nil {
		return nil, err
	}
	if err := s.loadEvents(); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *server) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", s.handleHealth)

	mux.HandleFunc("PUT /v1/blobs/{id}", s.requireToken(s.handlePutBlob))
	mux.HandleFunc("GET /v1/blobs/{id}", s.requireToken(s.handleGetBlob))
	mux.HandleFunc("GET /v1/scopes/{id}/head", s.requireToken(s.handleGetHead))
	mux.HandleFunc("PUT /v1/scopes/{id}/snapshots/{snapshot}", s.requireToken(s.handlePutSnapshot))
	mux.HandleFunc("PUT /v1/scopes/{id}/metadata", s.requireToken(s.handlePutScopeMetadata))
	mux.HandleFunc("POST /v1/devices/heartbeat", s.requireToken(s.handleDeviceHeartbeat))

	s.registerAdmin(mux)
	return s.withCommonHeaders(mux)
}

func (s *server) withCommonHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.requests.Add(1)
		header := w.Header()
		header.Set("X-Content-Type-Options", "nosniff")
		header.Set("Referrer-Policy", "no-referrer")
		header.Set("Server", "eden-syncd")
		if strings.HasPrefix(r.URL.Path, "/admin") {
			header.Set("X-Frame-Options", "DENY")
			header.Set("Content-Security-Policy", "default-src 'self'; img-src 'self' data: https: http:; "+
				"style-src 'self' 'unsafe-inline'; script-src 'self'; connect-src 'self'; frame-ancestors 'none'; "+
				"base-uri 'none'; form-action 'self'")
		}
		next.ServeHTTP(w, r)
	})
}

func validLogoURL(value string) bool {
	if value == "" {
		return true
	}
	parsed, err := url.ParseRequestURI(value)
	return err == nil && (parsed.Scheme == "https" || parsed.Scheme == "http") && parsed.Host != ""
}

func validLogoData(value string) bool {
	if value == "" {
		return true
	}
	_, decoded, ok := decodeLogoData(value)
	return ok && len(decoded) <= 1024*1024
}

func decodeLogoData(value string) (string, []byte, bool) {
	header, encoded, ok := strings.Cut(value, ",")
	if !ok || !strings.HasPrefix(header, "data:image/") || !strings.HasSuffix(header, ";base64") {
		return "", nil, false
	}
	mediaType := strings.TrimSuffix(strings.TrimPrefix(header, "data:"), ";base64")
	if strings.ContainsAny(mediaType, "\r\n; \t") {
		return "", nil, false
	}
	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil || len(decoded) == 0 || len(decoded) > 1024*1024 {
		return "", nil, false
	}
	return mediaType, decoded, true
}

func formatBytes(value int64) string {
	units := []string{"B", "KiB", "MiB", "GiB", "TiB"}
	size := float64(value)
	unit := 0
	for size >= 1024 && unit < len(units)-1 {
		size /= 1024
		unit++
	}
	if unit == 0 {
		return fmt.Sprintf("%d %s", value, units[unit])
	}
	return fmt.Sprintf("%.1f %s", size, units[unit])
}

func validObjectID(id string) bool {
	if len(id) != sha256.Size*2 {
		return false
	}
	_, err := hex.DecodeString(id)
	return err == nil && strings.ToLower(id) == id
}

func validScopeID(id string) bool {
	return validIdentifier(id, 128)
}

func validSnapshotID(id string) bool {
	return validIdentifier(id, 128)
}

func validIdentifier(value string, maximum int) bool {
	if value == "" || len(value) > maximum {
		return false
	}
	for _, character := range value {
		if (character < 'a' || character > 'z') &&
			(character < 'A' || character > 'Z') &&
			(character < '0' || character > '9') &&
			character != '-' && character != '_' && character != '.' {
			return false
		}
	}
	return true
}

func writeError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, map[string]string{"error": message})
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(value); err != nil {
		slog.Warn("encode response", "error", err)
	}
}
