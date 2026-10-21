// SPDX-FileCopyrightText: Copyright 2026 Eden Emulator Project
// SPDX-License-Identifier: GPL-3.0-or-later

package main

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"html/template"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	defaultMaxObjectBytes int64 = 512 * 1024 * 1024
	maxMetadataBytes            = 64 * 1024
)

type snapshot struct {
	ID        string    `json:"id"`
	Blob      string    `json:"blob"`
	Parent    string    `json:"parent"`
	CreatedAt time.Time `json:"created_at"`
}

type scope struct {
	Head      string              `json:"head"`
	Snapshots map[string]snapshot `json:"snapshots"`
}

type serverState struct {
	Scopes map[string]scope `json:"scopes"`
}

type scopeMetadata struct {
	Title    string `json:"title,omitempty"`
	LogoURL  string `json:"logo_url,omitempty"`
	LogoData string `json:"logo_data,omitempty"`
}

type deviceInfo struct {
	ID       string    `json:"id"`
	Name     string    `json:"name,omitempty"`
	Platform string    `json:"platform,omitempty"`
	Version  string    `json:"version,omitempty"`
	LastSeen time.Time `json:"last_seen"`
}

type dashboardState struct {
	Scopes  map[string]scopeMetadata `json:"scopes"`
	Devices map[string]deviceInfo    `json:"devices,omitempty"`
}

type server struct {
	dataDir        string
	token          string
	adminToken     string
	maxObjectBytes int64

	mu        sync.Mutex
	state     serverState
	dashboard dashboardState
}

func newServer(dataDir, token string, maxObjectBytes int64, adminTokens ...string) (*server, error) {
	if token == "" {
		return nil, errors.New("EDEN_SYNCD_TOKEN or --token is required")
	}
	if maxObjectBytes <= 0 {
		return nil, errors.New("max object size must be positive")
	}
	if err := os.MkdirAll(filepath.Join(dataDir, "objects"), 0o700); err != nil {
		return nil, fmt.Errorf("create data directory: %w", err)
	}

	adminToken := ""
	if len(adminTokens) > 0 {
		adminToken = adminTokens[0]
	}

	s := &server{
		dataDir:        dataDir,
		token:          token,
		adminToken:     adminToken,
		maxObjectBytes: maxObjectBytes,
		state:          serverState{Scopes: make(map[string]scope)},
		dashboard: dashboardState{
			Scopes:  make(map[string]scopeMetadata),
			Devices: make(map[string]deviceInfo),
		},
	}
	if err := s.loadState(); err != nil {
		return nil, err
	}
	if err := s.loadDashboard(); err != nil {
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
	mux.HandleFunc("GET /admin/", s.requireAdmin(s.handleDashboard))
	mux.HandleFunc("GET /admin/scopes/{id}/logo", s.requireAdmin(s.handleScopeLogo))
	mux.HandleFunc("POST /admin/scopes/{id}", s.requireAdmin(s.handleUpdateScopeMetadata))
	return mux
}

func (s *server) requireToken(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		const prefix = "Bearer "
		authorization := r.Header.Get("Authorization")
		if !strings.HasPrefix(authorization, prefix) ||
			subtle.ConstantTimeCompare([]byte(strings.TrimPrefix(authorization, prefix)), []byte(s.token)) != 1 {
			writeError(w, http.StatusUnauthorized, "authentication required")
			return
		}
		s.recordDevice(r)
		next(w, r)
	}
}

func (s *server) recordDevice(r *http.Request) {
	deviceID := strings.TrimSpace(r.Header.Get("X-Eden-Device-ID"))
	if !validIdentifier(deviceID, 128) {
		return
	}
	device := deviceInfo{
		ID:       deviceID,
		Name:     trimDeviceField(r.Header.Get("X-Eden-Device-Name"), 80),
		Platform: trimDeviceField(r.Header.Get("X-Eden-Platform"), 32),
		Version:  trimDeviceField(r.Header.Get("X-Eden-Version"), 64),
		LastSeen: time.Now().UTC(),
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if previous, ok := s.dashboard.Devices[deviceID]; ok &&
		device.Name == previous.Name && device.Platform == previous.Platform &&
		device.Version == previous.Version && device.LastSeen.Sub(previous.LastSeen) < 30*time.Second {
		return
	}
	next := dashboardState{
		Scopes:  make(map[string]scopeMetadata, len(s.dashboard.Scopes)),
		Devices: make(map[string]deviceInfo, len(s.dashboard.Devices)+1),
	}
	for id, metadata := range s.dashboard.Scopes {
		next.Scopes[id] = metadata
	}
	for id, known := range s.dashboard.Devices {
		next.Devices[id] = known
	}
	next.Devices[deviceID] = device
	if err := s.persistDashboard(next); err != nil {
		log.Printf("record device %s: %v", deviceID, err)
		return
	}
	s.dashboard = next
}

func trimDeviceField(value string, maximum int) string {
	value = strings.TrimSpace(value)
	if len([]rune(value)) > maximum {
		return string([]rune(value)[:maximum])
	}
	return value
}

func (s *server) requireAdmin(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if s.adminToken == "" {
			http.NotFound(w, r)
			return
		}
		_, password, ok := r.BasicAuth()
		if !ok || subtle.ConstantTimeCompare([]byte(password), []byte(s.adminToken)) != 1 {
			w.Header().Set("WWW-Authenticate", `Basic realm="eden-syncd admin", charset="UTF-8"`)
			writeError(w, http.StatusUnauthorized, "administrator authentication required")
			return
		}
		next(w, r)
	}
}

func (s *server) handleHealth(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write([]byte("{\"status\":\"ok\"}\n"))
}

func (s *server) handleDeviceHeartbeat(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusNoContent)
}

func (s *server) handlePutBlob(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if !validObjectID(id) {
		writeError(w, http.StatusBadRequest, "invalid blob id")
		return
	}

	destination := s.objectPath(id)
	if _, err := os.Stat(destination); err == nil {
		w.WriteHeader(http.StatusNoContent)
		return
	} else if !errors.Is(err, os.ErrNotExist) {
		writeError(w, http.StatusInternalServerError, "cannot inspect blob")
		return
	}

	if err := os.MkdirAll(filepath.Dir(destination), 0o700); err != nil {
		writeError(w, http.StatusInternalServerError, "cannot create object directory")
		return
	}

	temporary, err := os.CreateTemp(filepath.Dir(destination), ".upload-*")
	if err != nil {
		writeError(w, http.StatusInternalServerError, "cannot create temporary object")
		return
	}
	temporaryPath := temporary.Name()
	defer func() { _ = os.Remove(temporaryPath) }()

	hash := sha256.New()
	bytesWritten, copyErr := io.Copy(io.MultiWriter(temporary, hash), http.MaxBytesReader(w, r.Body, s.maxObjectBytes+1))
	if copyErr == nil {
		copyErr = temporary.Sync()
	}
	if closeErr := temporary.Close(); closeErr != nil && copyErr == nil {
		copyErr = closeErr
	}
	if copyErr != nil {
		var maxBytesError *http.MaxBytesError
		if errors.As(copyErr, &maxBytesError) || bytesWritten > s.maxObjectBytes {
			writeError(w, http.StatusRequestEntityTooLarge, "blob exceeds configured size limit")
		} else {
			writeError(w, http.StatusBadRequest, "cannot read blob")
		}
		return
	}
	if bytesWritten > s.maxObjectBytes {
		writeError(w, http.StatusRequestEntityTooLarge, "blob exceeds configured size limit")
		return
	}
	if hex.EncodeToString(hash.Sum(nil)) != id {
		writeError(w, http.StatusUnprocessableEntity, "blob hash does not match id")
		return
	}

	if err := os.Rename(temporaryPath, destination); err != nil {
		if _, statErr := os.Stat(destination); statErr == nil {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		writeError(w, http.StatusInternalServerError, "cannot publish blob")
		return
	}
	w.WriteHeader(http.StatusCreated)
}

func (s *server) handleGetBlob(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if !validObjectID(id) {
		writeError(w, http.StatusBadRequest, "invalid blob id")
		return
	}

	file, err := os.Open(s.objectPath(id))
	if errors.Is(err, os.ErrNotExist) {
		writeError(w, http.StatusNotFound, "blob not found")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "cannot open blob")
		return
	}
	defer file.Close()

	w.Header().Set("Content-Type", "application/octet-stream")
	if _, err := io.Copy(w, file); err != nil {
		log.Printf("stream blob %s: %v", id, err)
	}
}

func (s *server) handleGetHead(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if !validScopeID(id) {
		writeError(w, http.StatusBadRequest, "invalid scope id")
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	storedScope, ok := s.state.Scopes[id]
	if !ok || storedScope.Head == "" {
		writeError(w, http.StatusNotFound, "scope has no snapshots")
		return
	}
	writeJSON(w, http.StatusOK, storedScope.Snapshots[storedScope.Head])
}

func (s *server) handlePutSnapshot(w http.ResponseWriter, r *http.Request) {
	scopeID := r.PathValue("id")
	snapshotID := r.PathValue("snapshot")
	if !validScopeID(scopeID) || !validSnapshotID(snapshotID) {
		writeError(w, http.StatusBadRequest, "invalid scope or snapshot id")
		return
	}

	var candidate snapshot
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxMetadataBytes))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&candidate); err != nil {
		writeError(w, http.StatusBadRequest, "invalid snapshot metadata")
		return
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		writeError(w, http.StatusBadRequest, "invalid snapshot metadata")
		return
	}
	if candidate.ID != snapshotID || !validObjectID(candidate.Blob) ||
		(candidate.Parent != "" && !validSnapshotID(candidate.Parent)) || candidate.CreatedAt.IsZero() {
		writeError(w, http.StatusBadRequest, "invalid snapshot fields")
		return
	}
	if _, err := os.Stat(s.objectPath(candidate.Blob)); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			writeError(w, http.StatusFailedDependency, "snapshot blob is missing")
		} else {
			writeError(w, http.StatusInternalServerError, "cannot inspect snapshot blob")
		}
		return
	}

	expectedHead := strings.Trim(r.Header.Get("If-Match"), "\"")
	s.mu.Lock()
	defer s.mu.Unlock()
	storedScope := s.state.Scopes[scopeID]
	if storedScope.Snapshots == nil {
		storedScope.Snapshots = make(map[string]snapshot)
	}
	if existing, ok := storedScope.Snapshots[snapshotID]; ok {
		if existing == candidate && storedScope.Head == snapshotID {
			writeJSON(w, http.StatusOK, existing)
			return
		}
		writeError(w, http.StatusConflict, "snapshot id already exists")
		return
	}
	if storedScope.Head != expectedHead || candidate.Parent != storedScope.Head {
		writeJSON(w, http.StatusConflict, map[string]string{"head": storedScope.Head})
		return
	}

	nextState := s.state
	nextState.Scopes = make(map[string]scope, len(s.state.Scopes)+1)
	for key, value := range s.state.Scopes {
		nextState.Scopes[key] = value
	}
	nextSnapshots := make(map[string]snapshot, len(storedScope.Snapshots)+1)
	for key, value := range storedScope.Snapshots {
		nextSnapshots[key] = value
	}
	nextSnapshots[snapshotID] = candidate
	nextState.Scopes[scopeID] = scope{Head: snapshotID, Snapshots: nextSnapshots}
	if err := s.persistState(nextState); err != nil {
		writeError(w, http.StatusInternalServerError, "cannot persist snapshot metadata")
		return
	}
	s.state = nextState
	writeJSON(w, http.StatusCreated, candidate)
}

type dashboardSnapshot struct {
	ID        string
	Parent    string
	CreatedAt time.Time
	Bytes     int64
}

type dashboardScope struct {
	ID            string
	Title         string
	LogoURL       string
	EditLogoURL   string
	Head          string
	Named         bool
	SnapshotCount int
	Snapshots     []dashboardSnapshot
}

type dashboardDevice struct {
	ID       string
	Name     string
	Platform string
	Version  string
	LastSeen time.Time
	Online   bool
}

type dashboardView struct {
	ScopeCount          int
	SnapshotCount       int
	ObjectCount         int
	DuplicateObjectRefs int
	TotalBytes          int64
	DeviceCount         int
	OnlineDeviceCount   int
	Devices             []dashboardDevice
	Scopes              []dashboardScope
}

var dashboardTemplate = template.Must(template.New("dashboard").Funcs(template.FuncMap{
	"formatBytes": formatBytes,
	"deviceTime":  func(value time.Time) string { return value.Local().Format("2006-01-02 15:04:05") },
}).Parse(`<!doctype html>
<html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Eden 存档同步</title><style>
:root{color-scheme:light dark;font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;color:#1c2732;background:#eef3f5}
*{box-sizing:border-box}body{margin:0}.top{background:#133d52;color:#fff;padding:22px max(24px,calc((100vw - 1180px)/2));display:flex;justify-content:space-between;align-items:flex-start;gap:24px}.top h1{margin:0;font-size:25px}.top p{margin:4px 0 0;color:#bed6df;font-size:14px}.metrics{display:grid;grid-template-columns:repeat(5,minmax(72px,auto));gap:20px}.metric{font-size:12px;color:#bed6df;white-space:nowrap}.metric strong{display:block;color:#fff;font-size:20px}.content{max-width:1180px;margin:0 auto;padding:26px 24px 50px}.empty{padding:20px 0;color:#5b6871}.devices{background:#fff;border:1px solid #d8e0e4;border-radius:8px;margin:0 0 16px;padding:16px 18px}.devices h2{font-size:17px;margin:0 0 12px}.device-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(240px,1fr));gap:10px}.device{border:1px solid #e3eaed;border-radius:6px;padding:11px 12px}.device strong{font-size:14px}.device small{display:block;color:#65747d;line-height:1.5;margin-top:6px}.device code{display:block;color:#51616c;font-size:11px;overflow-wrap:anywhere;margin-top:8px}.device-status{border-radius:999px;padding:2px 7px;font-size:11px;margin-left:7px}.online{background:#d9f0e2;color:#21643a}.offline{background:#edf1f2;color:#65747d}.scope{background:#fff;border:1px solid #d8e0e4;border-radius:8px;margin:0 0 16px;overflow:hidden}.scope-head{display:flex;gap:14px;align-items:center;padding:16px 18px;border-bottom:1px solid #e5ebed}.logo,.logo-placeholder{width:48px;height:48px;border-radius:6px;background:#dde7eb;object-fit:cover;flex:none}.logo-placeholder{display:grid;place-items:center;color:#78909c;font-size:18px}.scope-title{min-width:0;flex:1}.scope-title h2{font-size:17px;margin:0 0 5px;overflow-wrap:anywhere}.scope-id{font-size:12px;color:#51616c;overflow-wrap:anywhere}.status{display:inline-block;margin-left:8px;border-radius:999px;padding:2px 7px;font-size:11px;font-weight:600;vertical-align:2px}.matched{background:#d9f0e2;color:#21643a}.unmatched{background:#fff0cc;color:#805a00}.head{font-size:12px;color:#51616c;text-align:right;white-space:nowrap}.head code{display:block;max-width:220px;overflow-wrap:anywhere;color:#173e50}.scope-body{display:grid;grid-template-columns:minmax(0,1fr) 340px;gap:0}.history{padding:14px 18px}.history h3,.edit h3{font-size:13px;margin:0 0 10px;color:#40515c}.history-summary{font-size:12px;color:#65747d;margin:-3px 0 8px}.snapshot{display:grid;grid-template-columns:1fr auto;gap:5px;padding:9px 0;border-top:1px solid #edf1f2;font-size:13px}.snapshot:first-of-type{border-top:0}.snapshot code{overflow-wrap:anywhere;color:#1c485e}.snapshot small{color:#65747d}.edit{background:#f6f9fa;border-left:1px solid #e3eaed;padding:14px 18px}.edit label{display:block;font-size:12px;margin:10px 0 4px;color:#40515c}.edit input{width:100%;border:1px solid #b9c8cf;border-radius:4px;padding:8px;background:#fff;color:#192630}.edit button{margin-top:13px;border:0;border-radius:4px;background:#006b80;color:#fff;padding:9px 14px;font-weight:600;cursor:pointer}@media (prefers-color-scheme:dark){:root{color:#e6edf0;background:#10191e}.devices,.scope{background:#172329;border-color:#34444d}.scope-head{border-color:#34444d}.edit{background:#132027;border-color:#34444d}.edit input{background:#0e171c;color:#e6edf0;border-color:#53666f}.snapshot,.device{border-color:#2b3a42}.scope-title code,.head,.snapshot small,.history-summary,.device small,.device code{color:#aebfc7}.matched{background:#1b432a;color:#b9ebc8}.unmatched{background:#4b3b12;color:#f7d676}.offline{background:#2b3a42;color:#aebfc7}}@media(max-width:840px){.top{display:block}.metrics{margin-top:18px}}@media(max-width:720px){.metrics{grid-template-columns:repeat(2,1fr)}.scope-body{grid-template-columns:1fr}.edit{border-left:0;border-top:1px solid #e3eaed}.head{display:none}}
</style></head><body><header class="top"><div><h1>Eden 存档同步</h1><p>按存档范围查看快照与同步状态</p></div><div class="metrics"><span class="metric"><strong>{{.ScopeCount}}</strong>存档范围</span><span class="metric"><strong>{{.SnapshotCount}}</strong>快照</span><span class="metric"><strong>{{.ObjectCount}}</strong>唯一对象</span><span class="metric"><strong>{{.DuplicateObjectRefs}}</strong>重复引用</span><span class="metric"><strong>{{.OnlineDeviceCount}}/{{.DeviceCount}}</strong>在线设备</span></div></header><main class="content"><section class="devices"><h2>接入设备</h2>{{if .Devices}}<div class="device-grid">{{range .Devices}}<div class="device"><div><strong>{{if .Name}}{{.Name}}{{else}}未命名设备{{end}}</strong><span class="device-status {{if .Online}}online{{else}}offline{{end}}">{{if .Online}}在线{{else}}离线{{end}}</span></div><small>{{.Platform}}{{if .Version}} · {{.Version}}{{end}}<br>最后活动：{{deviceTime .LastSeen}}</small><code>{{.ID}}</code></div>{{end}}</div>{{else}}<p class="empty">尚未发现设备接入。</p>{{end}}</section>{{if .Scopes}}{{range .Scopes}}<section class="scope"><div class="scope-head">{{if .LogoURL}}<img class="logo" src="{{.LogoURL}}" alt="{{.Title}}">{{else}}<div class="logo-placeholder" aria-hidden="true">E</div>{{end}}<div class="scope-title"><h2>{{.Title}}{{if .Named}}<span class="status matched">已匹配</span>{{else}}<span class="status unmatched">待匹配</span>{{end}}</h2><code class="scope-id">范围 {{.ID}}</code></div><div class="head">当前版本<code>{{.Head}}</code></div></div><div class="scope-body"><div class="history"><h3>快照历史</h3><p class="history-summary">{{.SnapshotCount}} 个快照</p>{{range .Snapshots}}<div class="snapshot"><div><code>{{.ID}}</code><small>{{if .Parent}}父版本 {{.Parent}}{{else}}初始快照{{end}}</small></div><div><small>{{.CreatedAt.Local.Format "2006-01-02 15:04:05"}}<br>{{formatBytes .Bytes}}</small></div></div>{{end}}</div><form class="edit" method="post" action="/admin/scopes/{{.ID}}"><h3>显示设置</h3><label for="title-{{.ID}}">显示名称</label><input id="title-{{.ID}}" name="title" maxlength="80" value="{{.Title}}" placeholder="游戏或设备名称"><label for="logo-{{.ID}}">Logo 图片地址</label><input id="logo-{{.ID}}" name="logo_url" maxlength="2048" value="{{.EditLogoURL}}" placeholder="可选，填写图片地址"><button type="submit">保存</button></form></div></section>{{end}}{{else}}<p class="empty">尚未上传存档快照。</p>{{end}}</main></body></html>`))

func (s *server) handleDashboard(w http.ResponseWriter, _ *http.Request) {
	s.mu.Lock()
	view := dashboardView{ScopeCount: len(s.state.Scopes)}
	now := time.Now().UTC()
	for _, device := range s.dashboard.Devices {
		display := dashboardDevice{
			ID:       device.ID,
			Name:     device.Name,
			Platform: device.Platform,
			Version:  device.Version,
			LastSeen: device.LastSeen,
			Online:   now.Sub(device.LastSeen) <= 90*time.Second,
		}
		view.Devices = append(view.Devices, display)
		view.DeviceCount++
		if display.Online {
			view.OnlineDeviceCount++
		}
	}
	objects := make(map[string]int)
	for scopeID, storedScope := range s.state.Scopes {
		metadata := s.dashboard.Scopes[scopeID]
		title := metadata.Title
		if title == "" {
			title = "未命名存档范围"
		}
		logo := metadata.LogoURL
		if metadata.LogoData != "" {
			logo = "/admin/scopes/" + scopeID + "/logo"
		}
		display := dashboardScope{
			ID:          scopeID,
			Title:       title,
			LogoURL:     logo,
			EditLogoURL: metadata.LogoURL,
			Head:        storedScope.Head,
			Named:       metadata.Title != "",
		}
		for _, item := range storedScope.Snapshots {
			view.SnapshotCount++
			objects[item.Blob]++
			bytes := int64(0)
			if info, err := os.Stat(s.objectPath(item.Blob)); err == nil {
				bytes = info.Size()
				if objects[item.Blob] == 1 {
					view.TotalBytes += bytes
					view.ObjectCount++
				}
			}
			display.Snapshots = append(display.Snapshots, dashboardSnapshot{
				ID: item.ID, Parent: item.Parent, CreatedAt: item.CreatedAt, Bytes: bytes,
			})
		}
		display.SnapshotCount = len(display.Snapshots)
		sort.Slice(display.Snapshots, func(left, right int) bool {
			return display.Snapshots[left].CreatedAt.After(display.Snapshots[right].CreatedAt)
		})
		view.Scopes = append(view.Scopes, display)
	}
	s.mu.Unlock()
	sort.Slice(view.Devices, func(left, right int) bool {
		if view.Devices[left].Online != view.Devices[right].Online {
			return view.Devices[left].Online
		}
		return view.Devices[left].LastSeen.After(view.Devices[right].LastSeen)
	})
	for _, references := range objects {
		if references > 1 {
			view.DuplicateObjectRefs += references - 1
		}
	}
	sort.Slice(view.Scopes, func(left, right int) bool {
		if view.Scopes[left].Named != view.Scopes[right].Named {
			return view.Scopes[left].Named
		}
		return view.Scopes[left].Title < view.Scopes[right].Title
	})
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := dashboardTemplate.Execute(w, view); err != nil {
		log.Printf("render dashboard: %v", err)
	}
}

func (s *server) handleScopeLogo(w http.ResponseWriter, r *http.Request) {
	scopeID := r.PathValue("id")
	if !validScopeID(scopeID) {
		writeError(w, http.StatusBadRequest, "invalid scope")
		return
	}
	s.mu.Lock()
	logoData := s.dashboard.Scopes[scopeID].LogoData
	s.mu.Unlock()
	mediaType, decoded, ok := decodeLogoData(logoData)
	if !ok {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", mediaType)
	w.Header().Set("Cache-Control", "private, max-age=3600")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(decoded)
}

func (s *server) handleUpdateScopeMetadata(w http.ResponseWriter, r *http.Request) {
	scopeID := r.PathValue("id")
	if !validScopeID(scopeID) {
		writeError(w, http.StatusBadRequest, "invalid scope")
		return
	}
	if err := r.ParseForm(); err != nil {
		writeError(w, http.StatusBadRequest, "invalid form")
		return
	}
	metadata := scopeMetadata{
		Title:   strings.TrimSpace(r.PostForm.Get("title")),
		LogoURL: strings.TrimSpace(r.PostForm.Get("logo_url")),
	}
	if len([]rune(metadata.Title)) > 80 || !validLogoURL(metadata.LogoURL) {
		writeError(w, http.StatusBadRequest, "invalid display settings")
		return
	}

	s.mu.Lock()
	if _, exists := s.state.Scopes[scopeID]; !exists {
		s.mu.Unlock()
		writeError(w, http.StatusNotFound, "scope not found")
		return
	}
	metadata.LogoData = s.dashboard.Scopes[scopeID].LogoData
	if metadata.LogoURL != "" {
		metadata.LogoData = ""
	}
	next := dashboardState{
		Scopes:  make(map[string]scopeMetadata, len(s.dashboard.Scopes)+1),
		Devices: make(map[string]deviceInfo, len(s.dashboard.Devices)),
	}
	for id, current := range s.dashboard.Scopes {
		next.Scopes[id] = current
	}
	for id, device := range s.dashboard.Devices {
		next.Devices[id] = device
	}
	if metadata.Title == "" && metadata.LogoURL == "" && metadata.LogoData == "" {
		delete(next.Scopes, scopeID)
	} else {
		next.Scopes[scopeID] = metadata
	}
	if err := s.persistDashboard(next); err != nil {
		s.mu.Unlock()
		writeError(w, http.StatusInternalServerError, "cannot persist display settings")
		return
	}
	s.dashboard = next
	s.mu.Unlock()
	http.Redirect(w, r, "/admin/", http.StatusSeeOther)
}

func (s *server) handlePutScopeMetadata(w http.ResponseWriter, r *http.Request) {
	scopeID := r.PathValue("id")
	if !validScopeID(scopeID) {
		writeError(w, http.StatusBadRequest, "invalid scope")
		return
	}
	var metadata scopeMetadata
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 2*1024*1024))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&metadata); err != nil {
		writeError(w, http.StatusBadRequest, "invalid metadata")
		return
	}
	if len([]rune(metadata.Title)) > 120 || !validLogoData(metadata.LogoData) {
		writeError(w, http.StatusBadRequest, "invalid metadata")
		return
	}
	s.mu.Lock()
	next := dashboardState{
		Scopes:  make(map[string]scopeMetadata, len(s.dashboard.Scopes)+1),
		Devices: make(map[string]deviceInfo, len(s.dashboard.Devices)),
	}
	for id, current := range s.dashboard.Scopes {
		next.Scopes[id] = current
	}
	for id, device := range s.dashboard.Devices {
		next.Devices[id] = device
	}
	current := next.Scopes[scopeID]
	if metadata.Title != "" {
		current.Title = metadata.Title
	}
	if metadata.LogoData != "" {
		current.LogoData = metadata.LogoData
		current.LogoURL = ""
	}
	next.Scopes[scopeID] = current
	if err := s.persistDashboard(next); err != nil {
		s.mu.Unlock()
		writeError(w, http.StatusInternalServerError, "cannot persist metadata")
		return
	}
	s.dashboard = next
	s.mu.Unlock()
	w.WriteHeader(http.StatusNoContent)
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

func (s *server) loadState() error {
	contents, err := os.ReadFile(filepath.Join(s.dataDir, "state.json"))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("read state: %w", err)
	}
	if err := json.Unmarshal(contents, &s.state); err != nil {
		return fmt.Errorf("parse state: %w", err)
	}
	if s.state.Scopes == nil {
		s.state.Scopes = make(map[string]scope)
	}
	return nil
}

func (s *server) loadDashboard() error {
	contents, err := os.ReadFile(filepath.Join(s.dataDir, "dashboard.json"))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("read dashboard: %w", err)
	}
	if err := json.Unmarshal(contents, &s.dashboard); err != nil {
		return fmt.Errorf("parse dashboard: %w", err)
	}
	if s.dashboard.Scopes == nil {
		s.dashboard.Scopes = make(map[string]scopeMetadata)
	}
	if s.dashboard.Devices == nil {
		s.dashboard.Devices = make(map[string]deviceInfo)
	}
	return nil
}

func (s *server) persistState(state serverState) error {
	contents, err := json.Marshal(state)
	if err != nil {
		return err
	}
	return writeAtomic(filepath.Join(s.dataDir, "state.json"), contents)
}

func (s *server) persistDashboard(state dashboardState) error {
	contents, err := json.Marshal(state)
	if err != nil {
		return err
	}
	return writeAtomic(filepath.Join(s.dataDir, "dashboard.json"), contents)
}

func writeAtomic(path string, contents []byte) error {
	temporary, err := os.CreateTemp(filepath.Dir(path), ".write-*")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	defer func() { _ = os.Remove(temporaryPath) }()
	if _, err := temporary.Write(contents); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Chmod(0o600); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	return os.Rename(temporaryPath, path)
}

func (s *server) objectPath(id string) string {
	return filepath.Join(s.dataDir, "objects", id[:2], id)
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
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(value); err != nil {
		log.Printf("encode response: %v", err)
	}
}

func main() {
	dataDir := flag.String("data-dir", "./data", "directory for objects and metadata")
	listenAddress := flag.String("listen", ":8787", "HTTP listen address")
	token := flag.String("token", os.Getenv("EDEN_SYNCD_TOKEN"), "bearer token")
	adminToken := flag.String("admin-token", os.Getenv("EDEN_SYNCD_ADMIN_TOKEN"), "administrator token for the web dashboard")
	maxObjectMiB := flag.Int64("max-object-mib", defaultMaxObjectBytes/(1024*1024), "maximum object size in MiB")
	flag.Parse()

	s, err := newServer(*dataDir, *token, *maxObjectMiB*1024*1024, *adminToken)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("eden-syncd listening on %s", *listenAddress)
	if err := http.ListenAndServe(*listenAddress, s.handler()); err != nil {
		log.Fatal(err)
	}
}
