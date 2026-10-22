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
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// Handlers for the /v1 API used by Eden clients. The request and response shapes here are part of
// the client protocol and must remain compatible with released Eden builds.

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

func requestDeviceID(r *http.Request) string {
	deviceID := strings.TrimSpace(r.Header.Get("X-Eden-Device-ID"))
	if !validIdentifier(deviceID, 128) {
		return ""
	}
	return deviceID
}

func remoteHost(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func (s *server) recordDevice(r *http.Request) {
	deviceID := requestDeviceID(r)
	if deviceID == "" {
		return
	}
	now := time.Now().UTC()
	device := deviceInfo{
		ID:        deviceID,
		Name:      trimDeviceField(r.Header.Get("X-Eden-Device-Name"), 80),
		Platform:  trimDeviceField(r.Header.Get("X-Eden-Platform"), 32),
		Version:   trimDeviceField(r.Header.Get("X-Eden-Version"), 64),
		Address:   remoteHost(r),
		FirstSeen: now,
		LastSeen:  now,
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	previous, known := s.dashboard.Devices[deviceID]
	if known {
		if device.Name == previous.Name && device.Platform == previous.Platform &&
			device.Version == previous.Version && device.Address == previous.Address &&
			now.Sub(previous.LastSeen) < 30*time.Second {
			return
		}
		device.Alias = previous.Alias
		if !previous.FirstSeen.IsZero() {
			device.FirstSeen = previous.FirstSeen
		}
	}
	next := s.dashboard.clone()
	next.Devices[deviceID] = device
	if err := s.persistDashboard(next); err != nil {
		slog.Warn("record device", "device", deviceID, "error", err)
		return
	}
	s.dashboard = next
	if !known {
		s.recordEventLocked(event{Kind: eventDeviceNew, Device: deviceID,
			Detail: strings.TrimSpace(device.Name + " " + device.Platform)})
	}
}

func trimDeviceField(value string, maximum int) string {
	value = strings.TrimSpace(value)
	if len([]rune(value)) > maximum {
		return string([]rune(value)[:maximum])
	}
	return value
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
		// Refresh the timestamp so a concurrent garbage collection treats it as freshly uploaded.
		now := time.Now()
		_ = os.Chtimes(destination, now, now)
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
	s.serveObject(w, r, id, "")
}

// serveObject streams an encrypted object. When attachmentName is set the response is offered
// as a download.
func (s *server) serveObject(w http.ResponseWriter, r *http.Request, id, attachmentName string) {
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
	info, err := file.Stat()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "cannot open blob")
		return
	}

	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("ETag", `"`+id+`"`)
	if attachmentName != "" {
		w.Header().Set("Content-Disposition", `attachment; filename="`+attachmentName+`"`)
	}
	// Objects are content addressed, so ranges and conditional requests are always safe.
	http.ServeContent(w, r, "", info.ModTime(), file)
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
	writeJSON(w, http.StatusOK, storedScope.Snapshots[storedScope.Head].snapshot)
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
	info, err := os.Stat(s.objectPath(candidate.Blob))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			writeError(w, http.StatusFailedDependency, "snapshot blob is missing")
		} else {
			writeError(w, http.StatusInternalServerError, "cannot inspect snapshot blob")
		}
		return
	}

	deviceID := requestDeviceID(r)
	expectedHead := strings.Trim(r.Header.Get("If-Match"), "\"")
	s.mu.Lock()
	defer s.mu.Unlock()
	storedScope := s.state.Scopes[scopeID]
	if existing, ok := storedScope.Snapshots[snapshotID]; ok {
		if existing.snapshot == candidate && storedScope.Head == snapshotID {
			writeJSON(w, http.StatusOK, existing.snapshot)
			return
		}
		writeError(w, http.StatusConflict, "snapshot id already exists")
		return
	}
	if storedScope.Head != expectedHead || candidate.Parent != storedScope.Head {
		s.recordEventLocked(event{Kind: eventConflict, Scope: scopeID, Snapshot: snapshotID,
			Device: deviceID, Detail: "head " + storedScope.Head})
		writeJSON(w, http.StatusConflict, map[string]string{"head": storedScope.Head})
		return
	}

	nextScope := storedScope.clone()
	nextScope.Head = snapshotID
	nextScope.Snapshots[snapshotID] = snapshotRecord{
		snapshot:   candidate,
		Size:       info.Size(),
		Device:     deviceID,
		ReceivedAt: time.Now().UTC(),
	}
	nextState := s.state.clone()
	nextState.Scopes[scopeID] = nextScope
	if err := s.persistState(nextState); err != nil {
		writeError(w, http.StatusInternalServerError, "cannot persist snapshot metadata")
		return
	}
	s.state = nextState
	s.recordEventLocked(event{Kind: eventUpload, Scope: scopeID, Snapshot: snapshotID,
		Device: deviceID, Detail: formatBytes(info.Size())})
	if s.settings.Retention.enabled() {
		if removed, err := s.pruneScopeLocked(scopeID, time.Now().UTC()); err != nil {
			slog.Warn("apply retention", "scope", scopeID, "error", err)
		} else if removed > 0 {
			s.recordEventLocked(event{Kind: eventPrune, Scope: scopeID,
				Detail: "removed " + itoa(removed) + " snapshots"})
		}
	}
	writeJSON(w, http.StatusCreated, candidate)
}

func (s *server) handlePutScopeMetadata(w http.ResponseWriter, r *http.Request) {
	scopeID := r.PathValue("id")
	if !validScopeID(scopeID) {
		writeError(w, http.StatusBadRequest, "invalid scope")
		return
	}
	var metadata struct {
		Title      string `json:"title"`
		LogoURL    string `json:"logo_url"`
		LogoData   string `json:"logo_data"`
		UserName   string `json:"user_name"`
		Descriptor string `json:"descriptor"`
	}
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 2*1024*1024))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&metadata); err != nil {
		writeError(w, http.StatusBadRequest, "invalid metadata")
		return
	}
	metadata.UserName = strings.TrimSpace(metadata.UserName)
	if len([]rune(metadata.Title)) > 120 || !validLogoData(metadata.LogoData) ||
		len([]rune(metadata.UserName)) > maxUserNameRunes || !validDescriptor(metadata.Descriptor) {
		writeError(w, http.StatusBadRequest, "invalid metadata")
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	current := s.dashboard.Scopes[scopeID]
	updated := current
	if metadata.Title != "" {
		updated.Title = metadata.Title
	}
	if metadata.LogoData != "" {
		updated.LogoData = metadata.LogoData
		updated.LogoURL = ""
	}
	if metadata.UserName != "" {
		updated.UserName = metadata.UserName
	}
	if metadata.Descriptor != "" {
		updated.Descriptor = metadata.Descriptor
	}
	if updated == current {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	next := s.dashboard.clone()
	next.Scopes[scopeID] = updated
	if err := s.persistDashboard(next); err != nil {
		writeError(w, http.StatusInternalServerError, "cannot persist metadata")
		return
	}
	s.dashboard = next
	w.WriteHeader(http.StatusNoContent)
}

func validDescriptor(value string) bool {
	if value == "" {
		return true
	}
	if len(value) > maxDescriptorBytes {
		return false
	}
	decoded, err := base64.StdEncoding.DecodeString(value)
	return err == nil && len(decoded) > 0
}

// catalogEntry describes one scope to clients choosing which cloud saves to use. Clients decrypt
// the descriptor to learn the owning user and game; scopes written by other sync keys stay opaque.
type catalogEntry struct {
	ID         string    `json:"id"`
	Head       string    `json:"head"`
	UpdatedAt  time.Time `json:"updated_at"`
	Size       int64     `json:"size"`
	Title      string    `json:"title,omitempty"`
	UserName   string    `json:"user_name,omitempty"`
	Descriptor string    `json:"descriptor,omitempty"`
}

func (s *server) handleListScopes(w http.ResponseWriter, _ *http.Request) {
	s.mu.Lock()
	entries := make([]catalogEntry, 0, len(s.state.Scopes))
	for scopeID, stored := range s.state.Scopes {
		head, ok := stored.Snapshots[stored.Head]
		if !ok {
			continue
		}
		metadata := s.dashboard.Scopes[scopeID]
		entries = append(entries, catalogEntry{
			ID:         scopeID,
			Head:       stored.Head,
			UpdatedAt:  head.CreatedAt,
			Size:       head.Size,
			Title:      metadata.Title,
			UserName:   metadata.UserName,
			Descriptor: metadata.Descriptor,
		})
	}
	s.mu.Unlock()
	sort.Slice(entries, func(left, right int) bool { return entries[left].ID < entries[right].ID })
	writeJSON(w, http.StatusOK, map[string]any{"scopes": entries})
}
