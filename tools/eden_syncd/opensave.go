// SPDX-FileCopyrightText: Copyright 2026 Eden Emulator Project
// SPDX-License-Identifier: GPL-3.0-or-later

package main

import (
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// OpenSave archives are ordinary ZIP files, unlike Eden's encrypted blobs.
// Keep them outside objects/ so neither retention nor garbage collection can
// mistake a desktop backup for an Eden save-sync object.
type openSaveFile struct {
	Type        string    `json:"type"`
	Name        string    `json:"name"`
	SizeBytes   int64     `json:"sizeBytes"`
	CreatedTime time.Time `json:"createdTime"`
}

func validOpenSaveType(value string) bool {
	if value == "pc" || value == "switch" {
		return true
	}
	return strings.HasPrefix(value, "emulator-") && validIdentifier(value, 64)
}

func validOpenSaveName(value string) bool {
	return validIdentifier(value, 255) && strings.HasSuffix(strings.ToLower(value), ".zip")
}

func (s *server) openSavePath(kind, name string) (string, bool) {
	if !validOpenSaveType(kind) || !validOpenSaveName(name) {
		return "", false
	}
	return filepath.Join(s.dataDir, "opensave", kind, name), true
}

func (s *server) handleOpenSaveList(w http.ResponseWriter, _ *http.Request) {
	root := filepath.Join(s.dataDir, "opensave")
	entries := []openSaveFile{}
	for _, kind := range []string{"pc", "switch"} {
		entries = append(entries, s.openSaveFilesForType(root, kind)...)
	}
	// Emulator types are extensible. Only immediate directories are accepted.
	if dirs, err := os.ReadDir(root); err == nil {
		for _, dir := range dirs {
			if dir.IsDir() && strings.HasPrefix(dir.Name(), "emulator-") && validOpenSaveType(dir.Name()) {
				entries = append(entries, s.openSaveFilesForType(root, dir.Name())...)
			}
		}
	}
	sort.Slice(entries, func(i, j int) bool {
		if entries[i].Type != entries[j].Type {
			return entries[i].Type < entries[j].Type
		}
		return entries[i].Name < entries[j].Name
	})
	writeJSON(w, http.StatusOK, map[string]any{"files": entries})
}

func (s *server) openSaveFilesForType(root, kind string) []openSaveFile {
	dir := filepath.Join(root, kind)
	items, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	files := make([]openSaveFile, 0, len(items))
	for _, item := range items {
		if item.IsDir() || !validOpenSaveName(item.Name()) {
			continue
		}
		if info, err := item.Info(); err == nil {
			files = append(files, openSaveFile{Type: kind, Name: item.Name(), SizeBytes: info.Size(), CreatedTime: info.ModTime().UTC()})
		}
	}
	return files
}

func (s *server) handleOpenSaveNativePut(w http.ResponseWriter, r *http.Request) {
	kind, name := r.PathValue("type"), r.PathValue("name")
	destination, ok := s.openSavePath(kind, name)
	if !ok {
		writeError(w, http.StatusBadRequest, "invalid OpenSave type or file name")
		return
	}
	if err := os.MkdirAll(filepath.Dir(destination), 0o700); err != nil {
		writeError(w, http.StatusInternalServerError, "cannot create OpenSave storage")
		return
	}
	temporary, err := os.CreateTemp(filepath.Dir(destination), ".upload-*")
	if err != nil {
		writeError(w, http.StatusInternalServerError, "cannot create OpenSave upload")
		return
	}
	temporaryPath := temporary.Name()
	defer func() { _ = os.Remove(temporaryPath) }()
	written, copyErr := io.Copy(temporary, http.MaxBytesReader(w, r.Body, s.maxObjectBytes+1))
	if copyErr == nil {
		copyErr = temporary.Sync()
	}
	if closeErr := temporary.Close(); closeErr != nil && copyErr == nil {
		copyErr = closeErr
	}
	if copyErr != nil || written > s.maxObjectBytes {
		writeError(w, http.StatusRequestEntityTooLarge, "OpenSave archive exceeds configured size limit")
		return
	}
	if err := os.Rename(temporaryPath, destination); err != nil {
		writeError(w, http.StatusInternalServerError, "cannot publish OpenSave archive")
		return
	}
	w.WriteHeader(http.StatusCreated)
}

func (s *server) handleOpenSaveNativeGet(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	path, ok := s.openSavePath(r.PathValue("type"), name)
	if !ok {
		writeError(w, http.StatusBadRequest, "invalid OpenSave type or file name")
		return
	}
	file, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		writeError(w, http.StatusNotFound, "OpenSave archive not found")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "cannot open OpenSave archive")
		return
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "cannot inspect OpenSave archive")
		return
	}
	w.Header().Set("Content-Type", "application/zip")
	http.ServeContent(w, r, name, info.ModTime(), file)
}

func (s *server) handleOpenSaveNativeDelete(w http.ResponseWriter, r *http.Request) {
	path, ok := s.openSavePath(r.PathValue("type"), r.PathValue("name"))
	if !ok {
		writeError(w, http.StatusBadRequest, "invalid OpenSave type or file name")
		return
	}
	if err := os.Remove(path); errors.Is(err, os.ErrNotExist) {
		writeError(w, http.StatusNotFound, "OpenSave archive not found")
	} else if err != nil {
		writeError(w, http.StatusInternalServerError, "cannot delete OpenSave archive")
	} else {
		w.WriteHeader(http.StatusNoContent)
	}
}
