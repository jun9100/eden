// SPDX-FileCopyrightText: Copyright 2026 Eden Emulator Project
// SPDX-License-Identifier: GPL-3.0-or-later

package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestOpenSaveNativeFilesAreTypedAndTokenProtected(t *testing.T) {
	s, err := newServer(t.TempDir(), "sync-token", 1024*1024)
	if err != nil {
		t.Fatal(err)
	}
	httpServer := httptest.NewServer(s.handler())
	defer httpServer.Close()

	url := httpServer.URL + "/v1/opensave/files/switch/mario__main__snap_1.zip"
	unauthorized, err := http.NewRequest(http.MethodPut, url, bytes.NewReader([]byte("save")))
	if err != nil {
		t.Fatal(err)
	}
	response, err := http.DefaultClient.Do(unauthorized)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusUnauthorized {
		t.Fatalf("unauthenticated upload status = %d, want 401", response.StatusCode)
	}

	request, err := http.NewRequest(http.MethodPut, url, bytes.NewReader([]byte("save")))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Authorization", "Bearer sync-token")
	response, err = http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusCreated {
		t.Fatalf("upload status = %d, want 201", response.StatusCode)
	}

	list, err := http.NewRequest(http.MethodGet, httpServer.URL+"/v1/opensave/files", nil)
	if err != nil {
		t.Fatal(err)
	}
	list.Header.Set("Authorization", "Bearer sync-token")
	response, err = http.DefaultClient.Do(list)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	var body struct {
		Files []openSaveFile `json:"files"`
	}
	if err := json.NewDecoder(response.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	if len(body.Files) != 1 || body.Files[0].Type != "switch" || body.Files[0].Name != "mario__main__snap_1.zip" {
		t.Fatalf("list = %+v", body.Files)
	}
}
