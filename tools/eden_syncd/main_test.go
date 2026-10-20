// SPDX-FileCopyrightText: Copyright 2026 Eden Emulator Project
// SPDX-License-Identifier: GPL-3.0-or-later

package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

const testToken = "test-token"

func newTestServer(t *testing.T) (*server, *httptest.Server) {
	t.Helper()
	s, err := newServer(t.TempDir(), testToken, 1024*1024)
	if err != nil {
		t.Fatal(err)
	}
	return s, httptest.NewServer(s.handler())
}

func authorizedRequest(t *testing.T, method, url string, body []byte) *http.Request {
	t.Helper()
	request, err := http.NewRequest(method, url, bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Authorization", "Bearer "+testToken)
	return request
}

func adminRequest(t *testing.T, method, url string, body []byte, token string) *http.Request {
	t.Helper()
	request, err := http.NewRequest(method, url, bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	request.SetBasicAuth("admin", token)
	return request
}

func putObject(t *testing.T, baseURL string, payload []byte) string {
	t.Helper()
	digest := sha256.Sum256(payload)
	id := hex.EncodeToString(digest[:])
	response, err := http.DefaultClient.Do(authorizedRequest(t, http.MethodPut, baseURL+"/v1/blobs/"+id, payload))
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusCreated {
		t.Fatalf("put object status = %d", response.StatusCode)
	}
	return id
}

func TestBlobRequiresTokenAndIsContentAddressed(t *testing.T) {
	_, httpServer := newTestServer(t)
	defer httpServer.Close()

	payload := []byte("encrypted snapshot")
	digest := sha256.Sum256(payload)
	id := hex.EncodeToString(digest[:])
	request, err := http.NewRequest(http.MethodPut, httpServer.URL+"/v1/blobs/"+id, bytes.NewReader(payload))
	if err != nil {
		t.Fatal(err)
	}
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusUnauthorized {
		t.Fatalf("unauthenticated put status = %d", response.StatusCode)
	}

	putObject(t, httpServer.URL, payload)
	response, err = http.DefaultClient.Do(authorizedRequest(t, http.MethodGet, httpServer.URL+"/v1/blobs/"+id, nil))
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("get object status = %d", response.StatusCode)
	}
	result := new(bytes.Buffer)
	if _, err := result.ReadFrom(response.Body); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(result.Bytes(), payload) {
		t.Fatalf("downloaded payload = %q", result.Bytes())
	}
}

func TestSnapshotCompareAndSwapPreservesConflict(t *testing.T) {
	_, httpServer := newTestServer(t)
	defer httpServer.Close()
	object := putObject(t, httpServer.URL, []byte("first snapshot"))

	first := snapshot{ID: "snapshot-1", Blob: object, CreatedAt: time.Now().UTC()}
	firstJSON, err := json.Marshal(first)
	if err != nil {
		t.Fatal(err)
	}
	request := authorizedRequest(t, http.MethodPut, httpServer.URL+"/v1/scopes/account-1/snapshots/snapshot-1", firstJSON)
	request.Header.Set("If-Match", "\"\"")
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusCreated {
		t.Fatalf("first snapshot status = %d", response.StatusCode)
	}

	second := snapshot{ID: "snapshot-2", Blob: object, Parent: "", CreatedAt: time.Now().UTC()}
	secondJSON, err := json.Marshal(second)
	if err != nil {
		t.Fatal(err)
	}
	request = authorizedRequest(t, http.MethodPut, httpServer.URL+"/v1/scopes/account-1/snapshots/snapshot-2", secondJSON)
	request.Header.Set("If-Match", "\"\"")
	response, err = http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusConflict {
		t.Fatalf("conflicting snapshot status = %d", response.StatusCode)
	}
	var conflict map[string]string
	if err := json.NewDecoder(response.Body).Decode(&conflict); err != nil {
		t.Fatal(err)
	}
	if conflict["head"] != first.ID {
		t.Fatalf("conflict head = %q", conflict["head"])
	}
}

func TestSnapshotCommitIsIdempotent(t *testing.T) {
	_, httpServer := newTestServer(t)
	defer httpServer.Close()
	object := putObject(t, httpServer.URL, []byte("retryable snapshot"))
	payload, err := json.Marshal(snapshot{ID: "snapshot-1", Blob: object, CreatedAt: time.Now().UTC()})
	if err != nil {
		t.Fatal(err)
	}
	for attempt := 0; attempt < 2; attempt++ {
		request := authorizedRequest(t, http.MethodPut,
			httpServer.URL+"/v1/scopes/account-1/snapshots/snapshot-1", payload)
		request.Header.Set("If-Match", "\"\"")
		response, err := http.DefaultClient.Do(request)
		if err != nil {
			t.Fatal(err)
		}
		response.Body.Close()
		expectedStatus := http.StatusCreated
		if attempt == 1 {
			expectedStatus = http.StatusOK
		}
		if response.StatusCode != expectedStatus {
			t.Fatalf("attempt %d status = %d", attempt, response.StatusCode)
		}
	}
}

func TestSnapshotRejectsInvalidMetadata(t *testing.T) {
	_, httpServer := newTestServer(t)
	defer httpServer.Close()
	object := putObject(t, httpServer.URL, []byte("metadata validation"))

	invalidParent, err := json.Marshal(snapshot{
		ID:        "snapshot-1",
		Blob:      object,
		Parent:    "../invalid",
		CreatedAt: time.Now().UTC(),
	})
	if err != nil {
		t.Fatal(err)
	}
	request := authorizedRequest(t, http.MethodPut,
		httpServer.URL+"/v1/scopes/account-1/snapshots/snapshot-1", invalidParent)
	request.Header.Set("If-Match", "\"\"")
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusBadRequest {
		t.Fatalf("invalid parent status = %d", response.StatusCode)
	}

	valid, err := json.Marshal(snapshot{ID: "snapshot-2", Blob: object, CreatedAt: time.Now().UTC()})
	if err != nil {
		t.Fatal(err)
	}
	request = authorizedRequest(t, http.MethodPut,
		httpServer.URL+"/v1/scopes/account-1/snapshots/snapshot-2", append(valid, []byte("\n{}")...))
	request.Header.Set("If-Match", "\"\"")
	response, err = http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusBadRequest {
		t.Fatalf("trailing metadata status = %d", response.StatusCode)
	}
}

func TestStateSurvivesRestart(t *testing.T) {
	dataDir := t.TempDir()
	s, err := newServer(dataDir, testToken, 1024*1024)
	if err != nil {
		t.Fatal(err)
	}
	serverOne := httptest.NewServer(s.handler())
	object := putObject(t, serverOne.URL, []byte("persistent snapshot"))
	payload, err := json.Marshal(snapshot{ID: "snapshot-1", Blob: object, CreatedAt: time.Now().UTC()})
	if err != nil {
		t.Fatal(err)
	}
	request := authorizedRequest(t, http.MethodPut, serverOne.URL+"/v1/scopes/account-1/snapshots/snapshot-1", payload)
	request.Header.Set("If-Match", "\"\"")
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	serverOne.Close()

	restarted, err := newServer(dataDir, testToken, 1024*1024)
	if err != nil {
		t.Fatal(err)
	}
	serverTwo := httptest.NewServer(restarted.handler())
	defer serverTwo.Close()
	response, err = http.DefaultClient.Do(authorizedRequest(t, http.MethodGet, serverTwo.URL+"/v1/scopes/account-1/head", nil))
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("restarted head status = %d", response.StatusCode)
	}
	var head snapshot
	if err := json.NewDecoder(response.Body).Decode(&head); err != nil {
		t.Fatal(err)
	}
	if head.ID != "snapshot-1" || head.Blob != object {
		t.Fatalf("restarted head = %#v", head)
	}
}

func TestDashboardRequiresIndependentAdminToken(t *testing.T) {
	s, err := newServer(t.TempDir(), testToken, 1024*1024, "dashboard-token")
	if err != nil {
		t.Fatal(err)
	}
	httpServer := httptest.NewServer(s.handler())
	defer httpServer.Close()

	response, err := http.Get(httpServer.URL + "/admin/")
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusUnauthorized {
		t.Fatalf("unauthenticated dashboard status = %d", response.StatusCode)
	}

	request := authorizedRequest(t, http.MethodGet, httpServer.URL+"/admin/", nil)
	response, err = http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusUnauthorized {
		t.Fatalf("sync token dashboard status = %d", response.StatusCode)
	}
}

func TestDashboardMetadataSurvivesRestart(t *testing.T) {
	dataDir := t.TempDir()
	s, err := newServer(dataDir, testToken, 1024*1024, "dashboard-token")
	if err != nil {
		t.Fatal(err)
	}
	httpServer := httptest.NewServer(s.handler())
	object := putObject(t, httpServer.URL, []byte("dashboard snapshot"))
	payload, err := json.Marshal(snapshot{ID: "snapshot-1", Blob: object, CreatedAt: time.Now().UTC()})
	if err != nil {
		t.Fatal(err)
	}
	request := authorizedRequest(t, http.MethodPut,
		httpServer.URL+"/v1/scopes/account-1/snapshots/snapshot-1", payload)
	request.Header.Set("If-Match", "\"\"")
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusCreated {
		t.Fatalf("snapshot status = %d", response.StatusCode)
	}

	request = adminRequest(t, http.MethodPost, httpServer.URL+"/admin/scopes/account-1",
		[]byte("title=Super+Mario+Odyssey&logo_url=https%3A%2F%2Fexample.com%2Fodyssey.png"), "dashboard-token")
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	adminClient := &http.Client{CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
		return http.ErrUseLastResponse
	}}
	response, err = adminClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusSeeOther {
		t.Fatalf("metadata update status = %d", response.StatusCode)
	}
	httpServer.Close()

	restarted, err := newServer(dataDir, testToken, 1024*1024, "dashboard-token")
	if err != nil {
		t.Fatal(err)
	}
	httpServer = httptest.NewServer(restarted.handler())
	defer httpServer.Close()
	response, err = http.DefaultClient.Do(adminRequest(t, http.MethodGet, httpServer.URL+"/admin/", nil, "dashboard-token"))
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("dashboard status = %d", response.StatusCode)
	}
	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(body, []byte("Super Mario Odyssey")) ||
		!bytes.Contains(body, []byte("https://example.com/odyssey.png")) {
		t.Fatalf("dashboard metadata missing from %q", body)
	}
}
