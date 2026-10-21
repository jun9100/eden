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
	"os"
	"path/filepath"
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

const testAdminToken = "dashboard-token"

func newAdminTestServer(t *testing.T, dataDir string) (*server, *httptest.Server) {
	t.Helper()
	s, err := newServer(dataDir, testToken, 1024*1024, testAdminToken)
	if err != nil {
		t.Fatal(err)
	}
	return s, httptest.NewServer(s.handler())
}

func commitSnapshot(t *testing.T, baseURL, scopeID string, value snapshot, ifMatch, deviceID string) int {
	t.Helper()
	payload, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	request := authorizedRequest(t, http.MethodPut, baseURL+"/v1/scopes/"+scopeID+"/snapshots/"+value.ID, payload)
	request.Header.Set("If-Match", `"`+ifMatch+`"`)
	if deviceID != "" {
		request.Header.Set("X-Eden-Device-ID", deviceID)
	}
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	return response.StatusCode
}

func adminDo(t *testing.T, method, url string, body any) (*http.Response, []byte) {
	t.Helper()
	var reader io.Reader
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		reader = bytes.NewReader(encoded)
	}
	request, err := http.NewRequest(method, url, reader)
	if err != nil {
		t.Fatal(err)
	}
	request.SetBasicAuth("admin", testAdminToken)
	request.Header.Set("X-Eden-Admin", "1")
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	contents, err := io.ReadAll(response.Body)
	response.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	return response, contents
}

func fetchOverview(t *testing.T, baseURL string) overviewResponse {
	t.Helper()
	response, body := adminDo(t, http.MethodGet, baseURL+"/admin/api/overview", nil)
	if response.StatusCode != http.StatusOK {
		t.Fatalf("overview status = %d: %s", response.StatusCode, body)
	}
	var overview overviewResponse
	if err := json.Unmarshal(body, &overview); err != nil {
		t.Fatal(err)
	}
	return overview
}

func TestDashboardRequiresIndependentAdminToken(t *testing.T) {
	_, httpServer := newAdminTestServer(t, t.TempDir())
	defer httpServer.Close()

	for _, request := range []*http.Request{
		mustRequest(t, http.MethodGet, httpServer.URL+"/admin/api/overview"),
		authorizedRequest(t, http.MethodGet, httpServer.URL+"/admin/api/overview", nil),
		adminRequest(t, http.MethodGet, httpServer.URL+"/admin/api/overview", nil, testToken),
		mustRequest(t, http.MethodGet, httpServer.URL+"/metrics"),
	} {
		response, err := http.DefaultClient.Do(request)
		if err != nil {
			t.Fatal(err)
		}
		response.Body.Close()
		if response.StatusCode != http.StatusUnauthorized {
			t.Fatalf("%s without admin credentials: status %d", request.URL.Path, response.StatusCode)
		}
	}

	response, err := http.Get(httpServer.URL + "/admin/")
	if err != nil {
		t.Fatal(err)
	}
	page, _ := io.ReadAll(response.Body)
	response.Body.Close()
	if response.StatusCode != http.StatusOK || !bytes.Contains(page, []byte("app.js")) ||
		response.Header.Get("Content-Security-Policy") == "" {
		t.Fatalf("dashboard shell status %d, csp %q", response.StatusCode, response.Header.Get("Content-Security-Policy"))
	}
}

func mustRequest(t *testing.T, method, url string) *http.Request {
	t.Helper()
	request, err := http.NewRequest(method, url, nil)
	if err != nil {
		t.Fatal(err)
	}
	return request
}

func TestDashboardDisabledWithoutAdminToken(t *testing.T) {
	_, httpServer := newTestServer(t)
	defer httpServer.Close()
	for _, path := range []string{"/admin/", "/admin/api/session", "/admin/api/overview"} {
		response, err := http.Get(httpServer.URL + path)
		if err != nil {
			t.Fatal(err)
		}
		response.Body.Close()
		if response.StatusCode != http.StatusNotFound {
			t.Fatalf("%s status = %d", path, response.StatusCode)
		}
	}
}

func TestAdminSessionLoginAndCSRF(t *testing.T) {
	_, httpServer := newAdminTestServer(t, t.TempDir())
	defer httpServer.Close()

	login := func(token string, csrf bool) *http.Response {
		request, err := http.NewRequest(http.MethodPost, httpServer.URL+"/admin/api/login",
			bytes.NewReader([]byte(`{"token":"`+token+`"}`)))
		if err != nil {
			t.Fatal(err)
		}
		if csrf {
			request.Header.Set("X-Eden-Admin", "1")
		}
		response, err := http.DefaultClient.Do(request)
		if err != nil {
			t.Fatal(err)
		}
		response.Body.Close()
		return response
	}
	if response := login(testAdminToken, false); response.StatusCode != http.StatusForbidden {
		t.Fatalf("login without csrf header status = %d", response.StatusCode)
	}
	if response := login("wrong", true); response.StatusCode != http.StatusUnauthorized {
		t.Fatalf("wrong token login status = %d", response.StatusCode)
	}
	response := login(testAdminToken, true)
	if response.StatusCode != http.StatusOK {
		t.Fatalf("login status = %d", response.StatusCode)
	}
	var session *http.Cookie
	for _, cookie := range response.Cookies() {
		if cookie.Name == sessionCookie {
			session = cookie
		}
	}
	if session == nil || !session.HttpOnly || session.SameSite != http.SameSiteStrictMode {
		t.Fatalf("session cookie = %+v", session)
	}

	request := mustRequest(t, http.MethodGet, httpServer.URL+"/admin/api/overview")
	request.AddCookie(session)
	overview, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	overview.Body.Close()
	if overview.StatusCode != http.StatusOK {
		t.Fatalf("cookie overview status = %d", overview.StatusCode)
	}

	write := httptest.NewRequest(http.MethodPut, httpServer.URL+"/admin/api/settings",
		bytes.NewReader([]byte(`{"retention":{"keep_snapshots":3,"keep_days":0}}`)))
	write.RequestURI = ""
	write.AddCookie(session)
	result, err := http.DefaultClient.Do(write)
	if err != nil {
		t.Fatal(err)
	}
	result.Body.Close()
	if result.StatusCode != http.StatusForbidden {
		t.Fatalf("cookie write without csrf header status = %d", result.StatusCode)
	}

	forged := mustRequest(t, http.MethodGet, httpServer.URL+"/admin/api/overview")
	forged.AddCookie(&http.Cookie{Name: sessionCookie, Value: "99999999999.deadbeef"})
	forgedResponse, err := http.DefaultClient.Do(forged)
	if err != nil {
		t.Fatal(err)
	}
	forgedResponse.Body.Close()
	if forgedResponse.StatusCode != http.StatusUnauthorized {
		t.Fatalf("forged session status = %d", forgedResponse.StatusCode)
	}
}

func TestLoginIsRateLimited(t *testing.T) {
	_, httpServer := newAdminTestServer(t, t.TempDir())
	defer httpServer.Close()
	status := 0
	for attempt := 0; attempt <= loginFailureLimit; attempt++ {
		request, _ := http.NewRequest(http.MethodPost, httpServer.URL+"/admin/api/login",
			bytes.NewReader([]byte(`{"token":"wrong"}`)))
		request.Header.Set("X-Eden-Admin", "1")
		response, err := http.DefaultClient.Do(request)
		if err != nil {
			t.Fatal(err)
		}
		response.Body.Close()
		status = response.StatusCode
	}
	if status != http.StatusTooManyRequests {
		t.Fatalf("status after repeated failures = %d", status)
	}
}

func TestDashboardMetadataSurvivesRestart(t *testing.T) {
	dataDir := t.TempDir()
	_, httpServer := newAdminTestServer(t, dataDir)
	object := putObject(t, httpServer.URL, []byte("dashboard snapshot"))
	if status := commitSnapshot(t, httpServer.URL, "account-1",
		snapshot{ID: "snapshot-1", Blob: object, CreatedAt: time.Now().UTC()}, "", ""); status != http.StatusCreated {
		t.Fatalf("snapshot status = %d", status)
	}

	response, body := adminDo(t, http.MethodPatch, httpServer.URL+"/admin/api/scopes/account-1",
		map[string]string{"title": "Super Mario Odyssey", "logo_url": "https://example.com/odyssey.png"})
	if response.StatusCode != http.StatusOK {
		t.Fatalf("metadata update status = %d: %s", response.StatusCode, body)
	}
	httpServer.Close()

	_, httpServer = newAdminTestServer(t, dataDir)
	defer httpServer.Close()
	overview := fetchOverview(t, httpServer.URL)
	if len(overview.Scopes) != 1 || overview.Scopes[0].Title != "Super Mario Odyssey" ||
		overview.Scopes[0].Logo != "https://example.com/odyssey.png" {
		t.Fatalf("dashboard metadata missing: %+v", overview.Scopes)
	}
}

func TestLegacyDashboardFormStillUpdatesMetadata(t *testing.T) {
	_, httpServer := newAdminTestServer(t, t.TempDir())
	defer httpServer.Close()
	object := putObject(t, httpServer.URL, []byte("legacy snapshot"))
	commitSnapshot(t, httpServer.URL, "account-1", snapshot{ID: "snapshot-1", Blob: object, CreatedAt: time.Now().UTC()}, "", "")

	request := adminRequest(t, http.MethodPost, httpServer.URL+"/admin/scopes/account-1",
		[]byte("title=Zelda&logo_url=https%3A%2F%2Fexample.com%2Fz.png"), testAdminToken)
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	client := &http.Client{CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
		return http.ErrUseLastResponse
	}}
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusSeeOther {
		t.Fatalf("legacy form status = %d", response.StatusCode)
	}
	if overview := fetchOverview(t, httpServer.URL); overview.Scopes[0].Title != "Zelda" {
		t.Fatalf("legacy form title = %q", overview.Scopes[0].Title)
	}
}

func TestScopeMetadataCanBePublishedBySyncClient(t *testing.T) {
	dataDir := t.TempDir()
	_, httpServer := newAdminTestServer(t, dataDir)
	defer httpServer.Close()

	object := putObject(t, httpServer.URL, []byte("dashboard logo snapshot"))
	if status := commitSnapshot(t, httpServer.URL, "account-1",
		snapshot{ID: "snapshot-1", Blob: object, CreatedAt: time.Now().UTC()}, "", ""); status != http.StatusCreated {
		t.Fatalf("snapshot status = %d", status)
	}

	request := authorizedRequest(t, http.MethodPut, httpServer.URL+"/v1/scopes/account-1/metadata",
		[]byte(`{"title":"Super Mario Odyssey","logo_data":"data:image/png;base64,AA=="}`))
	request.Header.Set("Content-Type", "application/json")
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusNoContent {
		t.Fatalf("metadata publish status = %d", response.StatusCode)
	}

	contents, err := os.ReadFile(filepath.Join(dataDir, "dashboard.json"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(contents, []byte("Super Mario Odyssey")) ||
		!bytes.Contains(contents, []byte("data:image/png;base64,AA==")) {
		t.Fatalf("published metadata missing from %q", contents)
	}

	overview := fetchOverview(t, httpServer.URL)
	if overview.Scopes[0].Logo != "api/scopes/account-1/logo" || !overview.Scopes[0].HasClientLogo {
		t.Fatalf("client logo should be served by reference, got %+v", overview.Scopes[0])
	}
	logo, body := adminDo(t, http.MethodGet, httpServer.URL+"/admin/api/scopes/account-1/logo", nil)
	if logo.StatusCode != http.StatusOK || logo.Header.Get("Content-Type") != "image/png" || !bytes.Equal(body, []byte{0}) {
		t.Fatalf("logo response = status %d, type %q, body %v", logo.StatusCode, logo.Header.Get("Content-Type"), body)
	}
}

func TestDashboardShowsConnectedDevices(t *testing.T) {
	_, httpServer := newAdminTestServer(t, t.TempDir())
	defer httpServer.Close()

	request := authorizedRequest(t, http.MethodPost, httpServer.URL+"/v1/devices/heartbeat", nil)
	request.Header.Set("X-Eden-Device-ID", "device-1")
	request.Header.Set("X-Eden-Device-Name", "Windows Desktop")
	request.Header.Set("X-Eden-Platform", "Windows")
	request.Header.Set("X-Eden-Version", "v2026.10.21-2")
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusNoContent {
		t.Fatalf("heartbeat status = %d", response.StatusCode)
	}

	overview := fetchOverview(t, httpServer.URL)
	if overview.Stats.OnlineDevices != 1 || len(overview.Devices) != 1 ||
		overview.Devices[0].Name != "Windows Desktop" || !overview.Devices[0].Online ||
		overview.Devices[0].Address == "" || overview.Devices[0].FirstSeen.IsZero() {
		t.Fatalf("device missing from overview: %+v", overview.Devices)
	}

	if response, _ := adminDo(t, http.MethodPatch, httpServer.URL+"/admin/api/devices/device-1",
		map[string]string{"alias": "书房电脑"}); response.StatusCode != http.StatusNoContent {
		t.Fatalf("alias status = %d", response.StatusCode)
	}
	// A later heartbeat must not discard the administrator's alias.
	request = authorizedRequest(t, http.MethodPost, httpServer.URL+"/v1/devices/heartbeat", nil)
	request.Header.Set("X-Eden-Device-ID", "device-1")
	request.Header.Set("X-Eden-Device-Name", "Renamed Desktop")
	response, err = http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	overview = fetchOverview(t, httpServer.URL)
	if overview.Devices[0].Alias != "书房电脑" || overview.Devices[0].Name != "Renamed Desktop" {
		t.Fatalf("alias lost after heartbeat: %+v", overview.Devices[0])
	}

	if response, _ := adminDo(t, http.MethodDelete, httpServer.URL+"/admin/api/devices/device-1", nil); response.StatusCode != http.StatusNoContent {
		t.Fatalf("delete device status = %d", response.StatusCode)
	}
	if overview := fetchOverview(t, httpServer.URL); len(overview.Devices) != 0 {
		t.Fatalf("device not removed: %+v", overview.Devices)
	}
}

func TestSnapshotRecordsUploaderAndSize(t *testing.T) {
	_, httpServer := newAdminTestServer(t, t.TempDir())
	defer httpServer.Close()
	payload := []byte("sized snapshot")
	object := putObject(t, httpServer.URL, payload)
	commitSnapshot(t, httpServer.URL, "scope-1", snapshot{ID: "s1", Blob: object, CreatedAt: time.Now().UTC()}, "", "device-7")

	response, body := adminDo(t, http.MethodGet, httpServer.URL+"/admin/api/scopes/scope-1", nil)
	if response.StatusCode != http.StatusOK {
		t.Fatalf("detail status = %d", response.StatusCode)
	}
	var detail struct {
		Snapshots []snapshotView `json:"snapshots"`
	}
	if err := json.Unmarshal(body, &detail); err != nil {
		t.Fatal(err)
	}
	if len(detail.Snapshots) != 1 || detail.Snapshots[0].Device != "device-7" ||
		detail.Snapshots[0].Size != int64(len(payload)) || !detail.Snapshots[0].Head {
		t.Fatalf("snapshot detail = %+v", detail.Snapshots)
	}

	// The head endpoint must return only the wire fields older clients understand.
	head, err := http.DefaultClient.Do(authorizedRequest(t, http.MethodGet, httpServer.URL+"/v1/scopes/scope-1/head", nil))
	if err != nil {
		t.Fatal(err)
	}
	headBody, _ := io.ReadAll(head.Body)
	head.Body.Close()
	var fields map[string]any
	if err := json.Unmarshal(headBody, &fields); err != nil {
		t.Fatal(err)
	}
	if len(fields) != 4 {
		t.Fatalf("head response has unexpected fields: %s", headBody)
	}
}

func TestRollbackCreatesNewHeadReferencingOldObject(t *testing.T) {
	_, httpServer := newAdminTestServer(t, t.TempDir())
	defer httpServer.Close()
	first := putObject(t, httpServer.URL, []byte("first"))
	second := putObject(t, httpServer.URL, []byte("second"))
	now := time.Now().UTC()
	commitSnapshot(t, httpServer.URL, "scope-1", snapshot{ID: "s1", Blob: first, CreatedAt: now.Add(-time.Hour)}, "", "")
	commitSnapshot(t, httpServer.URL, "scope-1", snapshot{ID: "s2", Blob: second, Parent: "s1", CreatedAt: now}, "s1", "")

	response, body := adminDo(t, http.MethodPost, httpServer.URL+"/admin/api/scopes/scope-1/rollback",
		map[string]string{"snapshot": "s1"})
	if response.StatusCode != http.StatusCreated {
		t.Fatalf("rollback status = %d: %s", response.StatusCode, body)
	}
	var result map[string]string
	if err := json.Unmarshal(body, &result); err != nil {
		t.Fatal(err)
	}

	head, err := http.DefaultClient.Do(authorizedRequest(t, http.MethodGet, httpServer.URL+"/v1/scopes/scope-1/head", nil))
	if err != nil {
		t.Fatal(err)
	}
	var current snapshot
	if err := json.NewDecoder(head.Body).Decode(&current); err != nil {
		t.Fatal(err)
	}
	head.Body.Close()
	if current.ID != result["head"] || current.Blob != first || current.Parent != "s2" {
		t.Fatalf("head after rollback = %+v", current)
	}

	// A client that still believes s2 is current must now be told about the conflict.
	third := putObject(t, httpServer.URL, []byte("third"))
	if status := commitSnapshot(t, httpServer.URL, "scope-1",
		snapshot{ID: "s3", Blob: third, Parent: "s2", CreatedAt: now}, "s2", ""); status != http.StatusConflict {
		t.Fatalf("stale commit status = %d", status)
	}
}

func TestHeadSnapshotCannotBeDeleted(t *testing.T) {
	_, httpServer := newAdminTestServer(t, t.TempDir())
	defer httpServer.Close()
	object := putObject(t, httpServer.URL, []byte("only"))
	commitSnapshot(t, httpServer.URL, "scope-1", snapshot{ID: "s1", Blob: object, CreatedAt: time.Now().UTC()}, "", "")
	if response, _ := adminDo(t, http.MethodDelete, httpServer.URL+"/admin/api/scopes/scope-1/snapshots/s1", nil); response.StatusCode != http.StatusConflict {
		t.Fatalf("delete head status = %d", response.StatusCode)
	}
	if response, _ := adminDo(t, http.MethodDelete, httpServer.URL+"/admin/api/scopes/scope-1", nil); response.StatusCode != http.StatusNoContent {
		t.Fatalf("delete scope status = %d", response.StatusCode)
	}
	response, err := http.DefaultClient.Do(authorizedRequest(t, http.MethodGet, httpServer.URL+"/v1/scopes/scope-1/head", nil))
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusNotFound {
		t.Fatalf("head after scope deletion = %d", response.StatusCode)
	}
}

func TestRetentionKeepsHeadPinnedAndNewest(t *testing.T) {
	dataDir := t.TempDir()
	s, httpServer := newAdminTestServer(t, dataDir)
	defer httpServer.Close()

	base := time.Now().UTC().Add(-10 * time.Hour)
	parent := ""
	var blobs []string
	for index := 1; index <= 5; index++ {
		blob := putObject(t, httpServer.URL, []byte("version "+itoa(index)))
		blobs = append(blobs, blob)
		id := "s" + itoa(index)
		commitSnapshot(t, httpServer.URL, "scope-1", snapshot{ID: id, Blob: blob, Parent: parent,
			CreatedAt: base.Add(time.Duration(index) * time.Hour)}, parent, "")
		parent = id
	}
	if response, _ := adminDo(t, http.MethodPatch, httpServer.URL+"/admin/api/scopes/scope-1/snapshots/s1",
		map[string]bool{"pinned": true}); response.StatusCode != http.StatusNoContent {
		t.Fatalf("pin status = %d", response.StatusCode)
	}
	if response, body := adminDo(t, http.MethodPut, httpServer.URL+"/admin/api/settings",
		serverSettings{Retention: retentionPolicy{KeepSnapshots: 2}}); response.StatusCode != http.StatusOK {
		t.Fatalf("settings status = %d: %s", response.StatusCode, body)
	}

	// Make every object old enough to be collected.
	old := time.Now().Add(-2 * garbageGracePeriod)
	for _, blob := range blobs {
		if err := os.Chtimes(s.objectPath(blob), old, old); err != nil {
			t.Fatal(err)
		}
	}

	response, body := adminDo(t, http.MethodPost, httpServer.URL+"/admin/api/maintenance/prune?dry_run=1", nil)
	var preview pruneReport
	if err := json.Unmarshal(body, &preview); err != nil || response.StatusCode != http.StatusOK {
		t.Fatalf("dry run status %d: %s", response.StatusCode, body)
	}
	if preview.Snapshots != 2 || preview.Objects != 2 {
		t.Fatalf("dry run report = %+v", preview)
	}
	if _, err := os.Stat(s.objectPath(blobs[1])); err != nil {
		t.Fatal("dry run removed an object")
	}

	_, body = adminDo(t, http.MethodPost, httpServer.URL+"/admin/api/maintenance/prune", nil)
	var report pruneReport
	if err := json.Unmarshal(body, &report); err != nil {
		t.Fatal(err)
	}
	if report.Snapshots != 2 || report.Objects != 2 {
		t.Fatalf("prune report = %+v", report)
	}
	s.mu.Lock()
	remaining := s.state.Scopes["scope-1"].Snapshots
	s.mu.Unlock()
	for _, id := range []string{"s1", "s4", "s5"} {
		if _, ok := remaining[id]; !ok {
			t.Fatalf("snapshot %s should have been kept; remaining %v", id, remaining)
		}
	}
	if len(remaining) != 3 {
		t.Fatalf("remaining snapshots = %d", len(remaining))
	}
	for index, blob := range blobs {
		_, err := os.Stat(s.objectPath(blob))
		wantPresent := index == 0 || index >= 3
		if wantPresent != (err == nil) {
			t.Fatalf("object %d present = %v", index+1, err == nil)
		}
	}
}

func TestRetentionRunsAfterUpload(t *testing.T) {
	s, err := newServerWithOptions(t.TempDir(), testToken, 1024*1024, serverOptions{
		settings: serverSettings{Retention: retentionPolicy{KeepSnapshots: 1}},
	})
	if err != nil {
		t.Fatal(err)
	}
	httpServer := httptest.NewServer(s.handler())
	defer httpServer.Close()
	first := putObject(t, httpServer.URL, []byte("a"))
	second := putObject(t, httpServer.URL, []byte("b"))
	commitSnapshot(t, httpServer.URL, "scope-1", snapshot{ID: "s1", Blob: first, CreatedAt: time.Now().UTC()}, "", "")
	commitSnapshot(t, httpServer.URL, "scope-1", snapshot{ID: "s2", Blob: second, Parent: "s1", CreatedAt: time.Now().UTC()}, "s1", "")
	s.mu.Lock()
	defer s.mu.Unlock()
	if snapshots := s.state.Scopes["scope-1"].Snapshots; len(snapshots) != 1 || snapshots["s2"].ID != "s2" {
		t.Fatalf("snapshots after upload = %v", snapshots)
	}
}

func TestVerifyDetectsCorruptObjects(t *testing.T) {
	s, httpServer := newAdminTestServer(t, t.TempDir())
	defer httpServer.Close()
	good := putObject(t, httpServer.URL, []byte("good"))
	bad := putObject(t, httpServer.URL, []byte("bad"))
	commitSnapshot(t, httpServer.URL, "scope-a", snapshot{ID: "a", Blob: good, CreatedAt: time.Now().UTC()}, "", "")
	commitSnapshot(t, httpServer.URL, "scope-b", snapshot{ID: "b", Blob: bad, CreatedAt: time.Now().UTC()}, "", "")
	if err := os.WriteFile(s.objectPath(bad), []byte("tampered"), 0o600); err != nil {
		t.Fatal(err)
	}
	response, body := adminDo(t, http.MethodPost, httpServer.URL+"/admin/api/maintenance/verify", nil)
	if response.StatusCode != http.StatusOK {
		t.Fatalf("verify status = %d", response.StatusCode)
	}
	var report verifyReport
	if err := json.Unmarshal(body, &report); err != nil {
		t.Fatal(err)
	}
	if report.Objects != 2 || len(report.Problems) != 1 || report.Problems[0].Problem != "corrupt" ||
		report.Problems[0].Scopes[0] != "scope-b" {
		t.Fatalf("verify report = %+v", report)
	}
}

func TestLegacyStateIsUpgradedWithSizes(t *testing.T) {
	dataDir := t.TempDir()
	payload := []byte("legacy object")
	digest := sha256.Sum256(payload)
	id := hex.EncodeToString(digest[:])
	if err := os.MkdirAll(filepath.Join(dataDir, "objects", id[:2]), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dataDir, "objects", id[:2], id), payload, 0o600); err != nil {
		t.Fatal(err)
	}
	legacy := `{"scopes":{"scope-1":{"head":"s1","snapshots":{"s1":{"id":"s1","blob":"` + id +
		`","parent":"","created_at":"2026-10-20T10:00:00Z"}}}}}`
	if err := os.WriteFile(filepath.Join(dataDir, "state.json"), []byte(legacy), 0o600); err != nil {
		t.Fatal(err)
	}
	_, httpServer := newAdminTestServer(t, dataDir)
	defer httpServer.Close()
	overview := fetchOverview(t, httpServer.URL)
	if overview.Stats.StoredBytes != int64(len(payload)) || overview.Scopes[0].HeadBytes != int64(len(payload)) {
		t.Fatalf("legacy sizes not recovered: %+v", overview.Stats)
	}
}

func TestMetricsExposeCounts(t *testing.T) {
	_, httpServer := newAdminTestServer(t, t.TempDir())
	defer httpServer.Close()
	object := putObject(t, httpServer.URL, []byte("metric"))
	commitSnapshot(t, httpServer.URL, "scope-1", snapshot{ID: "s1", Blob: object, CreatedAt: time.Now().UTC()}, "", "")
	response, body := adminDo(t, http.MethodGet, httpServer.URL+"/metrics", nil)
	if response.StatusCode != http.StatusOK || !bytes.Contains(body, []byte("eden_syncd_snapshots 1")) ||
		!bytes.Contains(body, []byte("eden_syncd_stored_bytes 6")) {
		t.Fatalf("metrics = %d %s", response.StatusCode, body)
	}
}
