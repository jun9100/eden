// SPDX-FileCopyrightText: Copyright 2026 Eden Emulator Project
// SPDX-License-Identifier: GPL-3.0-or-later

package main

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const (
	testOpenSaveUsername = "opensave-user"
	testOpenSavePassword = "opensave-password"
)

func newOpenSaveTestServer(t *testing.T, maxBytes int64) (*server, *httptest.Server, string) {
	t.Helper()
	dataDir := t.TempDir()
	s, err := newServerWithOptions(dataDir, testToken, maxBytes, serverOptions{
		openSaveUsername: testOpenSaveUsername,
		openSavePassword: testOpenSavePassword,
	})
	if err != nil {
		t.Fatal(err)
	}
	return s, httptest.NewServer(s.handler()), dataDir
}

func openSaveRequest(t *testing.T, method, target string, body []byte) *http.Request {
	t.Helper()
	request, err := http.NewRequest(method, target, bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	request.SetBasicAuth(testOpenSaveUsername, testOpenSavePassword)
	return request
}

func TestOpenSaveWebDAVIsDisabledWithoutSeparateCredentials(t *testing.T) {
	s, err := newServer(t.TempDir(), testToken, 1024*1024)
	if err != nil {
		t.Fatal(err)
	}
	httpServer := httptest.NewServer(s.handler())
	defer httpServer.Close()

	response, err := http.Get(httpServer.URL + "/opensave/")
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusNotFound {
		t.Fatalf("disabled /opensave/ status = %d, want 404", response.StatusCode)
	}

	if _, err := newServerWithOptions(t.TempDir(), testToken, 1024*1024, serverOptions{
		openSaveUsername: testOpenSaveUsername,
	}); err == nil {
		t.Fatal("server accepted a partial OpenSave credential pair")
	}
}

func TestOpenSaveWebDAVRequiresIndependentBasicAuth(t *testing.T) {
	_, httpServer, _ := newOpenSaveTestServer(t, 1024*1024)
	defer httpServer.Close()

	request, err := http.NewRequest("PROPFIND", httpServer.URL+"/opensave/", nil)
	if err != nil {
		t.Fatal(err)
	}
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusUnauthorized || !strings.Contains(response.Header.Get("WWW-Authenticate"), "Basic") {
		t.Fatalf("missing credentials response = %d, WWW-Authenticate=%q", response.StatusCode, response.Header.Get("WWW-Authenticate"))
	}

	request = openSaveRequest(t, "PROPFIND", httpServer.URL+"/opensave/", nil)
	request.SetBasicAuth(testOpenSaveUsername, "wrong-password")
	response, err = http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusUnauthorized {
		t.Fatalf("wrong credentials response = %d, want 401", response.StatusCode)
	}
}

func TestOpenSaveWebDAVRoundTripUsesIsolatedStorage(t *testing.T) {
	_, httpServer, dataDir := newOpenSaveTestServer(t, 1024*1024)
	defer httpServer.Close()

	options := openSaveRequest(t, http.MethodOptions, httpServer.URL+"/opensave/", nil)
	response, err := http.DefaultClient.Do(options)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusNoContent || response.Header.Get("DAV") != "1" ||
		!strings.Contains(response.Header.Get("Allow"), "MOVE") {
		t.Fatalf("OPTIONS = %d DAV=%q Allow=%q", response.StatusCode, response.Header.Get("DAV"), response.Header.Get("Allow"))
	}

	stageName := ".opensave-upload.part"
	finalName := "game__main__snap_1.zip"
	payload := []byte("complete snapshot bytes")
	put := openSaveRequest(t, http.MethodPut, httpServer.URL+"/opensave/"+stageName, payload)
	response, err = http.DefaultClient.Do(put)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusCreated {
		t.Fatalf("PUT status = %d", response.StatusCode)
	}

	head := openSaveRequest(t, http.MethodHead, httpServer.URL+"/opensave/"+stageName, nil)
	response, err = http.DefaultClient.Do(head)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusOK || response.ContentLength != int64(len(payload)) {
		t.Fatalf("HEAD status=%d length=%d, want %d", response.StatusCode, response.ContentLength, len(payload))
	}

	move := openSaveRequest(t, "MOVE", httpServer.URL+"/opensave/"+stageName, nil)
	move.Header.Set("Destination", httpServer.URL+"/opensave/"+finalName)
	move.Header.Set("Overwrite", "F")
	response, err = http.DefaultClient.Do(move)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusCreated {
		t.Fatalf("MOVE status = %d", response.StatusCode)
	}

	stored, err := os.ReadFile(filepath.Join(dataDir, "opensave", finalName))
	if err != nil || !bytes.Equal(stored, payload) {
		t.Fatalf("isolated OpenSave file = %q, err=%v", stored, err)
	}
	objects, err := os.ReadDir(filepath.Join(dataDir, "objects"))
	if err != nil {
		t.Fatal(err)
	}
	if len(objects) != 0 {
		t.Fatalf("OpenSave upload wrote Eden objects: %v", objects)
	}

	propfind := openSaveRequest(t, "PROPFIND", httpServer.URL+"/opensave/", nil)
	propfind.Header.Set("Depth", "1")
	response, err = http.DefaultClient.Do(propfind)
	if err != nil {
		t.Fatal(err)
	}
	listing, _ := io.ReadAll(response.Body)
	response.Body.Close()
	if response.StatusCode != http.StatusMultiStatus || !strings.Contains(string(listing), finalName) ||
		strings.Contains(string(listing), stageName) {
		t.Fatalf("PROPFIND status=%d listing=%s", response.StatusCode, listing)
	}

	get := openSaveRequest(t, http.MethodGet, httpServer.URL+"/opensave/"+finalName, nil)
	response, err = http.DefaultClient.Do(get)
	if err != nil {
		t.Fatal(err)
	}
	downloaded, _ := io.ReadAll(response.Body)
	response.Body.Close()
	if response.StatusCode != http.StatusOK || !bytes.Equal(downloaded, payload) {
		t.Fatalf("GET status=%d body=%q", response.StatusCode, downloaded)
	}

	deleteRequest := openSaveRequest(t, http.MethodDelete, httpServer.URL+"/opensave/"+finalName, nil)
	response, err = http.DefaultClient.Do(deleteRequest)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusNoContent {
		t.Fatalf("DELETE status = %d", response.StatusCode)
	}
	if _, err := os.Stat(filepath.Join(dataDir, "opensave", finalName)); !os.IsNotExist(err) {
		t.Fatalf("DELETE left the snapshot behind: %v", err)
	}
}

func TestOpenSaveWebDAVMoveDoesNotOverwriteAndRejectsUnsafeNames(t *testing.T) {
	_, httpServer, _ := newOpenSaveTestServer(t, 4)
	defer httpServer.Close()

	for _, name := range []string{"nested/file.zip", "%2Foutside.zip", "%5Coutside.zip", "%252Foutside.zip"} {
		request := openSaveRequest(t, http.MethodPut, httpServer.URL+"/opensave/"+name, []byte("x"))
		response, err := http.DefaultClient.Do(request)
		if err != nil {
			t.Fatal(err)
		}
		response.Body.Close()
		if response.StatusCode < http.StatusBadRequest {
			t.Errorf("unsafe name %q accepted with HTTP %d", name, response.StatusCode)
		}
	}

	tooLarge := openSaveRequest(t, http.MethodPut, httpServer.URL+"/opensave/.large.part", []byte("12345"))
	response, err := http.DefaultClient.Do(tooLarge)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusRequestEntityTooLarge {
		t.Fatalf("large PUT status = %d, want 413", response.StatusCode)
	}

	for name, value := range map[string]string{
		"existing.zip": "old",
		".new.part":    "new",
	} {
		request := openSaveRequest(t, http.MethodPut, httpServer.URL+"/opensave/"+name, []byte(value))
		response, err := http.DefaultClient.Do(request)
		if err != nil {
			t.Fatal(err)
		}
		response.Body.Close()
		if response.StatusCode != http.StatusCreated {
			t.Fatalf("PUT %s status = %d", name, response.StatusCode)
		}
	}
	move := openSaveRequest(t, "MOVE", httpServer.URL+"/opensave/.new.part", nil)
	move.Header.Set("Destination", httpServer.URL+"/opensave/existing.zip")
	move.Header.Set("Overwrite", "F")
	response, err = http.DefaultClient.Do(move)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusPreconditionFailed {
		t.Fatalf("MOVE collision status = %d, want 412", response.StatusCode)
	}

	get := openSaveRequest(t, http.MethodGet, httpServer.URL+"/opensave/existing.zip", nil)
	response, err = http.DefaultClient.Do(get)
	if err != nil {
		t.Fatal(err)
	}
	contents, _ := io.ReadAll(response.Body)
	response.Body.Close()
	if string(contents) != "old" {
		t.Fatalf("MOVE collision overwrote existing data: %q", contents)
	}
}
