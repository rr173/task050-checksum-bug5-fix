package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"task050-checksum/internal/manifest"
)

func newTestServer() (*server, http.Handler) {
	s := newServer()
	return s, s.routes()
}

func doJSON(t *testing.T, h http.Handler, method, path string, body any) (int, map[string]any) {
	t.Helper()
	var r *http.Request
	if body == nil {
		r = httptest.NewRequest(method, path, nil)
	} else {
		raw, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		r = httptest.NewRequest(method, path, bytes.NewReader(raw))
	}
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	var out map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &out)
	return w.Code, out
}

func TestHealthz(t *testing.T) {
	_, h := newTestServer()
	code, body := doJSON(t, h, "GET", "/healthz", nil)
	if code != 200 {
		t.Fatalf("code = %d want 200", code)
	}
	if body["ok"] != true {
		t.Errorf("body = %v want ok:true", body)
	}
}

func TestPutBlob(t *testing.T) {
	_, h := newTestServer()
	code, body := doJSON(t, h, "POST", "/blobs", putBlobRequest{
		Name:    "a.bin",
		Content: base64.StdEncoding.EncodeToString([]byte("hello world")),
	})
	if code != 200 {
		t.Fatalf("code = %d body=%v", code, body)
	}
	if body["name"] != "a.bin" {
		t.Errorf("name = %v", body["name"])
	}
	if body["size"].(float64) != float64(len("hello world")) {
		t.Errorf("size = %v want 11", body["size"])
	}
	// md5("hello world") = 5eb63bbbe01eeed093cb22bb8f5acdc3
	if body["md5"] != "5eb63bbbe01eeed093cb22bb8f5acdc3" {
		t.Errorf("md5 = %v", body["md5"])
	}
}

func TestPutBlobEmptyContent(t *testing.T) {
	_, h := newTestServer()
	// Empty base64 content decodes to empty bytes, which is a valid blob.
	code, body := doJSON(t, h, "POST", "/blobs", putBlobRequest{
		Name:    "empty",
		Content: "",
	})
	if code != 200 {
		t.Fatalf("code = %d body=%v", code, body)
	}
	if body["size"].(float64) != 0 {
		t.Errorf("size = %v want 0", body["size"])
	}
	if body["md5"] != "d41d8cd98f00b204e9800998ecf8427e" {
		t.Errorf("md5 = %v want empty-input md5", body["md5"])
	}
}

func TestPutBlobInvalidName(t *testing.T) {
	_, h := newTestServer()
	for _, name := range []string{"", "has space", "a/b", "café"} {
		code, body := doJSON(t, h, "POST", "/blobs", putBlobRequest{Name: name, Content: ""})
		if code != 400 {
			t.Errorf("name %q: code = %d want 400", name, code)
		}
		if body["error"] == nil {
			t.Errorf("name %q: expected error", name)
		}
	}
}

func TestPutBlobInvalidBase64(t *testing.T) {
	_, h := newTestServer()
	code, body := doJSON(t, h, "POST", "/blobs", putBlobRequest{Name: "a", Content: "!!!not base64!!!"})
	if code != 400 {
		t.Errorf("code = %d want 400", code)
	}
	if body["error"] == nil {
		t.Error("expected error")
	}
}

func TestGetBlob(t *testing.T) {
	_, h := newTestServer()
	doJSON(t, h, "POST", "/blobs", putBlobRequest{Name: "a", Content: base64.StdEncoding.EncodeToString([]byte("abc"))})
	code, body := doJSON(t, h, "GET", "/blobs/a", nil)
	if code != 200 {
		t.Fatalf("code = %d", code)
	}
	if body["md5"] != "900150983cd24fb0d6963f7d28e17f72" {
		t.Errorf("md5 = %v", body["md5"])
	}
}

func TestGetBlobNotFound(t *testing.T) {
	_, h := newTestServer()
	code, body := doJSON(t, h, "GET", "/blobs/ghost", nil)
	if code != 404 {
		t.Errorf("code = %d want 404", code)
	}
	if body["error"] == nil {
		t.Error("expected error")
	}
}

func TestDeleteBlob(t *testing.T) {
	_, h := newTestServer()
	doJSON(t, h, "POST", "/blobs", putBlobRequest{Name: "a", Content: base64.StdEncoding.EncodeToString([]byte("x"))})
	code, _ := doJSON(t, h, "DELETE", "/blobs/a", nil)
	if code != 200 {
		t.Errorf("delete code = %d want 200", code)
	}
	code, _ = doJSON(t, h, "GET", "/blobs/a", nil)
	if code != 404 {
		t.Errorf("after delete get code = %d want 404", code)
	}
}

func TestDeleteBlobNotFound(t *testing.T) {
	_, h := newTestServer()
	code, _ := doJSON(t, h, "DELETE", "/blobs/ghost", nil)
	if code != 404 {
		t.Errorf("code = %d want 404", code)
	}
}

func TestListBlobsSorted(t *testing.T) {
	_, h := newTestServer()
	doJSON(t, h, "POST", "/blobs", putBlobRequest{Name: "z", Content: base64.StdEncoding.EncodeToString([]byte("z"))})
	doJSON(t, h, "POST", "/blobs", putBlobRequest{Name: "a", Content: base64.StdEncoding.EncodeToString([]byte("a"))})
	code, body := doJSON(t, h, "GET", "/blobs", nil)
	if code != 200 {
		t.Fatalf("code = %d", code)
	}
	arr := body["blobs"].([]any)
	if len(arr) != 2 {
		t.Fatalf("len = %d want 2", len(arr))
	}
	if arr[0].(map[string]any)["name"] != "a" {
		t.Errorf("first = %v want a", arr[0])
	}
	if arr[1].(map[string]any)["name"] != "z" {
		t.Errorf("second = %v want z", arr[1])
	}
}

func TestManifestGenerate(t *testing.T) {
	_, h := newTestServer()
	doJSON(t, h, "POST", "/blobs", putBlobRequest{Name: "a", Content: base64.StdEncoding.EncodeToString([]byte("abc"))})
	doJSON(t, h, "POST", "/blobs", putBlobRequest{Name: "empty", Content: ""})
	code, body := doJSON(t, h, "POST", "/manifest/generate", generateRequest{Algo: "sha256", Names: []string{"a", "empty", "ghost"}})
	if code != 200 {
		t.Fatalf("code = %d body=%v", code, body)
	}
	man := body["manifest"].(string)
	// Each line uses two-space separator and lowercase sha256.
	if !strings.Contains(man, "sha256  ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad  a\n") {
		t.Errorf("manifest missing correct a line:\n%s", man)
	}
	if !strings.Contains(man, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855  empty\n") {
		t.Errorf("manifest missing empty line:\n%s", man)
	}
	missing := body["missing"].([]any)
	if len(missing) != 1 || missing[0] != "ghost" {
		t.Errorf("missing = %v want [ghost]", missing)
	}
}

func TestManifestGenerateUnknownAlgo(t *testing.T) {
	_, h := newTestServer()
	code, _ := doJSON(t, h, "POST", "/manifest/generate", generateRequest{Algo: "sha1", Names: []string{"a"}})
	if code != 400 {
		t.Errorf("code = %d want 400", code)
	}
}

func TestManifestVerifyOK(t *testing.T) {
	_, h := newTestServer()
	doJSON(t, h, "POST", "/blobs", putBlobRequest{Name: "a", Content: base64.StdEncoding.EncodeToString([]byte("abc"))})
	man := "md5  900150983cd24fb0d6963f7d28e17f72  a\n"
	code, body := doJSON(t, h, "POST", "/manifest/verify", verifyRequest{Manifest: man})
	if code != 200 {
		t.Fatalf("code = %d", code)
	}
	results := body["results"].([]any)
	if len(results) != 1 {
		t.Fatalf("len = %d want 1", len(results))
	}
	r := results[0].(map[string]any)
	if r["status"] != "ok" {
		t.Errorf("status = %v want ok", r["status"])
	}
	summary := body["summary"].(map[string]any)
	if summary["ok"].(float64) != 1 {
		t.Errorf("summary ok = %v want 1", summary["ok"])
	}
}

func TestManifestVerifyAllStatuses(t *testing.T) {
	_, h := newTestServer()
	doJSON(t, h, "POST", "/blobs", putBlobRequest{Name: "a", Content: base64.StdEncoding.EncodeToString([]byte("abc"))})
	doJSON(t, h, "POST", "/blobs", putBlobRequest{Name: "b", Content: base64.StdEncoding.EncodeToString([]byte("xyz"))})
	md5abc, _ := manifest.Hash(manifest.MD5, []byte("abc"))
	man := "md5  " + md5abc + "  a\n" + // ok
		"md5  " + md5abc + "  b\n" + // mismatch (b holds "xyz")
		"md5  " + md5abc + "  ghost\n" + // missing
		"md5  badhash  bad\n" + // malformed
		"# comment line\n" + // skipped
		"\n" // blank skipped
	code, body := doJSON(t, h, "POST", "/manifest/verify", verifyRequest{Manifest: man})
	if code != 200 {
		t.Fatalf("code = %d body=%v", code, body)
	}
	results := body["results"].([]any)
	if len(results) != 4 {
		t.Fatalf("len = %d want 4 (comment+blank skipped)", len(results))
	}
	want := []string{"ok", "mismatch", "missing", "malformed"}
	for i, w := range want {
		if results[i].(map[string]any)["status"] != w {
			t.Errorf("result %d = %v want %s", i, results[i].(map[string]any)["status"], w)
		}
	}
	summary := body["summary"].(map[string]any)
	if summary["ok"].(float64) != 1 || summary["mismatch"].(float64) != 1 ||
		summary["missing"].(float64) != 1 || summary["malformed"].(float64) != 1 {
		t.Errorf("summary = %v", summary)
	}
	if summary["total"].(float64) != 4 {
		t.Errorf("total = %v want 4", summary["total"])
	}
}

func TestManifestVerifyCaseInsensitiveHash(t *testing.T) {
	_, h := newTestServer()
	doJSON(t, h, "POST", "/blobs", putBlobRequest{Name: "a", Content: base64.StdEncoding.EncodeToString([]byte("abc"))})
	upper := strings.ToUpper("900150983cd24fb0d6963f7d28e17f72")
	man := "md5  " + upper + "  a\n"
	code, body := doJSON(t, h, "POST", "/manifest/verify", verifyRequest{Manifest: man})
	if code != 200 {
		t.Fatalf("code = %d", code)
	}
	results := body["results"].([]any)
	if results[0].(map[string]any)["status"] != "ok" {
		t.Errorf("status = %v want ok (case-insensitive)", results[0].(map[string]any)["status"])
	}
}

func TestManifestVerifyOverwriteReflectsLatest(t *testing.T) {
	_, h := newTestServer()
	// Register a with "v1", compute its hash, then overwrite with "v2".
	doJSON(t, h, "POST", "/blobs", putBlobRequest{Name: "a", Content: base64.StdEncoding.EncodeToString([]byte("v1"))})
	md5v1, _ := manifest.Hash(manifest.MD5, []byte("v1"))
	doJSON(t, h, "POST", "/blobs", putBlobRequest{Name: "a", Content: base64.StdEncoding.EncodeToString([]byte("v2"))})
	// Manifest still declares the v1 hash; verification must reflect the v2
	// content, hence a mismatch.
	man := "md5  " + md5v1 + "  a\n"
	code, body := doJSON(t, h, "POST", "/manifest/verify", verifyRequest{Manifest: man})
	if code != 200 {
		t.Fatalf("code = %d", code)
	}
	results := body["results"].([]any)
	if results[0].(map[string]any)["status"] != "mismatch" {
		t.Errorf("status = %v want mismatch after overwrite", results[0].(map[string]any)["status"])
	}
}