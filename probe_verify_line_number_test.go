package main

import (
	"encoding/base64"
	"net/http"
	"testing"
)

// TestProbeVerifyLineNumbers asserts that each verification result reports the
// manifest line number of its source line, not the position in the result
// slice. The manifest below has a comment on line 1, so the single real entry
// lives on line 2.
func TestProbeVerifyLineNumbers(t *testing.T) {
	_, h := newTestServer()
	doJSON(t, h, http.MethodPost, "/blobs", putBlobRequest{
		Name:    "a",
		Content: base64.StdEncoding.EncodeToString([]byte("abc")),
	})
	man := "# header comment\n" + "md5  900150983cd24fb0d6963f7d28e17f72  a\n"
	code, body := doJSON(t, h, http.MethodPost, "/manifest/verify", verifyRequest{Manifest: man})
	if code != http.StatusOK {
		t.Fatalf("code = %d body=%v", code, body)
	}
	results, _ := body["results"].([]any)
	if len(results) != 1 {
		t.Fatalf("results len = %d want 1", len(results))
	}
	r, _ := results[0].(map[string]any)
	lineNum, _ := r["line"].(float64)
	if int(lineNum) != 2 {
		t.Fatalf("result line = %v want 2 (manifest line number, not result-slice index)", r["line"])
	}
}
