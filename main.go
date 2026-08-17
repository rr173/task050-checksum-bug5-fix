// Command task050-checksum runs the in-memory file checksum batch compute and
// verification service.
//
// Use --smoke-test to run the built-in self-check, which exits the process on
// completion. Without flags it starts an HTTP server on the address given by
// the --addr flag (default ":8080").
package main

import (
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"

	"task050-checksum/internal/manifest"
	"task050-checksum/internal/selfcheck"
	"task050-checksum/internal/store"
)

func main() {
	smoke := flag.Bool("smoke-test", false, "run the built-in self-check and exit")
	addr := flag.String("addr", ":8080", "HTTP listen address")
	flag.Parse()

	if *smoke {
		if err := selfcheck.Run(); err != nil {
			fmt.Fprintf(os.Stderr, "smoke-test FAILED: %v\n", err)
			os.Exit(1)
		}
		fmt.Println("smoke-test PASSED")
		return
	}

	srv := newServer()
	mux := srv.routes()
	log.Printf("checksum service listening on %s", *addr)
	if err := http.ListenAndServe(*addr, mux); err != nil {
		log.Fatalf("listen: %v", err)
	}
}

// server holds the blob store and wires HTTP handlers.
type server struct {
	store *store.Store
}

func newServer() *server {
	return &server{store: store.New()}
}

// blobMeta is the JSON view of a blob returned by the API. It carries both
// supported algorithms' checksums so callers can build manifests without a
// second round-trip.
type blobMeta struct {
	Name   string `json:"name"`
	Size   int    `json:"size"`
	MD5    string `json:"md5"`
	SHA256 string `json:"sha256"`
}

// metaFor builds the JSON metadata for a blob by name. It assumes the blob
// exists; callers should have already validated presence.
func (s *server) metaFor(name string, content []byte) blobMeta {
	md5, _ := manifest.Hash(manifest.MD5, content)
	sha, _ := manifest.Hash(manifest.SHA256, content)
	return blobMeta{Name: name, Size: len(content), MD5: md5, SHA256: sha}
}

func (s *server) routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", s.handleHealthz)
	mux.HandleFunc("/blobs", s.handleBlobsCollection)
	mux.HandleFunc("/blobs/", s.handleBlobItem)
	mux.HandleFunc("/manifest/generate", s.handleManifestGenerate)
	mux.HandleFunc("/manifest/verify", s.handleManifestVerify)
	return mux
}

func (s *server) handleHealthz(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// putBlobRequest is the body for POST /blobs.
type putBlobRequest struct {
	Name    string `json:"name"`
	Content string `json:"content"` // base64-encoded; "" decodes to empty bytes
}

func (s *server) handleBlobsCollection(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodPost:
		s.putBlob(w, r)
	case http.MethodGet:
		s.listBlobs(w, r)
	default:
		writeJSON(w, http.StatusMethodNotAllowed, errMsg("method not allowed"))
	}
}

func (s *server) putBlob(w http.ResponseWriter, r *http.Request) {
	var req putBlobRequest
	if err := decodeJSON(r, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, errMsg(err.Error()))
		return
	}
	content, err := base64.StdEncoding.DecodeString(req.Content)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, errMsg("content must be valid base64: "+err.Error()))
		return
	}
	if err := s.store.Put(req.Name, content); err != nil {
		writeJSON(w, http.StatusBadRequest, errMsg(err.Error()))
		return
	}
	// Re-read the stored copy (a fresh deep copy) so the response reflects
	// exactly what the store holds.
	got, err := s.store.Get(req.Name)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, errMsg(err.Error()))
		return
	}
	writeJSON(w, http.StatusOK, s.metaFor(req.Name, got))
}

func (s *server) listBlobs(w http.ResponseWriter, r *http.Request) {
	blobs := s.store.List()
	out := make([]blobMeta, 0, len(blobs))
	for _, b := range blobs {
		content, err := s.store.Get(b.Name)
		if err != nil {
			// A concurrently-deleted blob is skipped rather than failing the
			// whole listing.
			continue
		}
		out = append(out, s.metaFor(b.Name, content))
	}
	writeJSON(w, http.StatusOK, map[string]any{"blobs": out})
}

func (s *server) handleBlobItem(w http.ResponseWriter, r *http.Request) {
	name := strings.TrimPrefix(r.URL.Path, "/blobs/")
	if name == "" {
		writeJSON(w, http.StatusBadRequest, errMsg("missing blob name"))
		return
	}
	switch r.Method {
	case http.MethodGet:
		s.getBlob(w, r, name)
	case http.MethodDelete:
		s.deleteBlob(w, r, name)
	default:
		writeJSON(w, http.StatusMethodNotAllowed, errMsg("method not allowed"))
	}
}

func (s *server) getBlob(w http.ResponseWriter, r *http.Request, name string) {
	content, err := s.store.Get(name)
	if err != nil {
		writeJSON(w, http.StatusNotFound, errMsg(err.Error()))
		return
	}
	writeJSON(w, http.StatusOK, s.metaFor(name, content))
}

func (s *server) deleteBlob(w http.ResponseWriter, r *http.Request, name string) {
	if err := s.store.Delete(name); err != nil {
		writeJSON(w, http.StatusNotFound, errMsg(err.Error()))
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"deleted": name})
}

// generateRequest is the body for POST /manifest/generate.
type generateRequest struct {
	Algo  string   `json:"algo"`
	Names []string `json:"names"`
}

func (s *server) handleManifestGenerate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, errMsg("method not allowed"))
		return
	}
	var req generateRequest
	if err := decodeJSON(r, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, errMsg(err.Error()))
		return
	}
	algo, err := manifest.ParseAlgorithm(req.Algo)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, errMsg(err.Error()))
		return
	}
	body, missing, err := manifest.Generate(algo, req.Names, s.store.Lookup)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, errMsg(err.Error()))
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"algo":     algo,
		"manifest": body,
		"missing":  missing,
	})
}

// verifyRequest is the body for POST /manifest/verify.
type verifyRequest struct {
	Manifest string `json:"manifest"`
}

// verifyLineResult is the JSON view of one manifest verification result.
type verifyLineResult struct {
	Line     int    `json:"line"`
	Status   string `json:"status"`
	Name     string `json:"name,omitempty"`
	Algo     string `json:"algo,omitempty"`
	Expected string `json:"expected,omitempty"`
	Actual   string `json:"actual,omitempty"`
	Reason   string `json:"reason,omitempty"`
}

func (s *server) handleManifestVerify(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, errMsg("method not allowed"))
		return
	}
	var req verifyRequest
	if err := decodeJSON(r, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, errMsg(err.Error()))
		return
	}
	lines := manifest.Parse(req.Manifest)
	results := manifest.Verify(lines, s.store.Lookup)
	summary := manifest.Summarize(results)

	out := make([]verifyLineResult, 0, len(results))
	for i, res := range results {
		out = append(out, verifyLineResult{
			Line:     i + 1,
			Status:   string(res.Status),
			Name:     res.Name,
			Algo:     string(res.Algo),
			Expected: res.Expected,
			Actual:   res.Actual,
			Reason:   res.Reason,
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"results": out,
		"summary": map[string]int{
			"ok":        summary.OK,
			"mismatch":  summary.Mismatch,
			"missing":   summary.Missing,
			"malformed": summary.Malformed,
			"total":     summary.Total(),
		},
	})
}

// --- HTTP helpers ---

var errBufPool = sync.Pool{New: func() any { b := make([]byte, 0, 4096); return &b }}

func decodeJSON(r *http.Request, dst any) error {
	buf := errBufPool.Get().(*[]byte)
	defer func() { *buf = (*buf)[:0]; errBufPool.Put(buf) }()
	// Read up to 16 MiB to bound memory on large manifests while still allowing
	// sizable batches.
	const maxBody = 16 << 20
	n, err := io.CopyBuffer(newBufAppender(buf), r.Body, nil)
	if err != nil {
		return fmt.Errorf("read body: %w", err)
	}
	if n > maxBody {
		return fmt.Errorf("request body too large: %d bytes (max %d)", n, maxBody)
	}
	if len(*buf) == 0 {
		return fmt.Errorf("empty request body")
	}
	if err := json.Unmarshal(*buf, dst); err != nil {
		return fmt.Errorf("invalid JSON: %w", err)
	}
	return nil
}

// bufAppender wraps a *[]byte as an io.Writer so decodeJSON can reuse a pooled
// buffer without allocating a new one per request.
type bufAppender struct{ b *[]byte }

func newBufAppender(b *[]byte) *bufAppender { return &bufAppender{b: b} }
func (a *bufAppender) Write(p []byte) (int, error) {
	*a.b = append(*a.b, p...)
	return len(p), nil
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func errMsg(msg string) map[string]any { return map[string]any{"error": msg} }
