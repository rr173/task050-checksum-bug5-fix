// Package store implements an in-memory, concurrency-safe registry of named
// binary blobs (byte content) used by the checksum service.
//
// The store deep-copies content on the way in (Put) and on the way out (Get),
// so callers and the store never share byte-slice storage. Blob names are
// validated against a restricted charset to keep manifest lines unambiguous.
package store

import (
	"errors"
	"sort"
	"sync"
)

// ErrInvalidName is returned when a blob name does not match the allowed
// charset (non-empty, only [A-Za-z0-9._-]).
var ErrInvalidName = errors.New("store: invalid blob name")

// ErrNotFound is returned when a blob name is not registered.
var ErrNotFound = errors.New("store: blob not found")

// namePattern reports whether name is a valid blob name: non-empty and only
// containing [A-Za-z0-9._-]. Names must not contain spaces, newlines, or any
// character that would break the two-space-separated manifest line format.
func nameValid(name string) bool {
	if name == "" {
		return false
	}
	for i := 0; i < len(name); i++ {
		c := name[i]
		switch {
		case c >= 'a' && c <= 'z':
		case c >= 'A' && c <= 'Z':
		case c >= '0' && c <= '9':
		case c == '.' || c == '_' || c == '-':
		default:
			return false
		}
	}
	return true
}

// Blob is the stored metadata for a registered blob.
type Blob struct {
	Name    string
	Size    int
	Content []byte // a private copy; never aliased to caller storage
}

// Store is a concurrency-safe in-memory registry of named blobs.
type Store struct {
	mu    sync.RWMutex
	blobs map[string]*Blob
}

// New returns an empty store.
func New() *Store {
	return &Store{blobs: make(map[string]*Blob)}
}

// Put registers content under name, overwriting any existing blob with the same
// name. The content is deep-copied so the caller may mutate the original slice
// afterwards without affecting the stored blob. An invalid name yields
// ErrInvalidName.
func (s *Store) Put(name string, content []byte) error {
	if !nameValid(name) {
		return ErrInvalidName
	}
	cp := make([]byte, len(content))
	copy(cp, content)
	s.mu.Lock()
	defer s.mu.Unlock()
	s.blobs[name] = &Blob{Name: name, Size: len(cp), Content: cp}
	return nil
}

// Get returns a deep copy of the blob content for name, or ErrNotFound.
func (s *Store) Get(name string) ([]byte, error) {
	s.mu.RLock()
	b, ok := s.blobs[name]
	s.mu.RUnlock()
	if !ok {
		return nil, ErrNotFound
	}
	cp := make([]byte, len(b.Content))
	copy(cp, b.Content)
	return cp, nil
}

// Lookup implements the manifest.Lookup contract: it returns the blob content
// (a private copy) and true if the name is registered, or (nil, false)
// otherwise. It never returns an error so the manifest layer can use it
// directly as a predicate.
func (s *Store) Lookup(name string) ([]byte, bool) {
	content, err := s.Get(name)
	if err != nil {
		return nil, false
	}
	return content, true
}

// Delete removes the blob named name. Removing an unknown name yields
// ErrNotFound.
func (s *Store) Delete(name string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.blobs[name]; !ok {
		return ErrNotFound
	}
	delete(s.blobs, name)
	return nil
}

// List returns all registered blobs sorted by name ascending. Content is not
// included in the returned items to keep listing cheap; callers needing content
// should use Get.
func (s *Store) List() []Blob {
	s.mu.RLock()
	out := make([]Blob, 0, len(s.blobs))
	for _, b := range s.blobs {
		out = append(out, Blob{Name: b.Name, Size: b.Size})
	}
	s.mu.RUnlock()
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// Size returns the number of registered blobs.
func (s *Store) Size() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.blobs)
}
