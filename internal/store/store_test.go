package store

import (
	"bytes"
	"errors"
	"testing"
)

func TestPutGetRoundTrip(t *testing.T) {
	s := New()
	content := []byte("hello world")
	if err := s.Put("a.bin", content); err != nil {
		t.Fatal(err)
	}
	got, err := s.Get("a.bin")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, content) {
		t.Errorf("got %q want %q", got, content)
	}
}

func TestPutOverwrites(t *testing.T) {
	s := New()
	s.Put("a", []byte("v1"))
	s.Put("a", []byte("v2"))
	got, _ := s.Get("a")
	if string(got) != "v2" {
		t.Errorf("got %q want v2 after overwrite", got)
	}
}

func TestPutDeepCopy(t *testing.T) {
	s := New()
	content := []byte("orig")
	s.Put("a", content)
	content[0] = 'X' // mutate caller slice after Put
	got, _ := s.Get("a")
	if string(got) != "orig" {
		t.Errorf("stored content mutated via caller slice: %q", got)
	}
}

func TestGetDeepCopy(t *testing.T) {
	s := New()
	s.Put("a", []byte("orig"))
	got1, _ := s.Get("a")
	got1[0] = 'X' // mutate returned copy
	got2, _ := s.Get("a")
	if string(got2) != "orig" {
		t.Errorf("internal content mutated via returned slice: %q", got2)
	}
}

func TestGetNotFound(t *testing.T) {
	s := New()
	if _, err := s.Get("ghost"); !errors.Is(err, ErrNotFound) {
		t.Errorf("err = %v want ErrNotFound", err)
	}
}

func TestDelete(t *testing.T) {
	s := New()
	s.Put("a", []byte("x"))
	if err := s.Delete("a"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Get("a"); !errors.Is(err, ErrNotFound) {
		t.Errorf("after delete: err = %v want ErrNotFound", err)
	}
}

func TestDeleteNotFound(t *testing.T) {
	s := New()
	if err := s.Delete("ghost"); !errors.Is(err, ErrNotFound) {
		t.Errorf("err = %v want ErrNotFound", err)
	}
}

func TestLookup(t *testing.T) {
	s := New()
	s.Put("a", []byte("v"))
	if c, ok := s.Lookup("a"); !ok || string(c) != "v" {
		t.Errorf("Lookup(a) = (%q,%v) want (v,true)", c, ok)
	}
	if _, ok := s.Lookup("ghost"); ok {
		t.Error("Lookup(ghost) should return false")
	}
}

func TestListSortedByName(t *testing.T) {
	s := New()
	s.Put("z", []byte("1"))
	s.Put("a", []byte("2"))
	s.Put("m", []byte("3"))
	out := s.List()
	if len(out) != 3 {
		t.Fatalf("len = %d want 3", len(out))
	}
	want := []string{"a", "m", "z"}
	for i, w := range want {
		if out[i].Name != w {
			t.Errorf("out[%d].Name = %q want %q", i, out[i].Name, w)
		}
	}
	// List must not expose the internal content slice.
	if out[0].Size != 1 || out[1].Size != 1 || out[2].Size != 1 {
		t.Errorf("sizes wrong: %v", out)
	}
}

func TestSize(t *testing.T) {
	s := New()
	if s.Size() != 0 {
		t.Fatal("new store size != 0")
	}
	s.Put("a", []byte("x"))
	s.Put("b", []byte("y"))
	if s.Size() != 2 {
		t.Errorf("size = %d want 2", s.Size())
	}
	s.Delete("a")
	if s.Size() != 1 {
		t.Errorf("size = %d want 1", s.Size())
	}
}

func TestInvalidNames(t *testing.T) {
	s := New()
	bad := []string{
		"",         // empty
		"has space", // space
		"a b",       // internal space
		"a  b",      // two spaces
		"with/slash",
		"with\\back",
		"new\nline",
		"tab\there",
		"café",      // non-ascii
		"with:colon",
		"with*star",
	}
	for _, n := range bad {
		if err := s.Put(n, []byte("x")); !errors.Is(err, ErrInvalidName) {
			t.Errorf("Put(%q): err = %v want ErrInvalidName", n, err)
		}
	}
}

func TestValidNames(t *testing.T) {
	s := New()
	good := []string{"a", "A", "0", "a.b", "a_b", "a-b", "file.txt", "A.B-C_D", "123"}
	for _, n := range good {
		if err := s.Put(n, []byte("x")); err != nil {
			t.Errorf("Put(%q): unexpected error %v", n, err)
		}
	}
}

func TestEmptyContentAllowed(t *testing.T) {
	s := New()
	if err := s.Put("empty", []byte{}); err != nil {
		t.Fatal(err)
	}
	if err := s.Put("nil", nil); err != nil {
		t.Fatal(err)
	}
	got, _ := s.Get("empty")
	if len(got) != 0 {
		t.Errorf("empty content size = %d want 0", len(got))
	}
}
