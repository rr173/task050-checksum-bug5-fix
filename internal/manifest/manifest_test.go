package manifest

import (
	"strings"
	"testing"
)

// fakeLookup builds a Lookup from a name→content map.
func fakeLookup(m map[string][]byte) Lookup {
	return func(name string) ([]byte, bool) {
		c, ok := m[name]
		return c, ok
	}
}

func TestParseAlgorithm(t *testing.T) {
	cases := []struct {
		in   string
		want Algorithm
		err  bool
	}{
		{"md5", MD5, false},
		{"MD5", MD5, false},
		{"  Sha256 ", SHA256, false},
		{"sha1", "", true},
		{"", "", true},
		{"crc32", "", true},
	}
	for _, c := range cases {
		got, err := ParseAlgorithm(c.in)
		if c.err {
			if err == nil {
				t.Errorf("ParseAlgorithm(%q): want error, got %q", c.in, got)
			}
			continue
		}
		if err != nil {
			t.Errorf("ParseAlgorithm(%q): unexpected error %v", c.in, err)
		}
		if got != c.want {
			t.Errorf("ParseAlgorithm(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestHexLength(t *testing.T) {
	if MD5.HexLength() != 32 {
		t.Errorf("md5 length = %d want 32", MD5.HexLength())
	}
	if SHA256.HexLength() != 64 {
		t.Errorf("sha256 length = %d want 64", SHA256.HexLength())
	}
}

func TestHashKnownVectors(t *testing.T) {
	// Empty input canonical digests.
	emptyMD5, _ := Hash(MD5, nil)
	if emptyMD5 != "d41d8cd98f00b204e9800998ecf8427e" {
		t.Errorf("md5(empty) = %q want d41d8cd98f00b204e9800998ecf8427e", emptyMD5)
	}
	emptySHA, _ := Hash(SHA256, nil)
	if emptySHA != "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" {
		t.Errorf("sha256(empty) = %q", emptySHA)
	}
	// "abc" known vectors.
	md5abc, _ := Hash(MD5, []byte("abc"))
	if md5abc != "900150983cd24fb0d6963f7d28e17f72" {
		t.Errorf("md5(abc) = %q", md5abc)
	}
	shaabc, _ := Hash(SHA256, []byte("abc"))
	if shaabc != "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad" {
		t.Errorf("sha256(abc) = %q", shaabc)
	}
}

func TestHashUnknownAlgorithm(t *testing.T) {
	if _, err := Hash(Algorithm("sha1"), []byte("x")); err == nil {
		t.Fatal("Hash(unknown) should error")
	}
	if _, err := EmptyHash(Algorithm("sha1")); err == nil {
		t.Fatal("EmptyHash(unknown) should error")
	}
}

func TestHashLowercaseCanonical(t *testing.T) {
	// All emitted hashes are lowercase hex.
	h, _ := Hash(MD5, []byte("ABC"))
	for _, r := range h {
		if r >= 'A' && r <= 'Z' {
			t.Fatalf("md5 contains uppercase: %q", h)
		}
	}
}

func TestParseValid(t *testing.T) {
	text := "md5  d41d8cd98f00b204e9800998ecf8427e  empty\nsha256  e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855  empty\n"
	lines := Parse(text)
	if len(lines) != 2 {
		t.Fatalf("len = %d want 2", len(lines))
	}
	if lines[0].LineNo != 1 || lines[1].LineNo != 2 {
		t.Fatalf("line numbers wrong: %v %v", lines[0].LineNo, lines[1].LineNo)
	}
	if lines[0].Entry == nil || lines[0].Entry.Algo != MD5 {
		t.Fatalf("first entry wrong: %+v", lines[0])
	}
	if lines[1].Entry == nil || lines[1].Entry.Algo != SHA256 {
		t.Fatalf("second entry wrong: %+v", lines[1])
	}
	if lines[0].Entry.Name != "empty" {
		t.Fatalf("name = %q", lines[0].Entry.Name)
	}
}

func TestParseBlankAndCommentSkipped(t *testing.T) {
	text := "# header comment\nmd5  d41d8cd98f00b204e9800998ecf8427e  e\n\n   \n# tail\n"
	lines := Parse(text)
	if len(lines) != 1 {
		t.Fatalf("len = %d want 1 (only the md5 line)", len(lines))
	}
	if lines[0].LineNo != 2 {
		t.Fatalf("line number = %d want 2", lines[0].LineNo)
	}
}

func TestParseMalformedFields(t *testing.T) {
	cases := []struct {
		name   string
		line   string
		reason string
	}{
		{"wrong separator (single space)", "md5 d41d8cd98f00b204e9800998ecf8427e e", "3 fields"},
		{"too few fields", "md5  d41d8cd98f00b204e9800998ecf8427e", "3 fields"},
		{"too many fields", "md5  d41d8cd98f00b204e9800998ecf8427e  a  b", "3 fields"},
		{"unknown algo", "sha1  0000000000000000000000000000000000000000  x", "algorithm"},
		{"md5 wrong length", "md5  d41d8cd98f00b204e9800998ecf8427  e", "hex"},
		{"sha256 wrong length", "sha256  d41d8cd98f00b204e9800998ecf8427e  e", "hex"},
		{"non-hex hash", "md5  zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz  e", "hex"},
		{"empty name", "md5  d41d8cd98f00b204e9800998ecf8427e   ", "empty name"},
	}
	for _, c := range cases {
		text := c.line + "\n"
		lines := Parse(text)
		if len(lines) != 1 {
			t.Errorf("%s: len = %d want 1", c.name, len(lines))
			continue
		}
		if lines[0].Err == nil {
			t.Errorf("%s: expected parse error", c.name)
			continue
		}
		if !strings.Contains(lines[0].Err.Reason, c.reason) {
			t.Errorf("%s: reason = %q, want substring %q", c.name, lines[0].Err.Reason, c.reason)
		}
	}
}

func TestParseHashCaseNormalized(t *testing.T) {
	// Uppercase hash input is accepted (compared case-insensitively later).
	text := "md5  D41D8CD98F00B204E9800998ECF8427E  e\n"
	lines := Parse(text)
	if len(lines) != 1 || lines[0].Err != nil {
		t.Fatalf("uppercase hash should parse: %+v", lines)
	}
	if lines[0].Entry.Hash != "d41d8cd98f00b204e9800998ecf8427e" {
		t.Errorf("hash not lowercased: %q", lines[0].Entry.Hash)
	}
}

func TestParseNameWithSingleSpaceRejected(t *testing.T) {
	// A name containing a space would split into extra fields via the two-space
	// separator only if it had two consecutive spaces; a single-space name like
	// "a b" is actually fine because the separator is exactly two spaces. But a
	// name with two consecutive spaces corrupts the structure.
	text := "md5  d41d8cd98f00b204e9800998ecf8427e  a  b\n"
	lines := Parse(text)
	if len(lines) != 1 {
		t.Fatalf("len = %d want 1", len(lines))
	}
	if lines[0].Err == nil {
		t.Fatalf("name with embedded two-space should be malformed: %+v", lines[0])
	}
}

func TestParseCRLFNormalized(t *testing.T) {
	// Windows line endings must parse the same as Unix.
	text := "md5  d41d8cd98f00b204e9800998ecf8427e  a\r\nmd5  d41d8cd98f00b204e9800998ecf8427e  b\r\n"
	lines := Parse(text)
	if len(lines) != 2 {
		t.Fatalf("len = %d want 2", len(lines))
	}
	if lines[0].Entry == nil || lines[0].Entry.Name != "a" {
		t.Fatalf("first entry wrong: %+v", lines[0])
	}
	if lines[1].Entry == nil || lines[1].Entry.Name != "b" {
		t.Fatalf("second entry wrong: %+v", lines[1])
	}
}

func TestParseEmpty(t *testing.T) {
	if lines := Parse(""); len(lines) != 0 {
		t.Errorf("Parse(\"\") = %v want nil", lines)
	}
}

func TestVerifyOK(t *testing.T) {
	text := "md5  900150983cd24fb0d6963f7d28e17f72  abc\n"
	blobs := map[string][]byte{"abc": []byte("abc")}
	results := Verify(Parse(text), fakeLookup(blobs))
	if len(results) != 1 {
		t.Fatalf("len = %d want 1", len(results))
	}
	if results[0].Status != StatusOK {
		t.Errorf("status = %s want ok", results[0].Status)
	}
	if results[0].Actual != "900150983cd24fb0d6963f7d28e17f72" {
		t.Errorf("actual = %q", results[0].Actual)
	}
}

func TestVerifyMismatch(t *testing.T) {
	text := "md5  900150983cd24fb0d6963f7d28e17f72  abc\n"
	blobs := map[string][]byte{"abc": []byte("xyz")} // different content
	results := Verify(Parse(text), fakeLookup(blobs))
	if results[0].Status != StatusMismatch {
		t.Errorf("status = %s want mismatch", results[0].Status)
	}
	if results[0].Actual != "fb8e18e1c7d52e4d0b1f2c1f4e1a0f0a" {
		// sanity: actual should differ from declared
		if results[0].Actual == results[0].Expected {
			t.Errorf("actual equals expected despite different content")
		}
	}
}

func TestVerifyMissing(t *testing.T) {
	text := "md5  900150983cd24fb0d6963f7d28e17f72  ghost\n"
	results := Verify(Parse(text), fakeLookup(map[string][]byte{}))
	if results[0].Status != StatusMissing {
		t.Errorf("status = %s want missing", results[0].Status)
	}
}

func TestVerifyMalformed(t *testing.T) {
	text := "md5  tooShort  e\n"
	results := Verify(Parse(text), fakeLookup(map[string][]byte{}))
	if results[0].Status != StatusMalformed {
		t.Errorf("status = %s want malformed", results[0].Status)
	}
	if results[0].Actual != "" {
		t.Errorf("malformed actual = %q want empty", results[0].Actual)
	}
}

func TestVerifyEmptyContentBlobOK(t *testing.T) {
	// An empty-content blob verifies against its canonical empty-input digest,
	// and must NOT be reported missing.
	emptyMD5, _ := Hash(MD5, nil)
	text := "md5  " + emptyMD5 + "  empty\n"
	blobs := map[string][]byte{"empty": {}}
	results := Verify(Parse(text), fakeLookup(blobs))
	if results[0].Status != StatusOK {
		t.Errorf("status = %s want ok (empty content is valid)", results[0].Status)
	}
}

func TestVerifyHashCaseInsensitive(t *testing.T) {
	// Manifest declares uppercase hash; actual computed is lowercase; comparison
	// must still yield OK.
	upper := strings.ToUpper("900150983cd24fb0d6963f7d28e17f72")
	text := "md5  " + upper + "  abc\n"
	blobs := map[string][]byte{"abc": []byte("abc")}
	results := Verify(Parse(text), fakeLookup(blobs))
	if results[0].Status != StatusOK {
		t.Errorf("status = %s want ok (case-insensitive)", results[0].Status)
	}
}

func TestVerifyMalformedDoesNotAbortBatch(t *testing.T) {
	// A malformed line in the middle does not abort the rest of the batch.
	md5abc, _ := Hash(MD5, []byte("abc"))
	md5xyz, _ := Hash(MD5, []byte("xyz"))
	text := "md5  " + md5abc + "  abc\n" +
		"md5  badhash  bad\n" +
		"md5  " + md5xyz + "  xyz\n" +
		"md5  " + md5abc + "  ghost\n"
	blobs := map[string][]byte{"abc": []byte("abc"), "xyz": []byte("xyz")}
	results := Verify(Parse(text), fakeLookup(blobs))
	if len(results) != 4 {
		t.Fatalf("len = %d want 4", len(results))
	}
	want := []Status{StatusOK, StatusMalformed, StatusOK, StatusMissing}
	for i, w := range want {
		if results[i].Status != w {
			t.Errorf("result %d status = %s want %s", i, results[i].Status, w)
		}
	}
}

func TestSummarize(t *testing.T) {
	md5abc, _ := Hash(MD5, []byte("abc"))
	text := "md5  " + md5abc + "  abc\n" + // ok
		"md5  deadbeef  bad\n" + // malformed
		"md5  " + md5abc + "  ghost\n" + // missing
		"md5  " + md5abc + "  other\n" // mismatch (other holds "xyz")
	blobs := map[string][]byte{"abc": []byte("abc"), "other": []byte("xyz")}
	results := Verify(Parse(text), fakeLookup(blobs))
	s := Summarize(results)
	if s.OK != 1 || s.Malformed != 1 || s.Missing != 1 || s.Mismatch != 1 {
		t.Errorf("summary = %+v want ok=1 malformed=1 missing=1 mismatch=1", s)
	}
	if s.Total() != 4 {
		t.Errorf("total = %d want 4", s.Total())
	}
}

func TestGenerate(t *testing.T) {
	blobs := map[string][]byte{"a": []byte("abc"), "b": {}}
	body, missing, err := Generate(MD5, []string{"a", "b", "ghost"}, fakeLookup(blobs))
	if err != nil {
		t.Fatal(err)
	}
	if len(missing) != 1 || missing[0] != "ghost" {
		t.Errorf("missing = %v want [ghost]", missing)
	}
	// Each manifest line uses the two-space separator and lowercase hash.
	md5abc, _ := Hash(MD5, []byte("abc"))
	md5empty, _ := Hash(MD5, nil)
	want := "md5  " + md5abc + "  a\n" + "md5  " + md5empty + "  b\n"
	if body != want {
		t.Errorf("body = %q want %q", body, want)
	}
}

func TestGenerateUnknownAlgorithm(t *testing.T) {
	if _, _, err := Generate(Algorithm("sha1"), []string{"a"}, fakeLookup(map[string][]byte{})); err == nil {
		t.Fatal("Generate with unknown algo should error")
	}
}

func TestGeneratePreservesOrder(t *testing.T) {
	blobs := map[string][]byte{"z": []byte("z"), "a": []byte("a")}
	body, _, _ := Generate(SHA256, []string{"z", "a"}, fakeLookup(blobs))
	// Order of output lines follows the input names, not sorted.
	if !strings.HasPrefix(body, "sha256") {
		t.Errorf("body should start with sha256: %q", body)
	}
	// The line for z must come before the line for a.
	zIdx := strings.Index(body, "  z\n")
	aIdx := strings.Index(body, "  a\n")
	if zIdx < 0 || aIdx < 0 || zIdx > aIdx {
		t.Errorf("order wrong: zIdx=%d aIdx=%d", zIdx, aIdx)
	}
}
