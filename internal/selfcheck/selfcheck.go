// Package selfcheck runs an end-to-end verification of the checksum service's
// core logic. It is invoked by the --smoke-test flag and exits the process on
// completion. It exercises the manifest and store packages directly (no
// network) so the check is deterministic and fast.
package selfcheck

import (
	"errors"
	"fmt"
	"strings"

	"task050-checksum/internal/manifest"
	"task050-checksum/internal/store"
)

// Run exercises the checksum computation, manifest parsing, generation, and
// verification across isolated scenarios, returning nil if every behavior
// matches the specification.
func Run() error {
	scenarios := []struct {
		name string
		fn   func() error
	}{
		{"已知向量校验和", scenarioKnownVectors},
		{"空内容规范校验和", scenarioEmptyContentHash},
		{"小写规范输出", scenarioLowercaseCanonical},
		{"数据块注册与查询", scenarioPutGet},
		{"数据块覆盖", scenarioOverwrite},
		{"数据块删除", scenarioDelete},
		{"列举按名排序", scenarioListSorted},
		{"存储隔离-写入侧", scenarioPutIsolation},
		{"存储隔离-读取侧", scenarioGetIsolation},
		{"名称字符集校验", scenarioNameCharset},
		{"清单解析合法", scenarioParseValid},
		{"清单解析空行注释跳过", scenarioParseBlankComment},
		{"清单解析非法行不中断", scenarioParseMalformedNoAbort},
		{"清单解析CRLF规范化", scenarioParseCRLF},
		{"哈希大小写不敏感", scenarioHashCaseInsensitive},
		{"验证一致", scenarioVerifyOK},
		{"验证不一致", scenarioVerifyMismatch},
		{"验证数据块缺失", scenarioVerifyMissing},
		{"验证非法行", scenarioVerifyMalformed},
		{"空内容数据块非缺失", scenarioEmptyBlobNotMissing},
		{"覆盖后验证反映最新", scenarioVerifyAfterOverwrite},
		{"批量验证四态混合", scenarioVerifyMixedBatch},
		{"清单生成", scenarioGenerate},
		{"清单生成未知算法", scenarioGenerateUnknownAlgo},
		{"清单生成保留顺序", scenarioGenerateOrder},
		{"生成后回环验证", scenarioGenerateThenVerify},
	}
	for _, sc := range scenarios {
		if err := sc.fn(); err != nil {
			return fmt.Errorf("%s: %w", sc.name, err)
		}
	}
	return nil
}

// scenarioKnownVectors checks MD5/SHA256 against published test vectors.
func scenarioKnownVectors() error {
	cases := []struct {
		algo manifest.Algorithm
		in   string
		want string
	}{
		{manifest.MD5, "", "d41d8cd98f00b204e9800998ecf8427e"},
		{manifest.MD5, "abc", "900150983cd24fb0d6963f7d28e17f72"},
		{manifest.SHA256, "", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"},
		{manifest.SHA256, "abc", "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"},
	}
	for _, c := range cases {
		got, err := manifest.Hash(c.algo, []byte(c.in))
		if err != nil {
			return fmt.Errorf("Hash(%s,%q): %w", c.algo, c.in, err)
		}
		if got != c.want {
			return fmt.Errorf("Hash(%s,%q) = %q want %q", c.algo, c.in, got, c.want)
		}
	}
	return nil
}

// scenarioEmptyContentHash ensures the empty-input digest is computed and is
// distinct for the two algorithms.
func scenarioEmptyContentHash() error {
	em, _ := manifest.EmptyHash(manifest.MD5)
	es, _ := manifest.EmptyHash(manifest.SHA256)
	if em != "d41d8cd98f00b204e9800998ecf8427e" {
		return fmt.Errorf("empty md5 = %q", em)
	}
	if len(es) != 64 {
		return fmt.Errorf("empty sha256 len = %d want 64", len(es))
	}
	if em == es {
		return errors.New("empty md5 and sha256 unexpectedly equal")
	}
	return nil
}

// scenarioLowercaseCanonical verifies every emitted hash is lowercase.
func scenarioLowercaseCanonical() error {
	for _, algo := range []manifest.Algorithm{manifest.MD5, manifest.SHA256} {
		h, _ := manifest.Hash(algo, []byte("MixedCASE Input 123"))
		for _, r := range h {
			if r >= 'A' && r <= 'Z' {
				return fmt.Errorf("%s hash contains uppercase: %q", algo, h)
			}
		}
	}
	return nil
}

// scenarioPutGet exercises basic store registration and retrieval.
func scenarioPutGet() error {
	s := store.New()
	if err := s.Put("a.bin", []byte("hello")); err != nil {
		return err
	}
	got, err := s.Get("a.bin")
	if err != nil {
		return err
	}
	if string(got) != "hello" {
		return fmt.Errorf("got %q want hello", got)
	}
	if _, err := s.Get("ghost"); !errors.Is(err, store.ErrNotFound) {
		return fmt.Errorf("Get(ghost): err=%v want ErrNotFound", err)
	}
	return nil
}

// scenarioOverwrite checks that re-registering a name replaces content.
func scenarioOverwrite() error {
	s := store.New()
	s.Put("a", []byte("v1"))
	s.Put("a", []byte("v2"))
	got, _ := s.Get("a")
	if string(got) != "v2" {
		return fmt.Errorf("after overwrite got %q want v2", got)
	}
	return nil
}

// scenarioDelete checks removal and that deleting twice fails.
func scenarioDelete() error {
	s := store.New()
	s.Put("a", []byte("x"))
	if err := s.Delete("a"); err != nil {
		return err
	}
	if err := s.Delete("a"); !errors.Is(err, store.ErrNotFound) {
		return fmt.Errorf("second delete: err=%v want ErrNotFound", err)
	}
	return nil
}

// scenarioListSorted checks that List returns names in ascending order without
// exposing content.
func scenarioListSorted() error {
	s := store.New()
	s.Put("z", []byte("1"))
	s.Put("a", []byte("2"))
	s.Put("m", []byte("3"))
	out := s.List()
	if len(out) != 3 {
		return fmt.Errorf("len = %d want 3", len(out))
	}
	want := []string{"a", "m", "z"}
	for i, w := range want {
		if out[i].Name != w {
			return fmt.Errorf("out[%d].Name = %q want %q", i, out[i].Name, w)
		}
		if out[i].Content != nil {
			return fmt.Errorf("List must not expose content, got %v", out[i].Content)
		}
	}
	return nil
}

// scenarioPutIsolation checks the store deep-copies on the way in.
func scenarioPutIsolation() error {
	s := store.New()
	content := []byte("orig")
	s.Put("a", content)
	content[0] = 'X'
	got, _ := s.Get("a")
	if string(got) != "orig" {
		return fmt.Errorf("stored content mutated via caller slice: %q", got)
	}
	return nil
}

// scenarioGetIsolation checks the store deep-copies on the way out.
func scenarioGetIsolation() error {
	s := store.New()
	s.Put("a", []byte("orig"))
	got1, _ := s.Get("a")
	got1[0] = 'X'
	got2, _ := s.Get("a")
	if string(got2) != "orig" {
		return fmt.Errorf("internal content mutated via returned slice: %q", got2)
	}
	return nil
}

// scenarioNameCharset verifies the restricted charset rejects bad names.
func scenarioNameCharset() error {
	s := store.New()
	bad := []string{"", "has space", "a  b", "a/b", "café", "a\nb"}
	for _, n := range bad {
		if err := s.Put(n, []byte("x")); !errors.Is(err, store.ErrInvalidName) {
			return fmt.Errorf("Put(%q): err=%v want ErrInvalidName", n, err)
		}
	}
	good := []string{"a", "A", "0", "a.b", "a-b", "a_b", "file.tar.gz"}
	for _, n := range good {
		if err := s.Put(n, []byte("x")); err != nil {
			return fmt.Errorf("Put(%q): unexpected error %v", n, err)
		}
	}
	return nil
}

// scenarioParseValid checks a well-formed manifest parses into entries.
func scenarioParseValid() error {
	text := "md5  d41d8cd98f00b204e9800998ecf8427e  empty\nsha256  e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855  empty\n"
	lines := manifest.Parse(text)
	if len(lines) != 2 {
		return fmt.Errorf("len = %d want 2", len(lines))
	}
	if lines[0].Entry == nil || lines[0].Entry.Algo != manifest.MD5 {
		return fmt.Errorf("first entry wrong: %+v", lines[0])
	}
	if lines[1].Entry == nil || lines[1].Entry.Algo != manifest.SHA256 {
		return fmt.Errorf("second entry wrong: %+v", lines[1])
	}
	// Uppercase hash input normalized to lowercase.
	if lines[0].Entry.Hash != "d41d8cd98f00b204e9800998ecf8427e" {
		return fmt.Errorf("hash not lowercased: %q", lines[0].Entry.Hash)
	}
	return nil
}

// scenarioParseBlankComment checks blank and comment lines are skipped, with
// line numbers reflecting the original text.
func scenarioParseBlankComment() error {
	text := "# header\nmd5  d41d8cd98f00b204e9800998ecf8427e  e\n\n# tail\n"
	lines := manifest.Parse(text)
	if len(lines) != 1 {
		return fmt.Errorf("len = %d want 1", len(lines))
	}
	if lines[0].LineNo != 2 {
		return fmt.Errorf("line number = %d want 2", lines[0].LineNo)
	}
	return nil
}

// scenarioParseMalformedNoAbort checks malformed lines are flagged but do not
// abort the batch.
func scenarioParseMalformedNoAbort() error {
	text := "md5  d41d8cd98f00b204e9800998ecf8427e  ok\n" +
		"md5  tooshort  bad\n" +
		"sha1  0000000000000000000000000000000000000000  bad2\n" +
		"md5  d41d8cd98f00b204e9800998ecf8427e  ok2\n"
	lines := manifest.Parse(text)
	if len(lines) != 4 {
		return fmt.Errorf("len = %d want 4", len(lines))
	}
	if lines[0].Err != nil || lines[0].Entry == nil {
		return fmt.Errorf("line 1 should parse: %+v", lines[0])
	}
	if lines[1].Err == nil || lines[2].Err == nil {
		return fmt.Errorf("lines 2,3 should be malformed")
	}
	if lines[3].Err != nil || lines[3].Entry == nil {
		return fmt.Errorf("line 4 should parse: %+v", lines[3])
	}
	return nil
}

// scenarioParseCRLF checks Windows line endings are normalized.
func scenarioParseCRLF() error {
	text := "md5  d41d8cd98f00b204e9800998ecf8427e  a\r\nmd5  d41d8cd98f00b204e9800998ecf8427e  b\r\n"
	lines := manifest.Parse(text)
	if len(lines) != 2 {
		return fmt.Errorf("len = %d want 2", len(lines))
	}
	if lines[0].Entry == nil || lines[0].Entry.Name != "a" {
		return fmt.Errorf("first entry wrong: %+v", lines[0])
	}
	if lines[1].Entry == nil || lines[1].Entry.Name != "b" {
		return fmt.Errorf("second entry wrong: %+v", lines[1])
	}
	return nil
}

// scenarioHashCaseInsensitive checks that an uppercase hash in a manifest still
// verifies as OK against lowercase actual.
func scenarioHashCaseInsensitive() error {
	s := store.New()
	s.Put("a", []byte("abc"))
	upper := strings.ToUpper("900150983cd24fb0d6963f7d28e17f72")
	text := "md5  " + upper + "  a\n"
	results := manifest.Verify(manifest.Parse(text), s.Lookup)
	if len(results) != 1 {
		return fmt.Errorf("len = %d want 1", len(results))
	}
	if results[0].Status != manifest.StatusOK {
		return fmt.Errorf("status = %s want ok", results[0].Status)
	}
	return nil
}

// scenarioVerifyOK checks a correct manifest verifies as OK.
func scenarioVerifyOK() error {
	s := store.New()
	s.Put("a", []byte("abc"))
	h, _ := manifest.Hash(manifest.MD5, []byte("abc"))
	text := "md5  " + h + "  a\n"
	results := manifest.Verify(manifest.Parse(text), s.Lookup)
	if results[0].Status != manifest.StatusOK {
		return fmt.Errorf("status = %s want ok", results[0].Status)
	}
	if results[0].Actual != h {
		return fmt.Errorf("actual = %q want %q", results[0].Actual, h)
	}
	return nil
}

// scenarioVerifyMismatch checks mismatched content is detected.
func scenarioVerifyMismatch() error {
	s := store.New()
	s.Put("a", []byte("xyz"))
	h, _ := manifest.Hash(manifest.MD5, []byte("abc"))
	text := "md5  " + h + "  a\n"
	results := manifest.Verify(manifest.Parse(text), s.Lookup)
	if results[0].Status != manifest.StatusMismatch {
		return fmt.Errorf("status = %s want mismatch", results[0].Status)
	}
	if results[0].Actual == results[0].Expected {
		return errors.New("actual equals expected despite different content")
	}
	return nil
}

// scenarioVerifyMissing checks an unregistered blob is reported missing.
func scenarioVerifyMissing() error {
	s := store.New()
	h, _ := manifest.Hash(manifest.MD5, []byte("abc"))
	text := "md5  " + h + "  ghost\n"
	results := manifest.Verify(manifest.Parse(text), s.Lookup)
	if results[0].Status != manifest.StatusMissing {
		return fmt.Errorf("status = %s want missing", results[0].Status)
	}
	return nil
}

// scenarioVerifyMalformed checks a malformed line yields MALFORMED without a
// lookup.
func scenarioVerifyMalformed() error {
	s := store.New()
	text := "md5  tooshort  e\n"
	results := manifest.Verify(manifest.Parse(text), s.Lookup)
	if results[0].Status != manifest.StatusMalformed {
		return fmt.Errorf("status = %s want malformed", results[0].Status)
	}
	if results[0].Actual != "" {
		return fmt.Errorf("malformed actual = %q want empty", results[0].Actual)
	}
	return nil
}

// scenarioEmptyBlobNotMissing checks an empty-content blob verifies OK against
// its canonical empty-input digest, and is not reported missing.
func scenarioEmptyBlobNotMissing() error {
	s := store.New()
	s.Put("empty", []byte{})
	emptyMD5, _ := manifest.Hash(manifest.MD5, nil)
	text := "md5  " + emptyMD5 + "  empty\n"
	results := manifest.Verify(manifest.Parse(text), s.Lookup)
	if results[0].Status != manifest.StatusOK {
		return fmt.Errorf("status = %s want ok (empty content is valid)", results[0].Status)
	}
	return nil
}

// scenarioVerifyAfterOverwrite checks verification reflects the latest content
// after a name is overwritten.
func scenarioVerifyAfterOverwrite() error {
	s := store.New()
	s.Put("a", []byte("v1"))
	hv1, _ := manifest.Hash(manifest.MD5, []byte("v1"))
	s.Put("a", []byte("v2")) // overwrite
	text := "md5  " + hv1 + "  a\n"
	results := manifest.Verify(manifest.Parse(text), s.Lookup)
	if results[0].Status != manifest.StatusMismatch {
		return fmt.Errorf("status = %s want mismatch after overwrite", results[0].Status)
	}
	return nil
}

// scenarioVerifyMixedBatch checks a manifest with all four statuses produces
// correct per-line and summary results.
func scenarioVerifyMixedBatch() error {
	s := store.New()
	s.Put("a", []byte("abc"))
	s.Put("b", []byte("xyz"))
	md5abc, _ := manifest.Hash(manifest.MD5, []byte("abc"))
	text := "md5  " + md5abc + "  a\n" + // ok
		"md5  " + md5abc + "  b\n" + // mismatch
		"md5  " + md5abc + "  ghost\n" + // missing
		"md5  badhash  bad\n" + // malformed
		"# comment\n" // skipped
	results := manifest.Verify(manifest.Parse(text), s.Lookup)
	if len(results) != 4 {
		return fmt.Errorf("len = %d want 4 (comment skipped)", len(results))
	}
	want := []manifest.Status{manifest.StatusOK, manifest.StatusMismatch, manifest.StatusMissing, manifest.StatusMalformed}
	for i, w := range want {
		if results[i].Status != w {
			return fmt.Errorf("result %d = %s want %s", i, results[i].Status, w)
		}
	}
	summary := manifest.Summarize(results)
	if summary.OK != 1 || summary.Mismatch != 1 || summary.Missing != 1 || summary.Malformed != 1 {
		return fmt.Errorf("summary = %+v want all 1", summary)
	}
	if summary.Total() != 4 {
		return fmt.Errorf("total = %d want 4", summary.Total())
	}
	return nil
}

// scenarioGenerate checks manifest generation produces correct lines and lists
// missing names.
func scenarioGenerate() error {
	s := store.New()
	s.Put("a", []byte("abc"))
	s.Put("empty", []byte{})
	body, missing, err := manifest.Generate(manifest.MD5, []string{"a", "empty", "ghost"}, s.Lookup)
	if err != nil {
		return err
	}
	if len(missing) != 1 || missing[0] != "ghost" {
		return fmt.Errorf("missing = %v want [ghost]", missing)
	}
	md5abc, _ := manifest.Hash(manifest.MD5, []byte("abc"))
	md5empty, _ := manifest.Hash(manifest.MD5, nil)
	want := "md5  " + md5abc + "  a\n" + "md5  " + md5empty + "  empty\n"
	if body != want {
		return fmt.Errorf("body = %q want %q", body, want)
	}
	return nil
}

// scenarioGenerateUnknownAlgo checks an unsupported algorithm is rejected.
func scenarioGenerateUnknownAlgo() error {
	s := store.New()
	if _, _, err := manifest.Generate(manifest.Algorithm("sha1"), []string{"a"}, s.Lookup); err == nil {
		return errors.New("Generate with unknown algo should error")
	}
	return nil
}

// scenarioGenerateOrder checks generated lines follow the input name order, not
// a sorted order.
func scenarioGenerateOrder() error {
	s := store.New()
	s.Put("z", []byte("z"))
	s.Put("a", []byte("a"))
	body, _, _ := manifest.Generate(manifest.SHA256, []string{"z", "a"}, s.Lookup)
	zIdx := strings.Index(body, "  z\n")
	aIdx := strings.Index(body, "  a\n")
	if zIdx < 0 || aIdx < 0 {
		return fmt.Errorf("body missing names: %q", body)
	}
	if zIdx > aIdx {
		return fmt.Errorf("order wrong: z should precede a")
	}
	return nil
}

// scenarioGenerateThenVerify checks the round-trip: generate a manifest, then
// verify it; all present blobs should be OK.
func scenarioGenerateThenVerify() error {
	s := store.New()
	s.Put("a", []byte("abc"))
	s.Put("b", []byte("xyz"))
	body, _, _ := manifest.Generate(manifest.SHA256, []string{"a", "b"}, s.Lookup)
	results := manifest.Verify(manifest.Parse(body), s.Lookup)
	if len(results) != 2 {
		return fmt.Errorf("len = %d want 2", len(results))
	}
	for i, r := range results {
		if r.Status != manifest.StatusOK {
			return fmt.Errorf("result %d = %s want ok (round-trip)", i, r.Status)
		}
	}
	return nil
}
