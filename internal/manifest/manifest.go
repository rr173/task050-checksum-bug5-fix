// Package manifest implements the checksum computation, manifest parsing, and
// batch verification logic for the checksum service.
//
// A manifest is a text document where each non-blank, non-comment line has the
// fixed shape:
//
//	<algorithm>  <hexhash>  <name>
//
// The three fields are separated by exactly two spaces. The algorithm must be
// one of the supported algorithms (md5, sha256) compared case-insensitively;
// the hex hash must be lowercase-canonical after normalization and its length
// must match the algorithm (md5 = 32 hex chars, sha256 = 64). Names are opaque
// blob identifiers looked up in the store; the manifest layer does not police
// their charset.
//
// Verification produces one result per input line (blank and comment lines
// aside), classifying each as OK, MISMATCH, MISSING, or MALFORMED. A single
// malformed line never aborts the batch.
package manifest

import (
	"crypto/md5"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
)

// Algorithm is a supported checksum algorithm. String values are the
// lowercase-canonical names used in manifests and in service output.
type Algorithm string

const (
	MD5    Algorithm = "md5"
	SHA256 Algorithm = "sha256"
)

// ErrUnknownAlgorithm is returned when an algorithm string is not supported.
var ErrUnknownAlgorithm = errors.New("manifest: unknown algorithm")

// SupportedAlgorithms lists every supported algorithm in canonical order.
var SupportedAlgorithms = []Algorithm{MD5, SHA256}

// ParseAlgorithm normalizes an algorithm name (trimmed, lowercased) and returns
// the canonical Algorithm, or ErrUnknownAlgorithm if it is not supported.
func ParseAlgorithm(s string) (Algorithm, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "md5":
		return MD5, nil
	case "sha256":
		return SHA256, nil
	default:
		return "", ErrUnknownAlgorithm
	}
}

// HexLength reports the canonical hex digest length for the algorithm.
func (a Algorithm) HexLength() int {
	switch a {
	case MD5:
		return 32
	case SHA256:
		return 64
	default:
		return 0
	}
}

// Hash returns the lowercase-hex checksum of content under the given algorithm.
// It does not allocate beyond what hex.EncodeToString requires. An unsupported
// algorithm returns ErrUnknownAlgorithm.
func Hash(a Algorithm, content []byte) (string, error) {
	switch a {
	case MD5:
		sum := md5.Sum(content)
		return hex.EncodeToString(sum[:]), nil
	case SHA256:
		sum := sha256.Sum256(content)
		return hex.EncodeToString(sum[:]), nil
	default:
		return "", ErrUnknownAlgorithm
	}
}

// EmptyHash returns the lowercase-hex checksum of empty content under the given
// algorithm. It is the canonical "empty-input" digest and must never be treated
// as "missing".
func EmptyHash(a Algorithm) (string, error) {
	return Hash(a, nil)
}

// FieldSep is the exact separator between fields on a manifest line.
const FieldSep = "  "

// CommentPrefix marks a line as a comment; comment lines are skipped silently.
const CommentPrefix = "#"

// Entry is a successfully parsed manifest line.
type Entry struct {
	Algo Algorithm
	Hash string // lowercased, length already validated against Algo
	Name string
}

// ParseError describes a non-blank, non-comment line that failed to parse.
type ParseError struct {
	LineNo int    // 1-based line index in the input text
	Line   string // the offending raw line
	Reason string // why it was rejected
}

// ParsedLine is the outcome of parsing a single manifest line. For a blank or
// comment line both Entry and Err are nil (the line produces no verification
// result). For a malformed line, Err is set. For a valid line, Entry is set.
type ParsedLine struct {
	LineNo int
	Entry  *Entry     // non-nil if the line parsed successfully
	Err    *ParseError // non-nil if the line was malformed
}

// IsBlank reports whether the line is blank or a comment and should be skipped.
func IsBlank(line string) bool {
	trimmed := strings.TrimSpace(line)
	return trimmed == "" || strings.HasPrefix(trimmed, CommentPrefix)
}

// Parse splits manifest text into parsed lines. Blank and comment lines are
// skipped (they yield no ParsedLine). Each remaining line is parsed into an
// Entry or recorded as a ParseError. Line numbers are 1-based and reflect the
// original input text so callers can map results back to source lines.
func Parse(text string) []ParsedLine {
	if text == "" {
		return nil
	}
	// Normalize a trailing "\r\n" / lone "\r" so manifests pasted from
	// Windows-style files parse the same as Unix ones. We do not strip other
	// carriage returns inside content.
	text = strings.ReplaceAll(text, "\r\n", "\n")
	text = strings.ReplaceAll(text, "\r", "\n")
	lines := strings.Split(text, "\n")
	out := make([]ParsedLine, 0, len(lines))
	for i, raw := range lines {
		lineNo := i + 1
		if IsBlank(raw) {
			continue
		}
		entry, perr := parseLine(raw)
		if perr != nil {
			out = append(out, ParsedLine{LineNo: lineNo, Err: perr})
			continue
		}
		out = append(out, ParsedLine{LineNo: lineNo, Entry: entry})
	}
	return out
}

// parseLine parses one non-blank, non-comment line into an Entry or a ParseError.
func parseLine(line string) (*Entry, *ParseError) {
	parts := strings.Split(line, FieldSep)
	if len(parts) != 3 {
		return nil, &ParseError{Line: line, Reason: "expected exactly 3 fields separated by two spaces"}
	}
	algoStr, hashStr, nameStr := parts[0], parts[1], parts[2]
	algo, err := ParseAlgorithm(algoStr)
	if err != nil {
		return nil, &ParseError{Line: line, Reason: "unsupported algorithm: " + algoStr}
	}
	hash := strings.ToLower(strings.TrimSpace(hashStr))
	if !isHex(hash) || len(hash) != algo.HexLength() {
		return nil, &ParseError{Line: line, Reason: "hash must be " + algoStr + " hex of " + itoa(algo.HexLength()) + " chars"}
	}
	name := strings.TrimSpace(nameStr)
	if name == "" {
		return nil, &ParseError{Line: line, Reason: "empty name"}
	}
	return &Entry{Algo: algo, Hash: hash, Name: name}, nil
}

// isHex reports whether s is a non-empty lowercase-or-uppercase hex string.
func isHex(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return true
}

// itoa is a tiny, allocation-free int to string used in parse error messages to
// avoid importing strconv solely for this.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}

// Status is the verification outcome for one manifest line.
type Status string

const (
	StatusOK        Status = "ok"
	StatusMismatch  Status = "mismatch"
	StatusMissing   Status = "missing"
	StatusMalformed Status = "malformed"
)

// Result is the verification outcome for one parsed line. Line numbers echo the
// original manifest text. For a malformed line, Entry is the parse error (and
// Actual/Expected are empty). For an OK or MISMATCH line, Actual holds the
// computed checksum; Expected holds the manifest-declared value.
type Result struct {
	LineNo   int
	Status   Status
	Name     string
	Algo     Algorithm
	Expected string
	Actual   string
	Reason   string // populated for MALFORMED lines
}

// Summary tallies verification outcomes across all lines of a manifest.
type Summary struct {
	OK        int
	Mismatch  int
	Missing   int
	Malformed int
}

// Total returns the total number of verified (non-blank, non-comment) lines.
func (s Summary) Total() int { return s.OK + s.Mismatch + s.Missing + s.Malformed }

// Lookup is the blob-lookup contract used by Verify: given a name, it returns
// the blob's current content and true, or false if no such blob is registered.
// The returned slice is used read-only by Verify.
type Lookup func(name string) (content []byte, ok bool)

// Verify verifies a slice of parsed lines against the provided blob lookup. It
// returns one Result per parsed line, in order. Malformed lines (parse errors)
// yield MALFORMED results without invoking the lookup. Valid lines look up the
// blob; a missing blob yields MISSING, a present blob whose computed checksum
// equals the declared hash (case-insensitively) yields OK, and otherwise yields
// MISMATCH with the actual checksum populated.
func Verify(lines []ParsedLine, lookup Lookup) []Result {
	out := make([]Result, 0, len(lines))
	for _, pl := range lines {
		if pl.Err != nil {
			out = append(out, Result{
				LineNo: pl.LineNo,
				Status: StatusMalformed,
				Reason: pl.Err.Reason,
			})
			continue
		}
		e := pl.Entry
		content, ok := lookup(e.Name)
		if !ok {
			out = append(out, Result{
				LineNo:   pl.LineNo,
				Status:   StatusMissing,
				Name:     e.Name,
				Algo:     e.Algo,
				Expected: e.Hash,
			})
			continue
		}
		actual, _ := Hash(e.Algo, content) // algo already validated by Parse
		if strings.EqualFold(actual, e.Hash) {
			out = append(out, Result{
				LineNo:   pl.LineNo,
				Status:   StatusOK,
				Name:     e.Name,
				Algo:     e.Algo,
				Expected: e.Hash,
				Actual:   actual,
			})
		} else {
			out = append(out, Result{
				LineNo:   pl.LineNo,
				Status:   StatusMismatch,
				Name:     e.Name,
				Algo:     e.Algo,
				Expected: e.Hash,
				Actual:   actual,
			})
		}
	}
	return out
}

// Summarize tallies a slice of results into a Summary.
func Summarize(results []Result) Summary {
	var s Summary
	for _, r := range results {
		switch r.Status {
		case StatusOK:
			s.OK++
		case StatusMismatch:
			s.Mismatch++
		case StatusMissing:
			s.Missing++
		case StatusMalformed:
			s.Malformed++
		}
	}
	return s
}

// Generate builds manifest text for the given algorithm and ordered names. It
// returns the manifest body, the list of names for which the lookup reported
// no blob (missing), and an error if the algorithm is unsupported. Each line is
// "<algo>  <hash>  <name>\n"; hashes are the lowercase-canonical checksums of
// each blob's current content.
func Generate(algo Algorithm, names []string, lookup Lookup) (string, []string, error) {
	if algo != MD5 && algo != SHA256 {
		return "", nil, ErrUnknownAlgorithm
	}
	var b strings.Builder
	missing := make([]string, 0)
	for _, name := range names {
		content, ok := lookup(name)
		if !ok {
			missing = append(missing, name)
			continue
		}
		hash, _ := Hash(algo, content)
		b.WriteString(string(algo))
		b.WriteString(FieldSep)
		b.WriteString(hash)
		b.WriteString(FieldSep)
		b.WriteString(name)
		b.WriteByte('\n')
	}
	return b.String(), missing, nil
}
