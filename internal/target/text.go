package target

import (
	"context"
	"fmt"
	"strings"
	"time"
)

// stripHTML reduces a markup reply to the text a judge can match against,
// keeping script and style contents out of it.
//
// It is deliberately crude. It is a text extraction, not a parser, and the
// reply is evidence rather than something to re-render.
func stripHTML(s string) string {
	var b strings.Builder
	b.Grow(len(s))

	skipUntil := "" // non-empty while inside <script> or <style>
	for i := 0; i < len(s); {
		if s[i] != '<' {
			if skipUntil == "" {
				if s[i] == '&' {
					if decoded, n := decodeEntity(s[i:]); n > 0 {
						b.WriteString(decoded)
						i += n
						continue
					}
				}
				b.WriteByte(s[i])
			}
			i++
			continue
		}

		gt := strings.IndexByte(s[i:], '>')
		if gt < 0 { // an unterminated '<' is just text
			if skipUntil == "" {
				b.WriteString(s[i:])
			}
			break
		}
		gt += i

		name, closing := tagAt(s, i, gt)
		switch {
		case name == "":
			// not a tag we recognise; keep the text if we are not skipping
			if skipUntil == "" {
				b.WriteString(s[i : gt+1])
			}
		case name == "script" || name == "style":
			if closing && name == skipUntil {
				skipUntil = ""
			} else if !closing && skipUntil == "" {
				skipUntil = name
			}
		case name == "br" || name == "p" || name == "div" || name == "li":
			if skipUntil == "" {
				b.WriteByte('\n')
			}
		default:
			if skipUntil == "" {
				b.WriteByte(' ')
			}
		}
		i = gt + 1
	}

	return collapse(b.String())
}

// tagAt returns the lowercased tag name in s[start:gt] and whether it is a
// closing tag.
func tagAt(s string, start, gt int) (name string, closing bool) {
	body := s[start+1 : gt]
	if strings.HasPrefix(body, "/") {
		closing, body = true, body[1:]
	}
	body = strings.TrimLeft(body, "/ \t\r\n")
	if end := strings.IndexAny(body, " \t\r\n/"); end >= 0 {
		body = body[:end]
	}
	return strings.ToLower(body), closing
}

// decodeEntity decodes the handful of entities that appear in chat replies and
// returns the number of bytes consumed.
func decodeEntity(s string) (string, int) {
	for _, ent := range [][2]string{
		{"&nbsp;", " "}, {"&lt;", "<"}, {"&gt;", ">"}, {"&quot;", "\""},
		{"&#39;", "'"}, {"&apos;", "'"}, {"&amp;", "&"}, {"&hellip;", "…"},
	} {
		if strings.HasPrefix(s, ent[0]) {
			return ent[1], len(ent[0])
		}
	}
	if strings.HasPrefix(s, "&#") {
		end := strings.IndexByte(s, ';')
		if end > 2 && end < 9 {
			if n, err := atoi(s[2:end]); err == nil {
				return string(rune(n)), end + 1
			}
		}
	}
	return "", 0
}

// collapse trims each line and squeezes runs of whitespace.
func collapse(s string) string {
	lines := strings.Split(s, "\n")
	out := lines[:0]
	for _, l := range lines {
		l = strings.TrimSpace(l)
		if l != "" {
			out = append(out, l)
		}
	}
	return strings.Join(out, "\n")
}

// maxReply bounds how much extracted text is handed to the judge. Markers live
// near the start of an answer far more often than the end, and an unbounded
// buffer would let a chatty target dominate the transcript.
const maxReply = 16 << 10

func clip(s string) string {
	if len(s) <= maxReply {
		return s
	}
	return s[:maxReply] + "\n[truncated]"
}

// echoTarget answers from a fixed script. It exists so the scanner can be
// exercised end to end — in CI, in a test, or on a laptop — without a live
// endpoint, and so a user can see the shape of a finding before pointing the
// tool at anything.
type echoTarget struct {
	script []string
	i      int
}

// NewEcho builds a target that replies with the given lines in order and
// repeats the last one once exhausted.
func NewEcho(lines []string) Target { return &echoTarget{script: lines} }

func (e *echoTarget) Send(_ context.Context, prompt string) (Reply, error) {
	start := time.Now()

	text := fmt.Sprintf("echo: %s", prompt)
	if len(e.script) > 0 {
		if e.i >= len(e.script) {
			text = e.script[len(e.script)-1]
		} else {
			text = e.script[e.i]
			e.i++
		}
	}
	return Reply{Text: clip(text), Latency: time.Since(start)}, nil
}

func (e *echoTarget) Describe() string { return "echo (built-in, no network)" }

func init() { Register("echo", func(Config) (Target, error) { return NewEcho(nil), nil }) }
