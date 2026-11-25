// Package htmlx extracts the structural signals we fingerprint from an HTML
// document. It is intentionally a tolerant tag scanner rather than a full
// DOM: we need to survive broken markup from partner site builders, and we
// only care about a fixed set of elements.
//
// Known blind spot: content that only exists after JavaScript runs is not
// seen here. That is why the scanner also (a) records external script
// origins, (b) runs the probe with several client profiles (see patrol), and
// (c) never lets a soft pass disable the interstitial. A page whose phishing
// behaviour is entirely client-side still fails the "new third-party script
// origin" and "interstitial shown" tests.
package htmlx

import (
	"net/url"
	"regexp"
	"sort"
	"strings"
)

// Doc is the subset of a page we extract.
type Doc struct {
	Title         string
	Forms         []Form
	MetaRefresh   []string
	Iframes       []string
	Scripts       []string // external script src
	InlineJS      []byte   // concatenated inline script text
	Links         []string // href targets (absolute where resolvable)
	Bases         []string
	BodyTextRunes int
}

type Form struct {
	Action      string
	Method      string
	HasPassword bool
	Inputs      []string // input types & names, for debugging
}

func Parse(body []byte, pageURL *url.URL) (*Doc, error) {
	d := &Doc{}
	toks := tokenize(body)
	base := pageURL
	for _, t := range toks {
		switch t.Name {
		case "base":
			if href := t.Attr("href"); href != "" {
				d.Bases = append(d.Bases, href)
				if u, err := pageURL.Parse(href); err == nil {
					base = u
				}
			}
		case "title":
			d.Title = strings.TrimSpace(collapse(t.Text))
		case "meta":
			if strings.EqualFold(t.Attr("http-equiv"), "refresh") {
				if target := parseRefresh(t.Attr("content")); target != "" {
					d.MetaRefresh = append(d.MetaRefresh, resolve(base, target))
				}
			}
		case "iframe", "frame":
			if src := t.Attr("src"); src != "" {
				d.Iframes = append(d.Iframes, resolve(base, src))
			}
		case "script":
			if src := t.Attr("src"); src != "" {
				d.Scripts = append(d.Scripts, resolve(base, src))
			}
			if t.Text != "" {
				d.InlineJS = append(d.InlineJS, '\n')
				d.InlineJS = append(d.InlineJS, t.Text...)
			}
		case "a":
			if href := t.Attr("href"); href != "" {
				if r := resolve(base, href); r != "" {
					d.Links = append(d.Links, r)
				}
			}
		case "form":
			f := Form{
				Action: resolve(base, t.Attr("action")),
				Method: strings.ToUpper(strings.TrimSpace(t.Attr("method"))),
			}
			if f.Method == "" {
				f.Method = "GET"
			}
			if f.Action == "" {
				f.Action = pageURL.String() // no action means "post to self"
			}
			// Collect inputs within this form: the tokenizer records them on
			// the form token when it can (see tokenize/attachInputs).
			for _, in := range t.Inputs {
				f.Inputs = append(f.Inputs, in.Type+"|"+in.Name)
				if strings.EqualFold(in.Type, "password") {
					f.HasPassword = true
				}
			}
			d.Forms = append(d.Forms, f)
		}
	}
	// Also catch password inputs that sit outside any <form> and are wired up
	// by script — a classic phishing-kit shape.
	for _, t := range toks {
		if t.Name == "input" && strings.EqualFold(t.Attr("type"), "password") {
			d.Forms = append(d.Forms, Form{Action: pageURL.String(), Method: "JS", HasPassword: true})
			break
		}
	}
	return d, nil
}

func collapse(s string) string { return strings.Join(strings.Fields(s), " ") }

var refreshRe = regexp.MustCompile(`(?i)^\s*(\d+(?:\.\d+)?)?\s*;?\s*(?:url\s*=\s*)?['"]?([^'"]*)['"]?\s*$`)

func parseRefresh(content string) string {
	m := refreshRe.FindStringSubmatch(content)
	if m == nil {
		return ""
	}
	return strings.TrimSpace(m[2])
}

// resolve makes raw absolute against base, returning "" for unusable values.
func resolve(base *url.URL, raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" || strings.HasPrefix(raw, "#") || strings.HasPrefix(raw, "javascript:") ||
		strings.HasPrefix(raw, "mailto:") || strings.HasPrefix(raw, "tel:") {
		return ""
	}
	u, err := base.Parse(raw)
	if err != nil {
		return ""
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return ""
	}
	return u.String()
}

// ---------------------------------------------------------------------------
// Tokenizer
//
// A deliberately small scanner: it emits start tags (with attributes), the
// text of <title> and <script> bodies, and ignores comments/doctypes/end
// tags. It is not a conforming HTML parser and does not need to be.
// ---------------------------------------------------------------------------

type inputTag struct{ Type, Name string }

type token struct {
	Name   string
	Attrs  map[string]string
	Text   string
	Inputs []inputTag // for <form>: inputs that appeared before its close tag
}

func (t token) Attr(name string) string { return t.Attrs[name] }

func tokenize(body []byte) []token {
	s := string(body)
	lower := strings.ToLower(s)
	var out []token
	// openForm indexes an element in out that is a <form> awaiting its inputs.
	openForm := -1
	i := 0
	for i < len(s) {
		lt := strings.IndexByte(s[i:], '<')
		if lt < 0 {
			break
		}
		i += lt
		if i+1 >= len(s) {
			break
		}
		// Comments and doctype.
		if strings.HasPrefix(s[i:], "<!--") {
			if end := strings.Index(s[i+4:], "-->"); end >= 0 {
				i = i + 4 + end + 3
			} else {
				break
			}
			continue
		}
		if strings.HasPrefix(s[i:], "<!") || strings.HasPrefix(s[i:], "<?") {
			if end := strings.IndexByte(s[i:], '>'); end >= 0 {
				i += end + 1
			} else {
				break
			}
			continue
		}
		// End tag.
		if s[i+1] == '/' {
			end := strings.IndexByte(s[i:], '>')
			if end < 0 {
				break
			}
			name := strings.ToLower(strings.TrimSpace(s[i+2 : i+end]))
			if name == "form" {
				openForm = -1
			}
			i += end + 1
			continue
		}
		// Start tag.
		end := findTagEnd(s, i)
		if end < 0 {
			break
		}
		raw := s[i : end+1]
		name, attrs, selfClose := parseStartTag(raw)
		i = end + 1
		if name == "" {
			continue
		}

		tk := token{Name: name, Attrs: attrs}
		switch name {
		case "title":
			if j := strings.Index(lower[i:], "</title"); j >= 0 {
				tk.Text = s[i : i+j]
				i = i + j
			}
		case "script":
			// Capture inline body only when there is no src.
			if attrs["src"] == "" {
				if j := strings.Index(lower[i:], "</script"); j >= 0 {
					tk.Text = s[i : i+j]
					i = i + j
				}
			}
		case "input":
			if openForm >= 0 {
				out[openForm].Inputs = append(out[openForm].Inputs, inputTag{
					Type: attrs["type"], Name: attrs["name"],
				})
			}
		case "textarea", "select":
			// skip their contents up to close tag
			if j := strings.Index(lower[i:], "</"+name); j >= 0 {
				i = i + j
			}
		case "form":
			if !selfClose {
				openForm = len(out)
			}
		}
		out = append(out, tk)
	}
	return out
}

// findTagEnd finds the '>' that closes a start tag, respecting quoted
// attribute values so a '>' inside an attribute does not end it early.
func findTagEnd(s string, start int) int {
	var quote byte
	for i := start + 1; i < len(s); i++ {
		c := s[i]
		switch {
		case quote != 0:
			if c == quote {
				quote = 0
			}
		case c == '"' || c == '\'':
			quote = c
		case c == '>':
			return i
		}
	}
	return -1
}

func parseStartTag(raw string) (name string, attrs map[string]string, selfClose bool) {
	attrs = make(map[string]string)
	// Strip < and >
	inner := strings.TrimSuffix(strings.TrimPrefix(raw, "<"), ">")
	if strings.HasSuffix(strings.TrimSpace(inner), "/") {
		selfClose = true
		inner = strings.TrimSuffix(strings.TrimSpace(inner), "/")
	}
	// Read name.
	j := 0
	for j < len(inner) && !isSpace(inner[j]) {
		j++
	}
	name = strings.ToLower(inner[:j])
	rest := inner[j:]

	k := 0
	for k < len(rest) {
		for k < len(rest) && isSpace(rest[k]) {
			k++
		}
		if k >= len(rest) {
			break
		}
		// attribute name
		ks := k
		for k < len(rest) && rest[k] != '=' && !isSpace(rest[k]) {
			k++
		}
		key := strings.ToLower(rest[ks:k])
		if key == "" {
			k++
			continue
		}
		// optional =value
		for k < len(rest) && isSpace(rest[k]) {
			k++
		}
		val := ""
		if k < len(rest) && rest[k] == '=' {
			k++
			for k < len(rest) && isSpace(rest[k]) {
				k++
			}
			if k < len(rest) && (rest[k] == '"' || rest[k] == '\'') {
				q := rest[k]
				k++
				vs := k
				for k < len(rest) && rest[k] != q {
					k++
				}
				val = rest[vs:k]
				if k < len(rest) {
					k++
				}
			} else {
				vs := k
				for k < len(rest) && !isSpace(rest[k]) {
					k++
				}
				val = rest[vs:k]
			}
		}
		if _, seen := attrs[key]; !seen {
			attrs[key] = val
		}
	}
	return name, attrs, selfClose
}

func isSpace(c byte) bool {
	return c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\f'
}

// ---------------------------------------------------------------------------
// JS redirect heuristics
// ---------------------------------------------------------------------------

var jsRedirectPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)location\.(?:href|replace|assign)\s*\(\s*['"]([^'"]+)['"]`),
	regexp.MustCompile(`(?i)location\.(?:href)?\s*=\s*['"]([^'"]+)['"]`),
	regexp.MustCompile(`(?i)window\.open\s*\(\s*['"]([^'"]+)['"]`),
	regexp.MustCompile(`(?i)document\.location\s*=\s*['"]([^'"]+)['"]`),
	regexp.MustCompile(`(?i)top\.location\s*=\s*['"]([^'"]+)['"]`),
	regexp.MustCompile(`(?i)meta\[['"]?refresh`),
}

// JSRedirects pulls literal navigation targets out of inline script. This is
// shallow on purpose: obfuscated or computed targets are exactly the sort of
// thing that should keep a link on the interstitial, and the set-difference
// drift check will catch them appearing later.
func JSRedirects(inline []byte, pageURL *url.URL) []string {
	if len(inline) == 0 {
		return nil
	}
	s := string(inline)
	var out []string
	seen := map[string]bool{}
	for _, re := range jsRedirectPatterns {
		for _, m := range re.FindAllStringSubmatch(s, -1) {
			if len(m) < 2 || m[1] == "" {
				continue
			}
			r := resolve(pageURL, m[1])
			if r == "" || seen[r] {
				continue
			}
			seen[r] = true
			out = append(out, r)
		}
	}
	sort.Strings(out)
	return out
}

// TextRunes counts a very rough proxy for visible text volume, used to spot
// a page that suddenly becomes an almost-empty credential form.
func TextRunes(body []byte) int {
	s := string(body)
	n := 0
	in := false
	for i := 0; i < len(s); i++ {
		switch {
		case s[i] == '<':
			in = true
		case s[i] == '>':
			in = false
		case !in && s[i] > ' ':
			n++
		}
	}
	return n
}
