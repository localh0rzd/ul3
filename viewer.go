package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/csv"
	"html/template"
	"io"
	"log/slog"
	"net/http"
	"path"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/yuin/goldmark"
	"github.com/yuin/goldmark/extension"
)

// markdown renders GFM (tables, strikethrough, task lists, autolinks). It must
// never get html.WithUnsafe(): raw HTML stays escaped/omitted and goldmark
// empties javascript:, vbscript:, file: and non-image data: link targets.
var markdown = goldmark.New(goldmark.WithExtensions(extension.GFM))

func isMarkdown(name string) bool {
	ext := strings.ToLower(path.Ext(name))
	return ext == ".md" || ext == ".markdown"
}

// goldmark is quadratic on adversarial input (e.g. ">" repeated: ~0.8 s at
// 32 KiB, ~2.7 s at 64 KiB, ~39 s at 256 KiB), so rendering is limited in
// size, in concurrency and in the time a visitor waits. Beyond that the viewer
// shows the source only.
const (
	markdownMaxBytes = 64 << 10
	markdownTimeout  = 2 * time.Second
)

var markdownSlots = make(chan struct{}, 2)

// renderMarkdown returns "" if the text is too large, the renderer is busy,
// rendering fails or takes too long. A render that outlives the timeout keeps
// its slot until it finishes, so at most two renders ever burn CPU.
func renderMarkdown(src string) template.HTML {
	if len(src) > markdownMaxBytes {
		return ""
	}
	select {
	case markdownSlots <- struct{}{}:
	default:
		return ""
	}
	done := make(chan template.HTML, 1)
	go func() {
		defer func() { <-markdownSlots }()
		var buf bytes.Buffer
		if err := markdown.Convert([]byte(src), &buf); err != nil {
			done <- ""
			return
		}
		done <- template.HTML(buf.String()) // #nosec: goldmark escapes raw HTML (no WithUnsafe)
	}()
	select {
	case h := <-done:
		return h
	case <-time.After(markdownTimeout):
		return ""
	}
}

// textExts lists the extensions shown in the text viewer. The list is built in
// (the container image has no /etc/mime.types) and mirrors the "code" and
// "text" kinds of web/filetypes.js plus csv/tsv. HTML and SVG are left out on
// purpose: HTML always downloads (see alwaysDownload), SVG is shown as image.
var textExts = func() map[string]bool {
	m := map[string]bool{}
	for _, e := range strings.Fields(`js mjs cjs ts tsx jsx py go rs c h cpp hpp cc cs java kt kts swift rb php pl lua sql
		css scss sass less json jsonc xml yaml yml toml ini conf cfg env vue svelte dart r scala zig nim ex exs erl hs ml clj
		sh bash zsh fish makefile dockerfile gradle lock proto graphql gql tf tfvars hcl nix
		gitignore dockerignore editorconfig gitattributes npmrc bashrc zshrc profile properties adoc asciidoc tex bat cmd ps1 txt text md markdown log rst nfo srt vtt ics vcf diff patch csv tsv`) {
		m[e] = true
	}
	return m
}()

// textBasenames are extensionless (or special) names shown as text.
var textBasenames = map[string]bool{
	"makefile": true, "dockerfile": true, "containerfile": true, "jenkinsfile": true, "procfile": true,
	"vagrantfile": true, "gemfile": true, "rakefile": true, "license": true, "readme": true,
	"changelog": true, "go.mod": true, "go.sum": true,
}

// isTextFile reports whether a stored file is shown in the text viewer.
func isTextFile(name string) bool {
	base := strings.ToLower(path.Base(name))
	if textBasenames[base] || strings.HasPrefix(base, "dockerfile.") || strings.HasPrefix(base, "containerfile.") {
		return true
	}
	return textExts[strings.TrimPrefix(path.Ext(base), ".")]
}

const (
	viewerMaxBytes = 1 << 20 // larger files show only their beginning
	viewerMaxLines = 20000
	viewerMaxRows  = 5000
	viewerMaxCopy  = 10 << 20 // above this the copy button is hidden
)

// The viewer's only script copies the file and switches between table and
// text; its hash is the sole script source in the CSP.
const viewerScript = `(function(){
var m=document.getElementById("msg"),t;
function say(s){m.textContent=s;clearTimeout(t);t=setTimeout(function(){m.textContent=""},2500)}
function fallback(s){var a=document.createElement("textarea");a.value=s;a.style.position="fixed";a.style.opacity="0";document.body.appendChild(a);a.select();var ok=false;try{ok=document.execCommand("copy")}catch(e){}a.remove();return ok}
var c=document.getElementById("copy");if(c){
function legacy(){return fetch(c.dataset.src,{credentials:"same-origin"}).then(function(r){if(!r.ok)throw 0;return r.text()}).then(function(s){
if(navigator.clipboard&&window.isSecureContext)return navigator.clipboard.writeText(s).then(function(){return true},function(){return fallback(s)});
return fallback(s)})}
function done(ok){say(ok?"In die Zwischenablage kopiert":"Kopieren nicht möglich")}
c.addEventListener("click",function(){
if(window.ClipboardItem&&navigator.clipboard&&navigator.clipboard.write&&window.isSecureContext){
var p=fetch(c.dataset.src,{credentials:"same-origin"}).then(function(r){if(!r.ok)throw 0;return r.blob()}).then(function(b){return new Blob([b],{type:"text/plain"})});
navigator.clipboard.write([new ClipboardItem({"text/plain":p})]).then(function(){done(true)},function(){legacy().then(done,function(){done(false)})});
return}
legacy().then(done,function(){done(false)})})}
var v=document.querySelectorAll("[data-view]");
for(var i=0;i<v.length;i++)v[i].addEventListener("click",function(){
for(var j=0;j<v.length;j++){var on=v[j]===this;v[j].setAttribute("aria-pressed",on);document.getElementById(v[j].dataset.view).hidden=!on}})
})();`

var viewerCSP = "default-src 'none'; script-src 'sha256-" + scriptHash(viewerScript) + "'; connect-src 'self'; img-src 'self' data:; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"

func scriptHash(s string) string {
	sum := sha256.Sum256([]byte(s))
	return base64.StdEncoding.EncodeToString(sum[:])
}

var viewerTmpl = template.Must(template.New("viewer").Parse(`<!doctype html>
<html lang="de">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex, nofollow">
<meta name="color-scheme" content="light dark">
<title>{{.Name}}</title>
<style>
:root { --bg: #f4f5f7; --card: #fff; --text: #1d2330; --muted: #6b7280; --border: #e3e6ea; --accent: #2f6fde; --head: #f0f2f5; --ok: #1a7f37; }
@media (prefers-color-scheme: dark) {
	:root { --bg: #12151b; --card: #1b1f27; --text: #e6e8ec; --muted: #9aa3b2; --border: #2b313c; --accent: #5b8ff0; --head: #232831; --ok: #4ac26b; }
}
* { box-sizing: border-box; }
body { margin: 0; padding: 16px; background: var(--bg); color: var(--text); font: 15px/1.5 system-ui, -apple-system, "Segoe UI", Roboto, sans-serif; }
main { width: 100%; max-width: 1200px; margin: 0 auto; background: var(--card); border: 1px solid var(--border); border-radius: 12px; overflow: hidden; }
.bar { display: flex; flex-wrap: wrap; align-items: center; gap: 8px 12px; padding: 10px 14px; background: var(--head); border-bottom: 1px solid var(--border); }
.name { flex: 1 1 12em; min-width: 0; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; font-weight: 600; }
.meta { color: var(--muted); font-size: .9em; white-space: nowrap; }
.btns { position: relative; display: flex; flex-wrap: wrap; gap: 6px; align-items: center; }
.btn { font: inherit; font-size: .9em; padding: 4px 12px; border-radius: 8px; border: 1px solid var(--border); background: var(--card); color: var(--text); text-decoration: none; cursor: pointer; }
.btn:hover { border-color: var(--accent); color: var(--accent); }
.btn.sq { display: inline-flex; padding: 4px 7px; }
.btn svg { width: 1.25em; height: 1.25em; margin: .125em 0; fill: currentColor; } /* as tall as a text line */
.btn[aria-pressed="true"] { background: var(--accent); border-color: var(--accent); color: #fff; }
/* tooltip under the buttons, so showing it never shifts the layout */
#msg { position: absolute; top: calc(100% + 6px); right: 0; z-index: 1; white-space: nowrap; pointer-events: none; padding: 4px 10px; border-radius: 6px; font-size: .85em; background: var(--text); color: var(--card); box-shadow: 0 2px 8px rgba(0,0,0,.2); }
#msg:empty { display: none; }
.note { margin: 0; padding: 8px 14px; border-bottom: 1px solid var(--border); color: var(--muted); font-size: .9em; }
.scroll { overflow-x: auto; }
.code { margin: 0; padding: 8px 0; counter-reset: n; font: 13px/1.5 ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; tab-size: 4; width: max-content; min-width: 100%; }
.l { display: block; padding-right: 14px; white-space: pre; min-height: 1.5em; }
.l::before { counter-increment: n; content: counter(n); display: inline-block; min-width: 5ch; margin-right: 14px; padding-left: 10px; text-align: right; color: var(--muted); user-select: none; -webkit-user-select: none; }
table { border-collapse: collapse; font-size: 13px; }
th, td { border: 1px solid var(--border); padding: 3px 10px; text-align: left; white-space: pre; vertical-align: top; }
th { background: var(--head); position: sticky; top: 0; }
#tbl { max-height: 75vh; overflow: auto; }
tbody { counter-reset: r; }
tbody tr { counter-increment: r; }
td.n, th.n { color: var(--muted); text-align: right; user-select: none; -webkit-user-select: none; }
td.n::before { content: counter(r); }
.md { padding: 16px 24px; overflow-wrap: anywhere; line-height: 1.6; }
.md > :first-child { margin-top: 0; } .md > :last-child { margin-bottom: 0; }
.md h1, .md h2 { padding-bottom: .3em; border-bottom: 1px solid var(--border); }
.md h1, .md h2, .md h3, .md h4 { margin: 1.4em 0 .6em; line-height: 1.25; }
.md a { color: var(--accent); }
.md img { max-width: 100%; }
.md code { font: .9em ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; background: var(--head); padding: .15em .35em; border-radius: 6px; }
.md pre { overflow-x: auto; padding: 12px 14px; background: var(--head); border-radius: 8px; }
.md pre code { padding: 0; background: none; }
.md blockquote { margin: 1em 0; padding: 0 1em; color: var(--muted); border-left: 4px solid var(--border); }
.md table { display: block; overflow-x: auto; max-width: 100%; }
.md th, .md td { white-space: normal; }
.md hr { border: 0; border-top: 1px solid var(--border); }
.md li > input { margin-right: .4em; }
.empty { padding: 16px 14px; color: var(--muted); }
</style>
</head>
<body>
<main>
<div class="bar">
<span class="name" title="{{.Name}}">{{.Name}}</span>
<span class="meta">{{.Size}}{{if .Lines}} · {{.Lines}} {{if eq .Lines "1"}}Zeile{{else}}Zeilen{{end}}{{end}}</span>
<span class="btns">
{{if .Rendered}}<button type="button" class="btn" data-view="md" aria-pressed="true">Gerendert</button><button type="button" class="btn" data-view="txt" aria-pressed="false">Quelltext</button>{{end}}
{{if .Table}}<button type="button" class="btn" data-view="tbl" aria-pressed="true">Tabelle</button><button type="button" class="btn" data-view="txt" aria-pressed="false">Text</button>{{end}}
<a class="btn" href="{{.Raw}}">Raw</a>
{{if .CanCopy}}<button type="button" class="btn sq" id="copy" data-src="{{.Raw}}" title="Kopieren" aria-label="Kopieren"><svg viewBox="0 0 24 24" aria-hidden="true"><path d="M16 1H4a2 2 0 0 0-2 2v14h2V3h12V1zm3 4H8a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h11a2 2 0 0 0 2-2V7a2 2 0 0 0-2-2zm0 16H8V7h11v14z"/></svg></button>{{end}}
<a class="btn sq" href="{{.Download}}" download="{{.Name}}" title="Herunterladen" aria-label="Herunterladen"><svg viewBox="0 0 24 24" aria-hidden="true"><path d="M11 3h2v9.2l3.3-3.3 1.4 1.4L12 16l-5.7-5.7 1.4-1.4 3.3 3.3V3zM5 18h14v3H5v-3z"/></svg></a>
<span id="msg" role="status"></span>
</span>
</div>
{{if .Notice}}<p class="note">{{.Notice}}</p>{{end}}
{{if .Rendered}}<div class="md" id="md">{{.Rendered}}</div>{{end}}
{{if .Table}}<div class="scroll" id="tbl"><table>
{{range $i, $r := .Table}}{{if eq $i 0}}<thead><tr><th class="n"></th>{{range $r}}<th>{{.}}</th>{{end}}</tr></thead><tbody>{{else}}<tr><td class="n"></td>{{range $r}}<td>{{.}}</td>{{end}}</tr>{{end}}{{end}}</tbody>
</table></div>{{end}}
<div class="scroll" id="txt"{{if or .Table .Rendered}} hidden{{end}}>{{if .Text}}<div class="code">{{range .Text}}<span class="l">{{.}}</span>{{end}}</div>{{else}}<div class="empty">Leere Datei</div>{{end}}</div>
</main>
<script>{{.Script}}</script>
</body>
</html>
`))

// serveViewer renders the text viewer page. It returns false, without having
// written anything, when the content is not text (NUL bytes, invalid UTF-8);
// the caller then falls back to a download.
func (a *app) serveViewer(w http.ResponseWriter, r *http.Request, name string, f io.Reader, size int64) bool {
	data, err := io.ReadAll(io.LimitReader(f, viewerMaxBytes+1))
	if err != nil {
		return false
	}
	truncated := len(data) > viewerMaxBytes
	if truncated {
		data = data[:viewerMaxBytes]
		if i := bytes.LastIndexByte(data, '\n'); i >= 0 {
			data = data[:i+1]
		} else {
			for n := 0; n < utf8.UTFMax && len(data) > 0 && !utf8.Valid(data); n++ {
				data = data[:len(data)-1]
			}
		}
	}
	if bytes.IndexByte(data, 0) >= 0 || !utf8.Valid(data) {
		return false
	}
	text := strings.TrimPrefix(string(data), "\uFEFF")

	var lines []string
	if text != "" {
		lines = strings.Split(strings.TrimSuffix(text, "\n"), "\n")
		for i, l := range lines {
			lines[i] = strings.TrimSuffix(l, "\r")
		}
	}
	if len(lines) > viewerMaxLines {
		lines, truncated = lines[:viewerMaxLines], true
	}

	var table [][]string
	var notices []string
	if ext := strings.ToLower(path.Ext(name)); ext == ".csv" || ext == ".tsv" {
		var cut bool
		table, cut = parseTable(strings.Join(lines, "\n"), ext == ".tsv", truncated)
		if cut {
			notices = append(notices, "Die Tabelle zeigt nur die ersten "+strconv.Itoa(len(table))+" Zeilen.")
		}
	}

	var rendered template.HTML
	if isMarkdown(name) {
		if rendered = renderMarkdown(strings.Join(lines, "\n")); rendered == "" && len(lines) > 0 {
			notices = append(notices, "Markdown wird nicht gerendert (Datei zu groß oder Renderer ausgelastet); der Quelltext wird angezeigt.")
		}
	}
	if truncated {
		shown := "nur der Anfang"
		if len(lines) == 1 {
			shown = "nur die erste Zeile"
		} else if len(lines) > 1 {
			shown = "nur die ersten " + strconv.Itoa(len(lines)) + " Zeilen"
		}
		notices = append(notices, "Große Datei: Es wird "+shown+" angezeigt. Die vollständige Datei gibt es über „Raw“ oder den Download-Knopf.")
	}
	notice := strings.Join(notices, " ")
	lineCount := ""
	if !truncated && len(lines) > 0 {
		lineCount = strconv.Itoa(len(lines))
	}

	h := w.Header()
	h.Set("Content-Security-Policy", viewerCSP)
	h.Set("Content-Type", "text/html; charset=utf-8")
	h.Set("Cache-Control", "private, no-cache")
	src := r.URL.EscapedPath()
	err = viewerTmpl.Execute(w, map[string]any{
		"Name":     displayName(name),
		"Size":     humanSize(size),
		"Lines":    lineCount,
		"Notice":   notice,
		"CanCopy":  size <= viewerMaxCopy,
		"Text":     lines,
		"Table":    table,
		"Rendered": rendered,
		"Raw":      template.URL(src + "?raw"),
		"Download": template.URL(src + "?dl"),
		"Script":   template.JS(viewerScript),
	})
	if err != nil {
		slog.Error("viewer page", "err", err)
	}
	return true
}

// parseTable parses CSV (quoted fields, "" escapes, embedded newlines) or TSV.
// It returns nil when the text is not a usable table, so only the text view is
// shown. Comma-separated files whose first line has more semicolons than
// commas (common in German locales) are split at semicolons.
func parseTable(text string, tsv, truncated bool) (rows [][]string, cut bool) {
	rd := csv.NewReader(strings.NewReader(text))
	rd.Comma = ','
	if tsv {
		rd.Comma = '\t'
		rd.LazyQuotes = true // tabs rarely come with CSV quoting; be forgiving
	} else {
		first, _, _ := strings.Cut(text, "\n")
		if strings.Count(first, ";") > strings.Count(first, ",") {
			rd.Comma = ';'
		}
		rd.LazyQuotes = true
	}
	rd.FieldsPerRecord = -1
	for {
		if len(rows) >= viewerMaxRows {
			if _, err := rd.Read(); err == nil {
				cut = true
			}
			break
		}
		rec, err := rd.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			if truncated && len(rows) > 0 {
				break // the cut-off tail may end inside a quoted field
			}
			return nil, false
		}
		rows = append(rows, rec)
	}
	return rows, cut
}
