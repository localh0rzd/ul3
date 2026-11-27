package main

import (
	"html/template"
	"log/slog"
	"mime"
	"net/http"
	"path"
	"strconv"
	"strings"
)

// playableMedia lists the formats all current browsers play natively, with
// their types. They are built in because the container image has no
// /etc/mime.types, so mime.TypeByExtension would know none of them and the
// file would be served as application/octet-stream (i.e. downloaded).
var playableMedia = map[string]string{
	".mp4": "video/mp4", ".m4v": "video/mp4", ".webm": "video/webm", ".ogv": "video/ogg",
	".mp3": "audio/mpeg", ".m4a": "audio/mp4", ".aac": "audio/aac", ".wav": "audio/wav",
	".flac": "audio/flac", ".ogg": "audio/ogg", ".oga": "audio/ogg", ".opus": "audio/ogg",
	".weba": "audio/webm",
}

func mediaType(name string) string { return playableMedia[strings.ToLower(path.Ext(name))] }

// wantsPlayerPage reports whether the browser is navigating to the file (as
// opposed to a <video>/<audio> element, curl or ShareX fetching it), in which
// case a media file gets a page with a player instead of the raw bytes.
func wantsPlayerPage(r *http.Request) bool {
	return r.Header.Get("Sec-Fetch-Dest") == "document" && !r.URL.Query().Has("raw")
}

// The page runs no script: default-src 'none' allows none. It is not
// sandboxed like the raw uploads, because browsers refuse to load media into
// a sandboxed document.
const playerCSP = "default-src 'none'; media-src 'self'; img-src 'self'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"

var playerTmpl = template.Must(template.New("player").Parse(`<!doctype html>
<html lang="de">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex, nofollow">
<meta name="color-scheme" content="light dark">
<title>{{.Name}}</title>
<style>
:root { --bg: #f4f5f7; --card: #fff; --text: #1d2330; --muted: #6b7280; --border: #e3e6ea; --accent: #2f6fde; }
@media (prefers-color-scheme: dark) {
	:root { --bg: #12151b; --card: #1b1f27; --text: #e6e8ec; --muted: #9aa3b2; --border: #2b313c; --accent: #5b8ff0; }
}
* { box-sizing: border-box; }
body { margin: 0; min-height: 100vh; display: flex; align-items: center; justify-content: center; padding: 16px;
	background: var(--bg); color: var(--text); font: 15px/1.5 system-ui, -apple-system, "Segoe UI", Roboto, sans-serif; }
main { width: 100%; max-width: {{if .Video}}1100px{{else}}560px{{end}}; background: var(--card); border: 1px solid var(--border);
	border-radius: 12px; padding: 16px; }
video { display: block; width: 100%; max-height: 75vh; background: #000; border-radius: 8px; }
audio { display: block; width: 100%; }
.bar { display: flex; align-items: center; gap: 12px; margin-top: 12px; }
.name { flex: 1; min-width: 0; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; font-weight: 600; }
.size { color: var(--muted); font-size: .9em; white-space: nowrap; }
a.dl { flex: none; padding: 7px 14px; border-radius: 8px; background: var(--accent); color: #fff; text-decoration: none; font-weight: 600; }
a.dl:hover { filter: brightness(1.08); }
</style>
</head>
<body>
<main>
{{if .Video}}<video src="{{.Src}}" controls autoplay playsinline preload="metadata"></video>
{{else}}<audio src="{{.Src}}" controls autoplay preload="metadata"></audio>
{{end}}<div class="bar">
<span class="name" title="{{.Name}}">{{.Name}}</span>
<span class="size">{{.Size}}</span>
<a class="dl" href="{{.Download}}" download="{{.Name}}">Herunterladen</a>
</div>
</main>
</body>
</html>
`))

func (a *app) servePlayer(w http.ResponseWriter, r *http.Request, name, ct string, size int64) {
	h := w.Header()
	h.Set("Content-Security-Policy", playerCSP)
	h.Set("Content-Type", "text/html; charset=utf-8")
	h.Set("Cache-Control", "private, no-cache")
	src := r.URL.EscapedPath()
	err := playerTmpl.Execute(w, map[string]any{
		"Name":     displayName(name),
		"Video":    strings.HasPrefix(ct, "video/"),
		"Src":      template.URL(src + "?raw"),
		"Download": template.URL(src + "?dl"),
		"Size":     humanSize(size),
	})
	if err != nil {
		slog.Error("player page", "err", err)
	}
}

// attachment marks the response as a download under the file's own name.
func attachment(w http.ResponseWriter, name string) {
	w.Header().Set("Content-Disposition", mime.FormatMediaType("attachment", map[string]string{"filename": displayName(name)}))
}

func humanSize(n int64) string {
	const unit = 1024
	if n < unit {
		return strconv.FormatInt(n, 10) + " B"
	}
	div, exp := int64(unit), 0
	for m := n / unit; m >= unit && exp < 3; m /= unit {
		div *= unit
		exp++
	}
	v := float64(n) / float64(div)
	s := strings.Replace(strconv.FormatFloat(v, 'f', 1, 64), ".", ",", 1) // German decimal comma, like the UI
	return s + " " + string("KMGT"[exp]) + "B"
}
