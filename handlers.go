package main

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"hash/crc32"
	"io"
	"io/fs"
	"log/slog"
	"mime"
	"net/http"
	"net/url"
	"os"
	"path"
	"regexp"
	"strings"
	"sync/atomic"
	"time"
	"unicode"
	"unicode/utf8"
)

type app struct {
	cfg      config
	store    *store
	files    *os.Root
	filesDir string

	uploads     quota    // upload requests per client and IPv6 /48
	uploadBytes quota    // uploaded bytes per client and IPv6 /48
	lookups     *limiter // history/delete requests per client (UUID guessing)
	adminFails  *limiter // failed admin logins per client

	// inFlight is the number of bytes reserved by uploads that are still
	// being received; the low-disk guard counts them as already used.
	inFlight atomic.Int64
}

func newApp(cfg config, st *store, files *os.Root, filesDir string) *app {
	return &app{
		cfg: cfg, store: st, files: files, filesDir: filesDir,
		uploads:     newQuota(float64(cfg.UploadsPerHour), float64(cfg.UploadsPerHour)),
		uploadBytes: newQuota(float64(cfg.UploadMBPerHour<<20), float64(cfg.UploadMBPerHour<<20)),
		lookups:     newLimiter(3600, 120), // 1/s sustained, bursts of 120
		// 10 tries, then one per 10 minutes, per IPv4 address or IPv6 /48
		// (netKey). Deliberately not shared by all clients: that would let
		// anyone lock the admin out.
		adminFails: newLimiter(6, 10),
	}
}

var (
	reOwner    = regexp.MustCompile(`^[A-Za-z0-9-]{8,64}$`)
	reToken    = regexp.MustCompile(`^[A-Za-z0-9_-]{22}$`)
	reFileName = regexp.MustCompile(`^[A-Za-z0-9_\-][A-Za-z0-9_.\-]*$`) // legacy ul2 names
)

// maxNameBytes bounds the stored original file name (filesystems allow 255).
const maxNameBytes = 200

func (a *app) routes() http.Handler {
	web, _ := fs.Sub(webFS, "web")
	static := http.FileServerFS(web)

	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "ok") })
	mux.HandleFunc("GET /api/config", a.handleConfig)
	mux.HandleFunc("POST /api/upload", a.handleUpload)
	mux.HandleFunc("POST /upload.php", a.handleUpload) // ul2 / old ShareX configs
	mux.HandleFunc("PUT /{$}", a.handlePut)            // curl -T - https://host/ (stdin)
	mux.HandleFunc("PUT /{name}", a.handlePut)         // curl -T file https://host/
	mux.HandleFunc("GET /api/history", a.handleHistory)
	mux.HandleFunc("POST /api/delete", a.handleDelete)
	mux.HandleFunc("POST /api/admin/login", a.handleAdminLogin)
	mux.HandleFunc("POST /api/admin/logout", a.handleAdminLogout)
	mux.HandleFunc("GET /api/admin/uploads", a.admin(a.handleAdminList))
	mux.HandleFunc("POST /api/admin/delete", a.admin(a.handleAdminDelete))
	mux.HandleFunc("POST /api/admin/cleanup", a.admin(a.handleAdminCleanup))
	mux.HandleFunc("GET /files/{token}/{name}", a.handleFile)
	mux.HandleFunc("GET /files/{name}", a.handleLegacyFile) // ul2 links: files/<name>
	mux.HandleFunc("GET /admin", func(w http.ResponseWriter, r *http.Request) {
		http.ServeFileFS(w, r, web, "admin.html")
	})
	mux.Handle("GET /", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-cache")
		static.ServeHTTP(w, r)
	}))
	return a.logRequests(securityHeaders(mux))
}

// ---------- middleware ----------

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "same-origin")
		h.Set("X-Robots-Tag", "noindex, nofollow")
		if !strings.HasPrefix(r.URL.Path, "/files/") {
			h.Set("Content-Security-Policy", "default-src 'self'; img-src 'self' data: blob:; media-src 'self' blob:; frame-src blob:; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
		}
		next.ServeHTTP(w, r)
	})
}

type statusWriter struct {
	http.ResponseWriter
	status int
}

func (s *statusWriter) WriteHeader(c int) { s.status = c; s.ResponseWriter.WriteHeader(c) }

// Unwrap lets http.ResponseController reach the connection (read deadlines).
func (s *statusWriter) Unwrap() http.ResponseWriter { return s.ResponseWriter }

func (a *app) logRequests(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sw := &statusWriter{ResponseWriter: w, status: 200}
		start := time.Now()
		next.ServeHTTP(sw, r)
		if r.URL.Path == "/healthz" {
			return
		}
		slog.Info("req", "client", a.clientAddr(r), "method", r.Method, "path", r.URL.Path, "status", sw.status, "dur", time.Since(start).Round(time.Millisecond))
	})
}

func (a *app) admin(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if a.cfg.AdminPassword == "" {
			jsonErr(w, http.StatusNotFound, "Admin-Bereich ist deaktiviert")
			return
		}
		if a.adminAuth(w, r) {
			h(w, r)
		}
	}
}

// ---------- helpers ----------

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func jsonErr(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

func (a *app) baseURL(r *http.Request) string {
	if a.cfg.PublicURL != "" {
		return a.cfg.PublicURL
	}
	scheme := "http"
	if p := r.Header.Get("X-Forwarded-Proto"); p == "https" || p == "http" {
		scheme = p
	} else if r.TLS != nil {
		scheme = "https"
	}
	host := r.Host
	if h := r.Header.Get("X-Forwarded-Host"); h != "" {
		host = strings.TrimSpace(strings.Split(h, ",")[0])
	}
	return scheme + "://" + host
}

// fileURL builds the public URL of a stored name: "<token>/<original name>"
// for new uploads, "<name>" for legacy ul2 uploads.
func (a *app) fileURL(r *http.Request, stored string) string {
	parts := strings.Split(stored, "/")
	for i := range parts {
		parts[i] = url.PathEscape(parts[i])
	}
	return a.baseURL(r) + "/files/" + strings.Join(parts, "/")
}

func (a *app) fileSize(name string) int64 {
	if fi, err := a.files.Stat(name); err == nil {
		return fi.Size()
	}
	return 0
}

// displayName is the name shown to users: the original file name.
func displayName(stored string) string { return path.Base(stored) }

// removeStored deletes an upload and, for token uploads, its token directory.
func (a *app) removeStored(name string) error {
	err := a.files.Remove(name)
	if dir := path.Dir(name); dir != "." && (err == nil || errors.Is(err, fs.ErrNotExist)) {
		_ = a.files.Remove(dir) // only succeeds when empty
	}
	return err
}

// newToken returns 128 random bits, URL-safe. It is the secret that makes an
// upload's URL unguessable.
func newToken() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

// cleanName keeps the uploader's original file name, minus what cannot be a
// single path element or would disguise how the name displays (control and
// bidi/format characters such as U+202E).
func cleanName(orig string) string {
	name := path.Base(strings.ReplaceAll(orig, `\`, "/"))
	name = strings.ToValidUTF8(name, "")
	name = strings.Map(func(r rune) rune {
		if unicode.In(r, unicode.Cc, unicode.Cf) {
			return -1
		}
		return r
	}, name)
	name = strings.TrimSpace(name)
	if name == "" || name == "." || name == ".." || name == "/" {
		return "file"
	}
	if len(name) > maxNameBytes {
		ext := path.Ext(name)
		if len(ext) > 20 {
			ext = ""
		}
		name = truncateUTF8(name[:len(name)-len(ext)], maxNameBytes-len(ext)) + ext
	}
	return name
}

func truncateUTF8(s string, n int) string {
	if n >= len(s) {
		return s
	}
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return s[:n]
}

// ---------- handlers ----------

func (a *app) handleConfig(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"maxBytes":      a.cfg.MaxBytes,
		"retentionDays": int(a.cfg.Retention.Hours() / 24),
		"baseUrl":       a.baseURL(r),
		"admin":         a.cfg.AdminPassword != "",
	})
}

var errTooLarge = errors.New("too large")

// beginUpload runs the checks every upload passes before its body is read:
// hourly byte and request budgets, the low-disk guard, and the longer read
// deadline. On success the caller must call done with the bytes that stayed
// on disk (0 on failure) so the unused reservation is refunded.
func (a *app) beginUpload(w http.ResponseWriter, r *http.Request, fail errFunc) (done func(stored int64), ok bool) {
	key := a.quotaKey(r)
	// Reserve the largest file this request can carry *before* reading it, so
	// parallel uploads cannot all pass the byte budget and the disk guard at
	// once. The unused part is refunded when the upload ends.
	reserve := a.uploadReservation(r)
	if !a.uploadBytes.Take(key, float64(reserve)) {
		fail(w, http.StatusTooManyRequests, "Zu viele Uploads – bitte später erneut versuchen")
		return nil, false
	}
	refund := func(stored int64) { a.uploadBytes.Refund(key, float64(reserve-stored)) }
	if !a.uploads.Take(key, 1) {
		refund(0)
		fail(w, http.StatusTooManyRequests, "Zu viele Uploads – bitte später erneut versuchen")
		return nil, false
	}
	release := func() {}
	if a.cfg.MinFreeBytes > 0 {
		pending := a.inFlight.Add(reserve) // includes this upload
		release = func() { a.inFlight.Add(-reserve) }
		if free, err := diskFree(a.filesDir); err == nil && free-pending < a.cfg.MinFreeBytes {
			release()
			refund(0)
			slog.Warn("upload refused: low disk space", "free_mb", free>>20, "in_flight_mb", pending>>20)
			fail(w, http.StatusInsufficientStorage, "Kein Speicherplatz mehr frei – bitte später erneut versuchen")
			return nil, false
		}
	}
	// The server's ReadTimeout is short; uploads get their own, longer deadline.
	if err := http.NewResponseController(w).SetReadDeadline(time.Now().Add(a.cfg.UploadTimeout)); err != nil &&
		!errors.Is(err, http.ErrNotSupported) {
		slog.Warn("set upload read deadline", "err", err)
	}
	return func(stored int64) { release(); refund(stored) }, true
}

type errFunc func(w http.ResponseWriter, status int, msg string)

func textErr(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	io.WriteString(w, msg+"\n")
}

// failSave reports an error returned by saveFile.
func (a *app) failSave(w http.ResponseWriter, r *http.Request, fail errFunc, err error, origName string) {
	switch {
	case errors.Is(err, errTooLarge):
		fail(w, http.StatusRequestEntityTooLarge, "Datei ist zu groß")
	case errors.Is(err, io.ErrUnexpectedEOF):
		// The client cancelled or lost the connection mid-file.
		slog.Info("upload aborted", "file", origName, "client", a.clientAddr(r))
		fail(w, http.StatusBadRequest, "Upload abgebrochen")
	default:
		slog.Error("save upload", "err", err)
		fail(w, http.StatusInternalServerError, "Fehler beim Hochladen von "+origName)
	}
}

// recordUpload inserts a saved file into the database, removing it on error.
func (a *app) recordUpload(w http.ResponseWriter, r *http.Request, fail errFunc, owner, saved string, size int64, crc uint32) (int64, bool) {
	id, err := a.store.Insert(r.Context(), owner, saved, crc, time.Now())
	if err != nil {
		_ = a.removeStored(saved)
		slog.Error("insert upload", "err", err)
		fail(w, http.StatusInternalServerError, "Datenbankfehler")
		return 0, false
	}
	slog.Info("uploaded", "id", id, "file", saved, "bytes", size, "client", a.clientAddr(r))
	return id, true
}

// handleUpload streams a single multipart file straight to disk.
// Response shape is compatible with ul2: {success: id, url, filename}.
// uploadCSRF stops other websites from making their visitors' browsers upload
// here (each visitor would bring a fresh per-IP quota). ShareX and curl send
// neither Origin nor Sec-Fetch-Site, so they pass.
var uploadCSRF = http.NewCrossOriginProtection()

func (a *app) handleUpload(w http.ResponseWriter, r *http.Request) {
	if err := uploadCSRF.Check(r); err != nil {
		jsonErr(w, http.StatusForbidden, "Anfrage von fremder Seite abgelehnt")
		return
	}
	done, ok := a.beginUpload(w, r, jsonErr)
	if !ok {
		return
	}
	var stored int64 // bytes that stay on disk once the upload succeeded
	defer func() { done(stored) }()

	r.Body = http.MaxBytesReader(w, r.Body, a.cfg.MaxBytes+1<<20)
	mr, err := r.MultipartReader()
	if err != nil {
		jsonErr(w, http.StatusBadRequest, "Ungültige Anfrage (multipart/form-data erwartet)")
		return
	}

	owner := r.URL.Query().Get("uuid")
	var saved, origName string
	var size int64
	var crc uint32
	cleanup := func() {
		if saved != "" {
			_ = a.removeStored(saved)
		}
	}

	for {
		part, err := mr.NextPart()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			cleanup()
			var mbe *http.MaxBytesError
			if errors.As(err, &mbe) {
				jsonErr(w, http.StatusRequestEntityTooLarge, "Datei ist zu groß")
			} else {
				jsonErr(w, http.StatusBadRequest, "Upload abgebrochen")
			}
			return
		}
		switch {
		case part.FormName() == "uuid":
			b, _ := io.ReadAll(io.LimitReader(part, 128))
			owner = strings.TrimSpace(string(b))
		case part.FileName() != "" && saved == "":
			origName = part.FileName()
			saved, size, crc, err = a.saveFile(part, origName)
			if err != nil {
				cleanup()
				a.failSave(w, r, jsonErr, err, origName)
				return
			}
		}
		part.Close()
	}

	if saved == "" {
		jsonErr(w, http.StatusBadRequest, "Keine Datei erhalten")
		return
	}
	if owner != "" && !reOwner.MatchString(owner) {
		cleanup()
		jsonErr(w, http.StatusBadRequest, "Ungültige UUID")
		return
	}

	id, ok := a.recordUpload(w, r, jsonErr, owner, saved, size, crc)
	if !ok {
		return
	}
	stored = size
	writeJSON(w, http.StatusOK, map[string]any{
		"success":  id,
		"url":      a.fileURL(r, saved),
		"filename": displayName(saved),
	})
}

// handlePut takes the raw request body as the file, for
// `curl -T file https://host/` (curl appends the file name to a URL ending in
// "/"). It answers with the file URL as plain text, so the output can be
// piped or copied directly. The owner UUID is optional: ?uuid=.
func (a *app) handlePut(w http.ResponseWriter, r *http.Request) {
	owner := r.URL.Query().Get("uuid")
	if owner != "" && !reOwner.MatchString(owner) {
		textErr(w, http.StatusBadRequest, "Ungültige UUID")
		return
	}
	// Refuse a declared oversize body before curl sends it (Expect: 100-continue).
	if r.ContentLength > a.cfg.MaxBytes {
		textErr(w, http.StatusRequestEntityTooLarge, "Datei ist zu groß")
		return
	}
	origName := r.PathValue("name")
	if origName == "" || origName == "-" { // no name, or curl -T - (stdin)
		origName = "file"
	}

	done, ok := a.beginUpload(w, r, textErr)
	if !ok {
		return
	}
	var stored int64
	defer func() { done(stored) }()

	r.Body = http.MaxBytesReader(w, r.Body, a.cfg.MaxBytes+1)
	saved, size, crc, err := a.saveFile(r.Body, origName)
	if err != nil {
		a.failSave(w, r, textErr, err, origName)
		return
	}
	if _, ok := a.recordUpload(w, r, textErr, owner, saved, size, crc); !ok {
		return
	}
	stored = size
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	io.WriteString(w, a.fileURL(r, saved)+"\n")
}

// uploadReservation is the most file data a request can deliver: the body
// length when the client sent one (the file is part of the body), else the
// per-file limit. It never exceeds the hourly byte budget, so a budget below
// MAX_UPLOAD_MB still admits uploads.
func (a *app) uploadReservation(r *http.Request) int64 {
	n := a.cfg.MaxBytes
	if r.ContentLength >= 0 && r.ContentLength < n {
		n = r.ContentLength
	}
	if b := a.cfg.UploadMBPerHour << 20; b > 0 && n > b {
		n = b
	}
	return n
}

// saveFile stores src as <token>/<original name> and returns that stored name.
func (a *app) saveFile(src io.Reader, orig string) (string, int64, uint32, error) {
	token := newToken()
	if err := a.files.Mkdir(token, 0o755); err != nil {
		return "", 0, 0, err
	}
	name := token + "/" + cleanName(orig)
	f, err := a.files.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if err != nil {
		_ = a.files.Remove(token)
		return "", 0, 0, err
	}

	h := crc32.NewIEEE()
	n, err := io.Copy(io.MultiWriter(f, h), io.LimitReader(src, a.cfg.MaxBytes+1))
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err == nil && n > a.cfg.MaxBytes {
		err = errTooLarge
	}
	if err != nil {
		_ = a.removeStored(name)
		var mbe *http.MaxBytesError
		if errors.As(err, &mbe) {
			err = errTooLarge
		}
		return "", 0, 0, err
	}
	return name, n, h.Sum32(), nil
}

func (a *app) handleHistory(w http.ResponseWriter, r *http.Request) {
	if !a.lookups.Take(a.clientKey(r), 1) {
		jsonErr(w, http.StatusTooManyRequests, "Zu viele Anfragen – bitte später erneut versuchen")
		return
	}
	// The UUID lists and deletes the owner's files, so the web UI sends it as a
	// header: reverse-proxy access logs record query strings. ?uuid= stays for
	// older clients and scripts.
	owner := r.Header.Get("X-UUID")
	if owner == "" {
		owner = r.URL.Query().Get("uuid")
	}
	if !reOwner.MatchString(owner) {
		jsonErr(w, http.StatusBadRequest, "Ungültige UUID")
		return
	}
	list, err := a.store.ListByOwner(r.Context(), owner)
	if err != nil {
		jsonErr(w, http.StatusInternalServerError, "Datenbankfehler")
		return
	}
	for i := range list {
		list[i].Owner = ""
		list[i].URL = a.fileURL(r, list[i].Filename)
		list[i].Size = a.fileSize(list[i].Filename)
		list[i].Filename = displayName(list[i].Filename)
	}
	writeJSON(w, http.StatusOK, map[string]any{"files": list})
}

type deleteReq struct {
	ID   int64  `json:"id"`
	UUID string `json:"uuid"`
}

func (a *app) handleDelete(w http.ResponseWriter, r *http.Request) {
	if !a.lookups.Take(a.clientKey(r), 1) {
		jsonErr(w, http.StatusTooManyRequests, "Zu viele Anfragen – bitte später erneut versuchen")
		return
	}
	if ct, _, _ := mime.ParseMediaType(r.Header.Get("Content-Type")); ct != "application/json" {
		jsonErr(w, http.StatusUnsupportedMediaType, "JSON erwartet")
		return
	}
	var req deleteReq
	if err := json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&req); err != nil || !reOwner.MatchString(req.UUID) {
		jsonErr(w, http.StatusBadRequest, "Ungültige Anfrage")
		return
	}
	a.deleteUpload(w, r, req.ID, &req.UUID)
}

func (a *app) deleteUpload(w http.ResponseWriter, r *http.Request, id int64, owner *string) {
	u, err := a.store.Get(r.Context(), id, owner)
	if errors.Is(err, sql.ErrNoRows) {
		jsonErr(w, http.StatusNotFound, "Datei nicht gefunden")
		return
	} else if err != nil {
		jsonErr(w, http.StatusInternalServerError, "Datenbankfehler")
		return
	}
	if err := a.removeStored(u.Filename); err != nil && !errors.Is(err, fs.ErrNotExist) {
		slog.Error("delete file", "file", u.Filename, "err", err)
		jsonErr(w, http.StatusInternalServerError, "Datei konnte nicht gelöscht werden")
		return
	}
	if err := a.store.MarkDeleted(r.Context(), id); err != nil {
		jsonErr(w, http.StatusInternalServerError, "Datenbankfehler")
		return
	}
	slog.Info("deleted", "id", id, "file", u.Filename, "admin", owner == nil)
	writeJSON(w, http.StatusOK, map[string]string{"success": "Deleted"})
}

// handleFile serves /files/{token}/{name}. The token is the access secret.
func (a *app) handleFile(w http.ResponseWriter, r *http.Request) {
	token, name := r.PathValue("token"), r.PathValue("name")
	// Only canonical names exist on disk, so anything else (an escaped "/",
	// "..", control characters) is rejected before touching the filesystem.
	if !reToken.MatchString(token) || name != cleanName(name) {
		http.NotFound(w, r)
		return
	}
	a.serveStored(w, r, token+"/"+name)
}

// handleLegacyFile serves files uploaded by ul2 or earlier ul3 versions.
func (a *app) handleLegacyFile(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if !reFileName.MatchString(name) {
		http.NotFound(w, r)
		return
	}
	a.serveStored(w, r, name)
}

func (a *app) serveStored(w http.ResponseWriter, r *http.Request, name string) {
	f, err := a.files.Open(name)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil || !fi.Mode().IsRegular() {
		http.NotFound(w, r)
		return
	}
	h := w.Header()
	// Uploaded content is untrusted: never let it run script on our origin.
	h.Set("Content-Security-Policy", "sandbox; default-src 'none'; img-src 'self' data:; media-src 'self'; style-src 'unsafe-inline'")
	// private: a shared cache (CDN, proxy) would keep serving a deleted upload.
	h.Set("Cache-Control", "private, max-age=3600")
	ct := uploadContentType(name)
	if mediaType(name) != "" {
		// The same URL answers a navigation with the player page and the
		// player's own request with the file, so caches must keep them apart.
		h.Add("Vary", "Sec-Fetch-Dest")
		if wantsPlayerPage(r) && !r.URL.Query().Has("dl") {
			a.servePlayer(w, r, name, ct, fi.Size())
			return
		}
	}
	if r.URL.Query().Has("dl") || alwaysDownload(ct) {
		attachment(w, name)
	}
	h.Set("Content-Type", ct)
	http.ServeContent(w, r, name, fi.ModTime(), f)
}

// scriptOrStyleTypes are the MIME types browsers accept for <script> (the
// WHATWG "JavaScript MIME type" list) and <link rel=stylesheet>. Because every
// response carries X-Content-Type-Options: nosniff, serving uploads with any
// other type means a page on this origin can never load an upload as script
// or style, even though the main CSP allows 'self'.
var scriptOrStyleTypes = map[string]bool{
	"application/ecmascript": true, "application/javascript": true, "application/x-ecmascript": true,
	"application/x-javascript": true, "text/ecmascript": true, "text/javascript": true,
	"text/javascript1.0": true, "text/javascript1.1": true, "text/javascript1.2": true,
	"text/javascript1.3": true, "text/javascript1.4": true, "text/javascript1.5": true,
	"text/jscript": true, "text/livescript": true, "text/x-ecmascript": true, "text/x-javascript": true,
	"text/css": true,
}

// alwaysDownload reports whether a type is never shown inline. HTML uploads
// can't run script (sandbox CSP), but a static page under our domain is still
// a ready-made phishing page, so browsers get it as a download instead.
func alwaysDownload(ct string) bool {
	essence, _, _ := mime.ParseMediaType(ct)
	return essence == "text/html" || essence == "application/xhtml+xml"
}

func uploadContentType(name string) string {
	if ct := mediaType(name); ct != "" {
		return ct
	}
	ct := mime.TypeByExtension(path.Ext(name))
	if ct == "" {
		return "application/octet-stream"
	}
	essence, _, err := mime.ParseMediaType(ct)
	if err != nil || scriptOrStyleTypes[essence] {
		return "text/plain; charset=utf-8"
	}
	return ct
}

// ---------- admin ----------

func (a *app) handleAdminList(w http.ResponseWriter, r *http.Request) {
	list, err := a.store.ListAll(r.Context())
	if err != nil {
		jsonErr(w, http.StatusInternalServerError, "Datenbankfehler")
		return
	}
	for i := range list {
		list[i].URL = a.fileURL(r, list[i].Filename)
		if !list[i].Deleted {
			list[i].Size = a.fileSize(list[i].Filename)
		}
		list[i].Filename = displayName(list[i].Filename)
	}
	c, _ := a.store.Cron(r.Context())
	writeJSON(w, http.StatusOK, map[string]any{"files": list, "cron": c})
}

func (a *app) handleAdminDelete(w http.ResponseWriter, r *http.Request) {
	var req deleteReq
	if err := json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&req); err != nil {
		jsonErr(w, http.StatusBadRequest, "Ungültige Anfrage")
		return
	}
	a.deleteUpload(w, r, req.ID, nil)
}

func (a *app) handleAdminCleanup(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, a.cleanup(r.Context()))
}

// ---------- expiry ----------

func (a *app) cleanupLoop(ctx context.Context) {
	a.cleanup(ctx)
	t := time.NewTicker(a.cfg.CleanupEvery)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			a.cleanup(ctx)
		}
	}
}

func (a *app) cleanup(ctx context.Context) cronStatus {
	now := time.Now()
	st := cronStatus{Time: now.Unix()}
	list, err := a.store.Expired(ctx, now.Add(-a.cfg.Retention))
	if err != nil {
		slog.Error("cleanup query", "err", err)
		st.Errors++
	}
	for _, u := range list {
		if !u.Deleted {
			if err := a.removeStored(u.Filename); err != nil && !errors.Is(err, fs.ErrNotExist) {
				slog.Warn("cleanup: not deleted", "file", u.Filename, "err", err)
				st.Errors++
				continue
			}
			st.NumDeleted++
		}
		if err := a.store.Remove(ctx, u.ID); err != nil {
			st.Errors++
		}
	}
	if err := a.store.SetCron(ctx, st); err != nil {
		slog.Error("cleanup status", "err", err)
	}
	if st.NumDeleted > 0 || st.Errors > 0 {
		slog.Info("cleanup finished", "deleted", st.NumDeleted, "errors", st.Errors)
	}
	return st
}
