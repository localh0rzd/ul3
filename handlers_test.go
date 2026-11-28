package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
)

func testConfig() config {
	trusted, _ := parseTrustedProxies(privateProxyRanges)
	return config{
		MaxBytes: 1 << 20, Retention: time.Hour, CleanupEvery: time.Hour,
		AdminPassword:  "correct horse battery staple",
		UploadsPerHour: 1000, UploadMBPerHour: 1000,
		UploadTimeout: time.Minute, TrustedProxies: trusted,
	}
}

func newTestApp(t *testing.T, mutate func(*config)) *app {
	t.Helper()
	cfg := testConfig()
	if mutate != nil {
		mutate(&cfg)
	}
	dir := t.TempDir()
	filesDir := filepath.Join(dir, "files")
	if err := os.MkdirAll(filesDir, 0o755); err != nil {
		t.Fatal(err)
	}
	st, err := openStore(filepath.Join(dir, "uploads.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	root, err := os.OpenRoot(filesDir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { root.Close() })
	return newApp(cfg, st, root, filesDir)
}

func multipartBody(t *testing.T, uuid, filename, content string) (*bytes.Buffer, string) {
	t.Helper()
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	if uuid != "" {
		mw.WriteField("uuid", uuid)
	}
	fw, err := mw.CreateFormFile("file-upload", filename)
	if err != nil {
		t.Fatal(err)
	}
	io.WriteString(fw, content)
	mw.Close()
	return &buf, mw.FormDataContentType()
}

type uploadResp struct {
	Success  int64  `json:"success"`
	URL      string `json:"url"`
	Filename string `json:"filename"`
	Error    string `json:"error"`
}

func doUpload(t *testing.T, h http.Handler, uuid, filename, content string) (*httptest.ResponseRecorder, uploadResp) {
	t.Helper()
	body, ct := multipartBody(t, uuid, filename, content)
	req := httptest.NewRequest("POST", "/api/upload", body)
	req.Header.Set("Content-Type", ct)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	var res uploadResp
	json.Unmarshal(rec.Body.Bytes(), &res)
	return rec, res
}

func get(h http.Handler, target string, hdr ...string) *httptest.ResponseRecorder {
	req := httptest.NewRequest("GET", target, nil)
	for i := 0; i+1 < len(hdr); i += 2 {
		req.Header.Set(hdr[i], hdr[i+1])
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

// HIGH finding: URLs were base[:20] + 3 random chars. Now they carry a 128-bit
// token and the untouched original name.
func TestUploadURLHasSecretTokenAndOriginalName(t *testing.T) {
	a := newTestApp(t, nil)
	h := a.routes()
	const orig = "Screenshot From 2026-11-17 18-52-31.png"
	rec, res := doUpload(t, h, "", orig, "pixels")
	if rec.Code != 200 {
		t.Fatalf("upload: %d %s", rec.Code, rec.Body)
	}
	if res.Filename != orig {
		t.Errorf("filename = %q, want %q", res.Filename, orig)
	}
	u, _ := url.Parse(res.URL)
	m := regexp.MustCompile(`^/files/([A-Za-z0-9_-]{22})/(.+)$`).FindStringSubmatch(u.EscapedPath())
	if m == nil {
		t.Fatalf("url %q does not have the /files/<token>/<name> shape", res.URL)
	}
	if name, _ := url.PathUnescape(m[2]); name != orig {
		t.Errorf("url name = %q, want %q", name, orig)
	}
	if r := get(h, u.RequestURI()); r.Code != 200 || r.Body.String() != "pixels" {
		t.Fatalf("GET own url: %d %q", r.Code, r.Body)
	}
	// Right name, wrong token: must not be reachable.
	if r := get(h, "/files/"+newToken()+"/"+m[2]); r.Code != 404 {
		t.Errorf("wrong token: %d, want 404", r.Code)
	}
	// Token directory itself through the legacy single-segment route: not a file.
	if r := get(h, "/files/"+m[1]); r.Code != 404 {
		t.Errorf("token dir via legacy route: %d, want 404", r.Code)
	}
}

func TestTokensAreUnique(t *testing.T) {
	seen := map[string]bool{}
	for range 1000 {
		tok := newToken()
		if !reToken.MatchString(tok) || seen[tok] {
			t.Fatalf("bad or repeated token %q", tok)
		}
		seen[tok] = true
	}
}

func TestCleanName(t *testing.T) {
	long := strings.Repeat("ä", 150) + ".png" // 300 bytes of base
	for _, tc := range []struct{ in, want string }{
		{"Screenshot From 2026-11-17 18-52-31.png", "Screenshot From 2026-11-17 18-52-31.png"},
		{`C:\fakepath\Bericht März.pdf`, "Bericht März.pdf"},
		{"../../uploads.db", "uploads.db"},
		{"..", "file"},
		{"/", "file"},
		{"", "file"},
		{" \t", "file"},
		{"photo\u202egnp.exe", "photognp.exe"},
		{"a\x00b\nc.txt", "abc.txt"},
		{"bad\xffutf8.txt", "badutf8.txt"},
	} {
		if got := cleanName(tc.in); got != tc.want {
			t.Errorf("cleanName(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
	got := cleanName(long)
	if len(got) > maxNameBytes || !strings.HasSuffix(got, ".png") || !strings.HasPrefix(got, "ää") {
		t.Errorf("long name: %d bytes, %q", len(got), got)
	}
	if strings.ContainsRune(got, '\uFFFD') || !utf8Valid(got) {
		t.Errorf("long name cut inside a rune: %q", got)
	}
}

func utf8Valid(s string) bool { return strings.ToValidUTF8(s, "") == s }

func TestFileRouteRejectsNonCanonicalNames(t *testing.T) {
	a := newTestApp(t, nil)
	h := a.routes()
	// A real file one level above an existing token dir must not be reachable
	// through that token (os.Root alone would allow "tok/../secret.txt").
	os.WriteFile(filepath.Join(a.filesDir, "secret.txt"), []byte("x"), 0o644)
	_, res := doUpload(t, h, "", "a.txt", "a")
	u, _ := url.Parse(res.URL)
	tok := strings.Split(u.Path, "/")[2]
	for _, p := range []string{
		"/files/" + tok + "/..%2Fsecret.txt",
		"/files/" + tok + "/a%2Fb",
		"/files/" + tok + "/%2E%2E",
		"/files/" + tok + "/a%00b",
		"/files/short/secret.txt",
	} {
		if r := get(h, p); r.Code != 404 {
			t.Errorf("GET %s = %d, want 404", p, r.Code)
		}
	}
}

func TestLegacyFilesStillServed(t *testing.T) {
	a := newTestApp(t, nil)
	os.WriteFile(filepath.Join(a.filesDir, "old-abc.png"), []byte("legacy"), 0o644)
	if r := get(a.routes(), "/files/old-abc.png"); r.Code != 200 || r.Body.String() != "legacy" {
		t.Fatalf("legacy file: %d %q", r.Code, r.Body)
	}
}

// LOW finding: uploads could be referenced as <script>/<link> from this origin.
func TestScriptAndStyleUploadsServedAsText(t *testing.T) {
	a := newTestApp(t, nil)
	h := a.routes()
	for name, want := range map[string]string{
		"x.js":     "text/plain; charset=utf-8",
		"x.mjs":    "text/plain; charset=utf-8",
		"x.css":    "text/plain; charset=utf-8",
		"x.png":    "image/png",
		"x.unknwn": "application/octet-stream",
	} {
		_, res := doUpload(t, h, "", name, "body")
		u, _ := url.Parse(res.URL)
		r := get(h, u.RequestURI())
		if got := r.Header().Get("Content-Type"); got != want {
			t.Errorf("%s: Content-Type %q, want %q", name, got, want)
		}
		if r.Header().Get("X-Content-Type-Options") != "nosniff" {
			t.Errorf("%s: missing nosniff", name)
		}
		if !strings.HasPrefix(r.Header().Get("Content-Security-Policy"), "sandbox") {
			t.Errorf("%s: missing sandbox CSP", name)
		}
	}
}

func TestDeleteRemovesFileAndTokenDir(t *testing.T) {
	a := newTestApp(t, nil)
	h := a.routes()
	const uuid = "0b9a7c1e-1111-4222-8333-444455556666"
	_, res := doUpload(t, h, uuid, "a.txt", "hi")
	u, _ := url.Parse(res.URL)

	req := httptest.NewRequest("POST", "/api/delete", strings.NewReader(`{"id":`+jsonNum(res.Success)+`,"uuid":"`+uuid+`"}`))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != 200 {
		t.Fatalf("delete: %d %s", rec.Code, rec.Body)
	}
	if r := get(h, u.RequestURI()); r.Code != 404 {
		t.Errorf("deleted file still served: %d", r.Code)
	}
	entries, _ := os.ReadDir(a.filesDir)
	if len(entries) != 0 {
		t.Errorf("files dir not empty after delete: %v", entries)
	}
}

func jsonNum(n int64) string { b, _ := json.Marshal(n); return string(b) }

func TestHistoryShowsOriginalName(t *testing.T) {
	a := newTestApp(t, nil)
	h := a.routes()
	const uuid = "0b9a7c1e-1111-4222-8333-444455556666"
	_, up := doUpload(t, h, uuid, "Urlaub 2026.jpg", "jpg")
	r := get(h, "/api/history?uuid="+uuid)
	var res struct{ Files []upload }
	json.Unmarshal(r.Body.Bytes(), &res)
	if len(res.Files) != 1 || res.Files[0].Filename != "Urlaub 2026.jpg" || res.Files[0].URL != up.URL || res.Files[0].Size != 3 {
		t.Fatalf("history = %+v", res.Files)
	}
}

// MEDIUM finding: unlimited anonymous uploads.
// LOW finding: the web UI sent the owner UUID – a bearer secret – in the query
// string, which reverse proxies log. It now goes in X-UUID; ?uuid= still works.
func TestHistoryUUIDFromHeader(t *testing.T) {
	a := newTestApp(t, nil)
	h := a.routes()
	const uuid = "0b9a7c1e-1111-4222-8333-777788889999"
	doUpload(t, h, uuid, "mine.txt", "x")
	r := get(h, "/api/history", "X-UUID", uuid)
	if r.Code != 200 || !strings.Contains(r.Body.String(), "mine.txt") {
		t.Fatalf("header lookup: %d %s", r.Code, r.Body)
	}
	if r := get(h, "/api/history?uuid=someone-else-1234", "X-UUID", uuid); !strings.Contains(r.Body.String(), "mine.txt") {
		t.Fatalf("header must win over the query: %s", r.Body)
	}
	if r := get(h, "/api/history", "X-UUID", "bad uuid"); r.Code != http.StatusBadRequest {
		t.Fatalf("invalid header UUID: %d, want 400", r.Code)
	}
}

// INFO finding: "public" let shared caches keep serving deleted uploads.
func TestUploadsNotStoredBySharedCaches(t *testing.T) {
	a := newTestApp(t, nil)
	h := a.routes()
	_, up := doUpload(t, h, "", "a.txt", "x")
	u, _ := url.Parse(up.URL)
	cc := get(h, u.EscapedPath()).Header().Get("Cache-Control")
	if !strings.Contains(cc, "private") || strings.Contains(cc, "public") {
		t.Fatalf("Cache-Control = %q, want private", cc)
	}
}

func TestAbortedUploadLeavesNothingBehind(t *testing.T) {
	a := newTestApp(t, nil)
	body, ct := multipartBody(t, "aborted-uuid-1234", "big.bin", strings.Repeat("x", 64<<10))
	cut := bytes.NewReader(body.Bytes()[:body.Len()/2]) // connection dropped mid-file
	req := httptest.NewRequest("POST", "/api/upload", cut)
	req.Header.Set("Content-Type", ct)
	rec := httptest.NewRecorder()
	a.routes().ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status %d, want 400: %s", rec.Code, rec.Body)
	}
	entries, err := os.ReadDir(a.filesDir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("files left behind: %v", entries)
	}
	if h := get(a.routes(), "/api/history?uuid=aborted-uuid-1234"); strings.Contains(h.Body.String(), "big.bin") {
		t.Fatalf("aborted upload listed in history: %s", h.Body)
	}
}

func TestUploadRateLimit(t *testing.T) {
	a := newTestApp(t, func(c *config) { c.UploadsPerHour = 2 })
	h := a.routes()
	for i := range 2 {
		if rec, _ := doUpload(t, h, "", "a.txt", "x"); rec.Code != 200 {
			t.Fatalf("upload %d: %d", i, rec.Code)
		}
	}
	if rec, _ := doUpload(t, h, "", "a.txt", "x"); rec.Code != http.StatusTooManyRequests {
		t.Fatalf("3rd upload: %d, want 429", rec.Code)
	}
}

func TestUploadByteBudget(t *testing.T) {
	a := newTestApp(t, func(c *config) { c.UploadMBPerHour = 1 })
	h := a.routes()
	big := strings.Repeat("x", 1<<20) // exactly the hourly budget
	if rec, _ := doUpload(t, h, "", "big.bin", big); rec.Code != 200 {
		t.Fatalf("first upload: %d", rec.Code)
	}
	if rec, _ := doUpload(t, h, "", "small.bin", "x"); rec.Code != http.StatusTooManyRequests {
		t.Fatalf("over budget: %d, want 429", rec.Code)
	}
}

func TestLowDiskRefusesUpload(t *testing.T) {
	a := newTestApp(t, func(c *config) { c.MinFreeBytes = 1 << 62 })
	if _, err := diskFree(a.filesDir); err != nil {
		t.Skip("diskFree unsupported here")
	}
	if rec, _ := doUpload(t, a.routes(), "", "a.txt", "x"); rec.Code != http.StatusInsufficientStorage {
		t.Fatalf("low disk: %d, want 507", rec.Code)
	}
	entries, _ := os.ReadDir(a.filesDir)
	if len(entries) != 0 {
		t.Errorf("file written despite refusal")
	}
}

// The server-wide ReadTimeout must not cut off slow uploads: the upload
// handler extends its own deadline through the logging wrapper.
func TestSlowUploadOutlivesServerReadTimeout(t *testing.T) {
	a := newTestApp(t, nil)
	srv := httptest.NewUnstartedServer(a.routes())
	srv.Config.ReadTimeout = 300 * time.Millisecond
	srv.Start()
	defer srv.Close()

	body, ct := multipartBody(t, "", "slow.txt", strings.Repeat("y", 4096))
	data := body.Bytes()
	pr, pw := io.Pipe()
	go func() {
		for i := 0; i < len(data); i += len(data) / 4 {
			end := min(i+len(data)/4, len(data))
			pw.Write(data[i:end])
			time.Sleep(250 * time.Millisecond) // ~1s total, > ReadTimeout
		}
		pw.Close()
	}()
	resp, err := http.Post(srv.URL+"/api/upload", ct, pr)
	if err != nil {
		t.Fatalf("slow upload failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("slow upload: %d %s", resp.StatusCode, b)
	}
}

// LOW finding: admin guessing was only slowed per request.
func TestAdminLockout(t *testing.T) {
	a := newTestApp(t, nil)
	h := a.routes()
	for i := range 10 {
		if r := get(h, "/api/admin/uploads", "Authorization", "Bearer wrong"); r.Code != 401 {
			t.Fatalf("attempt %d: %d, want 401", i, r.Code)
		}
	}
	if r := get(h, "/api/admin/uploads", "Authorization", "Bearer "+a.cfg.AdminPassword); r.Code != 429 {
		t.Fatalf("after 10 failures: %d, want 429", r.Code)
	}
	// Another client is unaffected.
	req := httptest.NewRequest("GET", "/api/admin/uploads", nil)
	req.RemoteAddr = "198.51.100.7:4000"
	req.Header.Set("Authorization", "Bearer "+a.cfg.AdminPassword)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != 200 {
		t.Fatalf("other client: %d, want 200", rec.Code)
	}
}

func TestAdminSession(t *testing.T) {
	a := newTestApp(t, nil)
	h := a.routes()
	if r := get(h, "/api/admin/session"); r.Code != 401 {
		t.Fatalf("signed out: %d, want 401", r.Code)
	}
	if r := get(h, "/api/admin/session", "Authorization", "Bearer "+a.cfg.AdminPassword); r.Code != 200 {
		t.Fatalf("signed in: %d, want 200", r.Code)
	}
}

// Follow-up to dropping the global lockout: rotating through the /64s of one
// IPv6 /48 must not give an attacker 10 fresh guesses per /64.
func TestAdminLockoutCoversIPv6Slash48(t *testing.T) {
	a := newTestApp(t, nil)
	h := a.routes()
	try := func(remote, pw string) int {
		req := httptest.NewRequest("GET", "/api/admin/uploads", nil)
		req.RemoteAddr = remote
		req.Header.Set("Authorization", "Bearer "+pw)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec.Code
	}
	for i := range 10 {
		if c := try(fmt.Sprintf("[2001:db8:7:%x::1]:443", i), "wrong"); c != 401 {
			t.Fatalf("attempt %d: %d, want 401", i, c)
		}
	}
	if c := try("[2001:db8:7:ffff::1]:443", a.cfg.AdminPassword); c != http.StatusTooManyRequests {
		t.Fatalf("new /64 in the same /48: %d, want 429", c)
	}
	if c := try("[2001:db8:8::1]:443", a.cfg.AdminPassword); c != http.StatusOK {
		t.Fatalf("other /48: %d, want 200", c)
	}
}

// MEDIUM finding: upload quotas were keyed per /64 only, so a /48 meant
// 65,536 budgets. Each /64 keeps its own budget, but a /48 shares netShare.
func TestUploadQuotaCoversIPv6Slash48(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(*config)
	}{
		{"requests", func(c *config) { c.UploadsPerHour = 1 }},
		{"bytes", func(c *config) { c.UploadMBPerHour = 1 }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a := newTestApp(t, tc.mutate)
			h := a.routes()
			big := strings.Repeat("x", 1<<20) // one full byte budget
			put := func(remote string) int {
				req := httptest.NewRequest("PUT", "/a.bin", strings.NewReader(big))
				req.RemoteAddr = remote
				rec := httptest.NewRecorder()
				h.ServeHTTP(rec, req)
				return rec.Code
			}
			for i := range netShare {
				if c := put(fmt.Sprintf("[2001:db8:7:%x::1]:443", i)); c != 200 {
					t.Fatalf("/64 #%d: %d, want 200", i, c)
				}
			}
			if c := put("[2001:db8:7:ffff::1]:443"); c != http.StatusTooManyRequests {
				t.Fatalf("/64 beyond the /48's share: %d, want 429", c)
			}
			if c := put("[2001:db8:7:0::2]:443"); c != http.StatusTooManyRequests {
				t.Fatalf("spent /64: %d, want 429", c)
			}
			if c := put("[2001:db8:8::1]:443"); c != 200 {
				t.Fatalf("other /48: %d, want 200", c)
			}
		})
	}
}

// A /64 refused by its /48 must not lose its own budget: the tiers are
// charged together or not at all.
func TestQuotaTakeIsAllOrNothing(t *testing.T) {
	q := newQuota(1, 1)
	for i := range netShare {
		if !q.Take(quotaKey{fmt.Sprintf("c%d", i), "n"}, 1) {
			t.Fatalf("take %d refused", i)
		}
	}
	k := quotaKey{"fresh", "n"}
	if q.Take(k, 1) {
		t.Fatal("take beyond the network share allowed")
	}
	if !q.Take(quotaKey{"fresh", "other"}, 1) {
		t.Fatal("refused take still charged the client tier")
	}
}

func TestLookupRateLimit(t *testing.T) {
	a := newTestApp(t, nil)
	h := a.routes()
	var last int
	for range 121 {
		last = get(h, "/api/history?uuid=aaaaaaaa").Code
	}
	if last != http.StatusTooManyRequests {
		t.Fatalf("121st lookup: %d, want 429", last)
	}
}

func TestClientIP(t *testing.T) {
	trusted, _ := parseTrustedProxies(privateProxyRanges)
	for _, tc := range []struct{ remote, xff, want string }{
		{"203.0.113.9:1234", "", "203.0.113.9"},
		{"203.0.113.9:1234", "1.2.3.4", "203.0.113.9"},          // untrusted peer: XFF ignored
		{"172.18.0.2:1234", "6.6.6.6, 1.2.3.4", "1.2.3.4"},      // rightmost hop added by our proxy
		{"172.18.0.2:1234", "1.2.3.4, 10.0.0.5", "1.2.3.4"},     // chained trusted proxies
		{"172.18.0.2:1234", "", "172.18.0.2"},                   // proxy without XFF
		{"172.18.0.2:1234", "garbage", "172.18.0.2"},            // malformed
		{"[::ffff:172.18.0.2]:1", "2001:db8::1", "2001:db8::1"}, // v4-mapped peer
	} {
		req := httptest.NewRequest("GET", "/", nil)
		req.RemoteAddr = tc.remote
		if tc.xff != "" {
			req.Header.Set("X-Forwarded-For", tc.xff)
		}
		if got := clientIP(req, trusted); got != netip.MustParseAddr(tc.want) {
			t.Errorf("remote %s xff %q: got %s, want %s", tc.remote, tc.xff, got, tc.want)
		}
	}
	a := &app{cfg: config{TrustedProxies: trusted}}
	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "[2001:db8:1:2:3:4:5:6]:443"
	if got := a.clientKey(req); got != "2001:db8:1:2::/64" {
		t.Errorf("v6 key = %s", got)
	}
}

// LOW finding: the default trusted all private ranges, so a client reaching
// ul3 directly from one could pick its rate-limit key via X-Forwarded-For.
func TestDefaultTrustsNoProxy(t *testing.T) {
	trusted, err := parseTrustedProxies(defaultTrustedProxies)
	if err != nil || len(trusted) != 0 {
		t.Fatalf("default trusted proxies = %v, %v; want none", trusted, err)
	}
	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "172.17.0.1:1234"
	req.Header.Set("X-Forwarded-For", "6.6.6.6")
	if got := clientIP(req, trusted); got != netip.MustParseAddr("172.17.0.1") {
		t.Fatalf("spoofed XFF believed by default: got %s", got)
	}
}

func TestLimiterRefill(t *testing.T) {
	now := time.Unix(0, 0)
	l := newLimiter(3600, 2) // 1 token/s
	l.now = func() time.Time { return now }
	if !l.Take("k", 1) || !l.Take("k", 1) || l.Take("k", 1) {
		t.Fatal("burst of 2 not enforced")
	}
	now = now.Add(time.Second)
	if !l.Take("k", 1) {
		t.Fatal("no refill after 1s")
	}
	l.Charge("k", 5)
	now = now.Add(3 * time.Second)
	if l.Available("k") {
		t.Fatal("debt not honoured")
	}
	if newLimiter(0, 10) != nil || !(*limiter)(nil).Take("k", 1) {
		t.Fatal("disabled limiter must allow")
	}
}

// startHeldUpload begins a chunked upload (no Content-Length, so the server
// must reserve MaxBytes) and keeps it open until finish is called. It returns
// once the server has made its reservation.
func startHeldUpload(t *testing.T, a *app) (finish func() int) {
	t.Helper()
	srv := httptest.NewServer(a.routes())
	t.Cleanup(srv.Close)
	body, ct := multipartBody(t, "", "held.txt", "z")
	data := body.Bytes()
	pr, pw := io.Pipe()
	t.Cleanup(func() { pw.Close() }) // runs before srv.Close if the test fails early
	status := make(chan int, 1)
	go func() {
		resp, err := http.Post(srv.URL+"/api/upload", ct, pr)
		if err != nil {
			status <- -1
			return
		}
		resp.Body.Close()
		status <- resp.StatusCode
	}()
	pw.Write(data[:10])
	deadline := time.Now().Add(5 * time.Second)
	for a.inFlight.Load() == 0 {
		if time.Now().After(deadline) {
			t.Fatal("held upload never reserved its bytes")
		}
		time.Sleep(5 * time.Millisecond)
	}
	return func() int {
		pw.Write(data[10:])
		pw.Close()
		return <-status
	}
}

// MEDIUM finding: parallel uploads all passed the byte budget because it was
// only charged after each file had been written.
func TestUploadBudgetReservedWhileInFlight(t *testing.T) {
	a := newTestApp(t, func(c *config) { c.UploadMBPerHour = 1; c.MinFreeBytes = 1 })
	if _, err := diskFree(a.filesDir); err != nil {
		t.Skip("diskFree unsupported here")
	}
	// Same client as the held upload, which arrives from 127.0.0.1.
	sameClient := func(name string) int {
		body, ct := multipartBody(t, "", name, "x")
		req := httptest.NewRequest("POST", "/api/upload", body)
		req.Header.Set("Content-Type", ct)
		req.RemoteAddr = "127.0.0.1:5555"
		rec := httptest.NewRecorder()
		a.routes().ServeHTTP(rec, req)
		return rec.Code
	}
	finish := startHeldUpload(t, a) // reserves the whole 1 MB budget
	if c := sameClient("b.txt"); c != http.StatusTooManyRequests {
		t.Fatalf("upload during reservation: %d, want 429", c)
	}
	if code := finish(); code != 200 {
		t.Fatalf("held upload: %d", code)
	}
	// The unused reservation was refunded: small uploads work again.
	if c := sameClient("c.txt"); c != 200 {
		t.Fatalf("upload after refund: %d, want 200", c)
	}
}

// MEDIUM finding: the low-disk guard ignored uploads still being received.
func TestDiskGuardCountsInFlightUploads(t *testing.T) {
	const max = 64 << 20
	a := newTestApp(t, func(c *config) { c.MaxBytes = max })
	free, err := diskFree(a.filesDir)
	if err != nil {
		t.Skip("diskFree unsupported here")
	}
	// Room for one maximal upload plus half of another.
	a.cfg.MinFreeBytes = free - max*3/2
	if a.cfg.MinFreeBytes <= 0 {
		t.Skip("not enough free disk for this test")
	}
	finish := startHeldUpload(t, a)

	body, ct := multipartBody(t, "", "big.bin", "x")
	req := httptest.NewRequest("POST", "/api/upload", body)
	req.Header.Set("Content-Type", ct)
	req.ContentLength = max // announces a maximal file
	rec := httptest.NewRecorder()
	a.routes().ServeHTTP(rec, req)
	if rec.Code != http.StatusInsufficientStorage {
		t.Fatalf("second maximal upload: %d, want 507", rec.Code)
	}
	if code := finish(); code != 200 {
		t.Fatalf("held upload: %d", code)
	}
	if n := a.inFlight.Load(); n != 0 {
		t.Fatalf("inFlight after uploads = %d, want 0", n)
	}
}

// LOW finding: a lockout shared by all clients let anyone lock the admin out
// with 50 wrong passwords. Failures from other clients must not block the
// admin; the 16-character minimum is what defeats distributed guessing.
func TestAdminNotLockedOutByOtherClients(t *testing.T) {
	a := newTestApp(t, nil)
	h := a.routes()
	try := func(remote, pw string) int {
		req := httptest.NewRequest("GET", "/api/admin/uploads", nil)
		req.RemoteAddr = remote
		req.Header.Set("Authorization", "Bearer "+pw)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec.Code
	}
	for i := range 200 {
		remote := fmt.Sprintf("[2001:db8:%x::1]:443", i) // a new /64 each time
		for range 10 {
			try(remote, "wrong")
		}
	}
	if c := try("198.51.100.7:4000", a.cfg.AdminPassword); c != http.StatusOK {
		t.Fatalf("admin after 2000 failures from other clients: %d, want 200", c)
	}
}

func TestShortAdminPasswordDisablesAdmin(t *testing.T) {
	t.Setenv("ADMIN_PASSWORD_FILE", "")
	t.Setenv("ADMIN_PASSWORD", "hunter2")
	if pw := loadConfig().AdminPassword; pw != "" {
		t.Fatalf("short password accepted")
	}
	t.Setenv("ADMIN_PASSWORD", "0123456789abcdef")
	if pw := loadConfig().AdminPassword; pw != "0123456789abcdef" {
		t.Fatalf("16-char password rejected")
	}
}

func doPut(h http.Handler, target, content string) *httptest.ResponseRecorder {
	req := httptest.NewRequest("PUT", target, strings.NewReader(content))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestPutUploadReturnsPlainURL(t *testing.T) {
	a := newTestApp(t, nil)
	h := a.routes()
	uuid := "0123456789abcdef"
	rec := doPut(h, "/report%20final.txt?uuid="+uuid, "hello curl")
	if rec.Code != 200 {
		t.Fatalf("status %d: %s", rec.Code, rec.Body)
	}
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/plain") {
		t.Fatalf("content type %q", ct)
	}
	u, err := url.Parse(strings.TrimSuffix(rec.Body.String(), "\n"))
	if err != nil || !strings.HasSuffix(rec.Body.String(), "\n") {
		t.Fatalf("body %q", rec.Body)
	}
	if !regexp.MustCompile(`^/files/[A-Za-z0-9_-]{22}/report final\.txt$`).MatchString(u.Path) {
		t.Fatalf("path %q", u.Path)
	}
	if got := get(h, u.EscapedPath()); got.Body.String() != "hello curl" {
		t.Fatalf("download %q", got.Body)
	}
	hist := get(h, "/api/history?uuid="+uuid)
	if !strings.Contains(hist.Body.String(), "report final.txt") {
		t.Fatalf("history %s", hist.Body)
	}
}

func TestPutStdinGetsDefaultName(t *testing.T) {
	a := newTestApp(t, nil)
	h := a.routes()
	for _, target := range []string{"/", "/-"} {
		rec := doPut(h, target, "x")
		if rec.Code != 200 || !strings.HasSuffix(strings.TrimSpace(rec.Body.String()), "/file") {
			t.Fatalf("%s: %d %q", target, rec.Code, rec.Body)
		}
	}
}

func TestPutRejectsOversizeAndBadUUID(t *testing.T) {
	a := newTestApp(t, nil)
	h := a.routes()
	if rec := doPut(h, "/big.bin", strings.Repeat("x", int(a.cfg.MaxBytes)+1)); rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversize: %d", rec.Code)
	}
	if rec := doPut(h, "/a.txt?uuid=../x", "x"); rec.Code != http.StatusBadRequest {
		t.Fatalf("bad uuid: %d", rec.Code)
	}
	entries, _ := os.ReadDir(a.filesDir)
	if len(entries) != 0 {
		t.Fatalf("left behind %d entries", len(entries))
	}
}

func TestPutCountsTowardRateLimit(t *testing.T) {
	a := newTestApp(t, func(c *config) { c.UploadsPerHour = 1 })
	h := a.routes()
	if rec := doPut(h, "/a.txt", "x"); rec.Code != 200 {
		t.Fatalf("first: %d", rec.Code)
	}
	if rec := doPut(h, "/b.txt", "x"); rec.Code != http.StatusTooManyRequests {
		t.Fatalf("second: %d", rec.Code)
	}
}

// Names come from the URL path, where %2F decodes to "/": they must still end
// up as one canonical file name inside a fresh token directory.
func TestPutNameCannotEscapeTokenDir(t *testing.T) {
	a := newTestApp(t, nil)
	h := a.routes()
	cases := map[string]string{
		"/..%2F..%2Fevil.txt": "evil.txt",
		"/%2E%2E":             "file",
		"/a%5Cb.txt":          "b.txt",
		"/x%E2%80%AEtxt.exe":  "xtxt.exe", // U+202E (RLO) stripped
		"/%0Aname.txt":        "name.txt",
	}
	for target, want := range cases {
		rec := doPut(h, target, "x")
		if rec.Code != 200 {
			t.Fatalf("%s: %d %s", target, rec.Code, rec.Body)
		}
		u, _ := url.Parse(strings.TrimSpace(rec.Body.String()))
		parts := strings.Split(strings.TrimPrefix(u.Path, "/files/"), "/")
		if len(parts) != 2 || !reToken.MatchString(parts[0]) || parts[1] != want {
			t.Errorf("%s: stored as %q, want <token>/%s", target, u.Path, want)
		}
	}
	entries, _ := os.ReadDir(a.filesDir)
	if len(entries) != len(cases) {
		t.Fatalf("files dir has %d entries, want %d token dirs", len(entries), len(cases))
	}
	for _, e := range entries {
		if !e.IsDir() || !reToken.MatchString(e.Name()) {
			t.Errorf("unexpected entry %q", e.Name())
		}
	}
}

// Without Content-Length (chunked, e.g. curl -T - from a pipe) the size limit
// is enforced while streaming, and the reserved byte budget is refunded.
func TestPutChunkedOversizeRefundsBudget(t *testing.T) {
	a := newTestApp(t, func(c *config) { c.UploadMBPerHour = 1; c.MinFreeBytes = 1 })
	h := a.routes()
	req := httptest.NewRequest("PUT", "/big.bin", io.MultiReader(strings.NewReader(strings.Repeat("x", int(a.cfg.MaxBytes)+1))))
	req.ContentLength = -1
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status %d, want 413", rec.Code)
	}
	if entries, _ := os.ReadDir(a.filesDir); len(entries) != 0 {
		t.Fatalf("files left behind: %v", entries)
	}
	if n := a.inFlight.Load(); n != 0 {
		t.Fatalf("in-flight reservation leaked: %d", n)
	}
	// The failed upload used none of the hourly budget, so a full-size one fits.
	if rec := doPut(h, "/full.bin", strings.Repeat("x", int(a.cfg.MaxBytes))); rec.Code != 200 {
		t.Fatalf("full-budget upload after refund: %d %s", rec.Code, rec.Body)
	}
	if rec := doPut(h, "/more.bin", "x"); rec.Code != http.StatusTooManyRequests {
		t.Fatalf("over budget: %d, want 429", rec.Code)
	}
}

func TestPutLowDiskRefused(t *testing.T) {
	a := newTestApp(t, func(c *config) { c.MinFreeBytes = 1 << 62 })
	if _, err := diskFree(a.filesDir); err != nil {
		t.Skip("diskFree unsupported here")
	}
	if rec := doPut(a.routes(), "/a.txt", "x"); rec.Code != http.StatusInsufficientStorage {
		t.Fatalf("low disk: %d, want 507", rec.Code)
	}
	if entries, _ := os.ReadDir(a.filesDir); len(entries) != 0 {
		t.Errorf("file written despite refusal")
	}
	if n := a.inFlight.Load(); n != 0 {
		t.Fatalf("in-flight reservation leaked: %d", n)
	}
}

// A client that disconnects mid-body must leave no file and no history entry.
func TestPutAbortedLeavesNothingBehind(t *testing.T) {
	a := newTestApp(t, nil)
	srv := httptest.NewServer(a.routes())
	defer srv.Close()
	conn, err := net.Dial("tcp", srv.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	fmt.Fprintf(conn, "PUT /cut.bin?uuid=aborted-put-1234 HTTP/1.1\r\nHost: x\r\nContent-Length: 65536\r\n\r\n%s", strings.Repeat("x", 1000))
	time.Sleep(100 * time.Millisecond) // let the handler start writing
	conn.Close()
	deadline := time.Now().Add(5 * time.Second)
	for {
		entries, _ := os.ReadDir(a.filesDir)
		if len(entries) == 0 && a.inFlight.Load() == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("left behind after abort: %v", entries)
		}
		time.Sleep(20 * time.Millisecond)
	}
	if h := get(a.routes(), "/api/history?uuid=aborted-put-1234"); strings.Contains(h.Body.String(), "cut.bin") {
		t.Fatalf("aborted upload listed: %s", h.Body)
	}
}

// PUT is not a CORS-simple method, so browsers on other sites must preflight;
// the preflight must not be granted, or any website could upload as a visitor.
func TestPutNotAllowedCrossOrigin(t *testing.T) {
	a := newTestApp(t, nil)
	req := httptest.NewRequest("OPTIONS", "/a.txt", nil)
	req.Header.Set("Origin", "https://evil.example")
	req.Header.Set("Access-Control-Request-Method", "PUT")
	rec := httptest.NewRecorder()
	a.routes().ServeHTTP(rec, req)
	if v := rec.Header().Get("Access-Control-Allow-Origin"); v != "" {
		t.Fatalf("preflight granted: Access-Control-Allow-Origin %q", v)
	}
}

// curl -T sends Expect: 100-continue for larger files; a declared oversize
// body is refused without consuming any budget.
func TestPutDeclaredOversizeRefusedUpfront(t *testing.T) {
	a := newTestApp(t, func(c *config) { c.UploadsPerHour = 1 })
	h := a.routes()
	req := httptest.NewRequest("PUT", "/big.bin", strings.NewReader("x"))
	req.ContentLength = a.cfg.MaxBytes + 1
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status %d, want 413", rec.Code)
	}
	if rec := doPut(h, "/ok.txt", "x"); rec.Code != 200 {
		t.Fatalf("refused upload counted against rate limit: %d", rec.Code)
	}
}

func TestMediaNavigationGetsPlayerPage(t *testing.T) {
	a := newTestApp(t, nil)
	h := a.routes()
	_, res := doUpload(t, h, "", `clip "<b>".mp4`, "videobytes")
	u, _ := url.Parse(res.URL)
	p := u.EscapedPath()

	page := get(h, p, "Sec-Fetch-Dest", "document")
	body := page.Body.String()
	if page.Code != 200 || !strings.HasPrefix(page.Header().Get("Content-Type"), "text/html") {
		t.Fatalf("player page: %d %q", page.Code, page.Header().Get("Content-Type"))
	}
	if !strings.Contains(body, "<video") || !strings.Contains(body, "?dl") || strings.Contains(body, "<b>") {
		t.Fatalf("player page body: %s", body)
	}
	if csp := page.Header().Get("Content-Security-Policy"); !strings.HasPrefix(csp, "default-src 'none';") || strings.Contains(csp, "script") {
		t.Errorf("player CSP %q", csp)
	}
	if !strings.Contains(page.Header().Get("Vary"), "Sec-Fetch-Dest") {
		t.Errorf("missing Vary")
	}

	// The <video> element, curl/ShareX and ?raw get the bytes.
	for _, r := range []*httptest.ResponseRecorder{
		get(h, p, "Sec-Fetch-Dest", "video"),
		get(h, p),
		get(h, p+"?raw", "Sec-Fetch-Dest", "document"),
	} {
		if r.Body.String() != "videobytes" || r.Header().Get("Content-Type") != "video/mp4" || r.Header().Get("Content-Disposition") != "" {
			t.Errorf("raw: %q %q", r.Header().Get("Content-Type"), r.Body)
		}
	}

	dl := get(h, p+"?dl", "Sec-Fetch-Dest", "document")
	if dl.Body.String() != "videobytes" || !strings.HasPrefix(dl.Header().Get("Content-Disposition"), "attachment;") {
		t.Errorf("download: %q %q", dl.Header().Get("Content-Disposition"), dl.Body)
	}

	// Audio gets an <audio> player; non-media files are unaffected.
	_, res = doUpload(t, h, "", "song.MP3", "x")
	u, _ = url.Parse(res.URL)
	if r := get(h, u.EscapedPath(), "Sec-Fetch-Dest", "document"); !strings.Contains(r.Body.String(), "<audio") {
		t.Errorf("audio page: %s", r.Body)
	}
	_, res = doUpload(t, h, "", "a.png", "png")
	u, _ = url.Parse(res.URL)
	if r := get(h, u.EscapedPath(), "Sec-Fetch-Dest", "document"); r.Body.String() != "png" || r.Header().Get("Vary") != "" {
		t.Errorf("png: %q", r.Body)
	}
}

func TestHumanSize(t *testing.T) {
	for n, want := range map[int64]string{0: "0 B", 1023: "1023 B", 1536: "1,5 KB", 5 << 20: "5,0 MB"} {
		if got := humanSize(n); got != want {
			t.Errorf("humanSize(%d) = %q, want %q", n, got, want)
		}
	}
}

func adminReq(method, target, body string, hdr ...string) *http.Request {
	req := httptest.NewRequest(method, target, strings.NewReader(body))
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	for i := 0; i+1 < len(hdr); i += 2 {
		req.Header.Set(hdr[i], hdr[i+1])
	}
	return req
}

func TestAdminSessionCookie(t *testing.T) {
	a := newTestApp(t, nil)
	h := a.routes()
	serve := func(req *http.Request) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec
	}

	if r := serve(adminReq("POST", "/api/admin/login", `{"password":"wrong"}`)); r.Code != 401 || len(r.Result().Cookies()) != 0 {
		t.Fatalf("wrong password: %d %v", r.Code, r.Result().Cookies())
	}
	login := serve(adminReq("POST", "/api/admin/login", `{"password":"`+a.cfg.AdminPassword+`"}`))
	cs := login.Result().Cookies()
	if login.Code != 200 || len(cs) != 1 {
		t.Fatalf("login: %d %v", login.Code, cs)
	}
	c := cs[0]
	if c.Name != adminCookie || !c.HttpOnly || c.SameSite != http.SameSiteStrictMode || c.Path != "/api/admin" || c.MaxAge < 7*86400 {
		t.Fatalf("cookie attributes: %+v", c)
	}

	withCookie := func(req *http.Request) *http.Request { req.AddCookie(c); return req }
	if r := serve(withCookie(adminReq("GET", "/api/admin/uploads", ""))); r.Code != 200 {
		t.Fatalf("list with cookie: %d", r.Code)
	}
	if r := serve(withCookie(adminReq("POST", "/api/admin/cleanup", "{}", "Sec-Fetch-Site", "same-origin"))); r.Code != 200 {
		t.Fatalf("same-origin cleanup: %d %s", r.Code, r.Body)
	}
	// CSRF: another site's form/fetch carries the cookie but must be refused.
	if r := serve(withCookie(adminReq("POST", "/api/admin/cleanup", "{}", "Sec-Fetch-Site", "cross-site"))); r.Code != 403 {
		t.Fatalf("cross-site cleanup: %d", r.Code)
	}

	// Tampered, expired or old-password cookies are rejected without
	// counting toward the lockout.
	now := time.Now()
	for name, v := range map[string]string{
		"tampered": "9" + c.Value,
		"expired":  a.newSession(now.Add(-adminSessionTTL - time.Minute)),
		"garbage":  "x",
	} {
		req := adminReq("GET", "/api/admin/uploads", "")
		req.AddCookie(&http.Cookie{Name: adminCookie, Value: v})
		if r := serve(req); r.Code != 401 {
			t.Errorf("%s cookie: %d", name, r.Code)
		}
	}
	old := a.newSession(now)
	a.cfg.AdminPassword = "a different password, 32+ chars"
	if a.validSession(old, now) {
		t.Errorf("session survived password change")
	}
	for range 20 {
		req := adminReq("GET", "/api/admin/uploads", "")
		req.AddCookie(&http.Cookie{Name: adminCookie, Value: "x.y"})
		serve(req)
	}
	if r := serve(adminReq("GET", "/api/admin/uploads", "", "Authorization", "Bearer "+a.cfg.AdminPassword)); r.Code != 200 {
		t.Fatalf("bad cookies locked the admin out: %d", r.Code)
	}

	out := serve(adminReq("POST", "/api/admin/logout", "{}"))
	if cs := out.Result().Cookies(); len(cs) != 1 || cs[0].MaxAge >= 0 {
		t.Fatalf("logout did not clear cookie: %v", cs)
	}
}

// MEDIUM finding: any website could make its visitors' browsers upload here,
// each with its own per-IP quota. Cross-site uploads are now refused before
// any quota is charged; the web UI (same-origin) and ShareX/curl (no
// browser headers) still work.
func TestCrossSiteUploadRefused(t *testing.T) {
	a := newTestApp(t, nil)
	h := a.routes()
	post := func(path string, hdr ...string) *httptest.ResponseRecorder {
		body, ct := multipartBody(t, "", "x.txt", "x")
		req := httptest.NewRequest("POST", path, body)
		req.Header.Set("Content-Type", ct)
		for i := 0; i+1 < len(hdr); i += 2 {
			req.Header.Set(hdr[i], hdr[i+1])
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec
	}
	for _, p := range []string{"/api/upload", "/upload.php"} {
		if r := post(p, "Sec-Fetch-Site", "cross-site", "Origin", "https://evil.example"); r.Code != http.StatusForbidden {
			t.Fatalf("%s cross-site: got %d, want 403", p, r.Code)
		}
		if r := post(p, "Origin", "https://evil.example"); r.Code != http.StatusForbidden {
			t.Fatalf("%s foreign Origin without Sec-Fetch-Site: got %d, want 403", p, r.Code)
		}
		if r := post(p, "Sec-Fetch-Site", "same-origin", "Origin", "http://example.com"); r.Code != http.StatusOK {
			t.Fatalf("%s same-origin: got %d %s", p, r.Code, r.Body)
		}
		if r := post(p); r.Code != http.StatusOK { // ShareX / curl
			t.Fatalf("%s without browser headers: got %d %s", p, r.Code, r.Body)
		}
	}
}

// HTML uploads are always downloaded, never rendered on our domain, so they
// can't serve as a phishing page. Other types still open inline.
func TestHTMLUploadsAlwaysDownloaded(t *testing.T) {
	a := newTestApp(t, nil)
	h := a.routes()
	for _, name := range []string{"page.html", "PAGE.HTM"} {
		rec, res := doUpload(t, h, "", name, "<h1>hi</h1>")
		if rec.Code != http.StatusOK {
			t.Fatalf("upload %s: %d %s", name, rec.Code, rec.Body)
		}
		u, _ := url.Parse(res.URL)
		r := get(h, u.EscapedPath(), "Sec-Fetch-Dest", "document")
		if cd := r.Header().Get("Content-Disposition"); !strings.HasPrefix(cd, "attachment") {
			t.Fatalf("%s: Content-Disposition %q, want attachment", name, cd)
		}
	}
	rec, res := doUpload(t, h, "", "note.txt", "hi")
	if rec.Code != http.StatusOK {
		t.Fatalf("upload txt: %d", rec.Code)
	}
	u, _ := url.Parse(res.URL)
	if cd := get(h, u.EscapedPath()).Header().Get("Content-Disposition"); cd != "" {
		t.Fatalf("txt: Content-Disposition %q, want inline", cd)
	}
}

func TestManifestHasShareTarget(t *testing.T) {
	h := newTestApp(t, nil).routes()
	rec := get(h, "/manifest.json")
	if rec.Code != 200 || !strings.HasPrefix(rec.Header().Get("Content-Type"), "application/manifest+json") {
		t.Fatalf("manifest: %d %q", rec.Code, rec.Header().Get("Content-Type"))
	}
	var m struct {
		StartURL string `json:"start_url"`
		Display  string `json:"display"`
		Icons    []struct {
			Src   string `json:"src"`
			Sizes string `json:"sizes"`
		} `json:"icons"`
		ShareTarget struct {
			Action  string `json:"action"`
			Method  string `json:"method"`
			Enctype string `json:"enctype"`
			Params  struct {
				Title string `json:"title"`
				Text  string `json:"text"`
				URL   string `json:"url"`
				Files []struct {
					Name   string   `json:"name"`
					Accept []string `json:"accept"`
				} `json:"files"`
			} `json:"params"`
		} `json:"share_target"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &m); err != nil {
		t.Fatal(err)
	}
	st := m.ShareTarget
	if st.Action != "/share" || st.Method != "POST" || st.Enctype != "multipart/form-data" ||
		st.Params.Title != "title" || st.Params.Text != "text" || st.Params.URL != "url" || // names sw.js reads
		len(st.Params.Files) != 1 || st.Params.Files[0].Name != "files" || len(st.Params.Files[0].Accept) == 0 {
		t.Fatalf("share_target: %+v", st)
	}
	if m.StartURL != "/" || m.Display != "standalone" {
		t.Fatalf("start_url/display: %q %q", m.StartURL, m.Display)
	}
	sizes := map[string]bool{}
	for _, ic := range m.Icons {
		sizes[ic.Sizes] = true
		r := get(h, ic.Src)
		if r.Code != 200 || r.Header().Get("Content-Type") != "image/png" {
			t.Errorf("icon %s: %d %q", ic.Src, r.Code, r.Header().Get("Content-Type"))
		}
	}
	if !sizes["192x192"] || !sizes["512x512"] {
		t.Errorf("missing 192/512 icons: %v", sizes)
	}
	if !strings.Contains(get(h, "/").Body.String(), `rel="manifest" href="/manifest.json"`) {
		t.Error("index.html does not link the manifest")
	}
}

func TestServiceWorkerServed(t *testing.T) {
	rec := get(newTestApp(t, nil).routes(), "/sw.js")
	if rec.Code != 200 || !strings.Contains(rec.Header().Get("Content-Type"), "javascript") {
		t.Fatalf("sw.js: %d %q", rec.Code, rec.Header().Get("Content-Type"))
	}
	if rec.Header().Get("Cache-Control") != "no-cache" {
		t.Errorf("Cache-Control = %q", rec.Header().Get("Cache-Control"))
	}
	for _, want := range []string{`"/share"`, `"files"`, `"title"`, `"text"`, `"url"`, `"ul3-share"`} {
		if !strings.Contains(rec.Body.String(), want) {
			t.Errorf("sw.js does not mention %s", want)
		}
	}
	if app, _ := webFS.ReadFile("web/app.js"); !strings.Contains(string(app), `"ul3-share"`) {
		t.Error("app.js does not read the ul3-share cache")
	}
}

func TestShareFallbackStoresNothing(t *testing.T) {
	a := newTestApp(t, nil)
	body, ct := multipartBody(t, "11111111-2222-3333-4444-555555555555", "x.txt", "hello")
	req := httptest.NewRequest("POST", "/share", body)
	req.Header.Set("Content-Type", ct)
	rec := httptest.NewRecorder()
	a.routes().ServeHTTP(rec, req)
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/?share=failed" {
		t.Fatalf("got %d %q", rec.Code, rec.Header().Get("Location"))
	}
	all, err := a.store.ListAll(req.Context())
	if err != nil || len(all) != 0 {
		t.Fatalf("uploads after /share: %v %v", all, err)
	}
	if entries, _ := os.ReadDir(a.filesDir); len(entries) != 0 {
		t.Fatalf("files written: %d", len(entries))
	}
}

func TestTextFilesGetViewerPage(t *testing.T) {
	a := newTestApp(t, func(c *config) { c.MaxBytes = 8 << 20 })
	h := a.routes()
	_, res := doUpload(t, h, "", `n "<b>".txt`, "line1\r\n<script>alert(1)</script>\nline3\n")
	u, _ := url.Parse(res.URL)
	p := u.EscapedPath()

	page := get(h, p, "Sec-Fetch-Dest", "document")
	body := page.Body.String()
	if page.Code != 200 || !strings.HasPrefix(page.Header().Get("Content-Type"), "text/html") {
		t.Fatalf("viewer: %d %q", page.Code, page.Header().Get("Content-Type"))
	}
	if !strings.Contains(body, "3 Zeilen") || !strings.Contains(body, "?raw") || !strings.Contains(body, "?dl") ||
		!strings.Contains(body, "&lt;script&gt;alert(1)") || strings.Contains(body, "<b>") || strings.Contains(body, "<script>alert") {
		t.Fatalf("viewer body: %s", body)
	}
	if csp := page.Header().Get("Content-Security-Policy"); !strings.HasPrefix(csp, "default-src 'none';") ||
		!strings.Contains(csp, "script-src 'sha256-"+scriptHash(inlineScript(t, body))+"'") || strings.Contains(csp, "unsafe-eval") {
		t.Errorf("viewer CSP %q", csp)
	}
	if !strings.Contains(page.Header().Get("Vary"), "Sec-Fetch-Dest") || page.Header().Get("X-Content-Type-Options") != "nosniff" {
		t.Errorf("headers: %v", page.Header())
	}

	// ?raw, curl and fetch get the exact bytes as text/plain.
	for _, r := range []*httptest.ResponseRecorder{
		get(h, p+"?raw", "Sec-Fetch-Dest", "document"),
		get(h, p),
		get(h, p, "Sec-Fetch-Dest", "empty"),
	} {
		if r.Body.String() != "line1\r\n<script>alert(1)</script>\nline3\n" || r.Header().Get("Content-Type") != "text/plain; charset=utf-8" ||
			r.Header().Get("Content-Disposition") != "" || !strings.HasPrefix(r.Header().Get("Content-Security-Policy"), "sandbox") {
			t.Errorf("raw: %q %q %q", r.Header().Get("Content-Type"), r.Header().Get("Content-Security-Policy"), r.Body)
		}
	}
	dl := get(h, p+"?dl", "Sec-Fetch-Dest", "document")
	if !strings.HasPrefix(dl.Header().Get("Content-Disposition"), "attachment") || strings.Contains(dl.Body.String(), "<html") {
		t.Errorf("dl: %q", dl.Header().Get("Content-Disposition"))
	}

	// Binary content under a text name falls back to a download.
	for name, content := range map[string]string{"nul.txt": "a\x00b", "latin.log": "caf\xe9"} {
		_, res := doUpload(t, h, "", name, content)
		u, _ := url.Parse(res.URL)
		r := get(h, u.EscapedPath(), "Sec-Fetch-Dest", "document")
		if r.Body.String() != content || !strings.HasPrefix(r.Header().Get("Content-Disposition"), "attachment") {
			t.Errorf("%s: %q %q", name, r.Header().Get("Content-Disposition"), r.Body)
		}
	}

	// Large files show only the beginning; the buttons stay.
	_, res = doUpload(t, h, "", "big.log", strings.Repeat("0123456789abcdef\n", 70000))
	u, _ = url.Parse(res.URL)
	r := get(h, u.EscapedPath(), "Sec-Fetch-Dest", "document")
	if r.Code != 200 || !strings.Contains(r.Body.String(), "Große Datei") || !strings.Contains(r.Body.String(), "?dl") || r.Body.Len() > 2<<20 {
		t.Errorf("oversize: %d %d", r.Code, r.Body.Len())
	}

	// HTML never gets a viewer.
	_, res = doUpload(t, h, "", "page.html", "<h1>x</h1>")
	u, _ = url.Parse(res.URL)
	r = get(h, u.EscapedPath(), "Sec-Fetch-Dest", "document")
	if !strings.HasPrefix(r.Header().Get("Content-Disposition"), "attachment") || r.Body.String() != "<h1>x</h1>" {
		t.Errorf("html: %q", r.Header().Get("Content-Disposition"))
	}
	if opensInline("page.html") || !opensInline("a.csv") || !opensInline("Makefile") || opensInline("x.unknwn") {
		t.Errorf("opensInline mismatch")
	}
}

func TestCSVViewerTable(t *testing.T) {
	a := newTestApp(t, nil)
	h := a.routes()
	_, res := doUpload(t, h, "", "d.csv", "name,note\n\"Mu, \"\"M\"\"\",\"two\nlines\"\n<i>,x\n")
	u, _ := url.Parse(res.URL)
	body := get(h, u.EscapedPath(), "Sec-Fetch-Dest", "document").Body.String()
	for _, want := range []string{"<th>name</th>", "<td>Mu, &#34;M&#34;</td>", "<td>two\nlines</td>", "<td>&lt;i&gt;</td>", `data-view="tbl"`} {
		if !strings.Contains(body, want) {
			t.Errorf("missing %q in %s", want, body)
		}
	}
}

func TestMarkdownViewerIsSafe(t *testing.T) {
	a := newTestApp(t, nil)
	h := a.routes()
	md := "# Title\n\n| a | b |\n|---|---|\n| 1 | ~~2~~ |\n\n- [x] done\n\nhttps://example.com/auto\n\n" +
		"<script>alert(1)</script>\n\n<img src=x onerror=alert(2)>\n\n<iframe src=\"https://evil.example\"></iframe>\n\n" +
		"[x](javascript:alert(3)) [y](JaVaScRiPt:alert(4)) [z](data:text/html;base64,PHNjcmlwdD4=)\n\n![i](javascript:alert(5))\n"
	_, res := doUpload(t, h, "", "r.md", md)
	u, _ := url.Parse(res.URL)
	page := get(h, u.EscapedPath(), "Sec-Fetch-Dest", "document")
	body := page.Body.String()
	for _, want := range []string{"<h1>Title</h1>", "<table>", "<del>2</del>", `type="checkbox"`, `href="https://example.com/auto"`, `data-view="md"`} {
		if !strings.Contains(body, want) {
			t.Errorf("missing %q", want)
		}
	}
	// Only the viewer's own script may exist; no raw HTML from the markdown survives.
	if strings.Count(body, "<script") != 1 {
		t.Errorf("unexpected script tags: %d", strings.Count(body, "<script"))
	}
	rendered := body[strings.Index(body, `id="md"`):strings.Index(body, `id="txt"`)]
	rendered = strings.ReplaceAll(rendered, `<img src="" alt="i">`, "") // markdown image with neutralised target
	for _, bad := range []string{"<script", "<img", "<iframe", "onerror=\"", "onerror=a", "javascript:alert", "JaVaScRiPt:", "data:text/html"} {
		if strings.Contains(rendered, bad) {
			t.Errorf("rendered markdown contains %q:\n%s", bad, rendered)
		}
	}
	csp := page.Header().Get("Content-Security-Policy")
	if !strings.Contains(csp, "img-src 'self' data:") || strings.Contains(csp, "https:") || strings.Contains(csp, "unsafe-inline'; img") || strings.Contains(csp, "script-src 'unsafe") {
		t.Errorf("CSP %q", csp)
	}
	if raw := get(h, u.EscapedPath()+"?raw", "Sec-Fetch-Dest", "document"); raw.Body.String() != md {
		t.Errorf("raw markdown altered")
	}
}

// inlineScript returns the body of the page's only <script>, byte for byte.
func inlineScript(t *testing.T, body string) string {
	t.Helper()
	i := strings.Index(body, "<script>")
	j := strings.Index(body, "</script>")
	if i < 0 || j < i || strings.Count(body, "<script") != 1 {
		t.Fatalf("expected exactly one inline script")
	}
	return body[i+len("<script>") : j]
}

func viewerPage(t *testing.T, h http.Handler, name, content string) (string, *httptest.ResponseRecorder) {
	t.Helper()
	_, res := doUpload(t, h, "", name, content)
	u, _ := url.Parse(res.URL)
	r := get(h, u.EscapedPath(), "Sec-Fetch-Dest", "document")
	return r.Body.String(), r
}

func TestMarkdownLinkVectorsNeutralised(t *testing.T) {
	a := newTestApp(t, nil)
	h := a.routes()
	body, _ := viewerPage(t, h, "v.md", "<javascript:alert(1)>\n\n[a][ref] [b]( javascript:alert(2) ) [c](java&#115;cript:alert(3))\n\n[d](javascript&#58;alert(4))\n\n<vbscript:x> <data:text/html,x>\n\n[ref]: javascript:alert(5)\n")
	rendered := body[strings.Index(body, `id="md"`):strings.Index(body, `id="txt"`)]
	// Visible text may mention the scheme; no link target or tag may carry it.
	for _, m := range regexp.MustCompile(`(?i)\s(?:href|src)="([^"]*)"`).FindAllStringSubmatch(rendered, -1) {
		if v := strings.ToLower(m[1]); v != "" && !strings.HasPrefix(v, "http") {
			t.Errorf("unexpected link target %q in:\n%s", m[1], rendered)
		}
	}
	for _, bad := range []string{"<script", "<img", "<iframe", " onerror", " onclick"} {
		if strings.Contains(strings.ToLower(rendered), bad) {
			t.Errorf("rendered markdown contains %q:\n%s", bad, rendered)
		}
	}
	if !strings.Contains(rendered, `<a href="">`) {
		t.Errorf("expected neutralised links:\n%s", rendered)
	}
}

func TestMarkdownSizeCapAndTimeBudget(t *testing.T) {
	a := newTestApp(t, func(c *config) { c.MaxBytes = 8 << 20 })
	h := a.routes()
	for name, src := range map[string]string{
		"link.md": strings.Repeat("[a](<", 20000),
		"gt.md":   strings.Repeat(">", 30000),
		"huge.md": strings.Repeat(">", 300000), // over the cap: must not be rendered at all
	} {
		start := time.Now()
		body, r := viewerPage(t, h, name, src)
		if d := time.Since(start); d > 5*time.Second {
			t.Errorf("%s: took %v", name, d)
		}
		if r.Code != 200 || !strings.Contains(body, "?dl") {
			t.Errorf("%s: %d", name, r.Code)
		}
		if name == "huge.md" && (strings.Contains(body, `id="md"`) || !strings.Contains(body, "nicht gerendert")) {
			t.Errorf("%s: oversized markdown was rendered or no notice", name)
		}
	}
	if renderMarkdown(strings.Repeat("x", markdownMaxBytes+1)) != "" {
		t.Errorf("cap not applied")
	}
	// A busy renderer falls back to the source instead of waiting.
	markdownSlots <- struct{}{}
	markdownSlots <- struct{}{}
	defer func() { <-markdownSlots; <-markdownSlots }()
	if body, _ := viewerPage(t, h, "busy.md", "# hi"); strings.Contains(body, `id="md"`) || !strings.Contains(body, "# hi") {
		t.Errorf("busy fallback")
	}
}

func TestCSVRowCapNotice(t *testing.T) {
	a := newTestApp(t, nil)
	h := a.routes()
	var sb strings.Builder
	sb.WriteString("a,b\n")
	for i := 0; i < viewerMaxRows+10; i++ {
		sb.WriteString("1,2\n")
	}
	body, _ := viewerPage(t, h, "big.csv", sb.String())
	if !strings.Contains(body, "Die Tabelle zeigt nur die ersten 5000 Zeilen") {
		t.Errorf("missing CSV cap notice")
	}
	if body, _ := viewerPage(t, h, "small.csv", "a,b\n1,2\n"); strings.Contains(body, "Die Tabelle zeigt nur") {
		t.Errorf("unexpected notice")
	}
}

func TestJSONRawKeepsType(t *testing.T) {
	a := newTestApp(t, nil)
	h := a.routes()
	_, res := doUpload(t, h, "", "d.json", `{"a":1}`)
	u, _ := url.Parse(res.URL)
	if r := get(h, u.EscapedPath()); r.Header().Get("Content-Type") != "application/json" || !strings.HasPrefix(r.Header().Get("Content-Security-Policy"), "sandbox") {
		t.Errorf("json raw: %q", r.Header().Get("Content-Type"))
	}
	if body, r := viewerPage(t, h, "d2.json", `{"a":1}`); !strings.HasPrefix(r.Header().Get("Content-Type"), "text/html") || !strings.Contains(body, "&#34;a&#34;") {
		t.Errorf("json viewer missing")
	}
	_, res = doUpload(t, h, "", "d.xml", "<a/>")
	u, _ = url.Parse(res.URL)
	if r := get(h, u.EscapedPath()); r.Header().Get("Content-Type") != "text/plain; charset=utf-8" {
		t.Errorf("xml raw: %q", r.Header().Get("Content-Type"))
	}
}

func TestTextNames(t *testing.T) {
	for _, n := range []string{".gitignore", ".editorconfig", ".bashrc", "LICENSE", "README", "Jenkinsfile", "Gemfile", "Dockerfile.dev", "Containerfile.x", "go.mod", "go.sum", "a.lock", "a.proto", "a.tf", "a.nix", "a.gql"} {
		if !isTextFile(n) {
			t.Errorf("%s not text", n)
		}
	}
	for _, n := range []string{"a.html", "a.svg", "a.png", "a.bin", "licensed.exe"} {
		if isTextFile(n) {
			t.Errorf("%s is text", n)
		}
	}
}

func TestViewerSingularLineAndCopyLimit(t *testing.T) {
	a := newTestApp(t, func(c *config) { c.MaxBytes = 16 << 20 })
	h := a.routes()
	body, _ := viewerPage(t, h, "one.log", strings.Repeat("x", viewerMaxBytes+10))
	if strings.Contains(body, "ersten 1 Zeilen") || !strings.Contains(body, "id=\"copy\"") {
		t.Errorf("grammar/copy: %s", body[:300])
	}
	body, _ = viewerPage(t, h, "huge.log", strings.Repeat("0123456789abcdef\n", (viewerMaxCopy/17)+1000))
	if strings.Contains(body, `id="copy"`) {
		t.Errorf("copy button shown for huge file")
	}
}
