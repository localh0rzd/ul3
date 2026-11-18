// ul3 – a small anonymous file upload service.
package main

import (
	"context"
	"embed"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

//go:embed web
var webFS embed.FS

type config struct {
	Listen        string
	DataDir       string
	PublicURL     string // optional, e.g. https://ul.example.com
	MaxBytes      int64
	Retention     time.Duration
	AdminPassword string
	CleanupEvery  time.Duration

	UploadsPerHour  int64 // per client; 0 = unlimited
	UploadMBPerHour int64 // per client; 0 = unlimited
	MinFreeBytes    int64 // refuse uploads below this much free disk; 0 = off
	UploadTimeout   time.Duration
	TrustedProxies  []netip.Prefix
}

// minAdminPasswordLen: shorter passwords disable the admin area, because
// brute-force limits alone cannot protect a guessable password.
const minAdminPasswordLen = 16

func env(key, def string) string {
	if v, ok := os.LookupEnv(key); ok && v != "" {
		return v
	}
	return def
}

func envInt(key string, def int64) int64 {
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.ParseInt(v, 10, 64); err == nil && n > 0 {
			return n
		}
		slog.Warn("ignoring invalid integer env var", "key", key, "value", v)
	}
	return def
}

// envNonNeg is envInt but also accepts 0 (used to switch a limit off).
func envNonNeg(key string, def int64) int64 {
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.ParseInt(v, 10, 64); err == nil && n >= 0 {
			return n
		}
		slog.Warn("ignoring invalid integer env var", "key", key, "value", v)
	}
	return def
}

func loadConfig() config {
	adminPw := os.Getenv("ADMIN_PASSWORD")
	if f := os.Getenv("ADMIN_PASSWORD_FILE"); f != "" {
		b, err := os.ReadFile(f)
		if err != nil {
			slog.Error("cannot read ADMIN_PASSWORD_FILE", "err", err)
			os.Exit(1)
		}
		adminPw = strings.TrimSpace(string(b))
	}
	if adminPw != "" && len(adminPw) < minAdminPasswordLen {
		slog.Error("ADMIN_PASSWORD is shorter than 16 characters – admin area disabled; use e.g. `openssl rand -base64 24`")
		adminPw = ""
	}
	trusted, err := parseTrustedProxies(env("TRUSTED_PROXIES", defaultTrustedProxies))
	if err != nil {
		slog.Error("config", "err", err)
		os.Exit(1)
	}
	if len(trusted) == 0 {
		slog.Info("TRUSTED_PROXIES not set: X-Forwarded-For is ignored; behind a reverse proxy set it to the proxy's network, or all clients share one rate limit")
	}
	return config{
		Listen:        env("LISTEN", ":8080"),
		DataDir:       env("DATA_DIR", "/data"),
		PublicURL:     strings.TrimRight(os.Getenv("PUBLIC_URL"), "/"),
		MaxBytes:      envInt("MAX_UPLOAD_MB", 100) << 20,
		Retention:     time.Duration(envInt("RETENTION_DAYS", 7)) * 24 * time.Hour,
		AdminPassword: adminPw,
		CleanupEvery:  time.Duration(envInt("CLEANUP_INTERVAL_MINUTES", 60)) * time.Minute,

		UploadsPerHour:  envNonNeg("UPLOADS_PER_HOUR", 120),
		UploadMBPerHour: envNonNeg("UPLOAD_MB_PER_HOUR", 2048),
		MinFreeBytes:    envNonNeg("MIN_FREE_MB", 1024) << 20,
		UploadTimeout:   time.Duration(envInt("UPLOAD_TIMEOUT_MINUTES", 30)) * time.Minute,
		TrustedProxies:  trusted,
	}
}

func main() {
	healthcheck := flag.Bool("healthcheck", false, "probe the local server and exit (for Docker HEALTHCHECK)")
	flag.Parse()

	cfg := loadConfig()
	if *healthcheck {
		os.Exit(runHealthcheck(cfg.Listen))
	}

	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stdout, nil)))

	filesDir := filepath.Join(cfg.DataDir, "files")
	if err := os.MkdirAll(filesDir, 0o755); err != nil {
		slog.Error("create files dir", "err", err)
		os.Exit(1)
	}
	st, err := openStore(filepath.Join(cfg.DataDir, "uploads.db"))
	if err != nil {
		slog.Error("open database", "err", err)
		os.Exit(1)
	}
	defer st.Close()

	files, err := os.OpenRoot(filesDir)
	if err != nil {
		slog.Error("open files dir", "err", err)
		os.Exit(1)
	}

	app := newApp(cfg, st, files, filesDir)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	go app.cleanupLoop(ctx)

	srv := &http.Server{
		Addr:              cfg.Listen,
		Handler:           app.routes(),
		ReadHeaderTimeout: 15 * time.Second,
		ReadTimeout:       time.Minute, // uploads extend this per request (UPLOAD_TIMEOUT_MINUTES)
		IdleTimeout:       2 * time.Minute,
	}
	go func() {
		<-ctx.Done()
		shCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		_ = srv.Shutdown(shCtx)
	}()

	slog.Info("ul3 listening", "addr", cfg.Listen, "data", cfg.DataDir,
		"max_upload_mb", cfg.MaxBytes>>20, "retention", cfg.Retention, "admin", cfg.AdminPassword != "")
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		slog.Error("server", "err", err)
		os.Exit(1)
	}
}

func runHealthcheck(listen string) int {
	addr := listen
	if strings.HasPrefix(addr, ":") {
		addr = "127.0.0.1" + addr
	}
	c := http.Client{Timeout: 3 * time.Second}
	resp, err := c.Get("http://" + addr + "/healthz")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return 1
	}
	return 0
}
