package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// Admin sessions are stateless: the cookie holds its expiry and an HMAC over
// it, keyed with a hash of the admin password. They survive restarts, and
// changing ADMIN_PASSWORD signs every session out.
const (
	adminCookie     = "ul3_admin"
	adminSessionTTL = 30 * 24 * time.Hour
)

// The cookie is only sent to the admin API; the page itself is public.
const adminCookiePath = "/api/admin"

var adminCSRF = http.NewCrossOriginProtection()

func (a *app) sessionMAC(exp string) []byte {
	key := sha256.Sum256([]byte("ul3 admin session\x00" + a.cfg.AdminPassword))
	m := hmac.New(sha256.New, key[:])
	m.Write([]byte(exp))
	return m.Sum(nil)
}

func (a *app) newSession(now time.Time) string {
	exp := strconv.FormatInt(now.Add(adminSessionTTL).Unix(), 10)
	return exp + "." + base64.RawURLEncoding.EncodeToString(a.sessionMAC(exp))
}

func (a *app) validSession(v string, now time.Time) bool {
	exp, sig, ok := strings.Cut(v, ".")
	if !ok {
		return false
	}
	got, err := base64.RawURLEncoding.DecodeString(sig)
	if err != nil || !hmac.Equal(got, a.sessionMAC(exp)) {
		return false
	}
	t, err := strconv.ParseInt(exp, 10, 64)
	return err == nil && now.Unix() < t
}

func (a *app) secureRequest(r *http.Request) bool {
	return strings.HasPrefix(a.baseURL(r), "https://")
}

func (a *app) setSessionCookie(w http.ResponseWriter, r *http.Request, value string, maxAge int) {
	http.SetCookie(w, &http.Cookie{
		Name: adminCookie, Value: value, Path: adminCookiePath, MaxAge: maxAge,
		HttpOnly: true, Secure: a.secureRequest(r), SameSite: http.SameSiteStrictMode,
	})
}

// adminAuth checks a request for the admin API: a session cookie, or the
// password as "Authorization: Bearer" (scripts). Only wrong passwords count
// toward the lockout; a stale cookie is just "signed out".
func (a *app) adminAuth(w http.ResponseWriter, r *http.Request) bool {
	if bearer, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer "); ok {
		return a.checkAdminPassword(w, r, bearer)
	}
	if c, err := r.Cookie(adminCookie); err == nil && a.validSession(c.Value, time.Now()) {
		// Cookies are sent automatically, so refuse cross-origin writes (CSRF).
		if err := adminCSRF.Check(r); err != nil {
			jsonErr(w, http.StatusForbidden, "Anfrage von fremder Seite abgelehnt")
			return false
		}
		return true
	}
	jsonErr(w, http.StatusUnauthorized, "Nicht angemeldet")
	return false
}

func (a *app) checkAdminPassword(w http.ResponseWriter, r *http.Request, pw string) bool {
	key := a.netKey(r)
	if !a.adminFails.Available(key) {
		jsonErr(w, http.StatusTooManyRequests, "Zu viele Fehlversuche – bitte später erneut versuchen")
		return false
	}
	got := sha256.Sum256([]byte(pw))
	want := sha256.Sum256([]byte(a.cfg.AdminPassword))
	if subtle.ConstantTimeCompare(got[:], want[:]) != 1 {
		a.adminFails.Charge(key, 1)
		slog.Warn("admin auth failed", "client", a.clientAddr(r))
		jsonErr(w, http.StatusUnauthorized, "Zugriff verweigert")
		return false
	}
	return true
}

// handleAdminLogin exchanges the password for a session cookie.
func (a *app) handleAdminLogin(w http.ResponseWriter, r *http.Request) {
	if a.cfg.AdminPassword == "" {
		jsonErr(w, http.StatusNotFound, "Admin-Bereich ist deaktiviert")
		return
	}
	if err := adminCSRF.Check(r); err != nil {
		jsonErr(w, http.StatusForbidden, "Anfrage von fremder Seite abgelehnt")
		return
	}
	var body struct {
		Password string `json:"password"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&body); err != nil {
		jsonErr(w, http.StatusBadRequest, "Ungültige Anfrage")
		return
	}
	if !a.checkAdminPassword(w, r, body.Password) {
		return
	}
	a.setSessionCookie(w, r, a.newSession(time.Now()), int(adminSessionTTL/time.Second))
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (a *app) handleAdminLogout(w http.ResponseWriter, r *http.Request) {
	a.setSessionCookie(w, r, "", -1)
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}
