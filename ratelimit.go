package main

import (
	"fmt"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"time"
)

// limiter is a per-key token bucket. A nil *limiter allows everything.
type limiter struct {
	mu        sync.Mutex
	rate      float64 // tokens per second
	burst     float64
	buckets   map[string]*bucket
	lastPrune time.Time
	now       func() time.Time
}

type bucket struct {
	tokens float64
	last   time.Time
}

// newLimiter refills perHour tokens per hour up to burst. Either value <= 0
// disables the limiter.
func newLimiter(perHour, burst float64) *limiter {
	if perHour <= 0 || burst <= 0 {
		return nil
	}
	return &limiter{rate: perHour / 3600, burst: burst, buckets: map[string]*bucket{}, now: time.Now}
}

// get returns the refilled bucket for key. l.mu must be held.
func (l *limiter) get(key string) *bucket {
	now := l.now()
	if now.Sub(l.lastPrune) > 5*time.Minute {
		for k, b := range l.buckets {
			if b.tokens+now.Sub(b.last).Seconds()*l.rate >= l.burst {
				delete(l.buckets, k) // full again: same as a fresh bucket
			}
		}
		l.lastPrune = now
	}
	b, ok := l.buckets[key]
	if !ok {
		b = &bucket{tokens: l.burst, last: now}
		l.buckets[key] = b
		return b
	}
	b.tokens = min(l.burst, b.tokens+now.Sub(b.last).Seconds()*l.rate)
	b.last = now
	return b
}

// Take removes n tokens if at least n are available.
func (l *limiter) Take(key string, n float64) bool {
	if l == nil {
		return true
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	b := l.get(key)
	if b.tokens < n {
		return false
	}
	b.tokens -= n
	return true
}

// Available reports whether at least one token is left.
func (l *limiter) Available(key string) bool {
	if l == nil {
		return true
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.get(key).tokens >= 1
}

// Charge removes n tokens unconditionally; the balance may go negative and
// is paid back by the refill.
func (l *limiter) Charge(key string, n float64) {
	if l == nil {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	l.get(key).tokens -= n
}

// Refund gives back up to n tokens taken earlier, never beyond the burst.
func (l *limiter) Refund(key string, n float64) {
	if l == nil || n <= 0 {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	b := l.get(key)
	b.tokens = min(l.burst, b.tokens+n)
}

// ---------- client identity ----------

// defaultTrustedProxies trusts no one: X-Forwarded-For is ignored unless the
// operator names the proxy. Trusting private ranges by default let clients
// spoof their address whenever ul3 was reached directly from such a range
// (LAN, docker-proxy, a load balancer that passes the header through).
const defaultTrustedProxies = "none"

// privateProxyRanges is the usual TRUSTED_PROXIES value behind a reverse proxy
// on the same host or Docker network (see compose.yaml).
const privateProxyRanges = "127.0.0.0/8,::1/128,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,fc00::/7"

func parseTrustedProxies(s string) ([]netip.Prefix, error) {
	if strings.TrimSpace(s) == "none" {
		return nil, nil
	}
	var out []netip.Prefix
	for _, f := range strings.Split(s, ",") {
		f = strings.TrimSpace(f)
		if f == "" {
			continue
		}
		if p, err := netip.ParsePrefix(f); err == nil {
			out = append(out, p.Masked())
			continue
		}
		a, err := netip.ParseAddr(f)
		if err != nil {
			return nil, fmt.Errorf("invalid TRUSTED_PROXIES entry %q", f)
		}
		out = append(out, netip.PrefixFrom(a.Unmap(), a.Unmap().BitLen()))
	}
	return out, nil
}

func inAny(ip netip.Addr, nets []netip.Prefix) bool {
	for _, p := range nets {
		if p.Contains(ip) {
			return true
		}
	}
	return false
}

// clientIP returns the connecting address, or – when that is a trusted proxy –
// the right-most X-Forwarded-For hop that is not itself a trusted proxy.
// Entries further left are client-supplied and are never used.
func clientIP(r *http.Request, trusted []netip.Prefix) netip.Addr {
	ap, err := netip.ParseAddrPort(r.RemoteAddr)
	if err != nil {
		return netip.Addr{}
	}
	ip := ap.Addr().Unmap()
	if !inAny(ip, trusted) {
		return ip
	}
	hops := strings.Split(strings.Join(r.Header.Values("X-Forwarded-For"), ","), ",")
	for i := len(hops) - 1; i >= 0; i-- {
		h, err := netip.ParseAddr(strings.TrimSpace(hops[i]))
		if err != nil {
			return ip
		}
		ip = h.Unmap()
		if !inAny(ip, trusted) {
			return ip
		}
	}
	return ip
}

// clientAddr is the full client IP for logging (rate-limit keys are coarser
// for IPv6), resolved through TRUSTED_PROXIES like the keys.
func (a *app) clientAddr(r *http.Request) string {
	if ip := clientIP(r, a.cfg.TrustedProxies); ip.IsValid() {
		return ip.String()
	}
	return r.RemoteAddr
}

// netKey is the client IPv4 address, or its IPv6 /48 (the usual allocation to
// one customer, and free from tunnel brokers). It is the key for failed admin
// logins, so rotating through /64s does not multiply the guesses an attacker
// gets, and the second tier of the upload quotas.
func (a *app) netKey(r *http.Request) string { return a.ipKey(r, 48) }

// clientKey is the rate-limit key: the client IPv4 address, or its IPv6 /64
// (a single host usually controls a whole /64).
func (a *app) clientKey(r *http.Request) string { return a.ipKey(r, 64) }

func (a *app) ipKey(r *http.Request, v6bits int) string {
	ip := clientIP(r, a.cfg.TrustedProxies)
	if !ip.IsValid() {
		return r.RemoteAddr
	}
	if ip.Is6() {
		p, _ := ip.Prefix(v6bits)
		return p.String()
	}
	return ip.String()
}

// ---------- two-tier quotas ----------

// netShare is how many client budgets one IPv6 /48 gets in total. Per-/64
// keys keep separate devices on a shared /48 (mobile carriers, campuses)
// apart, but on their own they would give whoever controls a /48 65,536
// budgets – enough to fill the disk up to MIN_FREE_MB and block all uploads
// for the retention period.
const netShare = 8

// quota is a per-client limit plus, for IPv6 clients, a wider one on their /48.
// A zero quota allows everything.
type quota struct{ client, net *limiter }

func newQuota(perHour, burst float64) quota {
	return quota{newLimiter(perHour, burst), newLimiter(perHour*netShare, burst*netShare)}
}

// quotaKey names a client for a quota; net is "" when there is no wider
// network to charge (IPv4).
type quotaKey struct{ client, net string }

func (a *app) quotaKey(r *http.Request) quotaKey {
	k := quotaKey{a.clientKey(r), a.netKey(r)}
	if k.net == k.client {
		k.net = ""
	}
	return k
}

// Take removes n tokens from both tiers, or from neither.
func (q quota) Take(k quotaKey, n float64) bool {
	if !q.client.Take(k.client, n) {
		return false
	}
	if k.net != "" && !q.net.Take(k.net, n) {
		q.client.Refund(k.client, n)
		return false
	}
	return true
}

// Refund gives back up to n tokens to both tiers.
func (q quota) Refund(k quotaKey, n float64) {
	q.client.Refund(k.client, n)
	if k.net != "" {
		q.net.Refund(k.net, n)
	}
}
