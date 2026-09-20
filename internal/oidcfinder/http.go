package oidcfinder

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/publicsuffix"
)

const maxBody = 2 << 20

// Every request, including redirects and JWKS requests, passes this limiter.
type pacedTransport struct {
	base                   http.RoundTripper
	mu                     sync.Mutex
	interval, siteInterval time.Duration
	next                   time.Time
	sites                  map[string]time.Time
	backoff                map[string]time.Time
	timeout                time.Duration
	onBackoff              func(string, time.Time) error
}

func (t *pacedTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	site := r.URL.Hostname()
	if s, e := publicsuffix.EffectiveTLDPlusOne(site); e == nil {
		site = s
	}
	for {
		if err := r.Context().Err(); err != nil {
			return nil, err
		}
		t.mu.Lock()
		now := time.Now()
		if until := t.backoff[site]; until.After(now) {
			t.mu.Unlock()
			return nil, &fetchError{kind: "transient", delay: time.Until(until), message: "site Retry-After cooldown", stop: true}
		}
		at := maxTime(t.next, t.sites[site])
		if !at.After(now) {
			t.next = now.Add(t.interval)
			t.sites[site] = now.Add(t.siteInterval)
			if len(t.sites) > 1024 {
				for k, v := range t.sites {
					if v.Before(now) {
						delete(t.sites, k)
					}
				}
			}
			t.mu.Unlock()
			break
		}
		t.mu.Unlock()
		timer := time.NewTimer(time.Until(at))
		select {
		case <-r.Context().Done():
			timer.Stop()
			return nil, r.Context().Err()
		case <-timer.C:
		}
	}
	cancel := func() {}
	if t.timeout > 0 {
		var ctx context.Context
		ctx, cancel = context.WithTimeout(r.Context(), t.timeout)
		r = r.Clone(ctx)
	}
	resp, err := t.base.RoundTrip(r)
	if err != nil {
		cancel()
		return nil, err
	}
	resp.Body = &cancelBody{ReadCloser: resp.Body, cancel: cancel}
	if err == nil && (resp.StatusCode == 429 || resp.StatusCode == 503) {
		delay := retryAfter(resp.Header.Get("Retry-After"))
		if delay > 0 {
			t.mu.Lock()
			until := time.Now().Add(delay)
			if t.backoff == nil {
				t.backoff = map[string]time.Time{}
			}
			if until.After(t.backoff[site]) {
				t.backoff[site] = until
			}
			t.mu.Unlock()
			if t.onBackoff != nil {
				if err = t.onBackoff(site, until); err != nil {
					resp.Body.Close()
					return nil, err
				}
			}
		}
	}
	return resp, err
}
func retryAfter(v string) time.Duration {
	if n, e := strconv.Atoi(v); e == nil && n > 0 {
		return time.Duration(min(n, 86400)) * time.Second
	}
	if d, e := http.ParseTime(v); e == nil {
		return min(max(time.Until(d), 0), 24*time.Hour)
	}
	return 0
}
func publicIP(ip net.IP) bool {
	if !ip.IsGlobalUnicast() || ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() {
		return false
	}
	addr, ok := netip.AddrFromSlice(ip)
	if !ok {
		return false
	}
	addr = addr.Unmap()
	for _, prefix := range specialNetworks {
		if prefix.Contains(addr) {
			return false
		}
	}
	return true
}
func newClient(interval, siteInterval, timeout time.Duration) *http.Client {
	dialer := net.Dialer{Timeout: timeout}
	transport := &http.Transport{MaxIdleConns: 32, MaxIdleConnsPerHost: 2, IdleConnTimeout: 30 * time.Second, TLSHandshakeTimeout: timeout, ResponseHeaderTimeout: timeout}
	transport.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		host, port, e := net.SplitHostPort(address)
		if e != nil {
			return nil, e
		}
		ips, e := net.DefaultResolver.LookupIPAddr(ctx, host)
		if e != nil {
			return nil, e
		}
		for _, a := range ips {
			if !publicIP(a.IP) {
				return nil, fmt.Errorf("non-public address for %s", host)
			}
		}
		var last error
		for _, a := range ips {
			conn, e := dialer.DialContext(ctx, network, net.JoinHostPort(a.IP.String(), port))
			if e == nil {
				return conn, nil
			}
			last = e
		}
		if last == nil {
			last = fmt.Errorf("no addresses for %s", host)
		}
		return nil, last
	}
	return &http.Client{Transport: &pacedTransport{base: transport, interval: interval, siteInterval: siteInterval, timeout: timeout, sites: map[string]time.Time{}}, CheckRedirect: func(r *http.Request, via []*http.Request) error {
		if len(via) >= 3 {
			return fmt.Errorf("redirect limit exceeded")
		}
		return validateURL(r.URL.String(), false)
	}}
}
func validateURL(raw string, issuer bool) error {
	u, e := url.Parse(raw)
	if e != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.Fragment != "" || (issuer && u.RawQuery != "") {
		return fmt.Errorf("invalid HTTPS URL %q", raw)
	}
	if u.Port() != "" {
		port, err := strconv.Atoi(u.Port())
		if err != nil || port < 1 || port > 65535 {
			return fmt.Errorf("invalid port in %q", raw)
		}
	}
	return nil
}

type fetchError struct {
	kind    string
	delay   time.Duration
	message string
	stop    bool
}

func (e *fetchError) Error() string { return e.message }
func fetchJSON(ctx context.Context, client *http.Client, raw string, out any) error {
	if e := validateURL(raw, false); e != nil {
		return &fetchError{kind: "invalid", message: e.Error()}
	}
	req, e := http.NewRequestWithContext(ctx, "GET", raw, nil)
	if e != nil {
		return e
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "oidcfinder/1.0 (+https://github.com/UnitVectorY-Labs/oidcfinder)")
	resp, e := client.Do(req)
	if e != nil {
		var dns *net.DNSError
		kind := "transient"
		if errors.As(e, &dns) && dns.IsNotFound {
			kind = "negative"
		}
		var paced *fetchError
		if errors.As(e, &paced) {
			return paced
		}
		return &fetchError{kind: kind, message: e.Error(), stop: true}
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		kind := "negative"
		if resp.StatusCode == 429 || resp.StatusCode >= 500 {
			kind = "transient"
		}
		return &fetchError{kind: kind, delay: retryAfter(resp.Header.Get("Retry-After")), message: fmt.Sprintf("HTTP %d", resp.StatusCode)}
	}
	b, e := io.ReadAll(io.LimitReader(resp.Body, maxBody+1))
	if e != nil {
		return &fetchError{kind: "transient", message: e.Error()}
	}
	if len(b) > maxBody {
		return &fetchError{kind: "invalid", message: "response exceeds 2 MiB"}
	}
	if e = json.Unmarshal(b, out); e != nil {
		return &fetchError{kind: "invalid", message: "response is not valid JSON"}
	}
	return nil
}
func clipped(s string) string {
	return strings.Map(func(r rune) rune {
		if r < 32 || r == 127 {
			return ' '
		}
		return r
	}, s[:min(len(s), 500)])
}

func maxTime(a, b time.Time) time.Time {
	if a.After(b) {
		return a
	}
	return b
}
func (t *pacedTransport) CloseIdleConnections() {
	if c, ok := t.base.(interface{ CloseIdleConnections() }); ok {
		c.CloseIdleConnections()
	}
}

type cancelBody struct {
	io.ReadCloser
	cancel context.CancelFunc
}

func (b *cancelBody) Close() error { defer b.cancel(); return b.ReadCloser.Close() }

// Additional non-public special-use ranges not covered by net.IP.IsPrivate.
var specialNetworks = func() []netip.Prefix {
	var result []netip.Prefix
	for _, cidr := range []string{"0.0.0.0/8", "100.64.0.0/10", "192.0.0.0/24", "192.0.2.0/24", "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "240.0.0.0/4", "100::/64", "2001:db8::/32", "2001:2::/48"} {
		result = append(result, netip.MustParsePrefix(cidr))
	}
	return result
}()
