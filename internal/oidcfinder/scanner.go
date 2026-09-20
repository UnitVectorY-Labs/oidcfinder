package oidcfinder

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

const oidcPath = "/.well-known/openid-configuration"
const oauthPath = "/.well-known/oauth-authorization-server"

type CrawlOptions struct {
	Workers, Limit                                                      int
	Interval, SiteInterval, Timeout, PositiveTTL, NegativeTTL, RetryTTL time.Duration
}
type target struct {
	ID   int64
	Host string
	Site string
}
type discovery struct{ Issuer, JWKS, OIDC, OAuth, Metadata string }
type outcome struct {
	target       target
	kind, detail string
	retry        time.Duration
	found        []discovery
}

func field(m map[string]any, k string) string { s, _ := m[k].(string); return s }
func nonemptyArray(m map[string]any, k string) bool {
	a, ok := m[k].([]any)
	if !ok || len(a) == 0 {
		return false
	}
	for _, v := range a {
		if s, ok := v.(string); !ok || s == "" {
			return false
		}
	}
	return true
}
func validateMetadata(m map[string]any, oidc bool) error {
	if validateURL(field(m, "issuer"), true) != nil || validateURL(field(m, "jwks_uri"), false) != nil {
		return fmt.Errorf("missing or invalid issuer/jwks_uri")
	}
	if oidc {
		for _, k := range []string{"response_types_supported", "subject_types_supported", "id_token_signing_alg_values_supported"} {
			if !nonemptyArray(m, k) {
				return fmt.Errorf("missing OIDC %s", k)
			}
		}
		if validateURL(field(m, "authorization_endpoint"), false) != nil {
			return fmt.Errorf("missing OIDC authorization_endpoint")
		}
	}
	// OAuth metadata has fewer mandatory fields, but must describe an AS.
	if !oidc && field(m, "authorization_endpoint") == "" && field(m, "token_endpoint") == "" {
		return fmt.Errorf("OAuth metadata has no authorization or token endpoint")
	}
	for _, k := range []string{"authorization_endpoint", "token_endpoint"} {
		if field(m, k) != "" {
			if e := validateURL(field(m, k), false); e != nil {
				return e
			}
		}
	}
	return nil
}
func validJWK(k map[string]any) bool {
	// Public key material only. Symmetric secrets and private parameters are rejected.
	for _, v := range []string{"d", "p", "q", "dp", "dq", "qi", "oth", "k"} {
		if _, ok := k[v]; ok {
			return false
		}
	}
	dec := func(key string) []byte { b, _ := base64.RawURLEncoding.DecodeString(field(k, key)); return b }
	switch field(k, "kty") {
	case "RSA":
		return len(dec("n")) >= 128 && len(dec("e")) > 0
	case "EC":
		size := map[string]int{"P-256": 32, "P-384": 48, "P-521": 66}[field(k, "crv")]
		return size > 0 && len(dec("x")) == size && len(dec("y")) == size
	case "OKP":
		size := map[string]int{"Ed25519": 32, "Ed448": 57}[field(k, "crv")]
		return size > 0 && len(dec("x")) == size
	}
	return false
}
func scan(ctx context.Context, client *http.Client, t target, known map[string]bool) outcome {
	out := outcome{target: t, kind: "negative"}
	base := "https://" + t.Host
	jwksCache := map[string]error{}
	for i, path := range []string{oidcPath, oauthPath} {
		raw := base + path
		// An exact discovery URL in the catalog is already accounted for.
		if known[raw] {
			if out.kind == "negative" {
				out.kind = "catalog"
			}
			continue
		}
		var m map[string]any
		err := fetchJSON(ctx, client, raw, &m)
		if err == nil {
			err = validateMetadata(m, i == 0)
		}
		if err == nil {
			jwks := field(m, "jwks_uri")
			cached, ok := jwksCache[jwks]
			if !ok {
				var keys struct {
					Keys []map[string]any `json:"keys"`
				}
				cached = fetchJSON(ctx, client, jwks, &keys)
				if cached == nil {
					if len(keys.Keys) == 0 {
						cached = fmt.Errorf("empty JWKS")
					}
					for _, k := range keys.Keys {
						if !validJWK(k) {
							cached = fmt.Errorf("JWKS contains invalid or non-public key")
							break
						}
					}
				}
				jwksCache[jwks] = cached
			}
			err = cached
		}
		if err != nil {
			var f *fetchError
			if errors.As(err, &f) && f.kind == "transient" {
				out.kind = "transient"
				out.retry = max(out.retry, f.delay)
			}
			out.detail = clipped(err.Error())
			if f != nil && f.stop {
				break
			}
			continue
		}
		b, _ := json.Marshal(m)
		d := discovery{Issuer: field(m, "issuer"), JWKS: field(m, "jwks_uri"), Metadata: string(b)}
		if i == 0 {
			d.OIDC = raw
		} else {
			d.OAuth = raw
		}
		out.found = append(out.found, d)
	}
	if len(out.found) > 0 {
		out.kind = "valid"
	}
	return out
}
func (s *Store) save(out outcome, opt CrawlOptions, known map[string]bool) error {
	now := time.Now().Unix()
	ttl := opt.NegativeTTL
	if out.kind == "valid" || out.kind == "catalog" {
		ttl = opt.PositiveTTL
	}
	if out.kind == "transient" {
		ttl = opt.RetryTTL
	}
	ttl = max(ttl, out.retry)
	tx, e := s.db.Begin()
	if e != nil {
		return e
	}
	defer tx.Rollback()
	for _, d := range out.found {
		hash := sha256.Sum256([]byte(d.Issuer + "|" + d.JWKS))
		u, _ := url.Parse(d.Issuer)
		label := strings.ReplaceAll(u.Hostname(), ".", "-")
		label = strings.Trim(label[:min(len(label), 54)], "-")
		id := label + "-" + hex.EncodeToString(hash[:4])
		_, e = tx.Exec(`INSERT INTO candidates(issuer,jwks_uri,oidc_url,oauth_url,first_seen,last_seen,in_catalog,service_id,name,metadata) VALUES(?,?,?,?,?,?,?,?,?,?) ON CONFLICT(issuer,jwks_uri) DO UPDATE SET oidc_url=CASE WHEN excluded.oidc_url<>'' THEN excluded.oidc_url ELSE candidates.oidc_url END,oauth_url=CASE WHEN excluded.oauth_url<>'' THEN excluded.oauth_url ELSE candidates.oauth_url END,last_seen=excluded.last_seen,in_catalog=excluded.in_catalog,metadata=excluded.metadata`, d.Issuer, d.JWKS, d.OIDC, d.OAuth, now, now, known[d.JWKS] || known[d.OIDC] || known[d.OAuth], id, u.Hostname(), d.Metadata)
		if e != nil {
			return e
		}
	}
	_, e = tx.Exec(`UPDATE targets SET last_attempt=?,next_attempt=MAX(next_attempt,?),attempts=attempts+1,result=?,error=? WHERE id=?`, now, time.Now().Add(ttl).Unix(), out.kind, out.detail, out.target.ID)
	if e != nil {
		return e
	}
	return tx.Commit()
}
func (s *Store) crawl(ctx context.Context, opt CrawlOptions, w io.Writer) error {
	known, e := s.catalogSet()
	if e != nil {
		return e
	}
	client := newClient(opt.Interval, opt.SiteInterval, opt.Timeout)
	defer client.CloseIdleConnections()
	pacing := client.Transport.(*pacedTransport)
	pacing.backoff, e = s.backoffs()
	if e != nil {
		return e
	}
	pacing.onBackoff = s.recordBackoff
	start := time.Now().Unix()
	done, found := 0, 0
	for {
		limit := 256
		if opt.Limit > 0 {
			limit = min(limit, opt.Limit-done)
			if limit <= 0 {
				break
			}
		}
		rows, e := s.db.Query(`SELECT id,host,site FROM targets WHERE next_attempt<=? ORDER BY next_attempt,id LIMIT ?`, start, limit)
		if e != nil {
			return e
		}
		var batch []target
		for rows.Next() {
			var t target
			if e = rows.Scan(&t.ID, &t.Host, &t.Site); e != nil {
				rows.Close()
				return e
			}
			batch = append(batch, t)
		}
		e = rows.Err()
		rows.Close()
		if e != nil {
			return e
		}
		if len(batch) == 0 {
			break
		}
		jobs := make(chan target)
		results := make(chan outcome, opt.Workers)
		var wg sync.WaitGroup
		runCtx, cancel := context.WithCancel(ctx)
		for i := 0; i < opt.Workers; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for t := range jobs {
					if runCtx.Err() != nil {
						return
					}
					out := scan(runCtx, client, t, known)
					select {
					case results <- out:
					case <-runCtx.Done():
						return
					}
				}
			}()
		}
		go func() {
			defer close(jobs)
			for _, t := range interleaveSites(batch) {
				select {
				case jobs <- t:
				case <-runCtx.Done():
					return
				}
			}
		}()
		go func() { wg.Wait(); close(results) }()
		var saveErr error
		for out := range results {
			if ctx.Err() != nil {
				continue
			}
			if saveErr != nil {
				continue
			}
			if e = s.save(out, opt, known); e != nil {
				saveErr = e
				cancel()
				continue
			}
			done++
			found += len(out.found)
			if done%25 == 0 || len(out.found) > 0 {
				fmt.Fprintf(w, "scanned=%d discoveries=%d last=%s result=%s\n", done, found, out.target.Host, out.kind)
			}
		}
		cancel()
		if saveErr != nil {
			return saveErr
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
	}
	fmt.Fprintf(w, "crawl complete: scanned=%d discoveries=%d (OIDC/OAuth documents; candidates deduplicated)\n", done, found)
	return nil
}

// Mix sites within each bounded batch so one site's pacing does not occupy
// every worker while unrelated sites could make progress.
func interleaveSites(batch []target) []target {
	groups := map[string][]target{}
	var sites []string
	for _, t := range batch {
		if len(groups[t.Site]) == 0 {
			sites = append(sites, t.Site)
		}
		groups[t.Site] = append(groups[t.Site], t)
	}
	out := make([]target, 0, len(batch))
	for len(out) < len(batch) {
		for _, site := range sites {
			if list := groups[site]; len(list) > 0 {
				out = append(out, list[0])
				groups[site] = list[1:]
			}
		}
	}
	return out
}
