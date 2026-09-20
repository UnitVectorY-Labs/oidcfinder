package oidcfinder

import (
	"bufio"
	"context"
	"encoding/csv"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"time"

	"golang.org/x/net/idna"
	"golang.org/x/net/publicsuffix"
	"gopkg.in/yaml.v3"
)

var defaultPrefixes = []string{"auth", "accounts", "login", "sso", "id", "identity", "oauth", "oidc", "connect", "signin", "www"}

func validDomain(raw string) (string, error) {
	d, err := idna.Lookup.ToASCII(strings.ToLower(strings.TrimSuffix(strings.TrimSpace(raw), ".")))
	if err != nil || len(d) > 253 || !strings.Contains(d, ".") || net.ParseIP(d) != nil {
		return "", fmt.Errorf("invalid public domain %q", raw)
	}
	for _, label := range strings.Split(d, ".") {
		if !validLabel(label) {
			return "", fmt.Errorf("invalid domain %q", raw)
		}
	}
	return d, nil
}
func validLabel(s string) bool {
	if len(s) == 0 || len(s) > 63 || s[0] == '-' || s[len(s)-1] == '-' {
		return false
	}
	for _, c := range s {
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
			return false
		}
	}
	return true
}
func loadPrefixes(path string) ([]string, error) {
	if path == "" {
		return defaultPrefixes, nil
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var config struct {
		Prefixes []string `yaml:"prefixes"`
	}
	dec := yaml.NewDecoder(strings.NewReader(string(b)))
	dec.KnownFields(true)
	if err = dec.Decode(&config); err != nil {
		return nil, err
	}
	if config.Prefixes == nil {
		return nil, fmt.Errorf("config must contain prefixes (use [] for apex only)")
	}
	seen := map[string]bool{}
	out := []string{}
	for _, p := range config.Prefixes {
		p = strings.ToLower(strings.TrimSpace(p))
		for _, label := range strings.Split(p, ".") {
			if !validLabel(label) {
				return nil, fmt.Errorf("invalid prefix %q", p)
			}
		}
		if !seen[p] {
			seen[p] = true
			out = append(out, p)
		}
	}
	return out, nil
}

// Domain input is streamed; only one transaction batch is held at a time.
// Invalid domain rows are skipped and optionally reported; CSV syntax errors
// remain fatal because record boundaries may no longer be reliable.
func (s *Store) importDomains(ctx context.Context, path string, prefixes []string, onInvalid func(int, error)) (int, int, error) {
	f, err := os.Open(path)
	if err != nil {
		return 0, 0, err
	}
	defer f.Close()
	reader := csv.NewReader(bufio.NewReader(f))
	reader.FieldsPerRecord = -1
	reader.TrimLeadingSpace = true
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, 0, err
	}
	defer func() {
		if tx != nil {
			_ = tx.Rollback()
		}
	}()
	insert := `INSERT INTO targets(host,site,first_seen,next_attempt) VALUES(?,?,?,COALESCE((SELECT until FROM site_backoff WHERE site=?),0)) ON CONFLICT(host) DO NOTHING`
	domains, added, col, line := 0, 0, 0, 0
	firstRecord := true
	for {
		if err := ctx.Err(); err != nil {
			return domains, added, err
		}
		row, e := reader.Read()
		if e == io.EOF {
			break
		}
		line++
		if e != nil {
			return domains, added, fmt.Errorf("domain input row %d: %w", line, e)
		}
		if len(row) == 0 {
			continue
		}
		row[0] = strings.TrimPrefix(row[0], "\ufeff")
		if strings.HasPrefix(strings.TrimSpace(row[0]), "#") {
			continue
		}
		if firstRecord {
			firstRecord = false
			header := false
			for i, v := range row {
				if strings.EqualFold(strings.TrimSpace(v), "domain") {
					col = i
					header = true
					break
				}
			}
			if header {
				continue
			}
			if len(row) > 1 {
				col = 1
			}
		}
		if col >= len(row) {
			if onInvalid != nil {
				onInvalid(line, fmt.Errorf("missing domain column"))
			}
			continue
		}
		domain, e := validDomain(row[col])
		if e != nil {
			if onInvalid != nil {
				onInvalid(line, e)
			}
			continue
		}
		site, e := publicsuffix.EffectiveTLDPlusOne(domain)
		if e != nil {
			site = domain
		}
		domains++
		for _, p := range append([]string{""}, prefixes...) {
			host := domain
			if p != "" {
				host = p + "." + domain
			}
			if len(host) > 253 {
				continue
			}
			r, e := tx.Exec(insert, host, site, time.Now().Unix(), site)
			if e != nil {
				return domains, added, e
			}
			n, _ := r.RowsAffected()
			added += int(n)
		}
		if domains%1000 == 0 {
			if e = tx.Commit(); e != nil {
				return domains, added, e
			}
			tx, e = s.db.BeginTx(ctx, nil)
			if e != nil {
				return domains, added, e
			}
		}
	}
	if domains == 0 {
		return 0, 0, fmt.Errorf("domain input contains no valid domains")
	}
	return domains, added, tx.Commit()
}
