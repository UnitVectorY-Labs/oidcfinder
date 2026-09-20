package oidcfinder

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

const catalogURL = "https://raw.githubusercontent.com/UnitVectorY-Labs/jwks-catalog/refs/heads/main/data/services.yaml"

type Service struct {
	ID         string `yaml:"id"`
	Name       string `yaml:"name"`
	OIDC       string `yaml:"openid-configuration,omitempty"`
	OAuth      string `yaml:"oauth-authorization-server,omitempty"`
	JWKS       string `yaml:"jwks_uri"`
	LegacyOIDC string `yaml:"open_id_configuration,omitempty"`
}
type Services struct {
	Services []Service `yaml:"services"`
}

func (s *Store) syncCatalog(ctx context.Context, source, local string) (int, error) {
	var b []byte
	var err error
	if local != "" {
		b, err = os.ReadFile(local)
	} else {
		if err = validateURL(source, false); err != nil {
			return 0, err
		}
		client := newClient(0, 0, 30*time.Second)
		defer client.CloseIdleConnections()
		req, e := http.NewRequestWithContext(ctx, "GET", source, nil)
		if e != nil {
			return 0, e
		}
		resp, e := client.Do(req)
		if e != nil {
			return 0, e
		}
		defer resp.Body.Close()
		if resp.StatusCode != 200 {
			return 0, fmt.Errorf("catalog returned HTTP %d", resp.StatusCode)
		}
		b, err = io.ReadAll(io.LimitReader(resp.Body, 8<<20+1))
	}
	if err != nil {
		return 0, err
	}
	if len(b) > 8<<20 {
		return 0, fmt.Errorf("catalog exceeds 8 MiB")
	}
	var file Services
	if err = yaml.Unmarshal(b, &file); err != nil {
		return 0, err
	}
	if file.Services == nil {
		return 0, fmt.Errorf("catalog must have a services sequence")
	}
	seen := map[string]bool{}
	for i := range file.Services {
		v := &file.Services[i]
		if v.OIDC == "" {
			v.OIDC = v.LegacyOIDC
		}
		if v.ID == "" || seen[v.ID] {
			return 0, fmt.Errorf("missing or duplicate catalog id %q", v.ID)
		}
		seen[v.ID] = true
		if err = validateURL(v.JWKS, false); err != nil {
			return 0, err
		}
		for _, u := range []string{v.OIDC, v.OAuth} {
			if u != "" {
				if err = validateURL(u, false); err != nil {
					return 0, err
				}
			}
		}
	}
	tx, err := s.db.Begin()
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	if _, err = tx.Exec(`DELETE FROM catalog`); err != nil {
		return 0, err
	}
	for _, v := range file.Services {
		if _, err = tx.Exec(`INSERT INTO catalog VALUES(?,?,?,?)`, v.ID, v.OIDC, v.OAuth, v.JWKS); err != nil {
			return 0, err
		}
	}
	// Membership is reconciled on every refresh; decisions are independent.
	if _, err = tx.Exec(`UPDATE candidates SET in_catalog=EXISTS(SELECT 1 FROM catalog c WHERE c.jwks_uri=candidates.jwks_uri OR (c.oidc_url<>'' AND c.oidc_url=candidates.oidc_url) OR (c.oauth_url<>'' AND c.oauth_url=candidates.oauth_url))`); err != nil {
		return 0, err
	}
	if _, err = tx.Exec(`INSERT INTO settings VALUES('catalog_fetched_at',?) ON CONFLICT(key) DO UPDATE SET value=excluded.value`, time.Now().UTC().Format(time.RFC3339)); err != nil {
		return 0, err
	}
	return len(file.Services), tx.Commit()
}
func (s *Store) catalogSet() (map[string]bool, error) {
	rows, e := s.db.Query(`SELECT oidc_url,oauth_url,jwks_uri FROM catalog`)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	set := map[string]bool{}
	for rows.Next() {
		var a, b, c string
		if e = rows.Scan(&a, &b, &c); e != nil {
			return nil, e
		}
		for _, v := range []string{a, b, c} {
			if v != "" {
				set[v] = true
			}
		}
	}
	return set, rows.Err()
}
