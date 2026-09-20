package oidcfinder

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

type Candidate struct {
	ID                                                             int64
	Issuer, JWKS, OIDC, OAuth, Decision, ServiceID, Name, Metadata string
	FirstSeen, LastSeen                                            int64
	InCatalog                                                      bool
}

func scanCandidate(row interface{ Scan(...any) error }) (Candidate, error) {
	var c Candidate
	e := row.Scan(&c.ID, &c.Issuer, &c.JWKS, &c.OIDC, &c.OAuth, &c.Decision, &c.ServiceID, &c.Name, &c.Metadata, &c.FirstSeen, &c.LastSeen, &c.InCatalog)
	return c, e
}

const candidateCols = `id,issuer,jwks_uri,oidc_url,oauth_url,decision,service_id,name,metadata,first_seen,last_seen,in_catalog`

func (s *Store) listCandidates(filter, search string, offset, limit int) ([]Candidate, error) {
	where := ` WHERE (issuer LIKE ? ESCAPE '\' OR name LIKE ? ESCAPE '\')`
	args := []any{likeSearch(search), likeSearch(search)}
	switch filter {
	case "pending":
		where += ` AND decision='pending' AND in_catalog=0`
	case "accepted", "rejected":
		where += ` AND decision=?`
		args = append(args, filter)
	case "catalog":
		where += ` AND in_catalog=1`
	case "all":
	default:
		return nil, fmt.Errorf("invalid filter %q", filter)
	}
	args = append(args, limit, offset)
	rows, e := s.db.Query(`SELECT `+candidateCols+` FROM candidates`+where+` ORDER BY id LIMIT ? OFFSET ?`, args...)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	out := []Candidate{}
	for rows.Next() {
		c, e := scanCandidate(rows)
		if e != nil {
			return nil, e
		}
		out = append(out, c)
	}
	return out, rows.Err()
}
func likeSearch(s string) string {
	r := strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`)
	return "%" + r.Replace(s) + "%"
}
func (s *Store) decide(id int64, decision, serviceID, name, path string) error {
	if decision != "accepted" && decision != "rejected" && decision != "pending" {
		return fmt.Errorf("invalid decision")
	}
	tx, e := s.db.Begin()
	if e != nil {
		return e
	}
	defer tx.Rollback()
	c, e := scanCandidate(tx.QueryRow(`SELECT `+candidateCols+` FROM candidates WHERE id=?`, id))
	if e != nil {
		return e
	}
	if c.Decision == "accepted" && decision != "accepted" {
		return fmt.Errorf("already exported: edit the YAML explicitly before changing an accepted entry")
	}
	if decision == "accepted" {
		if c.InCatalog {
			return fmt.Errorf("already in the catalog")
		}
		if !validLabel(serviceID) {
			return fmt.Errorf("service id must be 1–63 lowercase letters, digits or hyphens")
		}
		if strings.TrimSpace(name) == "" {
			return fmt.Errorf("name is required")
		}
		c.ServiceID = serviceID
		c.Name = strings.TrimSpace(name)
		if e = appendServices(path, []Candidate{c}); e != nil {
			return e
		}
	}
	_, e = tx.Exec(`UPDATE candidates SET decision=?,service_id=?,name=? WHERE id=?`, decision, c.ServiceID, c.Name, id)
	if e != nil {
		return e
	}
	return tx.Commit()
}

// Read-modify-rename preserves previous entries and makes repeat accepts idempotent.
// The caller holds the database write transaction, serializing reviews for this DB.
func appendServices(path string, candidates []Candidate) error {
	file := Services{Services: []Service{}}
	data, e := os.ReadFile(path)
	if e == nil {
		dec := yaml.NewDecoder(strings.NewReader(string(data)))
		dec.KnownFields(true)
		if e = dec.Decode(&file); e != nil {
			return fmt.Errorf("export file: %w", e)
		}
		if file.Services == nil {
			return fmt.Errorf("export must have a services sequence")
		}
	} else if !os.IsNotExist(e) {
		return e
	}
	for _, c := range candidates {
		entry := Service{ID: c.ServiceID, Name: c.Name, OIDC: c.OIDC, OAuth: c.OAuth, JWKS: c.JWKS}
		matched := -1
		for i, v := range file.Services {
			same := v.JWKS == c.JWKS && ((v.OIDC != "" && v.OIDC == c.OIDC) || (v.OAuth != "" && v.OAuth == c.OAuth))
			if v.ID == entry.ID && !same {
				return fmt.Errorf("export id %q already belongs to another service", entry.ID)
			}
			if same {
				matched = i
			}
		}
		if matched >= 0 {
			file.Services[matched] = entry
		} else {
			file.Services = append(file.Services, entry)
		}
	}
	data, e = yaml.Marshal(file)
	if e != nil {
		return e
	}
	return atomicWrite(path, data)
}
func atomicWrite(path string, data []byte) error {
	if e := os.MkdirAll(filepath.Dir(path), 0755); e != nil {
		return e
	}
	f, e := os.CreateTemp(filepath.Dir(path), ".oidcfinder-*.yaml")
	if e != nil {
		return e
	}
	defer os.Remove(f.Name())
	if _, e = f.Write(data); e != nil {
		f.Close()
		return e
	}
	if e = f.Sync(); e != nil {
		f.Close()
		return e
	}
	if e = f.Close(); e != nil {
		return e
	}
	return os.Rename(f.Name(), path)
}
func (s *Store) exportAccepted(path string) (int, error) {
	// A write transaction prevents simultaneous TUI accepts from losing entries.
	tx, e := s.db.Begin()
	if e != nil {
		return 0, e
	}
	defer tx.Rollback()
	rows, e := tx.Query(`SELECT ` + candidateCols + ` FROM candidates WHERE decision='accepted' ORDER BY id`)
	if e != nil {
		return 0, e
	}
	var list []Candidate
	for rows.Next() {
		c, e := scanCandidate(rows)
		if e != nil {
			rows.Close()
			return 0, e
		}
		list = append(list, c)
	}
	e = rows.Err()
	rows.Close()
	if e != nil {
		return 0, e
	}
	if e = appendServices(path, list); e != nil {
		return 0, e
	}
	return len(list), tx.Commit()
}

type Status struct {
	Targets, Due, Pending, Accepted, Rejected, CatalogCandidates, CatalogEntries int
	CatalogFetched                                                               string
	Results                                                                      map[string]int
}

func (s *Store) status() (Status, error) {
	out := Status{Results: map[string]int{}}
	queries := []struct {
		sql  string
		dest *int
	}{{`SELECT COUNT(*) FROM targets`, &out.Targets}, {`SELECT COUNT(*) FROM targets WHERE next_attempt<=unixepoch()`, &out.Due}, {`SELECT COUNT(*) FROM candidates WHERE decision='pending' AND in_catalog=0`, &out.Pending}, {`SELECT COUNT(*) FROM candidates WHERE decision='accepted'`, &out.Accepted}, {`SELECT COUNT(*) FROM candidates WHERE decision='rejected'`, &out.Rejected}, {`SELECT COUNT(*) FROM candidates WHERE in_catalog=1`, &out.CatalogCandidates}, {`SELECT COUNT(*) FROM catalog`, &out.CatalogEntries}}
	for _, q := range queries {
		if e := s.db.QueryRow(q.sql).Scan(q.dest); e != nil {
			return out, e
		}
	}
	e := s.db.QueryRow(`SELECT value FROM settings WHERE key='catalog_fetched_at'`).Scan(&out.CatalogFetched)
	if e != nil && e != sql.ErrNoRows {
		return out, e
	}
	rows, e := s.db.Query(`SELECT result,COUNT(*) FROM targets GROUP BY result`)
	if e != nil {
		return out, e
	}
	defer rows.Close()
	for rows.Next() {
		var k string
		var n int
		if e = rows.Scan(&k, &n); e != nil {
			return out, e
		}
		out.Results[k] = n
	}
	return out, rows.Err()
}
func date(t int64) string { return time.Unix(t, 0).UTC().Format(time.RFC3339) }
