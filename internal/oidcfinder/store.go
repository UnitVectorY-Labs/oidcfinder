package oidcfinder

import (
	"database/sql"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

// Store keeps one compact row per target and per discovered issuer/JWKS pair.
type Store struct{ db *sql.DB }

const schema = `
CREATE TABLE IF NOT EXISTS targets (
 id INTEGER PRIMARY KEY, host TEXT NOT NULL UNIQUE, site TEXT NOT NULL,
 first_seen INTEGER NOT NULL, last_attempt INTEGER, next_attempt INTEGER NOT NULL DEFAULT 0,
 attempts INTEGER NOT NULL DEFAULT 0, result TEXT NOT NULL DEFAULT 'pending', error TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS targets_due ON targets(next_attempt,id);
CREATE INDEX IF NOT EXISTS targets_site ON targets(site);
CREATE TABLE IF NOT EXISTS site_backoff(site TEXT PRIMARY KEY, until INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS candidates (
 id INTEGER PRIMARY KEY, issuer TEXT NOT NULL, jwks_uri TEXT NOT NULL,
 oidc_url TEXT NOT NULL DEFAULT '', oauth_url TEXT NOT NULL DEFAULT '',
 first_seen INTEGER NOT NULL, last_seen INTEGER NOT NULL,
 decision TEXT NOT NULL DEFAULT 'pending' CHECK(decision IN ('pending','accepted','rejected')),
 in_catalog INTEGER NOT NULL DEFAULT 0, service_id TEXT NOT NULL, name TEXT NOT NULL,
 metadata TEXT NOT NULL, UNIQUE(issuer,jwks_uri)
);
CREATE INDEX IF NOT EXISTS candidates_review ON candidates(decision,in_catalog,id);
CREATE TABLE IF NOT EXISTS catalog (id TEXT PRIMARY KEY, oidc_url TEXT NOT NULL, oauth_url TEXT NOT NULL, jwks_uri TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS crawl_lock (id INTEGER PRIMARY KEY CHECK(id=1), owner TEXT NOT NULL, expires INTEGER NOT NULL);
PRAGMA user_version=1;
`

func openStore(path string) (*Store, error) {
	var err error
	path, err = filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return nil, err
	}
	u := url.URL{Scheme: "file", Path: path}
	q := u.Query()
	q.Set("_busy_timeout", "5000")
	q.Set("_journal_mode", "WAL")
	q.Set("_foreign_keys", "on")
	q.Set("_txlock", "immediate")
	u.RawQuery = q.Encode()
	db, err := sql.Open("sqlite3", u.String())
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	fail := func(err error) (*Store, error) { db.Close(); return nil, err }
	var old int
	if err = db.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE name='candidate_cases'`).Scan(&old); err != nil {
		return fail(err)
	}
	if old > 0 {
		return fail(fmt.Errorf("legacy agent database: use a new --db path (default data/crawler.db); existing data was not changed"))
	}
	var version int
	if err = db.QueryRow(`PRAGMA user_version`).Scan(&version); err != nil {
		return fail(err)
	}
	if version > 1 {
		return fail(fmt.Errorf("database schema %d is newer than this application", version))
	}
	if _, err = db.Exec(schema); err != nil {
		return fail(err)
	}
	return &Store{db}, nil
}
func (s *Store) Close() error { return s.db.Close() }
func (s *Store) lock(owner string) error {
	r, err := s.db.Exec(`INSERT INTO crawl_lock VALUES(1,?,?) ON CONFLICT(id) DO UPDATE SET owner=excluded.owner,expires=excluded.expires WHERE crawl_lock.expires<?`, owner, time.Now().Add(time.Minute).Unix(), time.Now().Unix())
	if err != nil {
		return err
	}
	n, _ := r.RowsAffected()
	if n != 1 {
		return fmt.Errorf("another crawl is active for this database (stale locks expire after one minute)")
	}
	return nil
}
func (s *Store) unlock(owner string) { _, _ = s.db.Exec(`DELETE FROM crawl_lock WHERE owner=?`, owner) }

func (s *Store) recordBackoff(site string, until time.Time) error {
	tx, e := s.db.Begin()
	if e != nil {
		return e
	}
	defer tx.Rollback()
	if _, e = tx.Exec(`INSERT INTO site_backoff VALUES(?,?) ON CONFLICT(site) DO UPDATE SET until=MAX(until,excluded.until)`, site, until.Unix()+1); e != nil {
		return e
	}
	if _, e = tx.Exec(`UPDATE targets SET next_attempt=MAX(next_attempt,?) WHERE site=?`, until.Unix()+1, site); e != nil {
		return e
	}
	return tx.Commit()
}
func (s *Store) backoffs() (map[string]time.Time, error) {
	if _, e := s.db.Exec(`DELETE FROM site_backoff WHERE until<=unixepoch()`); e != nil {
		return nil, e
	}
	rows, e := s.db.Query(`SELECT site,until FROM site_backoff`)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	out := map[string]time.Time{}
	for rows.Next() {
		var site string
		var until int64
		if e = rows.Scan(&site, &until); e != nil {
			return nil, e
		}
		out[site] = time.Unix(until, 0)
	}
	return out, rows.Err()
}
