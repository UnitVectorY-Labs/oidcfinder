package oidcfinder

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"gopkg.in/yaml.v3"
)

func testStore(t *testing.T) *Store {
	t.Helper()
	s, e := openStore(filepath.Join(t.TempDir(), "test.db"))
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { s.Close() })
	return s
}
func writeTestFile(t *testing.T, text string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "input")
	if e := os.WriteFile(p, []byte(text), 0600); e != nil {
		t.Fatal(e)
	}
	return p
}
func check(t *testing.T, e error) {
	t.Helper()
	if e != nil {
		t.Fatal(e)
	}
}
func options() CrawlOptions {
	return CrawlOptions{Workers: 3, Interval: time.Millisecond, SiteInterval: time.Millisecond, Timeout: time.Second, PositiveTTL: time.Hour, NegativeTTL: 24 * time.Hour, RetryTTL: time.Minute}
}
func fixtureMetadata() map[string]any {
	return map[string]any{"issuer": "https://auth.example.com", "jwks_uri": "https://auth.example.com/keys", "authorization_endpoint": "https://auth.example.com/authorize", "token_endpoint": "https://auth.example.com/token", "response_types_supported": []any{"code"}, "subject_types_supported": []any{"public"}, "id_token_signing_alg_values_supported": []any{"RS256"}}
}
func fixtureKey() map[string]any {
	return map[string]any{"kty": "RSA", "n": base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{1}, 256)), "e": "AQAB"}
}

type transportFunc func(*http.Request) (*http.Response, error)

func (f transportFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
func response(r *http.Request, status int, body string) *http.Response {
	return &http.Response{StatusCode: status, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(body)), Request: r}
}
func fixtureClient(counter *int) *http.Client {
	return &http.Client{Transport: transportFunc(func(r *http.Request) (*http.Response, error) {
		*counter++
		var b []byte
		if r.URL.Path == "/keys" {
			b, _ = json.Marshal(map[string]any{"keys": []any{fixtureKey()}})
		} else {
			b, _ = json.Marshal(fixtureMetadata())
		}
		return response(r, 200, string(b)), nil
	})}
}
func TestImportCSVIdempotenceAndValidation(t *testing.T) {
	s := testStore(t)
	p := writeTestFile(t, "\ufeffrank,domain,categories\r\n1,Google.com,Search\r\n2,example.com,Test\r\n3,google.com,Duplicate\r\n")
	n, a, e := s.importDomains(context.Background(), p, []string{"accounts", "auth"}, nil)
	check(t, e)
	if n != 3 || a != 6 {
		t.Fatalf("domains %d added %d", n, a)
	}
	_, a, e = s.importDomains(context.Background(), p, []string{"accounts", "auth"}, nil)
	check(t, e)
	if a != 0 {
		t.Fatal("not idempotent")
	}
	for _, raw := range []string{"https://example.com", "127.0.0.1", "a..com", "-a.com", "example.com/path", "localhost"} {
		if _, e = validDomain(raw); e == nil {
			t.Errorf("accepted %q", raw)
		}
	}
	if d, e := validDomain("bücher.de"); e != nil || d != "xn--bcher-kva.de" {
		t.Fatalf("IDNA: %s %v", d, e)
	}
}
func TestScanValidationAndDecisionPersistence(t *testing.T) {
	s := testStore(t)
	_, _, e := s.importDomains(context.Background(), writeTestFile(t, "auth.example.com\n"), nil, nil)
	check(t, e)
	requests := 0
	out := scan(context.Background(), fixtureClient(&requests), target{ID: 1, Host: "auth.example.com"}, map[string]bool{})
	if len(out.found) != 2 || requests != 3 {
		t.Fatalf("scan: %+v requests=%d", out, requests)
	}
	check(t, s.save(out, options(), map[string]bool{}))
	list, e := s.listCandidates("pending", "", 0, 50)
	check(t, e)
	if len(list) != 1 || list[0].OIDC == "" || list[0].OAuth == "" {
		t.Fatalf("not merged: %+v", list)
	}
	c := list[0]
	check(t, s.decide(c.ID, "rejected", "", "", ""))
	check(t, s.save(out, options(), map[string]bool{}))
	list, e = s.listCandidates("rejected", "", 0, 50)
	check(t, e)
	if len(list) != 1 {
		t.Fatal("rejection lost")
	}
	check(t, s.decide(c.ID, "pending", "", "", ""))
	path := filepath.Join(t.TempDir(), "accepted.yaml")
	check(t, s.decide(c.ID, "accepted", "example", "Example", path))
	check(t, s.decide(c.ID, "accepted", "example", "Example", path))
	check(t, s.save(out, options(), map[string]bool{}))
	list, e = s.listCandidates("accepted", "", 0, 50)
	check(t, e)
	if len(list) != 1 || list[0].InCatalog {
		t.Fatal("acceptance became catalog membership")
	}
	b, e := os.ReadFile(path)
	check(t, e)
	var exported Services
	check(t, yaml.Unmarshal(b, &exported))
	if len(exported.Services) != 1 || exported.Services[0].ID != "example" {
		t.Fatalf("bad export: %s", b)
	}
	// Catalog refresh flags an accepted candidate without altering its decision.
	_, e = s.syncCatalog(context.Background(), "", path)
	check(t, e)
	list, e = s.listCandidates("accepted", "", 0, 50)
	check(t, e)
	if !list[0].InCatalog {
		t.Fatal("membership not refreshed")
	}
	_, e = s.syncCatalog(context.Background(), "", writeTestFile(t, "services: []\n"))
	check(t, e)
	list, e = s.listCandidates("accepted", "", 0, 50)
	check(t, e)
	if list[0].InCatalog {
		t.Fatal("stale membership")
	}
	// Nothing just scanned is due, and no request is needed by a repeated crawl.
	var log bytes.Buffer
	check(t, s.crawl(context.Background(), options(), &log))
	if !strings.Contains(log.String(), "scanned=0") {
		t.Fatal(log.String())
	}
}
func TestRejectFalsePositives(t *testing.T) {
	cases := []struct {
		name     string
		metadata map[string]any
		keys     any
		status   int
	}{{"HTML", nil, nil, 200}, {"error JSON", map[string]any{"error": "not found"}, nil, 200}, {"empty keys", fixtureMetadata(), []any{}, 200}, {"key type only", fixtureMetadata(), []any{map[string]any{"kty": "RSA"}}, 200}, {"private key", fixtureMetadata(), []any{map[string]any{"kty": "RSA", "d": "secret"}}, 200}, {"http error", fixtureMetadata(), []any{fixtureKey()}, 503}}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			client := &http.Client{Transport: transportFunc(func(r *http.Request) (*http.Response, error) {
				var b []byte
				if r.URL.Path == "/keys" {
					b, _ = json.Marshal(map[string]any{"keys": tc.keys})
				} else {
					b, _ = json.Marshal(tc.metadata)
				}
				return response(r, tc.status, string(b)), nil
			})}
			out := scan(context.Background(), client, target{Host: "auth.example.com"}, nil)
			if len(out.found) > 0 {
				t.Fatal("false positive", out)
			}
		})
	}
	m := fixtureMetadata()
	delete(m, "response_types_supported")
	if validateMetadata(m, true) == nil {
		t.Fatal("accepted incomplete OIDC")
	}
	if validateMetadata(m, false) != nil {
		t.Fatal("rejected OAuth metadata using OIDC-only requirements")
	}
}
func TestPacingGlobalSiteAndCancellation(t *testing.T) {
	var mu sync.Mutex
	var stamps []time.Time
	var hosts []string
	base := transportFunc(func(r *http.Request) (*http.Response, error) {
		mu.Lock()
		stamps = append(stamps, time.Now())
		hosts = append(hosts, r.URL.Hostname())
		mu.Unlock()
		return response(r, 200, `{}`), nil
	})
	tr := &pacedTransport{base: base, interval: 15 * time.Millisecond, siteInterval: 45 * time.Millisecond, sites: map[string]time.Time{}}
	var wg sync.WaitGroup
	for _, host := range []string{"a.example.com", "b.example.com", "example.net", "c.example.com"} {
		wg.Add(1)
		go func(host string) {
			defer wg.Done()
			r, _ := http.NewRequest("GET", "https://"+host, nil)
			resp, e := tr.RoundTrip(r)
			if e != nil {
				t.Error(e)
			} else {
				resp.Body.Close()
			}
		}(host)
	}
	wg.Wait()
	var priorSite time.Time
	for i, stamp := range stamps {
		if i > 0 && stamp.Sub(stamps[i-1]) < 13*time.Millisecond {
			t.Fatal("global pacing violated")
		}
		if strings.HasSuffix(hosts[i], "example.com") {
			if !priorSite.IsZero() && stamp.Sub(priorSite) < 43*time.Millisecond {
				t.Fatal("site pacing violated")
			}
			priorSite = stamp
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	r, _ := http.NewRequestWithContext(ctx, "GET", "https://a.example.com", nil)
	if _, e := tr.RoundTrip(r); e == nil {
		t.Fatal("ignored cancellation")
	}
}
func TestRetryAfterDoesNotBlockOtherSites(t *testing.T) {
	tr := &pacedTransport{base: transportFunc(func(r *http.Request) (*http.Response, error) {
		resp := response(r, 200, `{}`)
		if r.URL.Hostname() == "a.example.com" {
			resp.StatusCode = 429
			resp.Header.Set("Retry-After", "600")
		}
		return resp, nil
	}), sites: map[string]time.Time{}}
	r, _ := http.NewRequest("GET", "https://a.example.com", nil)
	resp, e := tr.RoundTrip(r)
	check(t, e)
	resp.Body.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Millisecond)
	defer cancel()
	r, _ = http.NewRequestWithContext(ctx, "GET", "https://b.example.com", nil)
	if _, e = tr.RoundTrip(r); e == nil {
		t.Fatal("Retry-After ignored")
	}
	r, _ = http.NewRequest("GET", "https://example.net", nil)
	start := time.Now()
	resp, e = tr.RoundTrip(r)
	check(t, e)
	resp.Body.Close()
	if time.Since(start) > time.Second {
		t.Fatal("another site was blocked")
	}
	if retryAfter("120") != 2*time.Minute {
		t.Fatal("retry delay")
	}
}
func TestCatalogAtomicityAndKnownURL(t *testing.T) {
	s := testStore(t)
	catalog := writeTestFile(t, "services:\n  - id: example\n    name: Example\n    openid-configuration: https://auth.example.com/.well-known/openid-configuration\n    jwks_uri: https://auth.example.com/keys\n")
	_, e := s.syncCatalog(context.Background(), "", catalog)
	check(t, e)
	_, e = s.syncCatalog(context.Background(), "", writeTestFile(t, "services:\n - id: invalid\n"))
	if e == nil {
		t.Fatal("invalid catalog accepted")
	}
	known, e := s.catalogSet()
	check(t, e)
	if !known["https://auth.example.com/keys"] {
		t.Fatal("failed refresh destroyed old catalog")
	}
	calls := 0
	out := scan(context.Background(), fixtureClient(&calls), target{Host: "auth.example.com"}, known)
	if calls != 2 || len(out.found) != 1 {
		t.Fatalf("known URL not skipped: %d %+v", calls, out)
	}
}
func TestExportFailureAndCollision(t *testing.T) {
	s := testStore(t)
	calls := 0
	out := scan(context.Background(), fixtureClient(&calls), target{Host: "auth.example.com"}, nil)
	check(t, s.save(out, options(), nil))
	list, e := s.listCandidates("pending", "", 0, 50)
	check(t, e)
	id := list[0].ID
	path := writeTestFile(t, "services:\n - id: example\n   name: Other\n   jwks_uri: https://other.example/keys\n")
	if e = s.decide(id, "accepted", "example", "Example", path); e == nil {
		t.Fatal("clobbered existing id")
	}
	list, e = s.listCandidates("pending", "", 0, 50)
	check(t, e)
	if len(list) != 1 {
		t.Fatal("failed export changed decision")
	}
	if e = s.decide(id, "accepted", "example", "Example", t.TempDir()); e == nil {
		t.Fatal("accepted directory as export")
	}
}
func TestLeaseAndPrivateAddresses(t *testing.T) {
	s := testStore(t)
	check(t, s.lock("one"))
	if e := s.lock("two"); e == nil {
		t.Fatal("concurrent crawl allowed")
	}
	s.unlock("one")
	check(t, s.lock("two"))
	for _, v := range []string{"127.0.0.1", "10.0.0.1", "169.254.169.254", "::1", "fc00::1", "100.64.0.1", "192.0.2.1", "2001:db8::1"} {
		if publicIP(net.ParseIP(v)) {
			t.Error("allowed", v)
		}
	}
	client := newClient(0, 0, time.Second)
	_, e := client.Get("https://127.0.0.1/")
	if e == nil {
		t.Fatal("connected to loopback")
	}
	for _, u := range []string{"http://example.com", "https://user:pass@example.com", "https://example.com:99999", "https://example.com/#fragment"} {
		if validateURL(u, false) == nil {
			t.Error("allowed", u)
		}
	}
}
func TestTUIEmptyNavigationAndReview(t *testing.T) {
	s := testStore(t)
	m := reviewModel{store: s, filter: "pending", width: 100, height: 24}
	model, _ := m.Update(tea.KeyMsg{Type: tea.KeyDown})
	m = model.(reviewModel)
	if m.cursor < 0 {
		t.Fatal("negative cursor on empty list")
	}
	if !strings.Contains(m.View(), "No candidates") {
		t.Fatal(m.View())
	}
	calls := 0
	out := scan(context.Background(), fixtureClient(&calls), target{Host: "auth.example.com"}, nil)
	check(t, s.save(out, options(), nil))
	model, _ = m.Update(m.load()())
	m = model.(reviewModel)
	model, _ = m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'a'}})
	m = model.(reviewModel)
	if m.mode != "accept" {
		t.Fatal("accept form missing")
	}
	if !strings.Contains(m.View(), "Name:") {
		t.Fatal(m.View())
	}
	model, _ = m.Update(tea.KeyMsg{Type: tea.KeyEsc})
	m = model.(reviewModel)
	model, cmd := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'r'}})
	m = model.(reviewModel)
	model, cmd = m.Update(cmd())
	m = model.(reviewModel)
	model, _ = m.Update(cmd())
	m = model.(reviewModel)
	if len(m.items) != 0 {
		t.Fatal("rejection not reflected")
	}
}
func TestCLIValidation(t *testing.T) {
	for _, args := range [][]string{{"crawl"}, {"crawl", "--domains", "missing", "--workers", "0"}, {"status", "unexpected"}, {"agent"}} {
		if e := Run(args, io.Discard, io.Discard); e == nil {
			t.Errorf("accepted %v", args)
		}
	}
	check(t, Run([]string{"crawl", "--help"}, io.Discard, io.Discard))
}
func TestLargeImport(t *testing.T) {
	if testing.Short() {
		t.Skip("scale test")
	}
	s := testStore(t)
	p := filepath.Join(t.TempDir(), "domains.csv")
	f, e := os.Create(p)
	check(t, e)
	var b strings.Builder
	b.WriteString("rank,domain\n")
	for i := 0; i < 100000; i++ {
		fmt.Fprintf(&b, "%d,domain%d.example.com\n", i+1, i)
	}
	_, e = f.WriteString(b.String())
	check(t, e)
	check(t, f.Close())
	start := time.Now()
	n, a, e := s.importDomains(context.Background(), p, []string{"auth", "login"}, nil)
	check(t, e)
	if n != 100000 || a != 300000 {
		t.Fatalf("lost targets: %d %d", n, a)
	}
	elapsed := time.Since(start)
	var pages, size int64
	check(t, s.db.QueryRow(`PRAGMA page_count`).Scan(&pages))
	check(t, s.db.QueryRow(`PRAGMA page_size`).Scan(&size))
	t.Logf("100k domains / 300k targets imported in %s; SQLite allocated %.1f MiB", elapsed, float64(pages*size)/(1<<20))
	var planID, parent, unused int
	var detail string
	check(t, s.db.QueryRow(`EXPLAIN QUERY PLAN SELECT id,host,site FROM targets WHERE next_attempt<=? ORDER BY next_attempt,id LIMIT 256`, time.Now().Unix()).Scan(&planID, &parent, &unused, &detail))
	if !strings.Contains(detail, "targets_due") {
		t.Fatalf("queue does not use due index: %s", detail)
	}
	t.Log(detail)
}

func TestBackoffPersistsAndCoversNewTargets(t *testing.T) {
	s := testStore(t)
	p := writeTestFile(t, "example.com\n")
	_, _, e := s.importDomains(context.Background(), p, []string{"auth"}, nil)
	check(t, e)
	until := time.Now().Add(2 * time.Hour)
	check(t, s.recordBackoff("example.com", until))
	_, _, e = s.importDomains(context.Background(), p, []string{"auth", "login"}, nil)
	check(t, e)
	var n int
	check(t, s.db.QueryRow(`SELECT COUNT(*) FROM targets WHERE next_attempt>=?`, until.Unix()).Scan(&n))
	if n != 3 {
		t.Fatalf("only %d targets cooled down", n)
	}
	backoff, e := s.backoffs()
	check(t, e)
	if !backoff["example.com"].After(time.Now()) {
		t.Fatal("lost persisted cooldown")
	}
	// Saving an already in-flight result must not shorten the site cooldown.
	check(t, s.save(outcome{target: target{ID: 1, Host: "example.com"}, kind: "valid"}, CrawlOptions{PositiveTTL: time.Minute}, nil))
	var due int64
	check(t, s.db.QueryRow(`SELECT next_attempt FROM targets WHERE id=1`).Scan(&due))
	if due < until.Unix() {
		t.Fatal("in-flight result shortened cooldown")
	}
}
func TestSchedulingTTLsAndImportCancellation(t *testing.T) {
	s := testStore(t)
	p := writeTestFile(t, "example.com\n")
	_, _, e := s.importDomains(context.Background(), p, nil, nil)
	check(t, e)
	for _, tc := range []struct {
		kind string
		want time.Duration
	}{{"negative", 24 * time.Hour}, {"transient", time.Minute}, {"valid", time.Hour}, {"catalog", time.Hour}} {
		check(t, s.db.QueryRow(`UPDATE targets SET next_attempt=0 WHERE id=1 RETURNING id`).Scan(new(int)))
		check(t, s.save(outcome{target: target{ID: 1, Host: "example.com"}, kind: tc.kind}, options(), nil))
		var next int64
		check(t, s.db.QueryRow(`SELECT next_attempt FROM targets WHERE id=1`).Scan(&next))
		delta := time.Until(time.Unix(next, 0))
		if delta < tc.want-time.Second || delta > tc.want {
			t.Fatalf("%s TTL: %s", tc.kind, delta)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, _, e = s.importDomains(ctx, p, nil, nil); e == nil {
		t.Fatal("canceled import succeeded")
	}
}
func TestRequestTimeoutExcludesPacing(t *testing.T) {
	tr := &pacedTransport{interval: 50 * time.Millisecond, timeout: 10 * time.Millisecond, sites: map[string]time.Time{}, base: transportFunc(func(r *http.Request) (*http.Response, error) {
		if r.Context().Err() != nil {
			return nil, r.Context().Err()
		}
		return response(r, 200, `{}`), nil
	})}
	client := &http.Client{Transport: tr}
	for range 2 {
		var m map[string]any
		check(t, fetchJSON(context.Background(), client, "https://example.com/", &m))
	}
	// Once dispatched, a stalled wire request is canceled by its deadline.
	tr.base = transportFunc(func(r *http.Request) (*http.Response, error) { <-r.Context().Done(); return nil, r.Context().Err() })
	var m map[string]any
	if fetchJSON(context.Background(), client, "https://example.com/", &m) == nil {
		t.Fatal("network timeout ignored")
	}
}
func TestSiteInterleaving(t *testing.T) {
	batch := []target{{ID: 1, Site: "a"}, {ID: 2, Site: "a"}, {ID: 3, Site: "b"}, {ID: 4, Site: "b"}}
	mixed := interleaveSites(batch)
	if mixed[0].ID != 1 || mixed[1].ID != 3 || mixed[2].ID != 2 || mixed[3].ID != 4 {
		t.Fatal(mixed)
	}
}
func TestFetchBoundsAndRedirectPolicy(t *testing.T) {
	for _, tc := range []struct {
		status int
		body   string
	}{{204, `{}`}, {302, `{}`}, {200, strings.Repeat("x", maxBody+1)}} {
		c := &http.Client{Transport: transportFunc(func(r *http.Request) (*http.Response, error) { return response(r, tc.status, tc.body), nil })}
		var out map[string]any
		if fetchJSON(context.Background(), c, "https://example.com/", &out) == nil {
			t.Fatalf("accepted HTTP %d body length %d", tc.status, len(tc.body))
		}
	}
	client := newClient(0, 0, time.Second)
	req, _ := http.NewRequest("GET", "http://example.com/", nil)
	if client.CheckRedirect(req, nil) == nil {
		t.Fatal("allowed downgrade")
	}
	req, _ = http.NewRequest("GET", "https://example.com/", nil)
	if client.CheckRedirect(req, make([]*http.Request, 3)) == nil {
		t.Fatal("ignored redirect bound")
	}
}

func TestEmptyExportAndBulkFailureAtomicity(t *testing.T) {
	s := testStore(t)
	path := filepath.Join(t.TempDir(), "accepted.yaml")
	n, e := s.exportAccepted(path)
	check(t, e)
	if n != 0 {
		t.Fatal(n)
	}
	b, e := os.ReadFile(path)
	check(t, e)
	if !strings.Contains(string(b), "services: []") {
		t.Fatal(string(b))
	}
	original := []byte("services:\n - id: reserved\n   name: Existing\n   jwks_uri: https://existing.example/keys\n")
	check(t, os.WriteFile(path, original, 0600))
	e = appendServices(path, []Candidate{{ServiceID: "first", Name: "First", OIDC: "https://first.example/config", JWKS: "https://first.example/keys"}, {ServiceID: "reserved", Name: "Collision", OIDC: "https://second.example/config", JWKS: "https://second.example/keys"}})
	if e == nil {
		t.Fatal("expected collision")
	}
	b, e = os.ReadFile(path)
	check(t, e)
	if !bytes.Equal(b, original) {
		t.Fatal("partial export on collision")
	}
}

func TestTUISearchCancelAndStaleResults(t *testing.T) {
	m := reviewModel{filter: "pending", search: "original"}
	model, _ := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'/'}})
	m = model.(reviewModel)
	model, _ = m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'x'}})
	m = model.(reviewModel)
	model, _ = m.Update(tea.KeyMsg{Type: tea.KeyEsc})
	m = model.(reviewModel)
	if m.search != "original" {
		t.Fatal("canceled search changed filter")
	}
	model, _ = m.Update(reviewLoaded{filter: "accepted", search: "original", items: []Candidate{{ID: 99}}})
	m = model.(reviewModel)
	if len(m.items) != 0 {
		t.Fatal("stale response replaced current view")
	}
}

func TestImportSkipsInvalidDomainsAndContinuesAcrossBatches(t *testing.T) {
	s := testStore(t)
	var input strings.Builder
	input.WriteString("rank,domain\n")
	for i := 0; i < 1001; i++ {
		fmt.Fprintf(&input, "%d,domain%d.example.com\n", i+1, i)
	}
	input.WriteString("1002,web\n1003,\n1004\n1005,127.0.0.1\n1006,after.example.com\n")
	path := writeTestFile(t, input.String())
	var warnings []int
	report := func(row int, err error) {
		if err == nil {
			t.Error("missing skip reason")
		}
		warnings = append(warnings, row)
	}
	n, a, e := s.importDomains(context.Background(), path, []string{"auth"}, report)
	check(t, e)
	if n != 1002 || a != 2004 || fmt.Sprint(warnings) != "[1003 1004 1005 1006]" {
		t.Fatalf("domains=%d added=%d warnings=%v", n, a, warnings)
	}
	var count int
	check(t, s.db.QueryRow(`SELECT COUNT(*) FROM targets WHERE host IN ('after.example.com','auth.after.example.com')`).Scan(&count))
	if count != 2 {
		t.Fatal("rows after invalid domain were lost")
	}
	warnings = nil
	n, a, e = s.importDomains(context.Background(), path, []string{"auth"}, report)
	check(t, e)
	if n != 1002 || a != 0 || len(warnings) != 4 {
		t.Fatalf("repeat: %d %d %v", n, a, warnings)
	}
}

func TestImportInvalidOnlyAndBrokenCSVFail(t *testing.T) {
	for _, input := range []string{"web\nlocalhost\n", "domain\n\"unterminated\n"} {
		s := testStore(t)
		if _, _, err := s.importDomains(context.Background(), writeTestFile(t, input), nil, nil); err == nil {
			t.Fatalf("accepted input %q", input)
		}
	}
}

func TestCLIInvalidDomainWarningsAreBounded(t *testing.T) {
	var stdout, stderr bytes.Buffer
	err := Run([]string{"crawl", "--domains", writeTestFile(t, "domain\n"+strings.Repeat("web\n", 15)), "--catalog-file", writeTestFile(t, "services: []\n"), "--db", filepath.Join(t.TempDir(), "crawl.db")}, &stdout, &stderr)
	if err == nil || !strings.Contains(err.Error(), "no valid domains") {
		t.Fatalf("unexpected error: %v", err)
	}
	if strings.Count(stderr.String(), "warning: skipping domain input row") != 10 || !strings.Contains(stderr.String(), "5 additional invalid domain rows skipped") {
		t.Fatal(stderr.String())
	}
}
