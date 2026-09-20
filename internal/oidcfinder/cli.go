package oidcfinder

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"
)

const usage = `oidcfinder — deterministic discovery for the JWKS Catalog

Usage:
  oidcfinder crawl --domains FILE [--prefixes prefixes.yaml] [flags]
  oidcfinder tui [--db data/crawler.db] [--export data/accepted.yaml]
  oidcfinder status [--db data/crawler.db]
  oidcfinder export [--db data/crawler.db] [--export data/accepted.yaml]

Run a command with --help for its flags. Runtime files belong in data/.
`

func Run(args []string, stdout, stderr io.Writer) error {
	if len(args) == 0 || args[0] == "help" || args[0] == "--help" || args[0] == "-h" {
		_, e := io.WriteString(stdout, usage)
		return e
	}
	command := args[0]
	if command != "crawl" && command != "tui" && command != "status" && command != "export" {
		return fmt.Errorf("unknown command %q\n%s", command, usage)
	}
	fs := flag.NewFlagSet(command, flag.ContinueOnError)
	fs.SetOutput(stderr)
	db := fs.String("db", "data/crawler.db", "SQLite path (new deterministic schema)")
	export := ""
	if command == "tui" || command == "export" {
		fs.StringVar(&export, "export", "", "Accepted services YAML (default: accepted.yaml beside database)")
	}
	var domains, prefixes, localCatalog, remoteCatalog string
	opt := CrawlOptions{}
	if command == "crawl" {
		fs.StringVar(&domains, "domains", "", "Cloudflare CSV or one domain per line (required)")
		fs.StringVar(&prefixes, "prefixes", "", "Prefix YAML; defaults to common prefixes")
		fs.StringVar(&localCatalog, "catalog-file", "", "Local catalog override for reproducible tests")
		fs.StringVar(&remoteCatalog, "catalog-url", catalogURL, "Catalog URL, fetched before every crawl")
		fs.IntVar(&opt.Workers, "workers", 4, "Concurrent target workers (1–32)")
		fs.IntVar(&opt.Limit, "limit", 0, "Maximum due targets this run; 0 drains the queue")
		fs.DurationVar(&opt.Interval, "interval", 500*time.Millisecond, "Minimum time between all HTTP requests")
		fs.DurationVar(&opt.SiteInterval, "site-interval", 2*time.Second, "Minimum time between requests to the same registrable domain")
		fs.DurationVar(&opt.Timeout, "timeout", 15*time.Second, "HTTP request timeout after pacing")
		fs.DurationVar(&opt.PositiveTTL, "positive-ttl", 7*24*time.Hour, "Revisit valid/catalog targets after")
		fs.DurationVar(&opt.NegativeTTL, "negative-ttl", 30*24*time.Hour, "Revisit negative targets after")
		fs.DurationVar(&opt.RetryTTL, "retry-ttl", 24*time.Hour, "Retry network errors, HTTP 429 and 5xx after")
	}
	if e := fs.Parse(args[1:]); e != nil {
		if errors.Is(e, flag.ErrHelp) {
			return nil
		}
		return e
	}
	if fs.NArg() != 0 {
		return fmt.Errorf("unexpected positional arguments: %v", fs.Args())
	}
	var prefixList []string
	var err error
	if command == "crawl" {
		if domains == "" {
			return fmt.Errorf("--domains is required")
		}
		if opt.Workers < 1 || opt.Workers > 32 || opt.Limit < 0 || opt.Interval < 50*time.Millisecond || opt.SiteInterval < 500*time.Millisecond || opt.Timeout <= 0 || opt.PositiveTTL < time.Second || opt.NegativeTTL < time.Second || opt.RetryTTL < time.Second {
			return fmt.Errorf("invalid crawl settings: workers 1–32, limit >=0, interval >=50ms, site-interval >=500ms, positive timeout, TTLs >=1s")
		}
		prefixList, err = loadPrefixes(prefixes)
		if err != nil {
			return err
		}
	}
	s, e := openStore(*db)
	if e != nil {
		return e
	}
	defer s.Close()
	if export == "" {
		export = filepath.Join(filepath.Dir(*db), "accepted.yaml")
	}
	switch command {
	case "status":
		status, e := s.status()
		if e != nil {
			return e
		}
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(status)
	case "export":
		n, e := s.exportAccepted(export)
		if e == nil {
			fmt.Fprintf(stdout, "exported %d accepted services to %s\n", n, export)
		}
		return e
	case "tui":
		return runTUI(s, export, os.Stdin, stdout)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	owner := fmt.Sprintf("%d-%d", os.Getpid(), time.Now().UnixNano())
	if e = s.lock(owner); e != nil {
		return e
	}
	defer s.unlock(owner)
	// Heartbeat covers ingestion and catalog sync, as well as network crawling.
	heartbeatDone := make(chan struct{})
	heartbeatErr := make(chan error, 1)
	go func() {
		defer close(heartbeatDone)
		tick := time.NewTicker(15 * time.Second)
		defer tick.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-tick.C:
				r, e := s.db.Exec(`UPDATE crawl_lock SET expires=? WHERE owner=?`, time.Now().Add(time.Minute).Unix(), owner)
				if e == nil {
					n, _ := r.RowsAffected()
					if n != 1 {
						e = fmt.Errorf("crawl lease lost")
					}
				}
				if e != nil {
					heartbeatErr <- e
					cancel()
					return
				}
			}
		}
	}()
	defer func() { cancel(); <-heartbeatDone }()
	n, e := s.syncCatalog(ctx, remoteCatalog, localCatalog)
	if e != nil {
		return fmt.Errorf("catalog refresh failed; crawl not started: %w", e)
	}
	fmt.Fprintf(stdout, "catalog refreshed: %d services\n", n)
	count, added, e := s.importDomains(ctx, domains, prefixList)
	if e != nil {
		return e
	}
	fmt.Fprintf(stdout, "domains=%d new_targets=%d prefixes=%d (+ apex)\n", count, added, len(prefixList))
	e = s.crawl(ctx, opt, stdout)
	select {
	case err := <-heartbeatErr:
		return err
	default:
	}
	if errors.Is(e, context.Canceled) {
		return fmt.Errorf("crawl interrupted; completed targets saved, rerun to resume")
	}
	return e
}
