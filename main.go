// main.go
package main

import (
	"bufio"
	"context"
	"database/sql"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

type domainResult struct {
	domain   string
	hasOIDC  bool
	oidcURL  string
	timedOut bool
}

func main() {
	// Flags
	dbPath := flag.String("db", "domains.db", "SQLite database file")
	listFlag := flag.Bool("list", false, "List valid and invalid domains")
	fileFlag := flag.String("file", "", "Path to file with domains to test (one per line)")
	addValid := flag.String("add-valid", "", "Add domain to valid list")
	addInvalid := flag.String("add-invalid", "", "Add domain to invalid list")
	rmValid := flag.String("remove-valid", "", "Remove domain from valid list")
	rmInvalid := flag.String("remove-invalid", "", "Remove domain from invalid list")
	rmAny := flag.String("remove", "", "Remove domain from any list")
	prefixFlag := flag.String("prefix", "", "Prefix to add to domains from file")
	outFlag := flag.String("out", "", "Output file to append OIDC endpoint URLs (optional)")
	parallelFlag := flag.Int("parallel", 1, "Number of parallel crawls to perform (default: 1)")
	timeoutFlag := flag.Int("timeout", 30, "Timeout in seconds for HTTP requests (default: 30)")
	flag.Parse()

	// Ensure exactly one action is specified
	actions := 0
	if *listFlag {
		actions++
	}
	if *fileFlag != "" {
		actions++
	}
	if *addValid != "" {
		actions++
	}
	if *addInvalid != "" {
		actions++
	}
	if *rmValid != "" {
		actions++
	}
	if *rmInvalid != "" {
		actions++
	}
	if *rmAny != "" {
		actions++
	}
	if actions != 1 {
		fmt.Fprintln(os.Stderr, "Error: specify exactly one action")
		flag.Usage()
		os.Exit(1)
	}

	// Open SQLite DB
	db, err := sql.Open("sqlite3", *dbPath)
	if err != nil {
		log.Fatalf("Failed to open database: %v", err)
	}
	defer db.Close()

	// Create table if not exists
	_, err = db.Exec(`
        CREATE TABLE IF NOT EXISTS domains (
            name TEXT PRIMARY KEY,
            has_oidc BOOLEAN NOT NULL,
            tested_at DATETIME DEFAULT CURRENT_TIMESTAMP
        );
    `)
	if err != nil {
		log.Fatalf("Failed to create table: %v", err)
	}

	switch {
	case *listFlag:
		listDomains(db)
	case *fileFlag != "":
		processFile(db, *fileFlag, *prefixFlag, *outFlag, *parallelFlag, *timeoutFlag)
	case *addValid != "":
		addDomain(db, strings.TrimSpace(*addValid), true)
	case *addInvalid != "":
		addDomain(db, strings.TrimSpace(*addInvalid), false)
	case *rmValid != "":
		removeDomain(db, strings.TrimSpace(*rmValid), true)
	case *rmInvalid != "":
		removeDomain(db, strings.TrimSpace(*rmInvalid), false)
	case *rmAny != "":
		removeAny(db, strings.TrimSpace(*rmAny))
	}
}

func listDomains(db *sql.DB) {
	fmt.Println("Valid domains:")
	rows, err := db.Query(`SELECT name FROM domains WHERE has_oidc = 1 ORDER BY name`)
	if err != nil {
		log.Fatalf("Query failed: %v", err)
	}
	defer rows.Close()
	for rows.Next() {
		var name string
		rows.Scan(&name)
		fmt.Println(" -", name)
	}

	fmt.Println("\nInvalid domains:")
	rows, err = db.Query(`SELECT name FROM domains WHERE has_oidc = 0 ORDER BY name`)
	if err != nil {
		log.Fatalf("Query failed: %v", err)
	}
	defer rows.Close()
	for rows.Next() {
		var name string
		rows.Scan(&name)
		fmt.Println(" -", name)
	}
}

func processFile(db *sql.DB, path string, prefix string, outFile string, parallel int, timeoutSecs int) {
	f, err := os.Open(path)
	if err != nil {
		log.Fatalf("Failed to open file: %v", err)
	}
	defer f.Close()

	// Read all domains from file
	var domains []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		domain := strings.TrimSpace(scanner.Text())
		if domain == "" {
			continue
		}
		if prefix != "" {
			domain = prefix + "." + domain
		}
		domains = append(domains, domain)
	}
	if err := scanner.Err(); err != nil {
		log.Fatalf("Error reading file: %v", err)
	}

	// Create channels for work distribution
	domainChan := make(chan string, len(domains))
	resultChan := make(chan domainResult, len(domains))

	// Populate domain channel
	for _, domain := range domains {
		domainChan <- domain
	}
	close(domainChan)

	// Create worker pool
	var wg sync.WaitGroup
	dbMutex := &sync.Mutex{}  // Mutex for database operations
	outMutex := &sync.Mutex{} // Mutex for output file operations

	for i := 0; i < parallel; i++ {
		wg.Add(1)
		go worker(domainChan, resultChan, db, dbMutex, outFile, outMutex, timeoutSecs, &wg)
	}

	// Close result channel when all workers are done
	go func() {
		wg.Wait()
		close(resultChan)
	}()

	// Process results
	for result := range resultChan {
		if result.timedOut {
			fmt.Printf("%s: request timed out (skipped) ⏰\n", result.domain)
		} else if result.hasOIDC {
			fmt.Printf("%s: OIDC endpoint found ✅\n", result.domain)
		} else {
			fmt.Printf("%s: no OIDC endpoint ❌\n", result.domain)
		}
	}
}

func worker(domainChan <-chan string, resultChan chan<- domainResult, db *sql.DB, dbMutex *sync.Mutex, outFile string, outMutex *sync.Mutex, timeoutSecs int, wg *sync.WaitGroup) {
	defer wg.Done()

	for domain := range domainChan {
		// Check if domain already exists in database
		dbMutex.Lock()
		var exists bool
		err := db.QueryRow(`SELECT has_oidc FROM domains WHERE name = ?`, domain).Scan(&exists)
		dbMutex.Unlock()

		if err == nil {
			fmt.Printf("%s: already known (has_oidc=%v)\n", domain, exists)
			continue
		}

		// Test OIDC with timeout
		oidcURL, hasOIDC, timedOut := testOIDCWithTimeout(domain, timeoutSecs)

		result := domainResult{
			domain:   domain,
			hasOIDC:  hasOIDC,
			oidcURL:  oidcURL,
			timedOut: timedOut,
		}

		// Only insert into database if not timed out
		if !timedOut {
			dbMutex.Lock()
			_, err = db.Exec(`
				INSERT INTO domains(name, has_oidc) VALUES(?, ?)
				ON CONFLICT(name) DO UPDATE SET has_oidc=excluded.has_oidc, tested_at=CURRENT_TIMESTAMP
			`, domain, hasOIDC)
			dbMutex.Unlock()

			if err != nil {
				log.Printf("Failed to insert %s: %v", domain, err)
			}

			// Write to output file if OIDC found
			if hasOIDC && outFile != "" {
				outMutex.Lock()
				appendToFile(outFile, oidcURL)
				outMutex.Unlock()
			}
		}

		resultChan <- result
	}
}

func addDomain(db *sql.DB, domain string, valid bool) {
	if domain == "" {
		log.Fatal("Domain is empty")
	}
	_, err := db.Exec(`
        INSERT INTO domains(name, has_oidc) VALUES(?, ?)
        ON CONFLICT(name) DO UPDATE SET has_oidc=excluded.has_oidc, tested_at=CURRENT_TIMESTAMP
    `, domain, valid)
	if err != nil {
		log.Fatalf("Failed to add domain: %v", err)
	}
	status := "invalid"
	if valid {
		status = "valid"
	}
	fmt.Printf("Added %s to %s list\n", domain, status)
}

func removeDomain(db *sql.DB, domain string, valid bool) {
	res, err := db.Exec(`
        DELETE FROM domains WHERE name = ? AND has_oidc = ?
    `, domain, valid)
	if err != nil {
		log.Fatalf("Failed to remove domain: %v", err)
	}
	n, _ := res.RowsAffected()
	if n > 0 {
		fmt.Printf("Removed %s from %s list\n", domain, map[bool]string{true: "valid", false: "invalid"}[valid])
	} else {
		fmt.Printf("Domain %s not found in %s list\n", domain, map[bool]string{true: "valid", false: "invalid"}[valid])
	}
}

func removeAny(db *sql.DB, domain string) {
	res, err := db.Exec(`DELETE FROM domains WHERE name = ?`, domain)
	if err != nil {
		log.Fatalf("Failed to remove domain: %v", err)
	}
	n, _ := res.RowsAffected()
	if n > 0 {
		fmt.Printf("Removed %s from all lists\n", domain)
	} else {
		fmt.Printf("Domain %s not found\n", domain)
	}
}

func testOIDCWithTimeout(domain string, timeoutSecs int) (string, bool, bool) {
	url := fmt.Sprintf("https://%s/.well-known/openid-configuration", domain)

	// Create HTTP client with timeout
	client := &http.Client{
		Timeout: time.Duration(timeoutSecs) * time.Second,
	}

	// Create context with timeout
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeoutSecs)*time.Second)
	defer cancel()

	// Create request with context
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return "", false, false
	}

	// Execute request
	resp, err := client.Do(req)
	if err != nil {
		// Check if it's a timeout error
		if ctx.Err() == context.DeadlineExceeded {
			log.Printf("Timeout testing %s", domain)
			return "", false, true // timedOut = true
		}
		return "", false, false
	}
	defer resp.Body.Close()

	ct := resp.Header.Get("Content-Type")
	if resp.StatusCode == 200 && strings.Contains(ct, "application/json") {
		return url, true, false
	}
	return "", false, false
}

func appendToFile(filename, content string) {
	f, err := os.OpenFile(filename, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Printf("Failed to open output file %s: %v", filename, err)
		return
	}
	defer f.Close()

	if _, err := f.WriteString(content + "\n"); err != nil {
		log.Printf("Failed to write to output file %s: %v", filename, err)
	}
}
