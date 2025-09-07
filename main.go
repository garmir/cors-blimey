package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
)

type Config struct {
	concurrency int
	timeout     time.Duration
	insecure    bool
	verbose     bool
	userAgent   string
	maxRedirects int
}

var config Config

func init() {
	flag.IntVar(&config.concurrency, "c", 20, "Number of concurrent workers")
	flag.DurationVar(&config.timeout, "t", 10*time.Second, "Request timeout")
	flag.BoolVar(&config.insecure, "insecure", false, "Skip SSL certificate verification")
	flag.BoolVar(&config.verbose, "v", false, "Verbose output (show errors)")
	flag.StringVar(&config.userAgent, "ua", "cors-blimey/2.0", "User-Agent header")
	flag.IntVar(&config.maxRedirects, "max-redirects", 0, "Maximum redirects to follow (0 = no redirects)")
}

func main() {
	flag.Parse()

	client := createClient()
	urls := make(chan string, config.concurrency*2)

	var wg sync.WaitGroup
	ctx := context.Background()

	// Start workers
	for i := 0; i < config.concurrency; i++ {
		wg.Add(1)
		go worker(ctx, client, urls, &wg)
	}

	// Read URLs from stdin
	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
		url := strings.TrimSpace(scanner.Text())
		if url == "" {
			continue
		}
		urls <- url
	}

	if err := scanner.Err(); err != nil {
		fmt.Fprintf(os.Stderr, "Error reading input: %v\n", err)
	}

	close(urls)
	wg.Wait()
}

func createClient() *http.Client {
	transport := &http.Transport{
		MaxIdleConns:        config.concurrency,
		MaxIdleConnsPerHost: config.concurrency,
		MaxConnsPerHost:     config.concurrency,
		IdleConnTimeout:     30 * time.Second,
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: config.insecure,
		},
		DialContext: (&net.Dialer{
			Timeout:   config.timeout,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		DisableKeepAlives: false,
	}

	checkRedirect := func(req *http.Request, via []*http.Request) error {
		if config.maxRedirects == 0 {
			return http.ErrUseLastResponse
		}
		if len(via) >= config.maxRedirects {
			return fmt.Errorf("too many redirects")
		}
		return nil
	}

	return &http.Client{
		Transport:     transport,
		CheckRedirect: checkRedirect,
		Timeout:       config.timeout,
	}
}

func worker(ctx context.Context, client *http.Client, urls <-chan string, wg *sync.WaitGroup) {
	defer wg.Done()

	for rawURL := range urls {
		testCORS(ctx, client, rawURL)
	}
}

func testCORS(ctx context.Context, client *http.Client, rawURL string) {
	// Validate URL
	if !strings.HasPrefix(rawURL, "http://") && !strings.HasPrefix(rawURL, "https://") {
		rawURL = "https://" + rawURL
	}

	origins, err := generateTestOrigins(rawURL)
	if err != nil {
		if config.verbose {
			fmt.Fprintf(os.Stderr, "Error parsing URL %s: %v\n", rawURL, err)
		}
		return
	}

	for _, origin := range origins {
		if err := testOrigin(ctx, client, rawURL, origin); err != nil {
			if config.verbose {
				fmt.Fprintf(os.Stderr, "Error testing %s with origin %s: %v\n", rawURL, origin, err)
			}
		}
	}
}

func testOrigin(ctx context.Context, client *http.Client, targetURL, origin string) error {
	req, err := http.NewRequestWithContext(ctx, "GET", targetURL, nil)
	if err != nil {
		return fmt.Errorf("creating request: %w", err)
	}

	// Set headers
	req.Header.Set("Origin", origin)
	req.Header.Set("User-Agent", config.userAgent)
	req.Header.Set("Accept", "*/*")

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	// Discard body to reuse connection
	io.Copy(io.Discard, resp.Body)

	// Check CORS headers
	acao := resp.Header.Get("Access-Control-Allow-Origin")
	acac := resp.Header.Get("Access-Control-Allow-Credentials")

	// Check for vulnerable configurations
	if isVulnerableCORS(acao, acac, origin) {
		severity := assessSeverity(acao, acac, origin)
		fmt.Printf("[%s] %s | Origin: %s | ACAO: %s | ACAC: %s | Status: %d\n", 
			severity, targetURL, origin, acao, acac, resp.StatusCode)
	}

	return nil
}

func generateTestOrigins(rawURL string) ([]string, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, fmt.Errorf("parsing URL: %w", err)
	}

	hostname := u.Hostname()
	if hostname == "" {
		return nil, fmt.Errorf("no hostname in URL")
	}

	// Test various origin patterns
	origins := []string{
		"null",                                    // null origin
		"https://evil.com",                       // arbitrary origin
		"http://evil.com",                        // HTTP downgrade
		fmt.Sprintf("https://%s.evil.com", hostname),     // subdomain injection
		fmt.Sprintf("https://%sevil.com", hostname),      // suffix injection
		fmt.Sprintf("https://evil%s", hostname),          // prefix injection
		fmt.Sprintf("http://%s", hostname),               // protocol downgrade
		fmt.Sprintf("https://%s.localhost", hostname),    // localhost subdomain
		fmt.Sprintf("https://not-%s", hostname),          // prefix variation
	}

	// Add variations of the original domain
	if strings.Contains(hostname, ".") {
		parts := strings.Split(hostname, ".")
		if len(parts) >= 2 {
			// Test parent domain
			origins = append(origins, fmt.Sprintf("https://%s", strings.Join(parts[1:], ".")))
			// Test subdomain
			origins = append(origins, fmt.Sprintf("https://evil.%s", hostname))
		}
	}

	return origins, nil
}

func isVulnerableCORS(acao, acac, origin string) bool {
	// Check for vulnerable patterns
	if acao == "" {
		return false
	}

	// Wildcard with credentials
	if acao == "*" && acac == "true" {
		return true
	}

	// Reflects origin
	if acao == origin {
		return true
	}

	// null origin accepted
	if acao == "null" && origin == "null" {
		return true
	}

	return false
}

func assessSeverity(acao, acac, origin string) string {
	// Critical: Wildcard with credentials or null with credentials
	if (acao == "*" && acac == "true") || (acao == "null" && acac == "true") {
		return "CRITICAL"
	}

	// High: Reflects arbitrary origin with credentials
	if acao == origin && acac == "true" && (origin == "https://evil.com" || origin == "http://evil.com") {
		return "HIGH"
	}

	// Medium: Reflects origin without credentials or accepts null
	if acao == origin || acao == "null" {
		return "MEDIUM"
	}

	// Low: Wildcard without credentials
	if acao == "*" {
		return "LOW"
	}

	return "INFO"
}