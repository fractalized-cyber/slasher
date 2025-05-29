package main

import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"net/http"
	neturl "net/url"
	"os"
	"strings"
	"sync"
	"time"
)

const version = "1.0.0"

var (
	followRedirects bool
	urlInput       string
)

// Banner text
const banner = `
████████╗██████╗  █████╗ ██╗██╗     ██╗███╗   ██╗ ██████╗          
╚══██╔══╝██╔══██╗██╔══██╗██║██║     ██║████╗  ██║██╔════╝          
   ██║   ██████╔╝███████║██║██║     ██║██╔██╗ ██║██║  ███╗         
   ██║   ██╔══██╗██╔══██║██║██║     ██║██║╚██╗██║██║   ██║         
   ██║   ██║  ██║██║  ██║██║███████╗██║██║ ╚████║╚██████╔╝         
   ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝╚══════╝╚═╝╚═╝  ╚═══╝ ╚═════╝          
                                                                   
███████╗██╗      █████╗ ███████╗██╗  ██╗███████╗██████╗         ██╗
██╔════╝██║     ██╔══██╗██╔════╝██║  ██║██╔════╝██╔══██╗       ██╔╝
███████╗██║     ███████║███████╗███████║█████╗  ██████╔╝      ██╔╝ 
╚════██║██║     ██╔══██║╚════██║██╔══██║██╔══╝  ██╔══██╗     ██╔╝  
███████║███████╗██║  ██║███████║██║  ██║███████╗██║  ██║    ██╔╝   
╚══════╝╚══════╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝    ╚═╝         
                                                                   v%s
A Path Traversal Scanner
`

// Help text
const helpText = `
DESCRIPTION:
  Slasher is a specialized path traversal vulnerability scanner that tests URLs using various 
  path manipulation techniques. It sends both GET and POST requests with different path variants 
  to identify potential directory traversal vulnerabilities.

FEATURES:
  - Tests multiple path manipulation techniques:
    • Trailing slashes (/)
    • Null bytes (%00)
    • Trailing dots (/.)
    • Double slashes (//)
    • Backslashes (\)
    • URL-encoded slashes (%2f)
    • URL-encoded backslashes (%5c)
    • Double-encoded slashes (%252f)
    • Triple-encoded slashes (%25252f)
  - Supports both GET and POST methods
  - Handles redirects (optional)
  - Processes single URLs or bulk testing from a file
  - Automatic retry mechanism for failed requests
  - Concurrent scanning for faster results

USAGE:
  slasher [options] -u <url_or_file>

OPTIONS:
  -u <url_or_file>    URL to test or file containing URLs (one per line)
  -follow             Follow redirects (default: false)
  -version            Show version information

EXAMPLES:
  Test a single URL:
    slasher -u https://example.com/path/to/test

  Test multiple URLs from a file:
    slasher -u urls.txt

  Test with redirect following enabled:
    slasher -follow -u https://example.com/path/to/test

OUTPUT:
  The tool reports differences in response sizes and status codes that might 
  indicate successful path traversal. Results include:
  - Original vs modified URL responses
  - Response sizes
  - Status codes
  - Redirect chains (if any)
`

var client = &http.Client{
	Timeout: 10 * time.Second,
	Transport: &http.Transport{
		MaxIdleConns:        100,
		IdleConnTimeout:     90 * time.Second,
		DisableCompression:  true,
		MaxConnsPerHost:     10,
		MaxIdleConnsPerHost: 10,
	},
	CheckRedirect: func(req *http.Request, via []*http.Request) error {
		if !followRedirects {
			return http.ErrUseLastResponse
		}
		// Allow up to 10 redirects
		if len(via) >= 10 {
			return http.ErrUseLastResponse
		}
		return nil
	},
}

type Result struct {
	URL            string
	FinalURL       string
	Label          string
	Method         string
	Size           int
	Status         int
	OriginalSize   int
	OriginalStatus int
	OriginalURL    string
	OriginalFinalURL string
	Error          error
}

// Helper to make GET or POST request and return size and status
func fetch(url string, method string) (int, int, string, error) {
	req, err := http.NewRequest(method, url, nil)
	if err != nil {
		return 0, 0, "", err
	}

	// Add common headers
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
	req.Header.Set("Accept", "*/*")
	req.Header.Set("Accept-Language", "en-US,en;q=0.9")

	// Create a custom client with increased timeouts
	client := &http.Client{
		Timeout: 30 * time.Second, // Increased from 10 to 30 seconds
		Transport: &http.Transport{
			MaxIdleConns:           100,
			MaxIdleConnsPerHost:    10,
			IdleConnTimeout:        90 * time.Second,
			DisableCompression:     true,
			MaxConnsPerHost:        10,
			// Add timeouts for the transport
			ResponseHeaderTimeout:   20 * time.Second,
			ExpectContinueTimeout:  10 * time.Second,
			TLSHandshakeTimeout:    10 * time.Second,
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if !followRedirects {
				return http.ErrUseLastResponse
			}
			// Allow up to 10 redirects
			if len(via) >= 10 {
				return http.ErrUseLastResponse
			}

			// Always use the original method from the first request
			originalMethod := via[0].Method
			req.Method = originalMethod

			// For POST requests, ensure proper handling through all redirects
			if originalMethod == "POST" {
				// Copy headers from the original request
				for k, v := range via[0].Header {
					req.Header[k] = v
				}
				// Set content length to 0 for POST requests
				req.ContentLength = 0
				// Ensure the request is treated as a POST
				req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			}

			return nil
		},
	}

	// For POST requests, set initial configuration
	if method == "POST" {
		req.ContentLength = 0
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}

	// Retry logic
	maxRetries := 3
	var lastErr error
	for i := 0; i < maxRetries; i++ {
		resp, err := client.Do(req)
		if err == nil {
			defer resp.Body.Close()
			body, err := io.ReadAll(resp.Body)
			if err != nil {
				return 0, 0, "", err
			}

			// Get the final URL after any redirects
			finalURL := resp.Request.URL.String()
			
			// Parse the URL to handle ports properly
			if parsedURL, err := neturl.Parse(finalURL); err == nil {
				// Remove default ports
				if parsedURL.Scheme == "http" && parsedURL.Port() == "80" {
					parsedURL.Host = parsedURL.Hostname()
				} else if parsedURL.Scheme == "https" && parsedURL.Port() == "443" {
					parsedURL.Host = parsedURL.Hostname()
				}
				finalURL = parsedURL.String()
			}

			return len(body), resp.StatusCode, finalURL, nil
		}

		lastErr = err
		// If it's not a timeout, don't retry
		if !strings.Contains(err.Error(), "timeout") {
			break
		}
		// Wait before retrying (exponential backoff)
		time.Sleep(time.Duration(i+1) * time.Second)
	}

	return 0, 0, "", lastErr
}

func processURL(original string, results chan<- Result, wg *sync.WaitGroup) {
	variants := map[string]string{
		"original":        original,
		"trailing-slash":  original + "/",
		"trailing-null":   original + "%00",
		"trailing-dot":    original + "/.",
		"double-slash":    original + "//",
		"backslash":       strings.Replace(original, "/", "\\", -1),
		"encoded-slash":   strings.Replace(original, "/", "%2f", -1),
		"encoded-backslash": strings.Replace(original, "/", "%5c", -1),
		"double-encoded-slash": strings.Replace(original, "/", "%252f", -1),
		"triple-encoded-slash": strings.Replace(original, "/", "%25252f", -1),
	}

	// Test both GET and POST methods
	methods := []string{"GET", "POST"}
	for _, method := range methods {
		origSize, origStatus, origFinalURL, err := fetch(original, method)
		if err != nil {
			if !strings.Contains(err.Error(), "no Host in request URL") {
				results <- Result{
					URL: original,
					Label: "original",
					Method: method,
					Error: err,
				}
			}
			continue
		}

		for label, variant := range variants {
			if variant == original {
				continue
			}

			size, status, finalURL, err := fetch(variant, method)
			if err != nil {
				if !strings.Contains(err.Error(), "no Host in request URL") {
					results <- Result{
						URL: variant,
						Label: label,
						Method: method,
						Error: err,
					}
				}
				continue
			}

			// Show mismatches for successful responses and 500-level errors
			if size != origSize && (status < 400 || status >= 500) {
				results <- Result{
					URL:            variant,
					FinalURL:       finalURL,
					Label:          label,
					Method:         method,
					Size:           size,
					Status:         status,
					OriginalSize:   origSize,
					OriginalStatus: origStatus,
					OriginalURL:    original,
					OriginalFinalURL: origFinalURL,
				}
			}
		}
	}
}

func processInput(input string, results chan<- Result, wg *sync.WaitGroup) {
	// Check if input is a file
	if _, err := os.Stat(input); err == nil {
		// It's a file, process it
		file, err := os.Open(input)
		if err != nil {
			fmt.Printf("Error opening file: %v\n", err)
			return
		}
		defer file.Close()

		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			original := strings.TrimSpace(scanner.Text())
			if original == "" {
				continue
			}

			wg.Add(1)
			go func(url string) {
				defer wg.Done()
				processURL(url, results, wg)
			}(original)
		}

		if err := scanner.Err(); err != nil {
			fmt.Printf("Error reading input: %v\n", err)
		}
	} else {
		// It's a single URL, process it
		wg.Add(1)
		go func(url string) {
			defer wg.Done()
			processURL(url, results, wg)
		}(input)
	}
}

func main() {
	// Parse command line flags
	showVersion := flag.Bool("version", false, "Show version information")
	flag.BoolVar(&followRedirects, "follow", false, "Follow redirects (default: false)")
	flag.StringVar(&urlInput, "u", "", "URL or file containing URLs to test")
	flag.Parse()

	if *showVersion {
		fmt.Printf(banner, version)
		return
	}

	if urlInput == "" && len(os.Args) < 2 {
		fmt.Printf(banner, version)
		fmt.Println(helpText)
		return
	}

	var wg sync.WaitGroup
	results := make(chan Result, 100)

	// Process input (either from -u flag or first argument)
	input := urlInput
	if input == "" {
		input = os.Args[1]
	}

	// Start a goroutine to process input
	go func() {
		processInput(input, results, &wg)
		wg.Wait()
		close(results)
	}()

	// Process results
	for result := range results {
		if result.Error != nil {
			fmt.Printf("❌ Error fetching %s (%s) [%s]: %v\n", result.Label, result.URL, result.Method, result.Error)
			continue
		}

		if result.Size != 0 {
			fmt.Printf("🔍 Mismatch at [%s] [%s]:\n", result.Label, result.Method)
			fmt.Printf("    ➤ Original: %s (Size: %d, Status: %d)\n", result.OriginalURL, result.OriginalSize, result.OriginalStatus)
			if result.OriginalURL != result.OriginalFinalURL {
				fmt.Printf("    ➤ Original Redirect: %s → %s\n", result.OriginalURL, result.OriginalFinalURL)
			}
			fmt.Printf("    ➤ Variant : %s (Size: %d, Status: %d)\n", result.FinalURL, result.Size, result.Status)
			if result.URL != result.FinalURL {
				fmt.Printf("    ➤ Variant Redirect: %s → %s\n", result.URL, result.FinalURL)
			}
			fmt.Println()
		}
	}
}
