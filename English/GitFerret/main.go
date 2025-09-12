package main

import (
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/fatih/color"
	jsoniter "github.com/json-iterator/go"
	"github.com/schollz/progressbar/v3"
)

// Client is a global HTTP client with a timeout.
var Client = http.Client{
	Timeout: 30 * time.Second,
}

// RateLimiter struct manages the API rate limit globally.
type RateLimiter struct {
	mu        sync.Mutex
	resetTime time.Time
}

// CheckAndWait silently checks if a wait is needed and sleeps if so.
func (rl *RateLimiter) CheckAndWait() {
	rl.mu.Lock()
	sleepDuration := time.Until(rl.resetTime)
	rl.mu.Unlock() // Unlock early to avoid blocking other goroutines.

	if sleepDuration > 0 {
		time.Sleep(sleepDuration)
	}
}

// SetResetTime updates the reset time.
func (rl *RateLimiter) SetResetTime(resetTimestamp int64) {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	newResetTime := time.Unix(resetTimestamp, 0)
	if newResetTime.After(rl.resetTime) {
		rl.resetTime = newResetTime
	}
}

var rateLimiter = &RateLimiter{}
var fileMutex sync.Mutex

// Command-line arguments
var (
	DorkFile       string
	Keyword        string
	TokenFile      string
	Target         string
	TargetFile     string
	OutputFilePath string
	NeedWaitSecond int64
	EachWait       int64
	Concurrency    int
)

// Error tracking
var (
	errorTimes                     int
	errorMaxTimes                  = 100
	errorMutex                     sync.Mutex
	highConfidenceFilenamePatterns []*regexp.Regexp
	contentPatterns                []*regexp.Regexp
)

// initSensitivePatterns initializes the regular expressions for sensitive information detection.
func initSensitivePatterns() {
	highConfidenceFiles := []string{
		`\.(env|pem|p12|pkcs12|pfx|asc|key)$`,
		`^\.?htpasswd$`,
	}
	for _, p := range highConfidenceFiles {
		re, err := regexp.Compile(p)
		if err == nil {
			highConfidenceFilenamePatterns = append(highConfidenceFilenamePatterns, re)
		}
	}

	contentOnlyPatterns := []string{
		`(?i)(api_key|apikey|api-key|access_token|accesstoken|access-token|secret_key|secretkey|secret-token|auth_token|authtoken|auth-token|client_secret|client-secret|private_key|privatekey)\s*[:=]\s*['"]([a-zA-Z0-9\-_.~!@#$%^&*+/=]{20,})['"]`,
		`(?i)("?password"?|"passwd"|"pwd")\s*[:=]\s*['"](?!.*\s)(.{8,})['"]`,
		`AKIA[0-9A-Z]{16}`,
		`(?i)aws_secret_access_key\s*[:=]\s*['"]?([a-zA-Z0-9/+=]{40})['"]?`,
		`AIza[0-9A-Za-z\\-_]{35}`,
		`xox[pborsa]-[0-9]{12}-[0-9]{12}-[0-9]{12}-[a-z0-9]{32}`,
		`-----BEGIN (RSA|EC|PGP|OPENSSH) PRIVATE KEY-----`,
	}
	for _, p := range contentOnlyPatterns {
		re, err := regexp.Compile(p)
		if err == nil {
			contentPatterns = append(contentPatterns, re)
		}
	}
}

// getRawContent downloads the raw content of a file.
func getRawContent(htmlURL string, token string) ([]byte, error) {
	rawURL := strings.Replace(htmlURL, "github.com", "raw.githubusercontent.com", 1)
	rawURL = strings.Replace(rawURL, "/blob/", "/", 1)
	req, err := http.NewRequest("GET", rawURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "token "+token)
	req.Header.Set("User-Agent", "GitFerret-v2.1-silent")
	resp, err := Client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("non-200 HTTP status code: %d", resp.StatusCode)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	const maxFileSize = 1 * 1024 * 1024 // 1MB
	if len(body) > maxFileSize {
		return body[:maxFileSize], nil
	}
	return body, nil
}

// isSensitive checks if the file content or path contains sensitive information.
func isSensitive(path string, rawContent []byte) (bool, string) {
	for _, re := range highConfidenceFilenamePatterns {
		if re.MatchString(path) {
			return true, "High-risk filename match: " + re.String()
		}
	}
	contentStr := string(rawContent)
	for _, re := range contentPatterns {
		if re.MatchString(contentStr) {
			return true, "File content match: " + re.String()
		}
	}
	return false, ""
}

// query function is responsible for searching and writing discovered results to a file.
func query(dork string, token string, outputFile *os.File) error {
	guri := "https://api.github.com/search/code"
	uri, _ := url.Parse(guri)
	param := url.Values{"q": {dork}}
	uri.RawQuery = param.Encode()
	req, _ := http.NewRequest("GET", uri.String(), nil)
	req.Header.Set("accept", "application/vnd.github.v3+json")
	req.Header.Set("Authorization", "token "+token)
	req.Header.Set("User-Agent", "GitFerret-v2.1-silent")
	resp, err := Client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode == 403 {
		resetTimestampStr := resp.Header.Get("X-RateLimit-Reset")
		resetTimestamp, _ := strconv.ParseInt(resetTimestampStr, 10, 64)
		if resetTimestamp > 0 {
			rateLimiter.SetResetTime(resetTimestamp)
		} else {
			rateLimiter.SetResetTime(time.Now().Unix() + NeedWaitSecond)
		}
		return fmt.Errorf("API rate limit reached")
	}

	source, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	if jsoniter.Get(source, "message").ToString() != "" {
		errMsg := jsoniter.Get(source, "message").ToString()
		if !strings.Contains(errMsg, "Validation Failed") {
			errorMutex.Lock()
			errorTimes++
			if errorTimes >= errorMaxTimes {
				fmt.Println()
				color.Red("Too many errors, the program will stop automatically.")
				os.Exit(1)
			}
			errorMutex.Unlock()
			return fmt.Errorf("API returned an error: %s", errMsg)
		}
	}

	itemsNode := jsoniter.Get(source, "items")
	if itemsNode.ValueType() == jsoniter.ArrayValue {
		items := itemsNode.GetInterface().([]interface{})
		for _, rawItem := range items {
			itemJSON, _ := jsoniter.Marshal(rawItem)
			path := jsoniter.Get(itemJSON, "path").ToString()
			htmlURL := jsoniter.Get(itemJSON, "html_url").ToString()
			rawContent, err := getRawContent(htmlURL, token)
			if err != nil {
				continue
			}
			sensitive, reason := isSensitive(path, rawContent)
			if !sensitive {
				continue
			}

			fmt.Println()
			color.Magenta("Sensitive information found!")
			color.Green("  Search Query: %s\n  File Path: %s\n  Match Reason: %s\n  File Link: %s", dork, path, reason, htmlURL)

			outputLine := fmt.Sprintf(
				"Search Query: %s\nFile Path: %s\nMatch Reason: %s\nFile Link: %s\n--------------------------------------------------\n",
				dork, path, reason, htmlURL,
			)

			fileMutex.Lock()
			if _, err := outputFile.WriteString(outputLine); err != nil {
				fmt.Fprintf(os.Stderr, "\n[ERROR] Failed to write to file: %v\n", err)
			} else {
				outputFile.Sync()
			}
			fileMutex.Unlock()
		}
	}
	return nil
}

// worker function is the goroutine that performs the actual tasks.
func worker(id int, dorkJobs chan string, tokenPool chan string, outputFile *os.File, wg *sync.WaitGroup, bar *progressbar.ProgressBar) {
	defer wg.Done()
	for dork := range dorkJobs {
		for {
			rateLimiter.CheckAndWait()
			token := <-tokenPool
			err := query(dork, token, outputFile)
			tokenPool <- token
			if err != nil {
				if strings.Contains(err.Error(), "API rate limit reached") {
					time.Sleep(500 * time.Millisecond)
					continue
				} else {
					bar.Add(1)
					break
				}
			} else {
				bar.Add(1)
				break
			}
		}
		time.Sleep(time.Second * time.Duration(EachWait))
	}
}

// menu function handles command-line arguments and help messages.
func menu() {
	flag.StringVar(&DorkFile, "d", "", "Path to the file containing multiple search dorks")
	flag.StringVar(&Keyword, "k", "", "A single search keyword")
	flag.StringVar(&TokenFile, "tf", "", "Path to the file containing multiple GitHub tokens")
	flag.StringVar(&Target, "t", "", "A single scan target (e.g., google.com)")
	flag.StringVar(&TargetFile, "tl", "", "Path to the file containing multiple targets")
	flag.StringVar(&OutputFilePath, "o", "GitHub_Scan_Results.txt", "Output file path for scan results")
	flag.Int64Var(&NeedWaitSecond, "w", 65, "Waiting time in seconds when API rate limit is hit")
	flag.Int64Var(&EachWait, "i", 3, "Interval in seconds between each API request")
	flag.IntVar(&Concurrency, "c", 10, "Number of concurrent scanning threads")
	flag.Usage = func() {
		color.Green(`
    _______ __  ______                    __ 
   / ____(_) /_/ ____/__  _____________  / /_
  / / __/ / __/ /_  / _ \/ ___/ ___/ _ \/ __/
 / /_/ / / /_/ __/ /  __/ /  / /  /  __/ /_  
 \____/_/\__/_/    \___/_/  /_/   \___/\__/    
                                      v1.0
`)
		fmt.Fprintf(flag.CommandLine.Output(), "Usage of %s:\n", os.Args[0])
		flag.PrintDefaults()
	}
	flag.Parse()
	if (Target == "" && TargetFile == "") || (DorkFile == "" && Keyword == "") || TokenFile == "" {
		flag.Usage()
		os.Exit(0)
	}
	if Target != "" && TargetFile != "" {
		color.Red("Error: -t and -tl flags cannot be used at the same time")
		os.Exit(1)
	}
	if DorkFile != "" && Keyword != "" {
		color.Red("Error: -d and -k flags cannot be used at the same time")
		os.Exit(1)
	}
}

// parseparam function parses and loads parameters from files.
func parseparam(tokens *[]string, dorks *[]string, targets *[]string) {
	if TokenFile != "" {
		tfres, err := os.ReadFile(TokenFile)
		if err != nil {
			color.Red("Error reading token file: %v", err)
			os.Exit(0)
		}
		rawTokens := strings.Split(string(tfres), "\n")
		for _, t := range rawTokens {
			t = strings.TrimSpace(strings.TrimSuffix(t, "\r"))
			if t != "" {
				*tokens = append(*tokens, t)
			}
		}
	}
	if len(*tokens) == 0 {
		color.Red("No valid tokens found!")
		os.Exit(1)
	}
	if Keyword != "" {
		*dorks = []string{Keyword}
	} else if DorkFile != "" {
		dkres, err := os.ReadFile(DorkFile)
		if err != nil {
			color.Red("Error reading dork file: %v", err)
			os.Exit(0)
		}
		rawDorks := strings.Split(string(dkres), "\n")
		for _, d := range rawDorks {
			d = strings.TrimSpace(strings.TrimSuffix(d, "\r"))
			if d != "" {
				*dorks = append(*dorks, d)
			}
		}
	}
	if Target != "" {
		*targets = []string{Target}
	} else if TargetFile != "" {
		targetRes, err := os.ReadFile(TargetFile)
		if err != nil {
			color.Red("Error reading target file: %v", err)
			os.Exit(0)
		}
		rawTargets := strings.Split(string(targetRes), "\n")
		for _, t := range rawTargets {
			t = strings.TrimSpace(strings.TrimSuffix(t, "\r"))
			if t != "" {
				*targets = append(*targets, t)
			}
		}
	}
	color.Blue("[+] Loaded %d tokens, %d dorks, and %d targets\n", len(*tokens), len(*dorks), len(*targets))
}

func main() {
	initSensitivePatterns()
	menu()

	var tokens []string
	var dorks []string
	var targets []string
	parseparam(&tokens, &dorks, &targets)

	outputFile, err := os.Create(OutputFilePath)
	if err != nil {
		// Check if it's a permission error
		if os.IsPermission(err) {
			color.Yellow("Warning: Permission denied to write in the current directory.")

			homeDir, homeErr := os.UserHomeDir()
			if homeErr != nil {
				color.Red("Failed to get user home directory, cannot create output file: %v", homeErr)
				os.Exit(1)
			}

			// Use the base filename from the original path for the fallback
			fallbackPath := filepath.Join(homeDir, filepath.Base(OutputFilePath))
			color.Yellow("Attempting to save results to your home directory: %s", fallbackPath)

			outputFile, err = os.Create(fallbackPath)
			if err != nil {
				color.Red("Failed to create output file in home directory: %v", err)
				os.Exit(1)
			}
			// Update the path so the final message is correct
			OutputFilePath = fallbackPath
		} else {
			// It's a different error (e.g., invalid path, disk full)
			color.Red("Failed to create output file: %v", err)
			os.Exit(1)
		}
	}
	defer outputFile.Close()

	var wg sync.WaitGroup
	totalJobs := len(dorks) * len(targets)
	dorkJobs := make(chan string, totalJobs)
	tokenPool := make(chan string, len(tokens))

	bar := progressbar.NewOptions(totalJobs,
		progressbar.OptionSetDescription("Scanning..."),
		progressbar.OptionSetWriter(os.Stderr),
		progressbar.OptionShowCount(),
		progressbar.OptionSetTheme(progressbar.Theme{
			Saucer:        "=",
			SaucerHead:    ">",
			SaucerPadding: " ",
			BarStart:      "[",
			BarEnd:        "]",
		}),
	)

	for _, token := range tokens {
		tokenPool <- token
	}
	if Concurrency > len(tokens) {
		color.Yellow("Warning: Concurrency (%d) is greater than the number of available tokens (%d). It has been automatically adjusted to %d\n", Concurrency, len(tokens), len(tokens))
		Concurrency = len(tokens)
	}
	for i := 1; i <= Concurrency; i++ {
		wg.Add(1)
		go worker(i, dorkJobs, tokenPool, outputFile, &wg, bar)
	}

	for _, t := range targets {
		for _, d := range dorks {
			dorkJobs <- fmt.Sprintf("%s %s", t, d)
		}
	}
	close(dorkJobs)
	wg.Wait()

	fmt.Println()
	color.Green("Task completed! Results have been saved to %s", OutputFilePath)
}
