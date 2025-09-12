package main

import (
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/fatih/color"
	jsoniter "github.com/json-iterator/go"
	"github.com/schollz/progressbar/v3"
)

// Client 是一个带有超时的全局HTTP客户端
var Client = http.Client{
	Timeout: 30 * time.Second,
}

// RateLimiter 结构用于全局管理API速率限制
type RateLimiter struct {
	mu        sync.Mutex
	resetTime time.Time
}

// CheckAndWait 静默地检查是否需要等待，并在需要时休眠
func (rl *RateLimiter) CheckAndWait() {
	rl.mu.Lock()
	sleepDuration := time.Until(rl.resetTime)
	rl.mu.Unlock() // 提前解锁，避免阻塞其他协程

	if sleepDuration > 0 {
		time.Sleep(sleepDuration)
	}
}

// SetResetTime 更新重置时间
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

// 命令行参数
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

// 错误追踪
var (
	errorTimes                     int
	errorMaxTimes                  = 100
	errorMutex                     sync.Mutex
	highConfidenceFilenamePatterns []*regexp.Regexp
	contentPatterns                []*regexp.Regexp
)

// initSensitivePatterns 初始化用于敏感信息检测的正则表达式
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

// getRawContent 下载文件的原始内容
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
		return nil, fmt.Errorf("HTTP状态码非200: %d", resp.StatusCode)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	const maxFileSize = 1 * 1024 * 1024
	if len(body) > maxFileSize {
		return body[:maxFileSize], nil
	}
	return body, nil
}

// isSensitive 检查文件内容或路径是否包含敏感信息
func isSensitive(path string, rawContent []byte) (bool, string) {
	for _, re := range highConfidenceFilenamePatterns {
		if re.MatchString(path) {
			return true, "高危文件名匹配: " + re.String()
		}
	}
	contentStr := string(rawContent)
	for _, re := range contentPatterns {
		if re.MatchString(contentStr) {
			return true, "文件内容匹配: " + re.String()
		}
	}
	return false, ""
}

// query 函数现在直接负责将发现的结果写入文件
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
		return fmt.Errorf("API速率限制")
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
				color.Red("错误次数过多，程序自动停止。")
				os.Exit(1)
			}
			errorMutex.Unlock()
			return fmt.Errorf("API返回错误: %s", errMsg)
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
			color.Magenta("发现敏感信息！")
			color.Green("  搜索语句: %s\n  文件路径: %s\n  匹配原因: %s\n  文件链接: %s", dork, path, reason, htmlURL)

			outputLine := fmt.Sprintf(
				"搜索语句: %s\n文件路径: %s\n匹配原因: %s\n文件链接: %s\n--------------------------------------------------\n",
				dork, path, reason, htmlURL,
			)

			fileMutex.Lock()
			if _, err := outputFile.WriteString(outputLine); err != nil {
				fmt.Fprintf(os.Stderr, "\n[错误] 写入文件失败: %v\n", err)
			} else {
				outputFile.Sync()
			}
			fileMutex.Unlock()
		}
	}
	return nil
}

// worker 函数是执行具体任务的协程
func worker(id int, dorkJobs chan string, tokenPool chan string, outputFile *os.File, wg *sync.WaitGroup, bar *progressbar.ProgressBar) {
	defer wg.Done()
	for dork := range dorkJobs {
		for {
			rateLimiter.CheckAndWait()
			token := <-tokenPool
			err := query(dork, token, outputFile)
			tokenPool <- token
			if err != nil {
				if strings.Contains(err.Error(), "API速率限制") {
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

// menu 函数用于处理命令行参数和帮助信息
func menu() {
	flag.StringVar(&DorkFile, "d", "", "包含多个搜索规则的文件路径")
	flag.StringVar(&Keyword, "k", "", "单个搜索关键词")
	flag.StringVar(&TokenFile, "tf", "", "包含多个GitHub令牌的文件路径")
	flag.StringVar(&Target, "t", "", "单个扫描目标 (例如: google.com)")
	flag.StringVar(&TargetFile, "tl", "", "包含多个目标的文件路径")
	flag.StringVar(&OutputFilePath, "o", "GitHub扫描结果.txt", "扫描结果的输出文件路径")
	flag.Int64Var(&NeedWaitSecond, "w", 65, "遇到API速率限制时的等待秒数")
	flag.Int64Var(&EachWait, "i", 3, "每次API请求之间的间隔秒数")
	flag.IntVar(&Concurrency, "c", 10, "并发扫描的线程数")
	flag.Usage = func() {
		color.Green(`
     _______ __  ______                    __ 
    / ____(_) /_/ ____/__  _____________  / /_
   / / __/ / __/ /_  / _ \/ ___/ ___/ _ \/ __/
  / /_/ / / /_/ __/ /  __/ /  / /  /  __/ /_  
  \____/_/\__/_/    \___/_/  /_/   \___/\__/     
                                       v1.0
`)
		fmt.Fprintf(flag.CommandLine.Output(), "程序用法 %s:\n", os.Args[0])
		flag.PrintDefaults()
	}
	flag.Parse()
	if (Target == "" && TargetFile == "") || (DorkFile == "" && Keyword == "") || TokenFile == "" {
		flag.Usage()
		os.Exit(0)
	}
	if Target != "" && TargetFile != "" {
		color.Red("错误: -t 和 -tl 参数不能同时使用")
		os.Exit(1)
	}
	if DorkFile != "" && Keyword != "" {
		color.Red("错误: -d 和 -k 参数不能同时使用")
		os.Exit(1)
	}
}

// parseparam 函数用于解析和加载来自文件的参数
func parseparam(tokens *[]string, dorks *[]string, targets *[]string) {
	if TokenFile != "" {
		tfres, err := os.ReadFile(TokenFile)
		if err != nil {
			color.Red("读取令牌文件错误: %v", err)
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
		color.Red("未找到有效的令牌！")
		os.Exit(1)
	}
	if Keyword != "" {
		*dorks = []string{Keyword}
	} else if DorkFile != "" {
		dkres, err := os.ReadFile(DorkFile)
		if err != nil {
			color.Red("读取规则文件错误: %v", err)
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
			color.Red("读取目标文件错误: %v", err)
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
	color.Blue("[+] 已加载 %d 个令牌, %d 个规则, 和 %d 个目标\n", len(*tokens), len(*dorks), len(*targets))
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
		color.Red("无法创建输出文件: %v", err)
		os.Exit(1)
	}
	defer outputFile.Close()

	var wg sync.WaitGroup
	totalJobs := len(dorks) * len(targets)
	dorkJobs := make(chan string, totalJobs)
	tokenPool := make(chan string, len(tokens))

	bar := progressbar.NewOptions(totalJobs,
		progressbar.OptionSetDescription("正在扫描..."),
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
		color.Yellow("警告: 并发数 (%d) 大于可用令牌数 (%d)，已自动调整为 %d\n", Concurrency, len(tokens), len(tokens))
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
	color.Green("任务完成！结果已保存至 %s", OutputFilePath)
}
