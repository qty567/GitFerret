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
	"sync/atomic"
	"time"

	"github.com/fatih/color"
	jsoniter "github.com/json-iterator/go"
	"github.com/schollz/progressbar/v3"
)

// dorkSets 存储了内置的搜索规则集 (内容已省略，请使用您自己的完整版本)
var dorkSets = map[string][]string{
	"small": {
		"token", "password", "secret", "passwd", "username", "key", "apidocs", "appspot", "auth", "aws_access", "config", "credentials", "dbuser", "ftp", "login", "mailchimp", "mailgun", "mysql", "pass", "pem private", "prod", "pwd", "secure", "ssh", "staging", "stg", "stripe", "swagger", "testuser", "jdbc",
	},
	"medium": {
		".mlab.com password", "AWSSecretKey", "JEKYLL_GITHUB_TOKEN", "SF_USERNAME salesforce", "access_key", "access_token", "amazonaws", "apiSecret", "api_key", "api_secret", "apidocs", "apikey", "app_key", "app_secret", "appkey", "appkeysecret", "application_key", "appsecret", "appspot", "auth", "auth_token", "authorizationToken", "aws_access", "aws_access_key_id", "aws_key", "aws_secret", "aws_token", "bashrc password", "bucket_password", "client_secret", "cloudfront", "codecov_token", "config", "conn.login", "connectionstring", "consumer_key", "credentials", "database_password", "db_password", "db_username", "dbpasswd", "dbpassword", "dbuser", "dot-files", "dotfiles", "encryption_key", "fabricApiSecret", "fb_secret", "firebase", "ftp", "gh_token", "github_key", "github_token", "gitlab", "gmail_password", "gmail_username", "api.googlemaps AIza", "herokuapp", "internal", "irc_pass", "key", "keyPassword", "ldap_password", "ldap_username", "login", "mailchimp", "mailgun", "master_key", "mydotfiles", "mysql", "node_env", "npmrc _auth", "oauth_token", "pass", "passwd", "password", "passwords", "pem private", "preprod", "private_key", "prod", "pwd", "pwds", "rds.amazonaws.com password", "redis_password", "root_password", "secret", "secret.password", "secret_access_key", "secret_key", "secret_token", "secrets", "secure", "security_credentials", "send.keys", "send_keys", "sendkeys", "sf_username", "slack_api", "slack_token", "sql_password", "ssh", "ssh2_auth_password", "sshpass", "staging", "stg", "storePassword", "stripe", "swagger", "testuser", "token", "x-api-key", "xoxp", "xoxb ", "HEROKU_API_KEY language:json", "HEROKU_API_KEY language:shell", "HOMEBREW_GITHUB_API_TOKEN language:shell", "PT_TOKEN language:bash", "[WFClient] Password= extension:ica", `extension:avastlic "support.avast.com"`, "extension:bat", "extension:cfg", "extension:env", "extension:exs", "extension:ini", "extension:json api.forecast.io", "extension:json googleusercontent client_secret", "extension:json mongolab.com", "extension:pem", "extension:pem private", "extension:ppk", "extension:ppk private", "extension:properties", "extension:sh", "extension:sls", "extension:sql", "extension:sql mysql dump", "extension:sql mysql dump password", "extension:yaml mongolab.com", "extension:zsh", "filename:.bash_history", "filename:.bash_profile aws", "filename:.bashrc mailchimp", "filename:.bashrc password", "filename:.cshrc", "filename:.dockercfg auth", "filename:.env DB_USERNAME NOT homestead", "filename:.env MAIL_HOST=smtp.gmail.com", "filename:.esmtprc password", "filename:.ftpconfig", "filename:.git-credentials", "filename:.history", "filename:.htpasswd", "filename:.netrc password", "filename:.npmrc _auth", "filename:.pgpass", "filename:.remote-sync.json", "filename:.s3cfg", "filename:.sh_history", "filename:.tugboat NOT _tugboat", "filename:CCCam.cfg", "filename:WebServers.xml", "filename:_netrc password", "filename:bash", "filename:bash_history", "filename:bash_profile", "filename:bashrc", "filename:beanstalkd.yml", "filename:composer.json", "filename:config", "filename:config irc_pass", "filename:config.json auths", "filename:config.php dbpasswd", "filename:configuration.php JConfig password", "filename:connections", "filename:connections.xml", "filename:constants", "filename:credentials", "filename:credentials aws_access_key_id", "filename:cshrc", "filename:database", "filename:dbeaver-data-sources.xml", "filename:deploy.rake", "filename:deployment-config.json", "filename:dhcpd.conf", "filename:dockercfg", "filename:environment", "filename:express.conf", "filename:express.conf path:.openshift", "filename:filezilla.xml", "filename:filezilla.xml Pass", "filename:git-credentials", "filename:gitconfig", "filename:global", "filename:history", "filename:htpasswd", "filename:hub oauth_token", "filename:id_dsa", "filename:id_rsa", "filename:id_rsa or filename:id_dsa", "filename:idea14.key", "filename:known_hosts", "filename:logins.json", "filename:makefile", "filename:master.key path:config", "filename:netrc", "filename:npmrc", "filename:pass", "filename:passwd path:etc", "filename:pgpass", "filename:prod.exs", "filename:prod.exs NOT prod.secret.exs", "filename:prod.secret.exs", "filename:proftpdpasswd", "filename:recentservers.xml", "filename:recentservers.xml Pass", "filename:robomongo.json", "filename:s3cfg", "filename:secrets.yml password", "filename:server.cfg", "filename:server.cfg rcon password", "filename:settings", "filename:settings.py SECRET_KEY", "filename:sftp-config.json", "filename:sftp.json path:.vscode", "filename:shadow", "filename:shadow path:etc", "filename:spec", "filename:sshd_config", "filename:tugboat", "filename:ventrilo_srv.ini", "filename:wp-config", "filename:wp-config.php", "filename:zhrc", "jsforce extension:js conn.login", "language:yaml -filename:travis", "msg nickserv identify filename:config", "path:sites databases password", "private -language:java", "shodan_api_key language:python",
	},
	"all": {
		".mlab.com password", "WFClient Password extension:ica", "access_key", "access_token", "admin_pass", "admin_user", "algolia_admin_key", "algolia_api_key", "alias_pass", "alicloud_access_key", "amazon_secret_access_key", "amazonaws", "ansible_vault_password", "aos_key", "api_key", "api_key_secret", "api_key_sid", "api_secret", "api.googlemaps AIza", "apidocs", "apikey", "apiSecret", "app_debug", "app_id", "app_key", "app_log_level", "app_secret", "appkey", "appkeysecret", "application_key", "appsecret", "appspot", "auth_token", "authorizationToken", "authsecret", "aws_access", "aws_access_key_id", "aws_bucket", "aws_key", "aws_secret", "aws_secret_key", "aws_token", "AWSSecretKey", "b2_app_key", "bashrc password", "bintray_apikey", "bintray_gpg_password", "bintray_key", "bintraykey", "bluemix_api_key", "bluemix_pass", "browserstack_access_key", "bucket_password", "bucketeer_aws_access_key_id", "bucketeer_aws_secret_access_key", "built_branch_deploy_key", "bx_password", "cache_driver", "cache_s3_secret_key", "cattle_access_key", "cattle_secret_key", "certificate_password", "ci_deploy_password", "client_secret", "client_zpk_secret_key", "clojars_password", "cloud_api_key", "cloud_watch_aws_access_key", "cloudant_password", "cloudflare_api_key", "cloudflare_auth_key", "cloudinary_api_secret", "cloudinary_name", "codecov_token", "config", "conn.login", "connectionstring", "consumer_key", "consumer_secret", "credentials", "cypress_record_key", "database_password", "database_schema_test", "datadog_api_key", "datadog_app_key", "db_password", "db_server", "db_username", "dbpasswd", "dbpassword", "dbuser", "deploy_password", "digitalocean_ssh_key_body", "digitalocean_ssh_key_ids", "docker_hub_password", "docker_key", "docker_pass", "docker_passwd", "docker_password", "dockerhub_password", "dockerhubpassword", "dot-files", "dotfiles", "droplet_travis_password", "dynamoaccesskeyid", "dynamosecretaccesskey", "elastica_host", "elastica_port", "elasticsearch_password", "encryption_key", "encryption_password", "env.heroku_api_key", "env.sonatype_password", "eureka.awssecretkey", "extension:avastlic support.avast.com", "extension:bat", "extension:cfg", "extension:dbeaver-data-sources.xml", "extension:env", "extension:exs", "extension:ini", "extension:json api.forecast.io", "extension:json googleusercontent client_secret", "extension:json mongolab.com", "extension:pem", "extension:pem private", "extension:ppk", "extension:ppk private", "extension:properties", "extension:sh", "extension:sls", "extension:sql", "extension:sql mysql dump", "extension:sql mysql dump password", "extension:yaml mongolab.com", "extension:zsh", "fabricApiSecret", "facebook_secret", "fb_secret", "filename:_netrc password", "filename:.bash_history", "filename:.bash_profile aws", "filename:.bashrc mailchimp", "filename:.bashrc password", "filename:.cshrc", "filename:.dockercfg auth", "filename:.env DB_USERNAME NOT homestead", "filename:.env MAIL_HOSTsmtp.gmail.com", "filename:.esmtprc password", "filename:.ftpconfig", "filename:.git-credentials", "filename:.history", "filename:.htpasswd", "filename:.netrc password", "filename:.npmrc _auth", "filename:.pgpass", "filename:.remote-sync.json", "filename:.s3cfg", "filename:.sh_history", "filename:.tugboat NOT _tugboat", "filename:bash", "filename:bash_history", "filename:bash_profile", "filename:bashrc", "filename:beanstalkd.yml", "filename:CCCam.cfg", "filename:composer.json", "filename:config", "filename:config irc_pass", "filename:config.json auths", "filename:config.php dbpasswd", "filename:configuration.php JConfig password", "filename:connections", "filename:connections.xml", "filename:constants", "filename:credentials", "filename:credentials aws_access_key_id", "filename:cshrc", "filename:database", "filename:dbeaver-data-sources.xml", "filename:deploy.rake", "filename:deployment-config.json", "filename:dhcpd.conf", "filename:dockercfg", "filename:env", "filename:environment", "filename:express.conf", "filename:express.conf path:.openshift", "filename:filezilla.xml", "filename:filezilla.xml Pass", "filename:git-credentials", "filename:gitconfig", "filename:global", "filename:history", "filename:htpasswd", "filename:hub oauth_token", "filename:id_dsa", "filename:id_rsa", "filename:id_rsa or filename:id_dsa", "filename:idea14.key", "filename:known_hosts", "filename:logins.json", "filename:makefile", "filename:master.key path:config", "filename:netrc", "filename:npmrc", "filename:pass", "filename:passwd path:etc", "filename:pgpass", "filename:prod.exs", "filename:prod.exs NOT prod.secret.exs", "filename:prod.secret.exs", "filename:proftpdpasswd", "filename:recentservers.xml", "filename:recentservers.xml Pass", "filename:robomongo.json", "filename:s3cfg", "filename:secrets.yml password", "filename:server.cfg", "filename:server.cfg rcon password", "filename:settings", "filename:settings.py SECRET_KEY", "filename:sftp-config.json", "filename:sftp.json path:.vscode", "filename:shadow", "filename:shadow path:etc", "filename:spec", "filename:sshd_config", "filename:tugboat", "filename:ventrilo_srv.ini", "filename:WebServers.xml", "filename:wp-config", "filename:wp-config.php", "filename:zhrc", "firebase", "flickr_api_key", "fossa_api_key", "ftp", "ftp_password", "gatsby_wordpress_base_url", "gatsby_wordpress_client_id", "gatsby_wordpress_user", "gh_api_key", "gh_token", "ghost_api_key", "github_api_key", "github_deploy_hb_doc_pass", "github_id", "github_key", "github_password", "github_token", "gitlab", "gmail_password", "gmail_username", "google_maps_api_key", "google_private_key", "google_secret", "google_server_key", "gpg_key_name", "gpg_keyname", "gpg_passphrase", "HEROKU_API_KEY language:json", "HEROKU_API_KEY language:shell", "heroku_oauth", "heroku_oauth_secret", "heroku_oauth_token", "heroku_secret", "heroku_secret_token", "herokuapp", "HOMEBREW_GITHUB_API_TOKEN language:shell", "htaccess_pass", "htaccess_user", "incident_channel_name", "internal", "irc_pass", "JEKYLL_GITHUB_TOKEN", "jsforce extension:js conn.login", "jwt_client_secret_key", "jwt_lookup_secert_key", "jwt_password", "jwt_secret", "jwt_secret_key", "jwt_token", "jwt_user", "jwt_web_secert_key", "jwt_xmpp_secert_key", "key", "keyPassword", "language:yaml -filename:travis", "ldap_password", "ldap_username", "linux_signing_key", "ll_shared_key", "location_protocol", "log_channel", "login", "lottie_happo_api_key", "lottie_happo_secret_key", "lottie_s3_api_key", "lottie_s3_secret_key", "magento password", "mail_password", "mail_port", "mailchimp", "mailchimp_api_key", "mailchimp_key", "mailgun", "mailgun apikey", "mailgun_key", "mailgun_password", "mailgun_priv_key", "mailgun_secret_api_key", "manage_key", "mandrill_api_key", "mapbox api key", "master_key", "mg_api_key", "mg_public_api_key", "mh_apikey", "mh_password", "mile_zero_key", "minio_access_key", "minio_secret_key", "mix_pusher_app_cluster", "mix_pusher_app_key", "msg nickserv identify filename:config", "mydotfiles", "mysql", "mysql password", "mysql_root_password", "netlify_api_key", "nexus password", "nexus_password", "node_env", "node_pre_gyp_accesskeyid", "node_pre_gyp_secretaccesskey", "npm_api_key", "npm_password", "npm_secret_key", "npmrc _auth", "nuget_api_key", "nuget_apikey", "nuget_key", "oauth_token", "object_storage_password", "octest_app_password", "octest_password", "okta_key", "omise_key", "onesignal_api_key", "onesignal_user_auth_key", "openwhisk_key", "org_gradle_project_sonatype_nexus_password", "org_project_gradle_sonatype_nexus_password", "os_password", "ossrh_jira_password", "ossrh_pass", "ossrh_password", "pagerduty_apikey", "parse_js_key", "pass", "passwd", "password", "password travis", "passwords", "path:sites databases password", "paypal_secret", "paypal_token", "pem private", "personal_key", "playbooks_url", "plotly_apikey", "plugin_password", "postgres_env_postgres_password", "postgresql_pass", "preprod", "private", "private -language:java", "private_key", "private_signing_password", "prod", "prod_password", "prod.access.key.id", "prod.secret.key", "PT_TOKEN language:bash", "publish_key", "pusher_app_id", "pwd", "queue_driver", "rabbitmq_password", "rds.amazonaws.com password", "redis_password", "response_auth_jwt_secret", "rest_api_key", "rinkeby_private_key", "root_password", "ropsten_private_key", "route53_access_key_id", "rtd_key_pass", "rtd_store_pass", "s3_access_key", "s3_access_key_id", "s3_key", "s3_key_app_logs", "s3_key_assets", "s3_secret_key", "salesforce_password", "sandbox_aws_access_key_id", "sandbox_aws_secret_access_key", "sauce_access_key", "secret", "secret access key", "secret_access_key", "secret_bearer", "secret_key", "secret_key_base", "secret_token", "secret.password", "secretaccesskey", "secretkey", "secrets", "secure", "security_credentials", "send_keys", "send.keys", "sendgrid_api_key", "sendgrid_key", "sendgrid_password", "sendkeys", "ses_access_key", "ses_secret_key", "setdstaccesskey", "setsecretkey", "sf_username", "SF_USERNAME salesforce", "shodan_api_key language:python", "sid_token", "signing_key_password", "signing_key_secret", "slack_api", "slack_channel", "slack_key", "slack_outgoing_token", "slack_signing_secret", "slack_token", "slack_webhook", "slash_developer_space_key", "snoowrap_password", "socrata_password", "sonar_organization_key", "sonar_project_key", "sonatype_password", "sonatype_token_password", "soundcloud_password", "sql_password", "sqsaccesskey", "square_access_token", "square_token", "squareSecret", "ssh", "ssh2_auth_password", "sshpass", "staging", "stg", "storePassword", "stormpath_api_key_id", "stormpath_api_key_secret", "strip_key", "strip_secret_key", "stripe", "stripe_key", "stripe_secret", "stripToken", "svn_pass", "swagger", "tesco_api_key", "tester_keys_password", "testuser", "thera_oss_access_key", "token", "trusted_hosts", "twilio_account_sid", "twilio_accountsid", "twilio_api_key", "twilio_api_secret", "twilio_secret", "twilio_secret_token", "TWILIO_SID NOT env", "twilio_token", "twilioapiauth", "twiliosecret", "twine_password", "twitter_secret", "twitterKey", "x-api-key", "xoxb ", "xoxp", "zen_tkn", "zen_token", "zendesk_url", "twilio secret", "twilio_account_id", "twilio_account_secret", "twilio_acount_sid NOT env", "twilio_api", "twilio_api_auth", "twilio_api_sid", "twilio_api_token", "zen_key", "zendesk_api_token", "zendesk_key", "zendesk_token", "zendesk_username",
	},
}

// Client 是一个带有超时的全局HTTP客户端
var Client = http.Client{
	Timeout: 30 * time.Second,
}

// RateLimiter 结构用于全局管理API速率限制
type RateLimiter struct {
	mu        sync.Mutex
	resetTime time.Time
}

func (rl *RateLimiter) CheckAndWait() {
	rl.mu.Lock()
	sleepDuration := time.Until(rl.resetTime)
	rl.mu.Unlock()
	if sleepDuration > 0 {
		time.Sleep(sleepDuration)
	}
}

func (rl *RateLimiter) SetResetTime(resetTimestamp int64) {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	newResetTime := time.Unix(resetTimestamp, 0)
	if newResetTime.After(rl.resetTime) {
		rl.resetTime = newResetTime
	}
}

var rateLimiter = &RateLimiter{}

// 命令行参数
var (
	TokenFile      string
	Target         string
	TargetFile     string
	DorkLevel      string
	OutputFilePath string
	NeedWaitSecond int64
	EachWait       int64
	Concurrency    int
)

// 错误追踪与结果处理
var (
	errorTimes                     int
	errorMaxTimes                  = 100
	errorMutex                     sync.Mutex
	highConfidenceFilenamePatterns []*regexp.Regexp
	contentPatterns                []*regexp.Regexp
	findingsCount                  int64
	outputFile                     *os.File
	fileCreationOnce               sync.Once
	fileMutex                      sync.Mutex
)

// initSensitivePatterns 初始化用于敏感信息检测的正则表达式 (调优严格模式)
func initSensitivePatterns() {
	// 模式1: 高危文件名
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

	// 模式2: 文件内容 - 结合了高确定性特征和高价值关键词
	tunedContentPatterns := []string{
		// 规则A: 匹配 api_key, secret_key 等高价值关键词，并有长度要求，以减少误报
		`(?i)(api_key|apikey|api-key|access_token|accesstoken|access-token|secret_key|secretkey|secret-token|auth_token|authtoken|auth-token|client_secret|client-secret|private_key|privatekey)\s*[:=]\s*['"]([a-zA-Z0-9\-_.~!@#$%^&*+/=]{20,})['"]`,
		// 规则B: 匹配具有明确格式特征的密钥/令牌
		`AKIA[0-9A-Z]{16}`, // AWS Access Key ID
		`(?i)aws_secret_access_key\s*[:=]\s*['"]?([a-zA-Z0-9/+=]{40})['"]?`, // AWS Secret Key
		`AIza[0-9A-Za-z\\-_]{35}`,                                // Google API Key
		`xox[pborsa]-[0-9]{12}-[0-9]{12}-[0-9]{12}-[a-z0-9]{32}`, // Slack Token
		// 规则C: 匹配私钥文件头
		`-----BEGIN (RSA|EC|PGP|OPENSSH) PRIVATE KEY-----`,
	}
	for _, p := range tunedContentPatterns {
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
	req.Header.Set("User-Agent", "GitFerret-v1.0")
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
	const maxFileSize = 1 * 1024 * 1024 // 1MB
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

// ensureOutputFileCreated 确保输出文件只被创建一次
func ensureOutputFileCreated() error {
	var err error
	fileCreationOnce.Do(func() {
		outputFile, err = os.Create(OutputFilePath)
		if err != nil {
			if os.IsPermission(err) {
				color.Yellow("警告: 无权写入当前目录。")
				homeDir, homeErr := os.UserHomeDir()
				if homeErr != nil {
					err = fmt.Errorf("无法获取用户主目录: %v", homeErr)
					return
				}
				fallbackPath := filepath.Join(homeDir, filepath.Base(OutputFilePath))
				color.Yellow("正尝试将结果保存到您的主目录: %s", fallbackPath)
				outputFile, err = os.Create(fallbackPath)
				if err == nil {
					OutputFilePath = fallbackPath
				}
			}
		}
	})
	return err
}

// query 函数负责搜索并将发现的结果写入文件
func query(dork string, token string) error {
	guri := "https://api.github.com/search/code"
	uri, _ := url.Parse(guri)
	param := url.Values{"q": {dork}}
	uri.RawQuery = param.Encode()
	req, _ := http.NewRequest("GET", uri.String(), nil)
	req.Header.Set("accept", "application/vnd.github.v3+json")
	req.Header.Set("Authorization", "token "+token)
	req.Header.Set("User-Agent", "GitFerret-v1.0")
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

			atomic.AddInt64(&findingsCount, 1)
			if err := ensureOutputFileCreated(); err != nil {
				color.Red("\n创建输出文件失败，后续结果将无法保存: %v", err)
				continue
			}

			fmt.Println()
			color.Magenta("发现敏感信息！")
			color.Green("  搜索语句: %s\n  文件路径: %s\n  匹配原因: %s\n  文件链接: %s", dork, path, reason, htmlURL)
			color.Unset()

			outputLine := fmt.Sprintf(
				"搜索语句: %s\n文件路径: %s\n匹配原因: %s\n文件链接: %s\n--------------------------------------------------\n",
				dork, path, reason, htmlURL,
			)

			fileMutex.Lock()
			if outputFile != nil {
				if _, err := outputFile.WriteString(outputLine); err != nil {
					fmt.Fprintf(os.Stderr, "\n[错误] 写入文件失败: %v\n", err)
				} else {
					outputFile.Sync()
				}
			}
			fileMutex.Unlock()
		}
	}
	return nil
}

// worker 函数是执行具体任务的协程
func worker(id int, dorkJobs chan string, tokenPool chan string, wg *sync.WaitGroup, bar *progressbar.ProgressBar) {
	defer wg.Done()
	for dork := range dorkJobs {
		for {
			rateLimiter.CheckAndWait()
			token := <-tokenPool
			err := query(dork, token)
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
	flag.StringVar(&TokenFile, "tf", "", "包含多个GitHub令牌的文件路径 (必需)")
	flag.StringVar(&Target, "t", "", "单个扫描目标 (例如: google.com)")
	flag.StringVar(&TargetFile, "tl", "", "包含多个目标的文件路径")
	flag.StringVar(&DorkLevel, "s", "medium", "选择搜索规则集 (small, medium, all)")
	flag.StringVar(&OutputFilePath, "o", "GitHub_Scan_Results.txt", "扫描结果的输出文件路径")
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

	targetMissing := Target == "" && TargetFile == ""
	tokenFileMissing := TokenFile == ""
	if targetMissing || tokenFileMissing {
		var errorMessages []string
		if targetMissing {
			errorMessages = append(errorMessages, "必须通过 -t 或 -tl 提供至少一个扫描目标。")
		}
		if tokenFileMissing {
			errorMessages = append(errorMessages, "必须通过 -tf 提供令牌文件。")
		}
		color.Red("错误: %s", strings.Join(errorMessages, "\n      "))
		flag.Usage()
		os.Exit(0)
	}

	if _, ok := dorkSets[DorkLevel]; !ok {
		color.Red("错误: 无效的规则集 '%s'. 可选项为: small, medium, all", DorkLevel)
		os.Exit(1)
	}
	if Target != "" && TargetFile != "" {
		color.Red("错误: -t 和 -tl 参数不能同时使用")
		os.Exit(1)
	}
}

// parseparam 函数用于解析和加载来自文件的参数
func parseparam(tokens *[]string, dorks *[]string, targets *[]string) {
	if TokenFile != "" {
		tfres, err := os.ReadFile(TokenFile)
		if err != nil {
			if os.IsNotExist(err) {
				color.Red("读取令牌文件错误：在指定路径未找到文件 '%s'。", TokenFile)
			} else {
				color.Red("读取令牌文件时发生错误: %v", err)
			}
			os.Exit(1)
		}
		rawTokens := strings.Split(string(tfres), "\n")
		for _, t := range rawTokens {
			t = strings.TrimSpace(strings.TrimSuffix(t, "\r"))
			if t != "" {
				*tokens = append(*tokens, t)
			}
		}
	}

	if Target != "" {
		*targets = []string{Target}
	} else if TargetFile != "" {
		targetRes, err := os.ReadFile(TargetFile)
		if err != nil {
			if os.IsNotExist(err) {
				color.Red("读取目标文件错误：在指定路径未找到文件 '%s'。", TargetFile)
			} else {
				color.Red("读取目标文件时发生错误: %v", err)
			}
			os.Exit(1)
		}
		rawTargets := strings.Split(string(targetRes), "\n")
		for _, t := range rawTargets {
			t = strings.TrimSpace(strings.TrimSuffix(t, "\r"))
			if t != "" {
				*targets = append(*targets, t)
			}
		}
	}

	tokensEmpty := len(*tokens) == 0
	targetsEmpty := len(*targets) == 0
	if tokensEmpty || targetsEmpty {
		color.Red("错误：启动前必须满足以下条件：")
		if targetsEmpty {
			color.Red("  - 必须通过 -t 或 -tl 提供至少一个有效的目标。")
		}
		if tokensEmpty {
			color.Red("  - 必须在令牌文件 '%s' 中提供至少一个有效的令牌。", TokenFile)
		}
		os.Exit(1)
	}

	if selectedDorks, ok := dorkSets[DorkLevel]; ok {
		*dorks = selectedDorks
	} else {
		color.Red("内部错误: 未找到选择的规则集 '%s'", DorkLevel)
		os.Exit(1)
	}
	color.Blue("[+] 已加载 %d 个令牌, %d 个规则 (来自 '%s' 规则集), 和 %d 个目标\n", len(*tokens), len(*dorks), DorkLevel, len(*targets))
}

func main() {
	initSensitivePatterns()
	menu()

	var tokens []string
	var dorks []string
	var targets []string
	parseparam(&tokens, &dorks, &targets)

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
		go worker(i, dorkJobs, tokenPool, &wg, bar)
	}

	for _, t := range targets {
		for _, d := range dorks {
			dorkJobs <- fmt.Sprintf("%s %s", t, d)
		}
	}
	close(dorkJobs)
	wg.Wait()

	fmt.Println()
	if atomic.LoadInt64(&findingsCount) > 0 {
		if outputFile != nil {
			outputFile.Close()
		}
		color.Green("任务完成！发现 %d 个敏感信息，结果已保存至 %s", findingsCount, OutputFilePath)
	} else {
		color.Yellow("任务完成！未发现任何敏感信息。")
	}
}
