# GitFerret - An Efficient GitHub Sensitive Information Scanner

## [中文](README.md)

GitFerret is a command-line tool written in Go, designed to help security researchers and developers efficiently scan GitHub code repositories for potential sensitive information leaks, such as API keys, passwords, and private keys, using customizable search rules (Dorks).

The design of this tool is inspired by excellent open-source projects like GitDorker, with significant optimizations in performance, concurrency, and rule precision to achieve a lower false-positive rate and a more stable scanning experience.

### ✨ Features (English Version)

- **High-Concurrency & High-Performance**: Utilizes Go's concurrency features to support multi-threaded scanning, significantly increasing speed.
- **Flexible Targets & Rules**: Supports batch importing of scan targets (e.g., domains, company names) and custom search keywords from files. Includes three built-in rule sets (`small`, `medium`, `all`) that can be selected via parameters.
- **High Accuracy & Low False-Positive Rate**: Employs a fine-tuned, strict detection model by matching high-risk filenames, high-certainty key patterns, and common keywords to significantly reduce false positives.
- **Robust API Rate-Limit Handling**: Supports multi-token rotation and automatically detects and silently handles GitHub API rate limits, ensuring stable and uninterrupted scans.
- **Intelligent Result Presentation**:
  - **Alert Aggregation**: Automatically consolidates multiple findings for the same file into a single alert for a cleaner report.
  - **Real-Time Output**: Discovered secrets are immediately written to the output file without delay.
  - **User-Friendly Interface**: Provides a clear command-line progress bar and optimized output formatting.
  - **Smart Output Path**: Automatically attempts to save the results to the user's home directory if a permission error occurs in the default location.
- **Bilingual Support**: Provides a complete user interface and documentation in both Chinese and English for users from different language backgrounds.

🛠️ Installation & Setup

**1. Requirements**

- Go environment (version >= 1.18)

**2. Download & Compile**

Clone or download the project to your local machine:

```
# Navigate to the project directory
cd /path/to/your/project
```

Download all dependencies:

```
go mod tidy
```

Compile the executable:

```
bash build.sh
```

After successful compilation, you will find an executable file named `GitFerret_amd_linux` (Linux), `GitFerret_darwin` (macOS), or `GitFerret.exe` (Windows) in the `release` directory.

🚀 Usage

**1. Prepare Files**

Before running the program, you need to prepare the following text files:

- **Token file (`tf.txt`)**: Contains one GitHub Personal Access Token per line.

  ```
  ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxx
  ghp_yyyyyyyyyyyyyyyyyyyyyyyyyyyyy
  ```

- **Target file (`tl.txt`)**: Contains one scan target per line, such as a company domain or name.

  ```
  google.com
  Microsoft
  ```

**2. Run the Command**

Use the following command format to run a scan:

```
./GitFerret -tf <token_file> -tl <target_file> -s <dork_set> [other_optional_flags]
```

**Examples**:

```
# Scan using the medium dork set
./GitFerret -tf tf.txt -tl tl.txt -s medium

# Scan using the 'all' dork set with a concurrency of 20
./GitFerret -tf tf.txt -tl tl.txt -s all -c 20
```

<img width="2520" height="1011" alt="wechat_2025-09-12_192339_396" src="https://github.com/user-attachments/assets/b929eac3-7f89-47c1-8d53-a4b41ea46c79" />


**3. Command-Line Arguments**

| Flag  | Required | Description                                          | Default Value             |
| ----- | -------- | ---------------------------------------------------- | ------------------------- |
| `-tf` | Yes      | Path to the file containing GitHub tokens.           |                           |
| `-tl` | Yes      | Path to the file containing multiple targets.        |                           |
| `-s`  | No       | Dork set to use (options: `small`, `medium`, `all`). | `medium`                  |
| `-t`  | No       | A single target to scan (conflicts with `-tl`).      |                           |
| `-o`  | No       | Output file path for scan results.                   | `GitHub_Scan_Results.txt` |
| `-c`  | No       | Number of concurrent scanning threads.               | `10`                      |
| `-i`  | No       | Interval in seconds between each API request.        | `3`                       |
| `-w`  | No       | Seconds to wait when the API rate limit is hit.      | `65`                      |

📄 Output Format

The scan results are appended in real-time to the output file you specify, in the following format:

```
Search Dork: google.com filename:.env
File Path: path/to/leaked/.env
Match Reason: High-confidence filename match: \.(env|pem|p12|pkcs12|pfx|asc|key)$
File URL: [https://github.com/user/repo/blob/commit-hash/path/to/leaked/.env](https://github.com/user/repo/blob/commit-hash/path/to/leaked/.env)
--------------------------------------------------
Search Dork: Microsoft "api_key"
File Path: src/config/settings.py
Match Reason: File content match: (?i)(api_key|...)\s*[:=]\s*['"](...)['"]
File URL: [https://github.com/user/another-repo/blob/commit-hash/src/config/settings.py](https://github.com/user/another-repo/blob/commit-hash/src/config/settings.py)
--------------------------------------------------
```

⚠️ Disclaimer

This tool is intended for authorized security testing and educational purposes only. Ensure that your use of this tool complies with local laws and regulations, as well as GitHub's terms of service. The developer assumes no liability and is not responsible for any misuse or damage caused by this tool.
