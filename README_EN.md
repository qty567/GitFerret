# GitFerret - An Efficient GitHub Sensitive Information Scanner

## [中文](README.md)

GitFerret is a command-line tool written in Go, designed to help security researchers and developers efficiently scan GitHub code repositories for potential sensitive information leaks, such as API keys, passwords, and private keys, using customizable search rules (Dorks).

The design of this tool is inspired by excellent open-source projects like GitDorker, with significant optimizations in performance, concurrency, and rule precision to achieve a lower false-positive rate and a more stable scanning experience.

✨ Features

- **High-Concurrency Scanning**: Leverages Go's concurrency features to support multi-threaded scanning tasks, greatly increasing scanning speed.
- **Multiple Token Support**: Supports loading multiple GitHub Personal Access Tokens (PATs) from a file, effectively circumventing API rate limits by rotating through them.
- **Flexible Targets & Rules**: Supports batch importing of scan targets (e.g., domains, company names) from a file. Features three built-in dork sets (`small`, `medium`, `all`) that can be easily selected via a flag.
- **High Precision & Low False-Positive Rate**: Implements a tuned strict detection mode that matches high-risk filenames, high-certainty key signatures (like AWS key formats), and common key-related keywords (like `api_key`) to significantly reduce false positives while maintaining a high recall rate.
- **Real-time Output**: Any sensitive information found during the scan is immediately written to the specified output file without waiting for the task to complete.
- **User-Friendly Progress Bar**: Intuitively displays the real-time progress of the scanning task, including completed items and estimated time remaining, directly in the command line.
- **Automatic Rate Limit Handling**: Automatically detects GitHub API rate limits and waits silently in the background, resuming the task once the limit is reset without manual intervention.
- **Intelligent Output Path**: Prioritizes saving the results file in the program's current directory. If a permission error occurs, it automatically attempts to save the file to your personal home directory to ensure the program runs smoothly.
- **Multi-Keyword File Query**: Supports batch importing of multiple search keywords from a file, enhancing the flexibility and efficiency of searches.
- **Bilingual Support** (Chinese & English): Provides a complete user interface and documentation in both Chinese and English, making it convenient for users from different language backgrounds.
- **Friendlier Output**: Optimizes the display format of scan results in both the command line and the output file, making the information clear and easy to locate and analyze.

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
