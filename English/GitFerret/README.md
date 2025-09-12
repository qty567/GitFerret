# GitFerret - An Efficient GitHub Sensitive Information Scanning Tool

GitFerret is a command-line tool written in Go, designed to help security researchers and developers efficiently scan GitHub repositories for potential sensitive information leaks, such as API keys, passwords, and private keys, using custom search rules (Dorks).

The design of this tool draws inspiration from excellent open-source projects like GitDorker, with significant optimizations in performance, concurrency handling, and rule precision to achieve a lower false positive rate and a more stable scanning experience.

### ✨ Features

- **High-Concurrency Scanning**: Leverages Go's concurrency features to support multi-threaded scanning tasks, greatly increasing scanning speed.
- **Multi-Token Support**: Supports loading multiple GitHub Personal Access Tokens (PATs) from a file, effectively circumventing API rate limits by rotating through them.
- **Flexible Targets & Rules**: Allows for batch importing of scanning targets (e.g., domains, company names) and search rules (Dorks) from files.
- **Low False-Positive Rate**: Utilizes built-in, optimized, and stricter regular expression rules that distinguish between high-risk filenames and file contents, effectively reducing invalid alerts.
- **Real-Time Results Output**: Any sensitive information found during the scan is immediately written to the specified output file without waiting for the task to complete.
- **User-Friendly Progress Bar**: Intuitively displays the real-time progress of the scanning task, the number of completed items, and the estimated time remaining in the command line.
- **Automatic Rate Limit Handling**: Can automatically detect GitHub API rate limits, wait silently in the background, and resume automatically once the limit is lifted, requiring no manual intervention.
- **Smart Output Path**: Prioritizes saving the results file in the current directory. If a permission error is encountered, it will automatically attempt to save the file to your user home directory, ensuring the program runs smoothly.

### 🛠️ Installation & Configuration

**1. Environment Requirements**

- Go programming language environment (version >= 1.16)

**2. Download & Compile**

Clone or download the project to your local machine:

```
# Navigate to the project directory
cd /path/to/your/project
```

Download all dependencies. If you are in mainland China, please set up a Go proxy first:

```
# (Optional, only for users in mainland China)
go env -w GOPROXY=[https://goproxy.cn](https://goproxy.cn),direct

# Download dependencies
go mod tidy
```

Compile to generate the executable file:

```
bash build.sh
```

After a successful compilation, you will find an executable file named `GitFerret_amd_linux` (Linux/macOS), `GitFerret_darwin` (macOS), or `GitFerret.exe` (Windows) in the `release` directory.

### 🚀 Usage

**1. Prepare Files**

Before running the program, you need to prepare the following text files:

- **Token File (`tf.txt`)**: Contains your GitHub Personal Access Tokens, one per line.

  ```
  ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxx
  ghp_yyyyyyyyyyyyyyyyyyyyyyyyyyyyy
  ```

- **Target File (`tl.txt`)**: Contains the scanning targets, one per line, such as a company domain or name (no prefixes like `org:` are needed).

  ```
  google.com
  ByteDance
  ```

- **Rules Files (`dorks`)**: The program comes with built-in rule files located in the `Dorks` directory. You can choose which one to use based on your needs, for example:

  - `alldorksv3.txt` (Most comprehensive rules)
  - `medium_dorks.txt` (Medium set of rules)
  - `smalldorks.txt` (Minimal set of rules)

**2. Run Command**

Use the following command format to run a scan:

```
./GitFerret -tf <token_file> -tl <target_file> -d <dorks_file_path> [other_optional_flags]
```

**Example:**

```
# Use the alldorksv3.txt rules file from the Dorks folder
./GitFerret.exe -d \GitFerret\Dorks\alldorksv3.txt -tl \GitFerret\tl.txt -tf \GitFerret\tf.txt
```

**3. Command-Line Arguments**

| Parameter | Required | Description                                         | Default Value             |
| --------- | -------- | --------------------------------------------------- | ------------------------- |
| `-tf`     | Yes      | Path to the file containing GitHub tokens.          |                           |
| `-tl`     | Yes      | Path to the file containing multiple targets.       |                           |
| `-d`      | Yes      | Path to the file containing multiple search dorks.  |                           |
| `-t`      | No       | A single scan target (conflicts with `-tl`).        |                           |
| `-k`      | No       | A single search keyword (conflicts with `-d`).      |                           |
| `-o`      | No       | Output file path for scan results.                  | `GitHub_Scan_Results.txt` |
| `-c`      | No       | Number of concurrent scanning threads.              | `10`                      |
| `-i`      | No       | Interval in seconds between API requests.           | `3`                       |
| `-w`      | No       | Waiting time in seconds when API rate limit is hit. | `65`                      |

### 📄 Output Format

The scan results will be appended in real-time to the output file you specified, in the following format:

```
Search Query: google.com filename:.env
File Path: path/to/leaked/.env
Match Reason: High-risk filename match: \.(env|pem|p12|pkcs12|pfx|asc|key)$
File Link: [https://github.com/user/repo/blob/commit-hash/path/to/leaked/.env](https://github.com/user/repo/blob/commit-hash/path/to/leaked/.env)
--------------------------------------------------
Search Query: ByteDance "api_key"
File Path: src/config/settings.py
Match Reason: File content match: (?i)(api_key|...)\s*[:=]\s*['"](...)['"]
File Link: [https://github.com/user/another-repo/blob/commit-hash/src/config/settings.py](https://github.com/user/another-repo/blob/commit-hash/src/config/settings.py)
--------------------------------------------------
```

### ⚠️ Disclaimer

This tool is intended for authorized security testing and educational purposes only. Please ensure that your use of this tool complies with local laws and regulations as well as GitHub's terms of service. The developers are not responsible for any legal liabilities or consequences resulting from the misuse of this tool.