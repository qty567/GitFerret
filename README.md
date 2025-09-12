# GitFerret - 高效的GitHub敏感信息扫描工具

## [English](README_EN.md)

GitFerret 是一款使用Go语言编写的命令行工具，旨在帮助安全研究人员和开发人员通过自定义的搜索规则（Dorks），高效地扫描GitHub上的代码仓库，以发现潜在的敏感信息泄露，例如API密钥、密码、私钥等。

本工具的设计思想借鉴了 GitDorker 等优秀的开源项目，并在性能、并发处理和规则精确度上进行了大量优化，以实现更低的误报率和更稳定的扫描体验。

✨ 功能特性

- **高并发扫描**：利用Go语言的并发特性，支持多线程同时执行扫描任务，大幅提升扫描速度。
- **多令牌支持**：支持从文件中加载多个GitHub个人访问令牌（PAT），通过轮换使用有效规避API速率限制。
- **灵活的目标与规则**：支持通过文件批量导入扫描目标（如域名、公司名）。内置`small`, `medium`, `all`三套规则集，可通过参数灵活选择。
- **高精确度与低误报率**：采用调优的严格检测模式，通过匹配高危文件名、高确定性密钥特征（如AWS密钥格式）以及常见的密钥关键词（如`api_key`），在保证高召回率的同时，显著降低了误报。
- **实时结果输出**：扫描过程中发现的任何敏感信息都会被立即写入指定的输出文件，无需等待任务结束。
- **用户友好的进度条**：在命令行中直观地显示扫描任务的实时进度、已完成数量和预计剩余时间。
- **自动速率限制处理**：能自动检测GitHub API的速率限制，并在后台静默等待，任务完成后自动恢复，无需人工干预。
- **智能输出路径**：优先在程序当前目录保存结果文件。如果遇到权限错误，会自动尝试将文件保存到您的个人主目录，确保程序顺利运行。

🛠️ 安装与配置

**1. 环境要求**

- Go 语言环境 (版本 >= 1.18)

**2. 下载与编译**

将项目克隆或下载到您的本地机器上：

```
# 进入代码所在目录
cd /path/to/your/project
```

下载所有依赖包。如果您在中国大陆，请先设置Go代理：

```
# (可选，仅中国大陆用户需要)
go env -w GOPROXY=[https://goproxy.cn](https://goproxy.cn),direct

# 下载依赖
go mod tidy
```

编译生成可执行文件：

```
bash build.sh
```

编译成功后，您将在`release`目录下看到一个名为 `GitFerret_amd_linux` (Linux)、`GitFerret_darwin` (macOS) 或 `GitFerret.exe` (Windows) 的可执行文件。

🚀 使用方法

**1. 准备文件**

在运行程序前，您需要准备以下文本文件：

- **令牌文件 (`tf.txt`)**: 每行存放一个您的GitHub个人访问令牌。

  ```
  ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxx
  ghp_yyyyyyyyyyyyyyyyyyyyyyyyyyyyy
  ```

- **目标文件 (`tl.txt`)**: 每行存放一个扫描目标，例如公司域名或名称。

  ```
  google.com
  北京字节跳动
  ```

**2. 运行命令**

使用以下命令格式运行扫描：

```
./GitFerret -tf <令牌文件> -tl <目标文件> -s <规则集> [其他可选参数]
```

**示例**:

```
# 使用中等规则集扫描
./GitFerret -tf tf.txt -tl tl.txt -s medium

# 使用所有规则集，并将并发数设为20
./GitFerret -tf tf.txt -tl tl.txt -s all -c 20
```

<img width="2526" height="1014" alt="wechat_2025-09-12_190803_314" src="https://github.com/user-attachments/assets/8581b349-aac7-4110-b3ae-8e6aa28ad975" />

**3. 命令行参数说明**

| 参数  | 必选 | 描述                                                | 默认值                    |
| ----- | ---- | --------------------------------------------------- | ------------------------- |
| `-tf` | 是   | 包含多个GitHub令牌的文件路径。                      |                           |
| `-tl` | 是   | 包含多个目标的文件路径。                            |                           |
| `-s`  | 否   | 选择搜索规则集 (可选项: `small`, `medium`, `all`)。 | `medium`                  |
| `-t`  | 否   | 单个扫描目标 (与 `-tl` 冲突)。                      |                           |
| `-o`  | 否   | 扫描结果的输出文件路径。                            | `GitHub_Scan_Results.txt` |
| `-c`  | 否   | 并发扫描的线程数。                                  | `10`                      |
| `-i`  | 否   | 每次API请求之间的间隔秒数。                         | `3`                       |
| `-w`  | 否   | 遇到API速率限制时的等待秒数。                       | `65`                      |

📄 输出格式

扫描结果会实时追加到您指定的输出文件中，格式如下：

```
搜索语句: google.com filename:.env
文件路径: path/to/leaked/.env
匹配原因: 高危文件名匹配: \.(env|pem|p12|pkcs12|pfx|asc|key)$
文件链接: [https://github.com/user/repo/blob/commit-hash/path/to/leaked/.env](https://github.com/user/repo/blob/commit-hash/path/to/leaked/.env)
--------------------------------------------------
搜索语句: 北京字节跳动 "api_key"
文件路径: src/config/settings.py
匹配原因: 文件内容匹配: (?i)(api_key|...)\s*[:=]\s*['"](...)['"]
文件链接: [https://github.com/user/another-repo/blob/commit-hash/src/config/settings.py](https://github.com/user/another-repo/blob/commit-hash/src/config/settings.py)
--------------------------------------------------
```

⚠️ 免责声明

本工具仅供授权的安全测试和教育目的使用。请确保您在使用本工具时遵守当地法律法规以及GitHub的服务条款。对于任何因滥用本工具而导致的法律责任或后果，开发者概不负责。
