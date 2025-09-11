# GitFerret
**GitFerret** 是一款专为安全研究人员和开发者设计的高效GitHub敏感信息自动化审计工具。它能够并发地、智能化地扫描GitHub代码库，精准发现并验证潜在的敏感信息泄露。
## 核心功能

- **并发扫描**: 利用Go语言的并发特性，启动多个“工人”同时执行扫描任务，速度远超传统串行脚本。
- **多目标支持**: 支持通过命令行参数 `-t` 指定单个目标，或通过 `-tl` 指定一个包含多个目标（域名、关键词等）的文件进行批量审计。
- **智能验证**: 并非简单地基于关键词返回结果，而是会下载文件内容，通过内置的正则表达式规则库进行二次验证，极大地降低了误报率。
- **自动过滤**: 默认只输出通过了敏感性校验的有效结果，自动剔除非敏感的“噪音”信息。
- **智能限速**: 自动处理GitHub API的速率限制，当触发限制时会协同所有“工人”暂停，并在限制解除后自动恢复，保证扫描的完整性。
- **高可读性报告**: 输出格式化的文本报告，清晰地展示每一个发现的敏感信息、触发的关键词、匹配原因以及对应的GitHub链接。
- **灵活配置**: 支持通过参数灵活配置并发数、请求间隔、等待时间等，以适应不同的网络环境和扫描策略。

## 安装与构建

**环境要求:**

- 已安装 [Go](https://go.dev/dl/) 语言环境 (版本 >= 1.18)。

**构建步骤:**

1. 克隆或下载本项目源代码。

2. 在项目根目录下，执行以下命令安装依赖（如果之前未安装过）：

   ```
   go mod tidy
   ```

3. 执行构建命令：

   - **Linux / macOS:**

     ```
     go build -o GitHound main.go
     ```

   - **Windows:**

     ```
     go build -o GitHound.exe main.go
     ```

   构建成功后，当前目录会生成一个名为 `GitHound` 或 `GitHound.exe` 的可执行文件。

## 使用方法

### 参数说明

```
用法 ./GitHound:
  -c int
        并发数 (工人数量) (默认 10)
  -d string
        Dorks规则文件路径
  -i int
        每个请求之间的间隔秒数 (默认 3)
  -k string
        单个搜索关键词
  -o string
        结果输出文件路径 (默认 "GitHub代码扫描结果.txt")
  -t string
        单个搜索目标
  -tf string
        Token令牌文件路径
  -tl string
        包含多个目标的文件路径
  -v
        详细模式 (显示'未找到'等信息)
  -w int
        API速率限制时的等待秒数 (默认 65)
```

### 使用示例

**1. 扫描单个目标:**

```
./GitHound -t "example.com" -tf tokens.txt -d dorks.txt
```

**2. 批量扫描多个目标:**

首先，创建一个名为 `targets.txt` 的文件，每行一个目标：

```
example.com
example-corp
"Internal Project Name"
```

然后，运行以下命令：

```
./GitHound -tl targets.txt -tf tokens.txt -d dorks.txt -c 20 -o scan_report.txt
```

- `-c 20`: 使用20个并发线程。
- `-o scan_report.txt`: 将结果保存到 `scan_report.txt` 文件。

## 配置文件说明

### Token 文件 (`-tf`)

一个纯文本文件，每行包含一个您的GitHub Personal Access Token (Classic)。建议提供多个以更好地应对速率限制。 *示例 `tokens.txt`:*

```
ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxx1
ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxx2
```

### Dorks 文件 (`-d`)

一个纯文本文件，每行包含一条搜索规则（关键词）。 *示例 `dorks.txt`:*

```
password
api_key
secret_key
"internal use only"
```

### 目标文件 (`-tl`)

一个纯文本文件，每行包含一个您希望扫描的目标（可以是域名、公司名、项目特征等）。 *示例 `targets.txt`:*

```
google.com
谷歌
```

## 致谢 (Acknowledgements)

本项目GitFerret的开发灵感来源于 `gitdork_rev `及其前身Gitdorks_go、GitDorker。在原有概念的基础上，我对程序架构、核心扫描逻辑及用户体验进行了完全的重构和功能增强，旨在打造一个更高效、更精准的GitHub敏感信息自动化收集工具。在此对原作者的开创性工作表示感谢。

## 免责声明 (Disclaimer)

本工具仅供授权的安全测试和教育目的使用。使用者应对其所有行为负责。请勿在未获得授权的情况下扫描任何目标。开发者不承担任何因滥用本工具而产生的法律责任。
