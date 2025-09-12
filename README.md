# GitFerret - 高效的GitHub敏感信息扫描工具

`GitFerret` 是一款使用Go语言编写的命令行工具，旨在帮助安全研究人员和开发人员通过自定义的搜索规则（Dorks），高效地扫描GitHub上的代码仓库，以发现潜在的敏感信息泄露，例如API密钥、密码、私钥等。

本工具的设计思想借鉴了 `GitDorker` 等优秀的开源项目，并在性能、并发处理和规则精确度上进行了大量优化，以实现更低的误报率和更稳定的扫描体验。

## ✨ 功能特性

- **高并发扫描**：利用Go语言的并发特性，支持多线程同时执行扫描任务，大幅提升扫描速度。
- **多令牌支持**：支持从文件中加载多个GitHub个人访问令牌（PAT），通过轮换使用有效规避API速率限制。
- **灵活的目标与规则**：支持通过文件批量导入扫描目标（如域名、公司名）和搜索规则（Dorks）。
- **低误报率**：内置经过优化的、更严格的正则表达式规则，区分高危文件名和文件内容，有效降低无效告警。
- **实时结果输出**：扫描过程中发现的任何敏感信息都会被**立即**写入指定的输出文件，无需等待任务结束。
- **用户友好的进度条**：在命令行中直观地显示扫描任务的实时进度、已完成数量和预计剩余时间。
- **自动速率限制处理**：能自动检测GitHub API的速率限制，并在后台静默等待，任务完成后自动恢复，无需人工干预。

## 🛠️ 安装与配置

#### 1. 环境要求

- Go 语言环境 (版本 >= 1.16)

#### 2. 下载与编译

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

编译成功后，您将在release目录下看到一个名为 `GitFerret_amd_linux` (Linux) 、`GitFerret_darwin` (macOS) 、`GitFerret.exe` (Windows) 的可执行文件。

## 🚀 使用方法

#### 1. 准备文件

在运行程序前，您需要准备以下文本文件：

- **令牌文件 (`tf.txt`)**: 每行存放一个您的GitHub个人访问令牌。

  ```
  ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxx
  ghp_yyyyyyyyyyyyyyyyyyyyyyyyyyyyy
  ```

- **目标文件 (`tl.txt`)**: 每行存放一个扫描目标，例如公司域名或名称（无需 `org:` 等前缀）。

  ```
  google.com
  北京字节跳动
  ```

- **规则文件 (`dorks`)**: 程序内置了规则文件，位于安装目录下的 `Dorks` 文件夹中。您可以根据需要选择使用，例如：

  - `alldorksv3.txt` (最全规则)
  - `medium_dorks.txt` (中等规则)
  - `smalldorks.txt` (精简规则)

#### 2. 运行命令

使用以下命令格式运行扫描：

```
./GitFerret -tf <令牌文件> -tl <目标文件> -d <规则文件路径> [其他可选参数]
```

**示例:**

```
# 使用 Dorks 文件夹下的 alldorksv3.txt 规则文件
./>GitFerret.exe -d \GitFerret\Dorks\alldorksv3.txt -tl \GitFerret\tl.txt -tf \GitFerret\tf.txt
```
<img width="2550" height="1296" alt="wechat_2025-09-12_130751_842" src="https://github.com/user-attachments/assets/a3c8283a-a4b6-4480-9865-894eb2b03657" />

#### 3. 命令行参数说明

| 参数  | 必选 | 描述                            | 默认值               |
| ----- | ---- | ------------------------------- | -------------------- |
| `-tf` | 是   | 包含多个GitHub令牌的文件路径。  |                      |
| `-tl` | 是   | 包含多个目标的文件路径。        |                      |
| `-d`  | 是   | 包含多个搜索规则的文件路径。    |                      |
| `-t`  | 否   | 单个扫描目标 (与 `-tl` 冲突)。  |                      |
| `-k`  | 否   | 单个搜索关键词 (与 `-d` 冲突)。 |                      |
| `-o`  | 否   | 扫描结果的输出文件路径。        | `GitHub扫描结果.txt` |
| `-c`  | 否   | 并发扫描的线程数。              | `10`                 |
| `-i`  | 否   | 每次API请求之间的间隔秒数。     | `3`                  |
| `-w`  | 否   | 遇到API速率限制时的等待秒数。   | `65`                 |

## 📄 输出格式

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

## ⚠️ 免责声明

本工具仅供授权的安全测试和教育目的使用。请确保您在使用本工具时遵守当地法律法规以及GitHub的服务条款。对于任何因滥用本工具而导致的法律责任或后果，开发者概不负责。
