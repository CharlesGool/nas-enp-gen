# nas-enp-mount — 设计

[English](DESIGN.md) | **简体中文**

> 译自 `DESIGN.md`（unreleased）。如有冲突，以英文版为准。

> 本文档的成败标准：另一个人拿着它，在另一台设备上能把项目重建出来。写的时候假设读者看不到你的机器。

## 目标与非目标

**目标**
- 让 Linux 客户端能在开机时自动挂载 NAS（CIFS/NFS）共享，且客户端磁盘上不留明文凭据文件。
- 让凭据轮换变成一步操作：重新生成二进制文件，重新部署。
- 故障安全：NAS 不可达时绝不能拖垮或卡住客户端的开机流程。

**非目标**
- 对拥有 root 权限的客户端做到真正的保密——这在结构上就做不到，因为客户端本身必须能恢复凭据才能挂载共享。见 README 的「诚实的安全说明」。
- 跨平台客户端（Windows/macOS）——仅支持 Debian/Ubuntu Linux。
- 通用的密钥管理或配置分发系统。

## 架构

```
config.json（真实密钥，绝不提交）
        |
        v
nas-enp-gen.py  --config config.json  --arch amd64,arm64
        |  1. 校验配置
        |  2. AES-256-GCM 加密 JSON 内容
        |  3. 拆分/异或混淆密钥，填入 Go 模板
        |  4. `go build`（或用 --no-build 输出 .go 源码）
        v
nas-enp-mount（每个架构一个静态二进制，内嵌密文 + 混淆后的密钥）
        |
        |  拷贝到每台客户端，以 root 运行
        v
客户端二进制
        |  --selftest         在内存中解密、校验，不打印任何敏感内容
        |  --oneshot           挂载每个配置的共享（幂等，自带重试）
        |  --install-service   写入 systemd 单元、启用、启动
        v
客户端上已挂载的 CIFS/NFS 共享
```

## 技术栈

| 层 | 选型 | 版本 | 理由 |
|---|---|---|---|
| 生成器 | Python | 3.8+（在 3.10 上测试过） | 编写「加密+填模板」这一步；`cryptography` 提供经审计的 AES-GCM |
| 生成器加密库 | `cryptography`（pyca） | 3.4.8 | 经审计，Python 里做 AES-256-GCM 的标准选择 |
| 客户端 | Go | go.dev 提供的任意工具链 | 编译成单一静态、去符号的二进制文件——客户端零运行时依赖，攻击面小，交叉编译简单 |
| 客户端加密库 | Go 标准库 `crypto/aes`、`crypto/cipher` | 标准库 | 不用第三方 Go 模块——没有需要归档或许可证追踪的依赖 |

被否决的方案和理由见 `DECISIONS.md`。

## 复现要求

**本文档最重要的一节。另一台机器需要的一切都在这里。**

### 环境

- 操作系统（生成器所在机器）：任意装有 Python 3.8+ 的系统；因构建目标是 Linux，推荐用 Linux
- 操作系统（客户端机器）：Debian/Ubuntu Linux，需要 root 权限
- 运行时 + 版本：Python 3.8+，`cryptography` 包
- 可选：Go 工具链，用于本地编译（用 `--no-build` 可以不需要它）
- 依赖恢复命令：`pip install -r requirements.txt`

### 外部依赖

| 项目 | 来源 | 存放位置 |
|---|---|---|
| NAS 凭据（host/用户名/密码） | 你的 NAS 管理面板 | `config.json`（已加入 .gitignore，绝不提交） |
| Go 工具链（可选） | https://go.dev/dl/ | 系统 `PATH` |
| `cifs-utils`（客户端，可选） | 客户端的包管理器 | `install_deps: true` 时由客户端二进制自动安装 |

任何会被提交的内容里一律用占位符，绝不用真实值——参见 `config.example.json`。

### 路径与挂载点

以下路径全部*由用户自己的 `config.json` 提供*，脚本里没有硬编码：

| 路径 | 由谁提供 | 用途 |
|---|---|---|
| `mounts[].remote` | 用户，写在配置里 | NAS 上要挂载的路径 |
| `mounts[].local` | 用户，写在配置里 | 客户端上的挂载点 |
| `--out` | 命令行参数，默认 `nas-enp-mount` | 生成器写出二进制文件的位置 |

客户端把自己的安装位置 `/root/nas-enp-mount` 写死为固定约定，并在 README 中说明——这是客户端侧的安装路径，不是生成器所在机器的路径，因此不需要模板化。

### 配置参考

`nas-enp-gen.py --config <file>` 读取的 JSON 配置字段（参见 `config.example.json`）：

| 字段 | 含义 | 默认值 | 是否必填 |
|---|---|---|---|
| `protocol` | `cifs` 或 `nfs` | — | 是 |
| `host` | NAS 的 IP 或主机名 | — | 是 |
| `username` | NAS 账号 | — | 是（CIFS） |
| `password` | NAS 账号密码 | — | 是（CIFS） |
| `domain` | Windows 域（如有） | `""` | 否 |
| `default_options` | 未单独覆盖时，应用到每个共享的挂载选项 | — | 是 |
| `mounts` | `{remote, local, options}` 数组 | — | 是，至少一项 |
| `retry_attempts` | 客户端挂载重试次数 | — | 是 |
| `retry_delay_sec` | 重试间隔秒数 | — | 是 |
| `install_deps` | 缺少时允许客户端 `apt install cifs-utils` | — | 是 |

生成器自身的命令行参数：`--config`、`--arch`（逗号分隔，如 `amd64,arm64`）、`--out`、`--no-build`、`--save-config`（把收集到的配置写回文件——包含明文密码，注意保管）。

## 从零搭建

1. 在生成器所在机器上：`pip install -r requirements.txt` —— 验证：`python3 -c "import cryptography"` 无报错。
2. 把 `config.example.json` 复制为 `config.json`，填入真实 NAS 信息 —— 验证：`python3 -m json.tool config.json` 能正常解析。
3. 运行 `python3 nas-enp-gen.py --config config.json` —— 验证：当前目录出现 `nas-enp-mount` 二进制文件。
4. 把二进制拷到一台测试客户端，跑 `--selftest` —— 验证：报告配置解密成功。
5. 在客户端跑 `--oneshot` —— 验证：`mount | grep <local路径>` 能看到共享已挂载。
6. 跑 `--install-service` —— 验证：`systemctl is-enabled nas-enp-mount.service` 显示 `enabled`。

本项目不用 Docker 部署——无需参照 docker 相关 Skill。

## 数据模型 / 文件布局

```
repo/
├── nas-enp-gen.py       # 生成器——读取 config.json，驱动整条流水线
├── config.example.json  # 配置文件的占位版本（可以安全提交）
├── requirements.txt      # 生成器侧 Python 依赖的锁定版本
└── （config.json、nas-enp-mount、*.go —— 构建输入/输出，均已 gitignore）
```

Go 客户端源码以 base64 形式嵌在 `nas-enp-gen.py` 内部（`GO_TEMPLATE_B64`），而不是单独的 `.go` 文件，这样生成器就是单文件、自包含的。用 `--no-build` 可以导出真实的 `.go` 源码供检查。

## 已知限制与坑

- `config.example.json` 曾经以「example」为名保存过**真实的生产凭据**——现已修正（只保留占位符，见 `DECISIONS.md` 2026-08-16 条目）。真实值现存放在已 gitignore 的 `config.json` 中，本机实际使用的工作配置保存在 `../nas.local.json`（项目根目录，`repo/` 之外，绝不提交）。
- 预编译的 `nas-enp-mount` 二进制文件内嵌了本机 NAS 的真实加密凭据，绝不能提交——它保存在项目根目录（`repo/` 之外），不被 git 追踪。
- 安全性是混淆，不是能真正挡住客户端 root 攻击者的加密——见 README。
- 生成器和内嵌的 Go 客户端目前都还没有自动化测试。

## 如何扩展

- 支持新的客户端平台：`GO_TEMPLATE_B64` 里的 Go 模板需要第二个变体；这么做之前，建议先把它外置成一个带 build tag 的真正 `.go` 文件——base64 塞进 Python 字符串这套办法撑不过第二个目标系统。
- 支持 CIFS/NFS 以外的新挂载协议：需要同时改 Go 模板里的 `MountSpec`/`Config` 和 `nas-enp-gen.py` 里的 `validate()`——两边必须保持同步，因为它们之间没有共享的 schema。
