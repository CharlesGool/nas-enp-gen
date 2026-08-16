# nas-enp-mount

[English](README.md) | **简体中文**

> 译自 `README.md`（unreleased）。如有冲突，以英文版为准。

一个两段式工具，用于在 Linux 客户端上自动挂载 NAS 共享，同时不在客户端留下明文的 NAS IP / 账号 / 密码。

## 它做什么

- **`nas-enp-gen.py`**（*生成器*，运行在你自己的工作机上）——填入 NAS 连接信息和挂载映射，用 AES-256-GCM 加密后，编译出一个内嵌密文的、去符号的静态 Linux 二进制文件。
- **生成的二进制文件**（*客户端*）——放到每台 Linux 机器（Debian/Ubuntu）上，以 root 运行；它会挂载配置好的共享，并可以自装为 systemd 开机服务。

非目标：本工具不能让拥有 root 权限的客户端彻底无法恢复凭据——见下方安全说明。它也不是通用的密钥管理系统。

## 诚实的安全说明（务必阅读）

"客户端上的凭据无法被逆向"这个目标**做不到**——任何能挂载共享的客户端都必须能拿出凭据，所以客户端上的 root 用户始终能恢复它们（内存转储、对挂载过程 `strace`、抓 SMB 认证的包）。本工具实际做到的是：

- 凭据经 **AES-256-GCM 加密**后嵌入编译好的 Go 二进制文件；密钥经过拆分/异或混淆。对二进制跑 `strings` 什么也看不到，客户端磁盘上也不会写入任何明文配置文件。
- 这是**混淆，不是不可破解的保密**——它能挡住随手查看和意外泄漏，也提高了蓄意攻击者的门槛。

**同时请这样做：** 在 NAS 上为这些客户端建一个**专用、最小权限（尽量只读）、可撤销**的账号。一旦泄漏，损失可控，改一次 NAS 密码就能了结。

## 环境要求

- 操作系统 / 运行时（生成器所在机器）：Python 3.8+，需要 `cryptography` 包
- Go 工具链（https://go.dev/dl/）用于编译——可交叉编译到任意架构。没有 Go 时用 `--no-build` 输出 Go 源码，在任意 Linux 机器上编译。
- 客户端机器：Debian/Ubuntu Linux，root 权限，`cifs-utils`（`install_deps: true` 时可由客户端自动安装）

## 安装

```bash
# 一律拉取 tag，不要拉默认分支——分支尖端可能是半成品。
# 最新发布 tag：git ls-remote --tags <repo-url>
git clone --branch v0.1.0 --depth 1 <repo-url> nas-enp-gen
cd nas-enp-gen
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
cp config.example.json config.json   # 然后填入真实 NAS 信息，见「配置」
```

## 快速开始

```bash
# 从 JSON 配置文件读取（参见 config.example.json）
python3 nas-enp-gen.py --config config.json

# 一次性为多个架构构建
python3 nas-enp-gen.py --config config.json --arch amd64,arm64

# 只输出 Go 源码，不编译（本机没有 Go 工具链时使用）
python3 nas-enp-gen.py --config config.json --no-build

# 交互式，不用配置文件
python3 nas-enp-gen.py
```

## 验证是否成功

当前目录下应该出现一个 `nas-enp-mount` 二进制文件（若用 `--no-build` 则是 `.go` 源码），脚本会打印它构建的目标架构。把二进制拷到一台测试客户端上跑 `--selftest`：

```bash
./nas-enp-mount --selftest
```

预期输出确认内嵌配置解密成功，且不打印任何密钥内容。

## 在每台客户端部署（以 root 执行）

```bash
mkdir -p /root/nas-enp-mount
cp nas-enp-mount /root/nas-enp-mount/
/root/nas-enp-mount/nas-enp-mount --selftest         # 验证配置能解密
/root/nas-enp-mount/nas-enp-mount --oneshot          # 立即挂载
/root/nas-enp-mount/nas-enp-mount --install-service  # 设为开机启动
```

客户端命令：

| 命令 | 效果 |
|---|---|
| `--oneshot`（默认） | 挂载全部共享一次，内部自带重试 |
| `--install-service` | 写入并启用 systemd 单元，随即启动 |
| `--uninstall` | 停止/移除服务，卸载共享 |
| `--status` | 显示哪些共享已挂载 |
| `--selftest` | 确认内嵌配置能解密（不打印密钥） |

随时用 `journalctl -u nas-enp-mount.service` 查看日志。

## 为什么它不会拖垮开机

- `Type=oneshot`、`Wants=network-online.target`、`After=network-online.target`。
- 没有其他单元 `Requires=` 它，且它只被 `WantedBy=multi-user.target`——即使失败，开机流程照常继续。
- `TimeoutStartSec=150` 限定了整次尝试的时间预算，重试/退避都发生在这个预算**之内**，因此绝不会无限期等待一台不可达的 NAS。
- 客户端是幂等的：会检查 `/proc/mounts` 并跳过已挂载的目标，自动创建缺失的挂载点，并（可选）安装 `cifs-utils`。

## 轮换凭据 / 更换 NAS

凭据只存在于二进制文件内部。NAS 的 IP 或密码变更时，重新运行生成器产出新的二进制文件并替换旧的即可（想要干净切换可以先 `--uninstall`）。客户端上没有可编辑的配置文件，也就不存在配置不同步的问题。

## 配置

完整字段说明见 `config.example.json`。完整参考见 `DESIGN.md` → Configuration reference。

## 许可

Apache License 2.0 —— 见 `LICENSE`。
