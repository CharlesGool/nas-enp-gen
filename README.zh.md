# nas-enp-mount

[English](README.md) | **简体中文**

> 译自 `README.md`（v0.1.0）。如有冲突，以英文版为准。

一个两段式工具，用于在 Linux 客户端上自动挂载 NAS 共享，同时不在客户端留下明文的 NAS IP / 账号 / 密码。

## 它做什么

- **`nas-enp-gen.py`**（*生成器*，运行在你自己的工作机上）——填入 NAS 连接信息和挂载映射，用 AES-256-GCM 加密后，写出一个自包含、内嵌密文的 Python 客户端脚本。不带参数运行会打开 **GUI 表单**（PySide6，左上角有语言下拉框可切换 **English / 中文**，默认跟随系统语言），或用 `--config`/`--cli` 走无界面/脚本化流程。也打包为可安装的 **`.deb`**（Linux）和 **`.exe`**（Windows）桌面应用——见「安装」。
- **生成的脚本**（*客户端*）——放到每台 Linux 机器（Debian/Ubuntu）上，用 `python3` 以 root 运行；它会挂载配置好的共享，并可以自装为 systemd 开机服务。
- **机器绑定（可选，推荐开启）**——`binding.mode: "machine"` 让客户端的解密密钥由每台目标机器自身的硬件指纹派生，而不是把可还原的密钥直接嵌入文件。生成的文件一旦离开它绑定的那台（那批）机器——不管是传错群、随备份外泄、随报废设备流出，还是误提交到公开仓库——在计算上都无法解密。这一层到底防住了什么、没防住什么，见下方「诚实的安全说明」。

非目标：本工具不能让拥有 root 权限的客户端彻底无法恢复凭据——见下方安全说明。它也不是通用的密钥管理系统。

## 诚实的安全说明（务必阅读）

"客户端上的凭据无法被逆向"这个目标**做不到**——任何能挂载共享的客户端都必须能拿出凭据，所以客户端上的 root 用户始终能恢复它们（内存转储、对挂载过程 `strace`、抓 SMB 认证的包）。这一点与 `binding.mode` 无关，两种模式下都成立。本工具实际做到的是（按模式区分）：

**`binding.mode: "machine"`（推荐）——对文件外泄提供真实保护：**
- 客户端真正的解密密钥从不存放在任何地方。它在运行时由机器自身硬件指纹（`product_uuid` 加上其它 DMI/磁盘标识符——见 `DESIGN.md` 「Envelope format」）经 Scrypt 派生得出。脚本的副本放到任何别的机器上都没有办法够到这把密钥——不是"藏得深不好找"，而是结构性地不存在。
- 在**已绑定**的那台机器上，这句话依然成立：该机器上的 root 仍能恢复一切（内存转储、`strace`、抓包），和任何模式一样。绑定提高的是*外泄*的门槛，不是本机 root 攻击者的门槛。

**`binding.mode: "none"`（兼容模式）——仅提供混淆：**
- 凭据经 AES-256-GCM 加密，密钥拆分/异或混淆后存放在同一个文件里。客户端磁盘上不会写入任何明文配置文件。
- 这是**混淆，不是不可破解的保密**——它能挡住随手查看和意外泄漏，但只要拿到脚本，在任何机器上都能还原出密钥。仅在无法预先采集目标机器指纹时使用这个模式。

**无论哪种模式都请同时做到：** 在 NAS 上为这些客户端建一个**专用、最小权限（尽量只读）、可撤销**的账号。一旦泄漏，损失可控，改一次 NAS 密码就能了结。

## 环境要求

- 操作系统 / 运行时（生成器所在机器）：Python 3.8+，需要 `cryptography`（GUI 还需要 `PySide6`，首次启动 GUI 时若缺失会自动通过 pip 安装）——或者直接用打包好的 `.deb`/`.exe`，已内含全部依赖。
- 客户端机器：Debian/Ubuntu Linux，root 权限，Python 3.8+。`cryptography` 和 `cifs-utils` 若缺失，客户端脚本首次运行时会自动安装。

## 安装

既可以从源码运行，也可以从发布页面下载打包好的安装程序（每次打 tag 时由 CI 自动构建——见 `.github/workflows/release-installers.yml`）：

```bash
# 一律拉取 tag，不要拉默认分支——分支尖端可能是半成品。
# 最新发布 tag：git ls-remote --tags <repo-url>
git clone --branch v0.1.0 --depth 1 <repo-url> nas-enp-gen
cd nas-enp-gen
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
cp config.example.json config.json   # 然后填入真实 NAS 信息，见「配置」
```

## 本地构建安装程序

CI（`.github/workflows/release-installers.yml`）会在每次推送 `v*.*.*` tag 时自动构建两种安装程序。想自己本地构建也可以：

```bash
pip install -r requirements.txt pyinstaller
pyinstaller packaging/nas-enp-gen.spec
```

输出：`dist/nas-enp-gen`（Linux）或 `dist/nas-enp-gen.exe`（Windows）。在 Linux 上，用 `packaging/build-deb.sh` 把它包装成 `.deb`。

**Windows 上的坑：** 运行 `pyinstaller`，不要运行 `python pyinstaller`——它是 `pip` 安装的一个独立控制台命令，不是要传给 `python` 的脚本。如果 `PATH` 里找不到 `pyinstaller`（常见于 Microsoft Store 版 Python 的别名，其 `Scripts` 目录经常不在 `PATH` 里），改用 `python -m PyInstaller packaging\nas-enp-gen.spec`——这个方式不依赖 `PATH`，总能生效。

## 第 0 步：采集目标机器的指纹（仅 `binding.mode: "machine"` 需要）

如果你用的是 `binding.mode: "none"`，跳过这一步。否则，在**每一台**目标机器上（以 root 身份）：

```bash
python3 nas-enp-gen.py --emit-collector          # 写出 nas-enp-fingerprint.py
# 把 nas-enp-fingerprint.py 拷到目标机器上，然后在那台机器上执行：
python3 nas-enp-fingerprint.py
```

它会打印一个 64 位十六进制的指纹，以及用到了哪些硬件字段——把这个指纹粘贴进
`config.json` 的 `binding.fingerprints` 数组（或 GUI 的指纹文本框）。一个含
N 个指纹的文件可以绑定整批机器——见 `DESIGN.md` 「Envelope format」。

## 快速开始

```bash
# GUI 表单（不带参数）
python3 nas-enp-gen.py

# 无界面，从 JSON 配置文件读取（参见 config.example.json）
python3 nas-enp-gen.py --config config.json

# 交互式终端提示，代替 GUI
python3 nas-enp-gen.py --cli

# 自定义输出路径
python3 nas-enp-gen.py --config config.json --out nas-enp-mount.py
```

## 验证是否成功

当前目录下应该出现一个写好的 `nas-enp-mount.py` 脚本（GUI 模式下同样的信息会显示在结果对话框里）。把它拷到一台测试客户端上，跑 `--selftest`：

```bash
python3 nas-enp-mount.py --selftest
```

预期输出确认内嵌配置解密成功，且不打印任何密钥内容。

## 在每台客户端部署（以 root 执行）

```bash
mkdir -p /root/nas-enp-mount
cp nas-enp-mount.py /root/nas-enp-mount/
python3 /root/nas-enp-mount/nas-enp-mount.py --selftest         # 验证配置能解密
python3 /root/nas-enp-mount/nas-enp-mount.py --oneshot          # 立即挂载
python3 /root/nas-enp-mount/nas-enp-mount.py --install-service  # 设为开机启动
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

凭据只存在于脚本内部。NAS 的 IP 或密码变更时，重新运行生成器产出新的脚本并替换旧的即可（想要干净切换可以先 `--uninstall`）。客户端上没有可编辑的配置文件，也就不存在配置不同步的问题。

## 硬件变更后怎么办（仅 `binding.mode: "machine"` 相关）

指纹是对*所有*有效硬件元件合并后算出的一个哈希（严格模式，设计如此——见
`DECISIONS.md`）。换硬盘、固件更新导致 BIOS/DMI 字段变化等硬件维护操作，
会改变已绑定机器的指纹，现有客户端会开始失败，报错如下：

```
fingerprint mismatch: this client was not generated for this machine
(or the hardware changed). Regenerate it with nas-enp-gen using this
machine's current fingerprint. Run --selftest for details.
```

这是刻意的失败关闭（fail-closed）设计，不是 bug——见 `DECISIONS.md`
「Strict mode, not fault-tolerant, for hardware changes」。恢复方法：在
发生变化的机器上重新运行 `--emit-collector`，拿到新指纹，用这个指纹重新
生成客户端。在重新生成之前，失败客户端上的 `--selftest` 会显示采集到了
哪些元件，并确认槽位查找失败。

## 配置

完整字段说明见 `config.example.json`，包括 `binding` 字段（`{"mode":
"machine", "fingerprints": [...]}` 或 `{"mode": "none"}`——必填，没有默
认值，见上方「诚实的安全说明」）。完整参考见 `DESIGN.md` → Configuration
reference。

## 许可

Apache License 2.0 —— 见 `LICENSE`。
