# nas-enp-mount — 设计

[English](DESIGN.md) | **简体中文**

> 译自 `DESIGN.md`（v0.1.3）。如有冲突，以英文版为准。

> 本文档的成败标准：另一个人拿着它，在另一台设备上能把项目重建出来。写的时候假设读者看不到你的机器。

## 目标与非目标

**目标**
- 让 Linux 客户端能在开机时自动挂载 NAS（CIFS/NFS）共享，且客户端磁盘上不留明文凭据文件。
- 让凭据轮换变成一步操作：重新生成脚本，重新部署。
- 故障安全：NAS 不可达时绝不能拖垮或卡住客户端的开机流程。

**非目标**
- 对**已绑定**客户端上拥有 root 权限的攻击者做到真正的保密——这在结构上就做不到，因为那台机器本身必须能恢复凭据才能挂载共享。见 README 的「诚实的安全说明」。这是一个两层的说法：文件离开它被生成时绑定的那台（那批）机器后在计算上毫无用处，但在已绑定的机器上，root 依然能恢复一切。
- 跨平台客户端（Windows/macOS）——仅支持 Debian/Ubuntu Linux。
- 通用的密钥管理或配置分发系统。
- TPM 支持的密钥存储（记为未来可能的增强项，本次未实现）。

## 架构

```
config.json（真实密钥，绝不提交）
        |
        v
nas-enp-gen.py                      nas-enp-gen.py --config config.json
  （不带参数 -> PySide6 GUI 表单）      （无界面/脚本化，或 --cli 走
        |                              终端提示）
        |  1. 校验配置，含 binding.mode（"machine" | "none"）
        |  2a. binding.mode = "none"：
        |        AES-256-GCM 加密 JSON 内容，拆分/异或混淆密钥
        |        （旧方案，自 v0.1.0 起未变）
        |  2b. binding.mode = "machine"：
        |        随机 DEK 一次性加密 JSON 内容（AES-256-GCM）；
        |        DEK 针对每台目标机器的指纹，经 Scrypt 派生的 KEK
        |        分别包裹一次 + AES-256-GCM——见「Envelope format」
        |  3. 把选定的密文块填入 Python 客户端模板
        |  4. 把填好的模板写入磁盘——无需构建/编译步骤
        |  5. 自检：对写出的文件做 grep，检查是否泄漏
        |     host/username/password 的明文或 base64 形式；
        |     命中则中止并删除输出文件
        v
nas-enp-mount.py（纯 Python 脚本，内嵌密文 + 密钥材料）
        |
        |  拷贝到每台客户端，以 root 运行（python3 nas-enp-mount.py ...）
        |  binding.mode = "machine"：客户端在运行时重新采集自己的
        |  硬件指纹，必须匹配某个槽位才能解密
        v
客户端脚本
        |  --selftest         在内存中解密、校验，不打印任何敏感内容
        |  --oneshot           挂载每个配置的共享（幂等，自带重试）
        |  --install-service   写入 systemd 单元、启用、启动
        v
客户端上已挂载的 CIFS/NFS 共享
```

`nas-enp-gen.py --emit-collector` 会产出第三个独立产物：一个零依赖的指纹
采集脚本，操作者在生成之前把它拷贝到每台*目标*机器上运行（解决鸡生蛋
问题——见下方「Envelope format」），从而拿到填入 `binding.fingerprints`
的十六进制指纹。

生成器本身也打包为可安装的 `.deb`（Linux）和 `.exe`（Windows）桌面应
用——见下方「Packaging & CI」——供更愿意点表单而不是敲 CLI 命令的人使
用。部署到客户端的挂载脚本从不这样打包；它始终是由 systemd 驱动的纯脚
本，没有 GUI。

## 技术栈

| 层 | 选型 | 版本 | 理由 |
|---|---|---|---|
| 生成器 | Python | 3.8+（在 3.10 上测试过） | 编写「加密+填模板」这一步；`cryptography` 提供经审计的 AES-GCM |
| 生成器加密库 | `cryptography`（pyca） | 3.4.8 | 经审计，Python 里做 AES-256-GCM 的标准选择 |
| 生成器 GUI | PySide6（Qt for Python） | latest | LGPLv3——与保持宽松（Apache-2.0）许可证兼容，不像 GPL/商业版 PyQt 那样。见 `DECISIONS.md` 2026-08-16。 |
| 生成器打包 | PyInstaller + `dpkg-deb`（Linux）、PyInstaller（Windows，经 CI） | latest | 打包成单文件可执行程序，再包装成安装程序；Windows 构建跑在 GitHub Actions `windows-latest` 上，因为本项目没有本地 Windows 环境 |
| 客户端 | Python | 3.8+ | 所有部署目标都保证有 Python 环境（用户已确认）；彻底去掉了对 Go 工具链的依赖。见 `DECISIONS.md` 2026-08-16。 |
| 客户端加密库 | `cryptography`（pyca） | 与生成器相同 | 双方用同一个库、同一套 AES-256-GCM 方案——只需追踪一个依赖，而不是两套工具链 |
| 机器绑定 KDF | `cryptography.hazmat...kdf.scrypt.Scrypt` | 与生成器相同 | `cryptography` 已内置——它是本项目唯一的运行时依赖；选它而不是 Argon2id，专门是为了不新增 `argon2-cffi`、也不抬高 `cryptography` 的版本下限。见 `DECISIONS.md` 2026-08-16「KDF: Scrypt over Argon2id」。 |

被否决的方案和理由见 `DECISIONS.md`。

## Envelope format（`binding.mode = "machine"`）

威胁模型：一个泄露出去的客户端脚本（传错群、随备份外泄、随报废设备
流出、误提交到公开仓库）对拿到它的任何人都必须在计算上毫无用处，除非
对方同时拥有其中一台被绑定的机器。这**不能**防御已经拿到某台已绑定机
器 root 权限的攻击者——见「非目标」。

**核心原则：** 机器的身份是密钥派生材料，不是用来做比对的存储值。文件
里没有任何东西能让人不付出完整 Scrypt 代价就验证一个猜测，而且指纹本
身从不写入磁盘任何地方。

```
生成时（操作者的工作站）
  指纹（预先在每台目标机器上采集，见 --emit-collector）
        |
        +-- selector = SHA256(fingerprint || "nas-enp/selector/v2")[:8 字节]
        |
        +-- KEK = Scrypt(password=fingerprint, salt=random16, n=2^15, r=8, p=1, dklen=32)
                    |
  DEK（随机 32 字节）-+-> wrapped_dek = AES-256-GCM(KEK, DEK, aad="nas-enp/slot/v2")
        |
        +-> payload = AES-256-GCM(DEK, json(nas_config), aad="nas-enp/payload/v2")

文件里只写入：selector、salt、nonce、wrapped_dek（每槽位一份）+ payload
（没有 KEK，没有 DEK，没有指纹本身）

运行时（客户端）
  重新采集指纹 -> selector -> 查找槽位 -> Scrypt -> KEK
  -> 解开 DEK -> 解密 payload -> 挂载
```

所有槽位共享同一个随机 DEK（多接收者信封），因此一个生成的文件可以面
向整批机器；每个槽位只通过自己那台机器 Scrypt 派生的 KEK 来证明「属于
这批机器」。不在指纹名单里的机器没有任何路径够到任何 KEK，连尝试解密
payload 都做不到。

**线上格式**（客户端脚本中 base64 编码的 JSON）：

```json
{
  "v": 2,
  "kdf": {"algo": "scrypt", "n": 32768, "r": 8, "p": 1, "dklen": 32},
  "slots": [
    {"selector": "<16 hex>", "salt": "<b64, 16B>", "nonce": "<b64, 12B>", "wrapped_dek": "<b64>"}
  ],
  "payload": {"nonce": "<b64, 12B>", "ct": "<b64>"}
}
```

- 每个槽位都有自己独立的随机 salt——salt 绝不共用。
- AAD 字符串（`"nas-enp/slot/v2"`、`"nas-enp/payload/v2"`）是固定的，把
  两处 AES-GCM 用途做了域分离，槽位密文不能被重放成 payload 密文，反之
  亦然。
- 槽位不携带任何可识别的元数据（没有主机名、没有备注、没有 IP），且在
  生成时被打乱顺序——位置不泄漏任何信息。
- `n=2^15` 在这类硬件上大约耗费 32MB 内存、每次尝试约 0.1 秒，即便是
  100 个槽位、走下方 `selector` 快速路径，也远在客户端
  `TimeoutStartSec=150` 的 systemd 预算之内。

**`selector`** 让客户端能直接跳到自己的槽位，而不必对全部 N 个槽位逐一
尝试 Scrypt（N=100 时最坏情况约 10 秒）。代价是：让一个*已经猜中正确指
纹*的攻击者能不付出 Scrypt 代价就验证这个猜测。这一点被接受，**仅仅**
是因为熵闸门（下方）保证了主要指纹元件 `product_uuid` 携带约 128 bit
的熵——不管有没有 selector 这条捷径，暴力破解出正确猜测始终不可行。**
这两者是绑定的：** 如果将来拿掉熵闸门却不同时拿掉 `selector`（改回逐槽
位尝试），就会在指纹变得可猜测之后，悄悄重新打开这条捷径。见
`DECISIONS.md`。

`binding.mode = "none"` 原样保留最初的异或拆分方案（随机密钥拆成两半，
和密文一起存放）——没有 Scrypt、没有指纹、没有外泄保护。它是为了那些
无法预先采集指纹的目标而存在的。客户端模板里同时含有两条代码路径；生
成时写死的 `CONFIG_MODE` 常量决定走哪一条——具体在源码里的位置见「Data
model / file layout」。

### 指纹采集

以 root 身份，按以下优先顺序，从*目标*机器读取：

| 顺序 | 来源 | 说明 |
|---|---|---|
| 1（必须） | `/sys/class/dmi/id/product_uuid` | 主锚点，约 128 bit 熵，仅 root 可读 |
| 2 | `/sys/class/dmi/id/board_serial` | |
| 3 | `/sys/class/dmi/id/product_serial` | |
| 4 | `/sys/block/<根盘>/device/serial` | `/` 所在的块设备，经 `/proc/mounts` 反查 |

明确排除：MAC 地址（实际熵约 24 bit，且极易伪造）和 `/etc/machine-id`
（只是个文件——会跟着复制的脚本一起走，单独用它等于没绑定）。

占位值（`""`、`"None"`、`"0"`、`"Default string"`、`"To be filled by
O.E.M."`、`"Not Specified"`、`"Not Applicable"`、`"System Serial
Number"`、`"Unknown"`、`"INVALID"`、全零 UUID——比较时忽略大小写并去除
首尾空白）会被丢弃，不参与哈希。

**熵闸门（硬性要求）：** 如果 `product_uuid` 缺失或是占位值，采集立即
失败——绝不会悄悄退化成用可选字段的低熵组合。这种悄悄降级会一直不被
察觉，直到有人恰好去查——对一个安全控制来说，这是最危险的失败方式。

有效元件按 `key=value` 的形式拼接成行，按 key 排序，UTF-8 编码后做
SHA-256，得到一个 64 位十六进制指纹。采集逻辑只写了一份
（`nas-enp-gen.py` 里的 `FINGERPRINT_LOGIC_SRC`），在生成时原样拼接进
`--emit-collector` 的输出和客户端模板——见「Data model / file layout」。

## Packaging & CI

- `packaging/nas-enp-gen.spec` —— 生成器 GUI/CLI 单文件可执行程序的 PyInstaller spec。
- `packaging/build-deb.sh` —— 运行 PyInstaller，组装 `DEBIAN/control` 目录树，调用 `dpkg-deb --build` 产出 `nas-enp-gen_<version>_amd64.deb`。在本 Linux 主机上可运行、可测试。
- `.github/workflows/release-installers.yml` —— 在推送 `v*.*.*` tag 时触发。在 `ubuntu-latest` 上构建 `.deb`，在 `windows-latest` 上构建 `.exe`，两者都作为 GitHub Release 附件上传。`.exe` 构建仅能在 CI 上完成——在本（Linux）开发主机上无法产出或验证。

## 复现要求

**本文档最重要的一节。另一台机器需要的一切都在这里。**

### 环境

- 操作系统（生成器所在机器）：任意装有 Python 3.8+ 的系统——Linux、Windows 或 macOS。GUI 模式需要显示器；`--config`/`--cli` 模式不需要。
- 操作系统（客户端机器）：Debian/Ubuntu Linux，需要 root 权限，Python 3.8+
- 运行时 + 版本：Python 3.8+，`cryptography` 包（生成器和客户端都需要；两边缺失时都会经 `pip` 自动安装）
- 可选（仅开发/CI 需要，运行本项目不需要）：本地构建 `.deb` 安装程序需要 PyInstaller + `dpkg-deb`；GitHub Actions `windows-latest` runner 构建 `.exe`
- 依赖恢复命令：`pip install -r requirements.txt`

### 外部依赖

| 项目 | 来源 | 存放位置 |
|---|---|---|
| NAS 凭据（host/用户名/密码） | 你的 NAS 管理面板 | `config.json`（已加入 .gitignore，绝不提交） |
| `cifs-utils`（客户端，可选） | 客户端的包管理器 | `install_deps: true` 时由客户端脚本自动安装 |
| `cryptography`（客户端） | PyPI | 客户端首次运行时若缺失，经 `pip` 自动安装 |

任何会被提交的内容里一律用占位符，绝不用真实值——参见 `config.example.json`。

### 路径与挂载点

以下路径全部*由用户自己的 `config.json` 提供*，脚本里没有硬编码：

| 路径 | 由谁提供 | 用途 |
|---|---|---|
| `mounts[].remote` | 用户，写在配置里 | NAS 上要挂载的路径 |
| `mounts[].local` | 用户，写在配置里 | 客户端上的挂载点 |
| `--out` | 命令行参数，默认 `nas-enp-mount.py` | 生成器写出填好的客户端脚本的位置 |

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
| `default_options` | 未单独覆盖时，应用到每个共享的挂载选项 | CIFS：`vers=3.0,iocharset=utf8,uid=0,gid=0,file_mode=0644,dir_mode=0755,hard,actimeo=30` · NFS：`vers=4,soft,timeo=50,retrans=3` | 是 |
| `mounts` | `{remote, local, options}` 数组 | — | 是，至少一项 |
| `retry_attempts` | 客户端挂载重试次数 | — | 是 |
| `retry_delay_sec` | 重试间隔秒数 | — | 是 |
| `install_deps` | 缺少时允许客户端 `apt install cifs-utils` | — | 是 |
| `binding.mode` | `"machine"` 或 `"none"`——见「Envelope format」 | — | 是，无默认值 |
| `binding.fingerprints` | 64 位十六进制指纹数组（来自 `--emit-collector`），每台目标机器一个 | `[]` | `mode: "machine"` 时必填，且不能为空 |

`binding` 没有默认值——配置里缺失该字段会被拒绝，并报错说明两个选项分
别是什么，`--config`/`--cli` 路径和 GUI 路径都一样。这是刻意的：无论
悄悄默认成哪一种（自动绑定，或悄悄退回不设防），都是代替用户做出了一
个有安全含义的选择，而且是让人意外的那种。

**为什么 CIFS 默认值明确设了 `hard,actimeo=30`（v0.1.3 新增）：** 不设
这两项并不等于"没有倾向"——内核 `cifs.ko` 在挂载选项没写明时，会悄悄
套用 `soft` 和 `actimeo=1`（见 `man mount.cifs`），而这个组合正是一次
真实故障的元凶：在一个 soft 挂载的共享上，`git` 高频元数据操作期间，
服务端一次瞬时的 lease-break 应答延迟，让 `.git/index` 上的一次
`rename()` 永久性返回 `EACCES`，而不是被内核重试，这个文件就一直卡死
直到挂载被刷新。`hard` 让瞬时抖动变成阻塞重试而不是直接报错；
`actimeo=30` 则在高频 git 操作期间减少对服务端属性状态的轮询次数。完
整故障复盘与被否决的备选方案见 `DECISIONS.md` 2026-08-17「Default
CIFS mount options」条目。

生成器自身的命令行参数：`--config`（无界面/脚本化）、`--cli`（强制走
老的终端提示流程而不是 GUI）、`--out`、`--save-config`（把收集到的配
置写回文件——包含明文密码，注意保管）、`--emit-collector [--out
PATH]`（为目标机器写出一个独立、无依赖的指纹采集脚本；默认文件名
`nas-enp-fingerprint.py`）。不带任何参数会启动 PySide6 GUI。`--arch`
和 `--no-build` 已移除——现在已经没有构建/编译步骤了。

## 从零搭建

1. 在生成器所在机器上：`pip install -r requirements.txt` —— 验证：`python3 -c "import cryptography, PySide6"` 无报错。
2. 把 `config.example.json` 复制为 `config.json`，填入真实 NAS 信息 —— 验证：`python3 -m json.tool config.json` 能正常解析。
3. 运行 `python3 nas-enp-gen.py --config config.json`（或不带参数启动 GUI 并填写表单）—— 验证：当前目录出现 `nas-enp-mount.py` 脚本。
4. 把脚本拷到一台测试客户端，运行 `python3 nas-enp-mount.py --selftest` —— 验证：报告配置解密成功（客户端若缺 `cryptography` 会自动安装）。
5. 在客户端跑 `--oneshot` —— 验证：`mount | grep <local路径>` 能看到共享已挂载。
6. 跑 `--install-service` —— 验证：`systemctl is-enabled nas-enp-mount.service` 显示 `enabled`。

本项目不用 Docker 部署——无需参照 docker 相关 Skill。

## 数据模型 / 文件布局

```
repo/
├── nas-enp-gen.py           # 生成器——GUI/CLI，读取 config.json，驱动整条流水线
├── config.example.json      # 配置文件的占位版本（可以安全提交）
├── requirements.txt         # 生成器 + 客户端 Python 依赖的锁定版本
├── packaging/
│   ├── nas-enp-gen.spec     # 生成器可执行程序的 PyInstaller spec
│   └── build-deb.sh         # 本地 .deb 构建（control 文件 + dpkg-deb）
├── .github/workflows/
│   └── release-installers.yml  # CI：推送 tag 时构建 .deb（ubuntu-latest）+ .exe（windows-latest）
└── （config.json、nas-enp-mount.py、dist/ —— 生成器/构建产物，均已 gitignore）
```

Python 客户端源码以 base64 形式嵌在 `nas-enp-gen.py` 内部
（`PY_CLIENT_TEMPLATE_B64`），这样生成器就是单文件、自包含的。不需要
`--no-build` 那样的检查手段——写入 `--out` 的填好的脚本*本身就是*真正
的源码，明文、可以直接阅读。

`FINGERPRINT_LOGIC_SRC`（纯文本，非 base64）保存着指纹采集函数唯一的
权威版本。它原样拼接进解码后的客户端模板（替换掉
`# __FINGERPRINT_LOGIC__` 标记）和 `--emit-collector` 的输出里，因此这
两处读取硬件标识符的代码永远不会跑偏——为什么手动复制第二份会是一个
潜伏的、可能让整批客户端一起失效的隐患，见 `DECISIONS.md`。

## 已知限制与坑

- `config.example.json` 曾经以「example」为名保存过**真实的生产凭据**——现已修正（只保留占位符，见 `DECISIONS.md` 2026-08-16 条目）。真实值现存放在已 gitignore 的 `config.json` 中，本机实际使用的工作配置保存在 `../nas.local.json`（项目根目录，`repo/` 之外，绝不提交）。
- 安全性是混淆，不是能真正挡住客户端 root 攻击者的加密——见 README。把客户端从编译好的二进制换成明文可读的 `.py` 脚本（2026-08-16）让随手查看比以前略微容易一点；这一点从来没有被当作真正的保密手段依赖过。
- `tests/test_binding.py`（`v0.1.0` 新增）直接覆盖了信封加密和指纹占位符逻辑（单元级别，不需要真实硬件）。生成器的非加密部分（GUI、打包）仍然没有自动化测试。
- 硬件变更（更换硬盘、BIOS/DMI 字段变化）会按设计让已绑定的客户端失效——见 README「硬件变更后怎么办」。这是刻意的严格模式取舍，不是 bug——见 `DECISIONS.md`。
- `.exe` 安装程序完全由 GitHub Actions CI（`windows-latest`）构建——本项目没有 Windows 开发环境，因此这条构建路径要等真正推送 tag 才能得到验证。
- GUI 的交互行为（控件布局、表单校验反馈）目前只在无头模式下做过冒烟测试（`QT_QPA_PLATFORM=offscreen`）——尚未在真实显示器上做过视觉验证。
- **引导循环——绝不要把配置（或生成出来的客户端）的唯一一份副本，放在这个工具自己负责挂载的共享上。** 这么放会让恢复陷入死锁：共享一旦被卸载，重新挂载所需的配置就读不到了；如果已部署的客户端（里面以加密形式带着凭据）也只存在那里，那么两条退路会同时消失。2026-08-17 在本项目自己的宿主机上实际发生过：`../nas.local.json` 就放在它自己挂载的那个 CIFS 共享上，于是为了清掉一个无关的、卡在服务器端的锁而卸载该共享之后，这台机器就再也挂不回去了。恢复过程只能是：从 GitHub 重新 clone 本仓库、在目标机器上重新跑 `--emit-collector` 取回指纹、然后从头重新生成客户端。**请把已部署的客户端放在任何挂载点之外的本地磁盘上**（`--install-service` 本身就是这么做的，会安装到 `/root/nas-enp-mount/`），并且把配置也另存一份在不依赖挂载成功的位置。

## 如何扩展

- 支持 Debian/Ubuntu 以外的新客户端平台：Python 客户端模板需要针对特定操作系统的挂载逻辑（当前实现是 shell 出去调用 `mount.cifs`/`mount -t nfs`，两者都是 Linux 专属的）；Windows/macOS 客户端目前是明确的非目标。
- 支持 CIFS/NFS 以外的新挂载协议：需要同时扩展 Python 客户端模板和 `nas-enp-gen.py` 里的 `validate()` 的配置 schema 和校验逻辑——两边必须保持同步，因为它们之间没有共享的 schema。
- 为打包的安装程序支持新的生成器平台（例如 macOS `.dmg`）：在 GitHub Actions 上新增第三个跑在 `macos-latest` 的 job，沿用和 `.exe` job 相同的 PyInstaller 模式。
