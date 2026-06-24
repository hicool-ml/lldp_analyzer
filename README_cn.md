# LLDP/CDP 协议分析器

离线/在线 LLDP/CDP 报文分析工具，支持厂商私有 TLV 解码。双界面：**CLI** 用于脚本化和快速检查，**GUI**（tkinter）用于交互式分析，支持捕获历史和网卡管理。

跨平台支持：**Windows**（完整测试）和 **macOS**（Apple Silicon + Intel）。

## 快速开始

### Windows
```powershell
# CLI — 在线抓包 + 邻居摘要
python lldp.py

# GUI — 交互模式
python lldp_gui.py
```

### macOS
```bash
# 先激活虚拟环境
source venv/bin/activate

# CLI — 在线抓包 + 邻居摘要（自动提权）
python lldp.py

# GUI — 交互模式（启动时自动提权）
python lldp_gui.py
```

> **macOS 14+ 注意**：GUI 启动时会自动使用系统 Python 提权以避免 TCC 限制。如果遇到 `Operation not permitted` 错误，请在系统设置 → 隐私与安全性 → 文件和文件夹中授予终端 / Python **完全磁盘访问权限**。

## CLI 用法

```bash
python lldp.py                          # 在线抓包 + 邻居摘要
python lldp.py -v                       # 详细解析输出
python lldp.py -d                       # 调试模式（偏移、原始 hex、位域）
python lldp.py -l -t                    # 原始 hex + 等待 LLDP 和 CDP 两种报文
python lldp.py <hex_file>               # 离线 hex 文件解析
```

| 参数 | 说明 |
|------|------|
| （无） | 扫描物理网卡 → 链路 down/up → 抓取 LLDP/CDP → 邻居摘要 |
| `-v` | 详细 — Type、Len、Subtype 及解码字段 |
| `-d` | 调试 — 偏移、原始 hex、TLV 头部位域 |
| `-l` | 原始日志 — payload hex 及全帧 hexdump |
| `-t` | 完整模式 — 等待 LLDP 和 CDP 都收到再停止（Cisco 设备适用） |
| `<文件>` | 解析离线 hex 文本文件 |
| `--no-renegotiate` | 跳过链路 down/up 操作 |
| `--wait-for-link` | 等待链路恢复后再开始抓包 |
| `--interface <名称>` | 指定接口名（跳过自动检测） |
| `--json-out <路径>` | 将结果输出为 JSON（供 GUI 调用） |

### CLI 提权行为

- **Windows**：在线抓包自动通过 UAC 提权；离线解析无需提权。
- **macOS/Linux**：在线抓包自动通过 `sudo` 提权。

CLI 退出：按 `q` 然后 `Enter`。

## GUI

```bash
python lldp_gui.py
python lldp_gui.py <离线文件>   # 启动时加载离线文件
```

三个标签页：

- **Capture（捕获）** — 选择以太网适配器、启动在线抓包（自动提权），或打开离线 hex 文件。显示设备身份、端口信息和语义分析（端口角色、设备类型、置信度）。
- **History（历史）** — 按时间范围、设备名称或端口角色查询历史记录。查看单条详情、原始报文 hex 和聚合统计。
- **Network（网络）** — 查看本地适配器状态（IP、网关、DNS、DHCP、链路速率、MTU）。修改 MAC 地址（需提权）、配置静态 IP 或 DHCP。

### macOS GUI 说明

1. **启动提权**：GUI 启动时自动申请管理员权限（不是在点击捕获时才弹），输入密码后以完全权限运行。
2. **捕获引擎**：GUI 复用 `lldp.py` 作为捕获引擎 — 通过提权启动 `lldp.py --json-out`，利用接口 down/up 触发交换机重发 LLDP+CDP 报文。
3. **Scapy 可用性**：捕获子进程使用系统 Python，通过 `PYTHONPATH` 指向虚拟环境的 site-packages，自动找到 scapy。
4. **自适应刷新**：捕获或网络操作后自动进行带进度点的刷新。

## 环境搭建

### Windows
```powershell
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
```

### macOS
```bash
# 使用 Homebrew Python 创建虚拟环境（不要用系统自带 Python）
python3.11 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

ChmodBPF（可选 — 允许非 root 用户抓包）：
```bash
brew install homebrew/cask/chmodbpf
```
安装后重启 Mac。不安装 ChmodBPF 时，工具会自动通过 `sudo` 提权。

### 依赖
- Python 3.10+
- `scapy` — 在线抓包
- `tkinter` — GUI（大多数 Python 发行版自带）

## 支持的协议

### LLDP（IEEE 802.1AB）

标准 TLV：Chassis ID、Port ID、TTL、Port Description、System Name、System Description、System Capabilities、Management Address。

按 OUI 分类的组织特定 TLV：

| OUI | 名称 | 覆盖范围 |
|-----|------|----------|
| `00:80:C2` | IEEE 802.1 | PVID、PPVID、VLAN Name、Protocol Identity、VID Usage Digest、Management VID、Link Aggregation、Congestion Notification、ETS、PFC、Application Priority |
| `00:12:0F` | IEEE 802.3 | MAC/PHY Config、Power via MDI、Link Aggregation、Max Frame Size、EEE |
| `00:12:BB` | LLDP-MED / 共享 | MED Capabilities、Network Policy、Location、Extended Power-via-MDI、Inventory |
| `00:12:BB` | H3C / 锐捷 / 华为 / Cisco | OUI 共享时按设备指纹分发 |
| `00:E0:FC` | 华为私有 | 厂商特定子类型 |
| `00:90:69` | Juniper 私有 | 三层解码（序列号、型号、固件版本、DCBXP 位图） |
| `00:00:0C` / `00:0C:05` | Cisco 私有 | CDP-over-LLDP TLV |

### CDP（Cisco Discovery Protocol）

支持全部 TLV 类型至 `0x001A`：Device ID、Address、Port ID、Capabilities、Software Version、Platform、Duplex、VLAN、Power、System Name、Management Address、Location。

### 示例文件

`samples/` 目录包含真实抓包文件，可用于离线测试：

```
samples/
  ruijie_S2910.txt            锐捷 S2910（LLDP）— 16 个 TLV
  H3C-S5120V2-28P-SI.txt      H3C S5120V2（LLDP）
  H3C_FINAL_453bytes.txt       H3C LLDP（精简）
  S12700E.txt                 华为 S12700E（LLDP）
  S5700-52P-LI-AC.txt         华为 S5700（LLDP）
  cisco_cdp.txt               Cisco CDP 报文
  cisco_lldp.txt              Cisco LLDP 报文
  juniper_10016.txt           Juniper MX10016（LLDP）
  juniper_qfx5110.txt         Juniper QFX5110（LLDP + DCBXP）
  ruijie.txt                  锐捷（LLDP）
```

## 架构概述

### 后端抽象层

项目使用平台特定的后端架构进行网络操作：

```
network/
  backend.py                   抽象 NetworkBackend（旧版）
  core/interfaces.py           NetworkInterface 数据类 + NetworkAdapterBackend（当前）
  backends/
    windows/adapter.py         WindowsNetworkBackend — PowerShell、注册表、cfgmgr32
    macos/adapter.py           MacOSNetworkBackend — lldp_helper.py、networksetup、ifconfig
    posix/adapter.py           PosixNetworkBackend — Linux 回退（ip/ethtool）
  elevated_op.py              特权操作助手（UAC / sudo）
  engine.py                   网络引擎
  platform.py                 平台检测和后端工厂
```

每个后端提供：
- 网卡枚举（名称、MAC、IP、网关、DNS、DHCP、速率、MTU）
- MAC 地址修改 / 恢复
- 静态 IP / DHCP 配置
- 网卡重启

### 捕获流程

```
用户点击捕获 → capture_page.py
  → subprocess（提权）→ lldp.py --json-out
  → utils/packet_capture.py :: run_online_capture()
    → _scapy_suppress() — 抑制 macOS ipconfig 错误输出
    → AsyncSniffer（BPF 内核过滤）— LLDP（0x88cc）+ CDP（01:00:0c:cc:cc:cc）
    → wait_for_link() + trigger_link_renegotiation() — 强制交换机发送新报文
    → 轮询等待 — 快速模式（首帧即止）或完整模式（等待两种协议）
  → 写入 JSON → GUI 读取并显示
```

### 决策引擎

捕获后自动进行端口语义分析：
- **端口角色**：access / trunk / hybrid / uplink
- **设备类型**：bridge / router / telephone / wlan
- **置信度**：基于 TLV 证据计算
- **用途推断**：管理 / 数据 / 语音 / 存储

## 打包

PyInstaller 单文件打包，排除开发/数据目录：

```powershell
venv\Scripts\pyinstaller.exe LLDP_CLI.spec --noconfirm
venv\Scripts\pyinstaller.exe LLDP_GUI.spec --noconfirm
```

输出：
- `dist\LLDP_CLI.exe`（约 12 MB）— CLI 版本
- `dist\LLDP_GUI.exe`（约 12 MB）— GUI 版本

## 国际化（i18n）

GUI 支持 7 种语言，自动检测系统语言：

| 语言 | 代码 |
|------|------|
| English | `en` |
| 中文 | `zh` |
| Français | `fr` |
| Español | `es` |
| Русский | `ru` |
| 日本語 | `ja` |
| 한국어 | `ko` |

从右上角下拉菜单选择，或使用命令行参数：

```bash
python lldp_gui.py --lang zh
```

## 已知问题与限制

### macOS

1. **内置网卡 MAC 修改**：Apple Silicon Mac（M1/M2/M3/M4）的板载以太网卡（`en0`）不支持修改 MAC 地址。工具会检测到失败并报告。**解决方案**：使用 USB 以太网卡 — 这些设备通常支持 MAC 修改。

2. **macOS 14+ TCC 限制**：由于内核级别的来源强制（provenance enforcement），`sudo` 可能无法读取 `~/Desktop/` 目录下的文件。**解决方法**：在系统设置中为终端/Python 授予完全磁盘访问权限，或将项目移到 `/Applications/` 或 `~/Documents/` 下。

3. **DHCP 服务器检测**：用于检测 DHCP 服务器的 `ipconfig getpacket` 命令在接口没有活跃 DHCP 租约时会返回 "not found"。工具会回退到 `networksetup -getinfo`。

4. **网卡命名**：macOS 将物理以太网接口命名为 `en0`、`en1` 等。扫描器会自动过滤虚拟接口（utun、awdl、llw、bridge 等）。

### Windows

- MAC 修改需要管理员权限（自动通过 UAC 提权）。
- DHCP 配置使用 netsh 命令。

## 项目结构

```
lldp.py                    CLI 入口 — 在线抓包、离线解析、提权
lldp_gui.py                GUI 入口 — tkinter 应用、macOS 启动提权
lldp_helper.py             macOS 特权助手 — networksetup、tcpdump、ifconfig
vendor_dispatcher.py       OUI/指纹分发，处理 LLDP TLV 127

decoders/
  cisco_decoder.py         Cisco OUI 00:00:0C / 00:0C:05 私有 TLV
  h3c_decoder.py           H3C / Comware OUI 00:12:BB 私有 TLV
  huawei_decoder.py        华为 OUI 00:E0:FC 私有 TLV
  juniper_decoder.py       Juniper OUI 00:90:69 私有 TLV（三层架构）
  ruijie_decoder.py        锐捷 OUI 00:12:BB 私有 TLV

engine/
  api.py                   引擎 API 层
  decision_engine.py       从解析结果接入推断规则
  port_profile.py          端口语义推断（角色、设备类型、置信度）

network/
  core/interfaces.py       NetworkInterface 数据类 + NetworkAdapterBackend
  backends/
    windows/adapter.py     基于 PowerShell 的 Windows 网卡后端
    macos/adapter.py       macOS 网卡后端（lldp_helper）
    posix/adapter.py       POSIX（Linux）网卡后端
    platform.py            平台检测和后端工厂
  elevated_op.py           特权操作助手
  engine.py                网络引擎核心

ui/
  main_window.py           Notebook 布局
  capture_page.py          在线抓包 + 离线文件解析 + 显示
  history_page.py          SQLite 历史记录浏览器
  network_page.py          本地网卡信息、MAC 修改、IP 配置
  widgets.py               InfoCard 可复用组件
  styles.py                亮色/暗色主题

db/
  database.py              SQLite 抓包历史（自动迁移）

i18n/
  config.py                语言配置持久化
  translations.py          翻译管理器
  locales/                 7 种语言 JSON 文件

utils/
  adapter_scanner.py       统一网卡枚举
  capture_engine.py        持久化捕获引擎
  elevator.py              统一提权：run_elevated() + is_admin()
  hexdump.py               纯字节展示
  interface_finder.py      物理网卡发现 + 链路重协商
  link_monitor.py          链路状态监控
  packet_capture.py        Scapy 抓包、去重、邻居摘要
  platform_utils.py        平台检测、主题、资源路径
  protocol_parser.py       LLDP/CDP 解析器与格式化

samples/                   10 个真实抓包文件，供离线测试
```
