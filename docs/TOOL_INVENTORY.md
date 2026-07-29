# Svetovid — Tool Inventory

> Auto-generated from `../agentic-dfir/agentic-dfir/results/*.json`.
> Re-run `python3 scripts/generate_tool_inventory.py` to refresh.

Every tool Svetovid depends on to fulfill its 22 investigation goals.
Commercial tools (X-Ways / EnCase / Magnet / Cellebrite) are listed with
their open-source replacement strategy — we don't bundle proprietary software.

## Summary

| ID | Tool | License (short) | build_vs_buy | Svetovid image | Goals |
|----|------|-----------------|--------------|----------------|-------|
| `A2` | MITRE ATT&CK / D3FEND / CAPEC mapping | ? | n/a | `baked into svetovid/base` | G01, G02, G07, G22 |
| `C11` | Acquisition & imaging tools | GPLv3 | wrap | `docker image: svetovid/imaging` | G20 |
| `C11a` | Autopsy + The Sleuth Kit | GPLv2 | wrap | `docker image: svetovid/eztools` | G01, G03, G09, G20 |
| `C11b` | X-Ways Forensics | proprietary | build | `NONE — proprietary, per-seat` | G03 |
| `C11c` | OpenText EnCase Forensic | proprietary | build | `NONE — proprietary, per-seat` | G03, G09 |
| `C11d` | Magnet AXIOM / Magnet AXIOM Cyber | proprietary | build | `NONE — proprietary, per-seat` | G03, G09, G10, G11 |
| `C11e` | Cellebrite UFED / Physical Analyzer / In | proprietary | hybrid | `NONE — proprietary, per-seat` | G10, G11 |
| `C11f` | Bulk Extractor | MIT | wrap | `docker image: svetovid/carving` | G03 |
| `C11g` | Scalpel | Apache-2 | wrap | `docker image: svetovid/carving` | G03 |
| `C12` | Windows triage tools | MIT | wrap | `docker image: svetovid/eztools` | G01, G02, G04, G05, G08, G12, G19 |
| `C12a` | iLEAPP | MIT | wrap | `docker image: svetovid/mobile` | G05, G10 |
| `C12b` | ALEAPP | MIT | wrap | `docker image: svetovid/mobile` | G11 |
| `C13` | Memory analysis tools | VSL | wrap | `docker image: svetovid/volatility` | G02, G06, G08 |
| `C13a` | WinPmem | Apache-2 | wrap | `prebuilt binary + docker image: svet` | G06, G20 |
| `C13b` | AVML | MIT | wrap | `static musl binary` | G06, G20 |
| `C13c` | OSXpmem | Apache-2 | build | `legacy binary` | G06, G20 |
| `C14` | Network analysis tools | GPLv2 | wrap | `docker image: svetovid/network` | G07, G08 |
| `C15` | Malware analysis tools | Apache-2 | wrap | `docker image: svetovid/malware` | G02, G07, G08, G18 |
| `C16` | Timeline & correlation tools | Apache-2 | wrap | `docker image: svetovid/timeline` | G01, G04, G05, G08, G12, G22 |
| `C17` | Open-source forensic parsing libraries | LGPL | wrap | `pip install into backend venv` | G01, G03, G22 |
| `C17a` | omerbenamram/evtx | MIT | wrap | `cargo add evtx` | G01, G07 |
| `C17b` | Chainsaw | GPL-3 | wrap | `docker image: svetovid/eztools` | G01, G02, G08 |
| `C17c` | Dissect | AGPL | wrap | `pip install dissect into backend ven` | G04, G05, G19, G21, G22 |
| `C18` | Turbinia | Apache-2 | wrap | `docker-compose stack` | G21 |

## Detailed entries

### `A2` — MITRE ATT&CK / D3FEND / CAPEC mapping

_将 DFIR 取证发现与检测结果映射到对手 TTP（MITRE ATT&CK）与防御技术（MITRE D3FEND）及攻击模式（CAPEC）的一组本体/分类法体系。它把原始证据（EVTX 命中、Sigma 告警、内存/网络工件）转化为带语义的对手行为叙述，是 agent 进行跨证据关联、攻击链重建与报告推理的核心知识本体。_

- **License**: [不适用]
- **Interface**: [不适用]
- **build_vs_buy**: n/a（纯本体/数据集，非工具）…
- **Svetovid install**: `baked into svetovid/base (STIX bundle)`
- **Svetovid invokes**: read-only MCP server (mitre_attack tool)
- **Invoked by goals**: G01, G02, G07, G22

### `C11` — Acquisition & imaging tools

_数字取证采集/镜像（acquisition & imaging）工具族：覆盖 Preservation/Collection 阶段将原始证据（物理磁盘、分区、内存、移动设备、云）以可验证、可法庭采信的形式固化的全部工具。包括物理/逻辑写阻断器（Tableau T8u、CRU WiebeTech WriteBloX/Ultradock）——硬件层保证只读；类 Unix 原生 dd（GNU coreutils，无内置 hash）；dc3dd（DoD DC3 对 dd 的取证 fork，内置 hash-on-the-fly/split/verify，GPLv2）；ewfacquire（libewf 套件，Joachim Metz，生成 E01/EnCase7-v2/L1EWF，LGPLv3+）；FTK Imager CLI（Exterro，免费，ftkimager source dest --e01，Windows 为主）；Tableau TX1（OpenText/表彩，取代 T3567cu，内置 imaging + CLI/timing schedule）；Guymager（Linux GUI，基于 libewf/dc3dd，开源，输出 dd/E01/AFF）；Magnet AXIOM Process CLI（Magnet AXIOM 的采集组件，-case/-evidence/-wi 参数）。全部工具的取证基线：输出 raw(dd)/E01/AFF4 格式、MD5+SHA1+SHA256 哈希、可配置 chunk/segment size、分卷（split）、采集元数据（操作员/时间/设备/序列号）写入证据头。_

- **License**: dd: GPLv3（GNU coreutils）…
- **Interface**: 混合，按子工具分：(1) dd/dc3dd/ewfacquire/FTK Imager CLI/AXIOM Process CLI — 纯 CLI，headless 100%…
- **build_vs_buy**: wrap — 全部开源 CLI 工具（dd/dc3dd/ewfacquire/Guymager-底层-lib）均直接可 wrap，无需重建；FTK Imager CLI（免费）/AXIOM Process CLI（商业）/TX1（商业）亦 wrap 客户既有安装（subprocess + log 解析 + 状态查询）…
- **Svetovid install**: `docker image: svetovid/imaging (dd, dc3dd, ewfacquire)`
- **Svetovid invokes**: raw_cli (subprocess)
- **Invoked by goals**: G20

> **Replacement strategy**: Svetovid uses the open-source stack
> (TSK + Volatility 3 + iLEAPP/ALEAPP + Dissect + Chainsaw) by default.
> Wrapping a customer's already-licensed commercial install is opt-in config.

### `C11a` — Autopsy + The Sleuth Kit (TSK)

_Open-source 数字取证平台。Autopsy 是基于 TSK 的图形化/可脚本化取证平台（Java/NetBeans 平台 + Python/Jython ingest/report module API），TSK 是底层库 + 命令行工具集合（fls/icat/mmls/fsstat/ils/hfind/sorter/mactime 等），二者通常一起评估。Autopsy 自 v4.13.0 起具备 Command Line Ingest（CreateCase + AddDataSource + RunIngest + GenerateReports），自 v4.22+ 内置 MCP-over-STDIO 服务端，是 agentic-DFIR 中‘wrap’评分最高的候选之一（4/5）。_

- **License**: Autopsy: GPLv2（来源 sleuthkit.org/autopsy/licenses.php；4.x 当前版本下 Apache-2 也曾用于部分发行，含若干不同 license 的依赖库，详见包内 licenses 清单）…
- **Interface**: Autopsy: hybrid（GUI on Java/NetBeans + Swing，但有 Command Line Ingest headless 入口 + 内置 MCP-over-STDIO 服务端 + Python/Jython ingest & report module API）…
- **build_vs_buy**: wrap — Autopsy 已具备 headless CLI（Command Line Ingest，4.13.0+）、完整 Python/Jython ingest & report module API、以及内置 MCP-over-STDIO server（4.22+）…
- **Svetovid install**: `docker image: svetovid/eztools`
- **Svetovid invokes**: TSK: raw_cli; Autopsy: MCP-over-STDIO (4.22+)
- **Invoked by goals**: G01, G03, G09, G20

### `C11b` — X-Ways Forensics

_Commercial, Windows-only, GUI-centric computer forensics workstation (current v21.8, by X-Ways Software Technology AG, Germany) for disk imaging, file-system analysis, file carving, hash-set matching, timeline/event-list generation, registry/event-log viewing and case reporting. It ships an X-Tensions API (compiled DLLs in C/C++/Delphi/Pascal, with community C#, Rust and Python bindings) but the API can only be invoked from inside the running GUI via the 'Tools | Run X-Tensions...' menu, the volume-snapshot refinement step, the simultaneous-search hook or context menus — there is no native headless CLI, no REST/gRPC API and no structured/JSON output, which makes it a textbook 'build-replacement' target for an agent._

- **License**: Proprietary commercial…
- **Interface**: GUI (primary)…
- **build_vs_buy**: build_replacement — and this is the canonical example of the build-vs-buy decision in this catalog…
- **Svetovid install**: `NONE — proprietary, per-seat`
- **Svetovid invokes**: build_replacement → svetovid/eztools stack
- **Invoked by goals**: G03

> **Replacement strategy**: Svetovid uses the open-source stack
> (TSK + Volatility 3 + iLEAPP/ALEAPP + Dissect + Chainsaw) by default.
> Wrapping a customer's already-licensed commercial install is opt-in config.

### `C11c` — OpenText EnCase Forensic (OpenText Forensic)

_商业旗舰级数字取证分析软件，OpenText（收购 Guidance Software 后）出品，2024 年起品牌统一更名为 OpenText Forensic（EnCase Forensic 是同一产品）。当前版本 CE 25.x（CE 25.1，2025）主打 artifacts-first 工作流——先抓关键工件再扩展——并宣称比竞品快 75% 的处理速度，支持 36,000+ 设备/云源 profile（含 Windows/macOS/Linux/移动/iCloud/M365/Facebook 等）。核心能力：E01/L01 证据格式采集与解析、案件管理、文件系统解析、EnScript（类 Java/C++ 专有语言）脚本生态、Conditions/Filters/GREP 复杂证据筛选、文件签名库、哈希集分析、Volume Shadow Copy 分析、BitLocker/FileVault 加密卷获取。取证全流程在 GUI 内完成；脚本（EnScript）须在加载 evidence 后于 EnCase 内置 EnScript IDE 中编译、通过 EnCase 进程执行，无独立 headless CLI，无官方 REST API，无原生 JSON 输出——这是 agent 化集成的根本障碍。_

- **License**: 专有商业（proprietary commercial）…
- **Interface**: GUI（绝对主导）。EnCase Forensic 是一个 Windows 桌面 GUI 应用（WPF/WinForms），全部调查工作流（加载 evidence、应用 Conditions、运行 EnScript、生成报告）都在 GUI 内完成。EnScript（专有脚本语言，类 Java/C++）虽然可由 `EnCase.exe` 进程在启动时通过命令行参数触发（`SystemClass::GetArgs()` 可读取命令行参数），但脚本本身必须在 EnCase GUI …
- **build_vs_buy**: hybrid（核心解析 build_replacement；客户既有安装 heavy wrap），与 C11b X-Ways 理由相同…
- **Svetovid install**: `NONE — proprietary, per-seat`
- **Svetovid invokes**: build_replacement → svetovid/eztools stack
- **Invoked by goals**: G03, G09

> **Replacement strategy**: Svetovid uses the open-source stack
> (TSK + Volatility 3 + iLEAPP/ALEAPP + Dissect + Chainsaw) by default.
> Wrapping a customer's already-licensed commercial install is opt-in config.

### `C11d` — Magnet AXIOM / Magnet AXIOM Cyber

_Magnet Forensics 的旗舰商业数字取证分析平台，将计算机、移动（与 GrayKey/Verakey 采集链路）、云、车辆四类证据源汇入同一个 case（.axiom 包，SQLite 内核 + 附件 + 索引），覆盖 Preservation→Collection→Examination→Analysis→Reporting 全流程。产品线分两条：(1) Magnet AXIOM — 面向公共安全/执法，强调移动 + cloud 取证、IM App Decoder、Magnet AI 图像分类与 gen-AI chat；(2) Magnet AXIOM Cyber — 面向企业 DFIR / IR / eDiscovery，强调 YARA + MITRE ATT&CK 集成、IOC Insights、Email Explorer、远程 endpoint 采集（Mac/Win/Linux）、可 AWS/Azure 部署。架构上分为两个组件：AXIOM Process（采集 + 处理引擎，含 CLI 可 headless 触发）和 AXIOM Examine（GUI 分析、可视化、报告）。Artifact Exchange 是社区共享 XML/Python 自定义 artifact 解析器的市场，通过 Axiom API 集成。Magnet Automate 是其上层 lab-automation 产品，调用 AXIOM + Griffeye 引擎批量并行处理（drag-and-drop workflow builder）。_

- **License**: 专有商业（proprietary commercial）…
- **Interface**: hybrid — 双组件架构：(1) **AXIOM Process**（采集 + 处理引擎）— 既可 GUI 启动（AXIOM.exe / AXIOMProcess.exe 弹 wizard），也提供命令行接口（AXIOMProcess.exe -case/-evidence/-source/-profile/-wi/-processing/-exportArtefacts/-out），是 AXIOM 唯一可 headless 触发的入口…
- **build_vs_buy**: **hybrid**（首选，与 C11c EnCase / C11b X-Ways 同属商业 GUI 取证工具族的统一结论）…
- **Svetovid install**: `NONE — proprietary, per-seat (AXIOM Process CLI wrappable)`
- **Svetovid invokes**: hybrid: wrap CLI + OSS stack
- **Invoked by goals**: G03, G09, G10, G11

> **Replacement strategy**: Svetovid uses the open-source stack
> (TSK + Volatility 3 + iLEAPP/ALEAPP + Dissect + Chainsaw) by default.
> Wrapping a customer's already-licensed commercial install is opt-in config.

### `C11e` — Cellebrite UFED / Physical Analyzer / Inspector

_Cellebrite DI Ltd. (Nasdaq: CLBT, Petah Tikva, Israel; majority-owned by Sun Corporation of Japan) flagship mobile-and-computer digital-intelligence suite. UFED (Universal Forensic Extraction Device) is the industry-standard mobile-data access/collection product family — deployed as UFED Touch3 ruggedized tablet, UFED 4PC software, UFED Ruggedized Laptop, or the high-end forensic workstation — performing logical, file-system and physical/full-file-system (FFS) extractions from iOS/Android/feature phones/drones/SIM/SD/GPS. Cellebrite UFED Premium adds the vendor's proprietary advanced-unlock / BFU (Before First Unlock) / full-file-system extraction capability. Physical Analyzer (PA) is the GUI decode/analysis surface that ingests UFED extractions and reassembles encrypted third-party app data, exposing a Python-scripting extension plus SQLite Wizard / App Genie / Hex highlighting. Cellebrite Inspector (successor to BlackBag BlackLight, acquired Jan 2020) is the Windows/macOS computer-data analysis product. Cellebrite Inseyets (announced ~2024–2025) is the newer integrated extraction engine; Cellebrite Pathfinder is the big-data analytics/correlation layer. The agent-relevant verdict: UFED collection IS scriptable through a documented CLI (UFED Command Line / Reader / batch) so its high-level acquisition can be wrapped; but the per-app DECODE logic inside PA/Inspector/Inseyets is a closed GUI black box with no JSON output and no redistribution rights, so deep artifact parsing must be re-built from open-source components (libimobiledevice + iLEAPP/ALEAPP + wa-crypt-tools + iOS-Backup-Analyzer)._

- **License**: Proprietary commercial…
- **Interface**: Hybrid — GUI-dominant with bounded CLI surface…
- **build_vs_buy**: hybrid — and this is the canonical 'partial-CLI-but-decode-black-box' case in the catalog…
- **Svetovid install**: `NONE — proprietary, per-seat`
- **Svetovid invokes**: hybrid: wrap UFED CLI + iLEAPP/ALEAPP for decode
- **Invoked by goals**: G10, G11

> **Replacement strategy**: Svetovid uses the open-source stack
> (TSK + Volatility 3 + iLEAPP/ALEAPP + Dissect + Chainsaw) by default.
> Wrapping a customer's already-licensed commercial install is opt-in config.

### `C11f` — Bulk Extractor

_Whole-image forensics scanner that extracts structured features (email/URL/IP/CC/EXIF/GPS/RFC822/credit-card/VIN/JSON, plus carved JPEG/ZIP/RAR) from raw/E01/AFF images WITHOUT parsing the filesystem — it probes every byte for decodable sequences (BASE64/gzip/zip-embedded data included). CLI-first, multi-threaded, output is TSV feature files + DFXML report.xml + histograms, trivially wrappable by an agent._

- **License**: Mixed but all redistribution-friendly: (1) Original Naval Postgraduate School / US-Government code = public domain / CC0 (not subject to copyright)…
- **Interface**: CLI. Single C++ binary `bulk_extractor` (no GUI in v2 — Java BEViewer was removed in 2020). Headless-native, fully scriptable. Companion Python scripts (bulk_extractor_reader.py, bulk_diff.py, identify_filenames.py, post_process_exif.py) pr…
- **build_vs_buy**: wrap — bulk_extractor is the canonical wrap candidate (explicitly named in the build_vs_buy field definition alongside Volatility 3 / KAPE / iLEAPP)…
- **Svetovid install**: `docker image: svetovid/carving`
- **Svetovid invokes**: raw_cli
- **Invoked by goals**: G03

### `C11g` — Scalpel

_Scalpel is a filesystem-independent header/footer file carver, a complete rewrite of Foremost 0.69 developed at the Naval Postgraduate School / Digital Forensics Solutions. The authoritative source on the Sleuth Kit GitHub is explicitly UNMAINTAINED; agents should prefer PhotoRec (TestDisk suite) or Bulk Extractor for new work._

- **License**: Apache-2.0 (since 2013-06-27 per the sleuthkit/scalpel README and the in-repo LICENSE-2.0.txt)…
- **Interface**: CLI. Pure command-line…
- **build_vs_buy**: wrap
- **Svetovid install**: `docker image: svetovid/carving`
- **Svetovid invokes**: raw_cli (prefer C11f Bulk Extractor)
- **Invoked by goals**: G03

### `C12` — Windows triage tools

_Windows 主机取证 triage 工具族：覆盖 PICERL 中 Collection（轻量级取证收集）+ Examination（解析）+ Analysis（关联）阶段的纯 CLI、JSON-first、高速工具集。本族是 agentic DFIR 最理想的『带 JSON 输出的命令行工具』集合——所有工具均为 headless-friendly，agent 可直接 subprocess 调用并消费结构化输出。包括：KAPE（Kroll，模块化 collector + processor，--target --module --csv --json，社区维护 KapeFiles 规则库）；Hayabusa（Yamato-Security，Rust 写的 EVTX Sigma-matching 时间线生成器，csv-timeline/json-timeline，内置 Sigma 规则）；Chainsaw（WithSecure，Rust 写的 EVTX 快速 search/hunt，Sigma + Chainsaw 规则，JSON/CSV 输出）；Eric Zimmerman Tools 全家桶（EvtxECmd/MFTECmd/PECmd/AmcacheParser/RECmd/JLECmd/LECmd/SrumECmd/RBCmd/AppCompatCacheParser/SQLECmd，C#/.NET，全部 --csv --json 输出，MIT 风格许可）；Hindsight（obsidianforensics/Ryan Benson，Chrome/Chromium/Firefox 浏览器历史，JSONL 输出）；Velociraptor（Rapid7/Velocidex，Go 写的端点可见性与采集平台，VQL 查询语言 + 离线 collector + REST API + Web GUI，输出 JSON/CSV）。全部 CLI-first + JSON 输出，是 agentic DFIR 最理想的工具集。_

- **License**: KAPE: kape.exe 二进制 — 专有但免费，Kroll 发布，禁止再分发，需注册/接受 EULA 下载（FAQ 明确『商业使用许可已澄清』见 KapeDocs FAQ）；KapeFiles（Targets/Modules）— MIT License (Copyright 2023 Eric Zimmerman)，可自由再分发…
- **Interface**: 全部 CLI-first（详见 tool_detail）…
- **build_vs_buy**: wrap — 全部子工具均 CLI-first + JSON 输出 + 无 GUI 强依赖，直接 subprocess wrap 即可，无需重建任何工具…
- **Svetovid install**: `docker image: svetovid/eztools`
- **Svetovid invokes**: raw_cli per sub-tool
- **Invoked by goals**: G01, G02, G04, G05, G08, G12, G19

### `C12a` — iLEAPP

_iOS Logs, Events, And Plists Parser — Alexis Brignoni 开源的 Python 取证解析器，解析 iOS/iPadOS 提取物（iTunes/Finder 备份、文件系统、zip/tar/gz 压缩包、单文件），输出 HTML/TSV/CSV/timeline/KML/LAVA 报告。模块化架构（346 个 artifact 解析器），与 ALEAPP（Android）同属 LEAPP 框架家族。支持 iOS/iPadOS 11 至当前版本。_

- **License**: MIT License (Copyright (c) 2020 Alexis Brignoni) — 宽松许可证，允许商业使用、修改、再分发、sublicense，仅需保留版权声明…
- **Interface**: hybrid — 同时提供 CLI（ileapp.py / 预编译 ileapp 二进制）和 GUI（ileappGUI.py / 预编译 ileappGUI）…
- **build_vs_buy**: wrap — iLEAPP 是纯 CLI + MIT 开源工具，已有完整 headless 接口（ileapp.py / ileapp 二进制）和结构化 TSV/CSV 输出…
- **Svetovid install**: `docker image: svetovid/mobile`
- **Svetovid invokes**: raw_cli (ileapp.py)
- **Invoked by goals**: G05, G10

> **Replacement strategy**: Svetovid uses the open-source stack
> (TSK + Volatility 3 + iLEAPP/ALEAPP + Dissect + Chainsaw) by default.
> Wrapping a customer's already-licensed commercial install is opt-in config.

### `C12b` — ALEAPP

_Android Logs Events And Protobuf Parser — the Android counterpart to iLEAPP. ALEAPP ingests an Android filesystem / tar / zip / gz extraction and runs 320+ dynamically-loaded Python artifact plugins (each declaring a `__artifacts_v2__` dict) that parse contacts2.db, mmssms.db, telephony/call logs, usagestats, Chrome/Cookies/History, settings, WiFiConfigStore, GoogleNowPlaying, Fitbit, plus dozens of OEM (Samsung/Xiaomi/Honor) and IM app artifacts. Output formats mirror iLEAPP exactly: per-artifact HTML reports, TSV/CSV, KML, timeline, and the structured LAVA database (_lava_artifacts.db SQLite + _lava_data.lava JSON manifest). 100% CLI/headless — wrap-only, no rebuild needed._

- **License**: MIT License (Copyright (c) 2020 Alexis Brignoni) — see repo root LICENSE…
- **Interface**: CLI (primary, headless) + optional GUI…
- **build_vs_buy**: wrap — ALEAPP is the canonical wrap candidate, explicitly named in the build_vs_buy field definition alongside iLEAPP/KAPE/Volatility 3…
- **Svetovid install**: `docker image: svetovid/mobile`
- **Svetovid invokes**: raw_cli (aleapp.py)
- **Invoked by goals**: G11

### `C13` — Memory analysis tools

_内存取证分析工具族：以 Volatility 3（volatilityfoundation，Python，模块化插件，CLI+JSON/JSONL 输出）与 MemProcFS（ufrisk/Ulf Frisk，C，把内存镜像挂载为虚拟文件系统并带 FindEvil 检测+丰富多语言 API）为当前主力；Rekall（google）已官方宣布停止维护并建议迁移到 Volatility 3；avml（microsoft，Rust，MIT）是 Linux 内存**采集**工具（acquisition，不是 analysis），与 WinPMEM/DumpIt/LiME 同属采集层，详见 C13b。本 item 聚焦 Volatility 3 + MemProcFS 的分析与 agentic 包装。_

- **License**: 差异显著：Volatility 3 = VSL 1.0（类 BSD，再分发友好）；MemProcFS = AGPLv3（copyleft，网络分发/SaaS 暴露有义务，打包需合规评估，可申请替代许可）；avml = MIT（最宽松）；Rekall = Apache/GPL 混合（已停止维护）…
- **Interface**: （合并视角）主力均为 CLI/可编程：Volatility 3 = 纯 CLI + Python 库 + volshell；MemProcFS = hybrid（CLI + 虚拟文件系统挂载 + 多语言 API）；avml = 纯 CLI 单二进制；Rekall = CLI（已停滞）…
- **build_vs_buy**: wrap — Volatility 3 与 avml 均为 fields.yaml build_vs_buy 定义中 wrap 的典型范例（与 Autopsy CLI、iLEAPP、KAPE、Bulk Extractor、Turbinia 同列）：纯 headless CLI、稳定 JSON/JSONL 输出、许可宽松（VSL/MIT）…
- **Svetovid install**: `docker image: svetovid/volatility`
- **Svetovid invokes**: raw_cli (--output-format jsonl)
- **Invoked by goals**: G02, G06, G08

> **Replacement strategy**: Svetovid uses the open-source stack
> (TSK + Volatility 3 + iLEAPP/ALEAPP + Dissect + Chainsaw) by default.
> Wrapping a customer's already-licensed commercial install is opt-in config.

### `C13a` — WinPmem

_Velocidex/Rekall 出身的开源物理内存采集驱动与 imager（Apache 2.0）。是事实上的开源内存采集层 —— Volatility 3 负责 analysis，pmem 负责 acquisition。提供 RAW（默认）/AFF4/可压缩输出，配套 Linpmem（Linux）、OSXpmem（macOS）三件套，统称 pmem。当前主线 v4.0.rc1（内部 4.0.1 BETA，2024-11），并新提供 go-winpmem Go 库与 sub-command CLI。_

- **License**: Apache License 2.0（README 明示：源码与签名二进制均在 Apache 2.0 下，permissive、可商用再分发）…
- **Interface**: CLI（headless）+ Go 库…
- **build_vs_buy**: wrap —— 100% 开源 CLI（Apache 2.0，可自由打包进 agent 镜像），传统 mini exe 与新一代 go-winpmem 都是纯 headless、参数稳定、支持 stdout 流式输出，完全满足 agent 驱动…
- **Svetovid install**: `prebuilt binary + docker image: svetovid/volatility`
- **Svetovid invokes**: raw_cli
- **Invoked by goals**: G06, G20

### `C13b` — AVML (Acquire Volatile Memory for Linux)

_微软开源的、用 Rust 编写的 Linux x86_64 用户态物理内存采集工具，以静态二进制形式部署，无需目标机编译、无需加载内核模块（区别于 LiME）。默认输出 LiME 格式内存快照（可选 Snappy 压缩），可直传 Azure Blob / HTTP PUT / TCP。在 Linux 内存取证场景中是 LiME/WinPmem 之外的首选隐蔽采集方案。_

- **License**: MIT License（Copyright (c) Microsoft Corporation）…
- **Interface**: CLI（headless）…
- **build_vs_buy**: wrap。理由：AVML 已具备干净的、基于 clap derive 的 headless CLI（acquire/convert/upload/stream），单一静态 musl 二进制零依赖、可脚本化、退出码与日志稳定，完全满足 'tool already has a headless CLI or stable script API' 的 wrap 判据（与 KAPE/Volatility 3/Turbinia 同类）。无需自建采集器，仅需在外层做：① JSON 结果规…
- **Svetovid install**: `static musl binary`
- **Svetovid invokes**: raw_cli
- **Invoked by goals**: G06, G20

### `C13c` — OSXpmem (memory acquisition)

_macOS 物理内存采集器，是 Google Rekall 项目 pmem 套件（WinPmem/Linpmem/OSXpmem 三件套）的 macOS 分支。它由一个用户态 imager 二进制 + 一个 kernel extension（MacPmem.kext）组成，经 kextload 加载后通过 /dev/pmem 设备读物理内存，输出 AFF4 / raw / ELF 三种容器（默认 AFF4，含 information.yaml 元数据）。历史发布仅到 2016-05（osxpmem-2.1.post4.zip，v1.5.1）与 2017-12 的 rekall-OSX-1.7.2rc1 整包，之后随 google/rekall 归档（2020-10 后无更新）而成为 legacy-unmaintained。Velocidex 维护了 WinPmem 与 Linpmem，但未接手 OSXpmem 分支。在现代 macOS 上因 SIP（10.11+）、kext notarization（10.15+）与 Apple Silicon 的 Reduced Security Policy 限制，原版 kext 实际已无法加载，需走替代方案。Apache 2.0（仅 pmem 子目录，Rekall 其余为 GPL-2.0）。_

- **License**: Apache License 2.0——仅适用于 Pmem 内存采集工具子目录（tools/pmem/LICENSE 明示：‘Apache license applies only to the Pmem memory acquisition tools. The rest of Rekall is still only available under the GPL.’）…
- **Interface**: CLI（headless）…
- **build_vs_buy**: hybrid — 原版 imager（Apache 2.0，headless CLI）在‘可加载 kext 的旧 macOS’场景属 wrap 类（同 WinPmem/Linpmem：开源、纯 CLI、information.yaml 结构化，agent 直接 subprocess 包一层即可）…
- **Svetovid install**: `legacy binary (modern macOS unsupported)`
- **Svetovid invokes**: hybrid: legacy + sysdiagnose fallback
- **Invoked by goals**: G06, G20

> **Replacement strategy**: Svetovid uses the open-source stack
> (TSK + Volatility 3 + iLEAPP/ALEAPP + Dissect + Chainsaw) by default.
> Wrapping a customer's already-licensed commercial install is opt-in config.

### `C14` — Network analysis tools

_网络取证/网络流量分析（NFAT/NTA/NSM）工具族：覆盖 Examination（解析 pcap 提取 session/文件/凭据/IOC）+ Analysis（关联、检测、狩猎）阶段。包括 tshark（Wireshark CLI，GPLv2，pcap 解析 1700+ 协议，-T json/jsonl/fields，display filter 引擎，dissector/CLI 反向工程）；Zeek（前 Bro，BSD-3，网络分析框架，默认 TSV logs + 可 redef LogAscii::use_json=T 切 JSON，Zeek script DSL 扩展，conn.log/dns.log/http.log/ssl.log 生态）；Suricata（OISF，GPLv2，IDS/IPS/NSM，-r file.pcap，eve.json NDJSON 输出含 alert/flow/http/dns/tls/ssh/fileinfo/smtp/drop）；NetworkMiner（Netresec，GPLv2 免费版 + 闭源 Pro，NFAT，GUI 为主，mono 跨平台运行，CLI 版能力受限）；RITA（Active CounterMeasures/BHIS，GPLv3，Go，吃 Zeek logs 输出，beaconing/DNS-tunneling/long-connection/threat-intel 检测，**v5 已从 MongoDB 迁移到 ClickHouse**，CSV/stdout 输出）；Arkime（前 Moloch，Apache-2.0，full packet capture + OpenSearch/Elasticsearch 索引，capture（C 采集器）+ viewer（node.js Web）+ REST API，输出 JSON SPI 数据 + 标准 PCAP）。全部工具均为 CLI-first 或具备 headless CLI，适合 MCP wrap。_

- **License**: tshark/Wireshark: GPLv2（COPYING 确认，1991 GPL v2 文本）…
- **Interface**: 混合，按子工具分：(1) tshark — 纯 CLI（headless 100%），无 GUI 依赖；Wireshark GUI 是同源 sister 工具，tshark 完全具备 Wireshark 的 dissection 能力…
- **build_vs_buy**: wrap — 全部工具的 CLI-first 性质决定 wrap 策略，零 build_replacement（除 NetworkMiner 例外）…
- **Svetovid install**: `docker image: svetovid/network`
- **Svetovid invokes**: raw_cli + Zeek scripts + Arkime REST
- **Invoked by goals**: G07, G08

> **Replacement strategy**: Svetovid uses the open-source stack
> (TSK + Volatility 3 + iLEAPP/ALEAPP + Dissect + Chainsaw) by default.
> Wrapping a customer's already-licensed commercial install is opt-in config.

### `C15` — Malware analysis tools

_恶意软件分析（malware analysis）工具族：覆盖 PICERL 的 Examination/Analysis 阶段，对从 C11 镜像/内存提取的可疑二进制（PE/ELF/MachO/shellcode/.NET）进行静态/动态逆向以判定家族、能力、C2、ATT&CK 技术。包括静态逆向框架——Ghidra（NSA，Apache-2.0，headless analyzeHeadless + Python/Java postScript）、IDA Free/Pro（Hex-Rays，商业为主，IDA Free 免费受限，idascript IDC/IDAPython，-B batch）、radare2/rizin（LGPLv3，纯 CLI，rabin2 -Ij/r2pipe cmdj JSON）；模式匹配——YARA（VirusTotal，BSD-3，维护模式，已被 Rust 重写的 YARA-X v1.19 取代）；能力检测——capa（Mandiant，Apache-2.0，PE/ELF/.NET/shellcode，capa -j JSON + ATT&CK/MBC 规则映射）；动态沙箱——CAPEv2（Context Information Security，GPLv3，Cuckoo fork，API hook + YARA-driven debugger 自动脱壳/配置提取，JSON report）、Hatching Triage（tria.ge，商业 SaaS + BSD-3 Go/Python API 客户端，web/API-first）；威胁情报枢纽——abuse.ch 平台族（URLhaus/MalwareBazaar/ThreatFox/Feodo Tracker 等 6 平台，REST API + JSON/CSV/MISP 导出）。族共性：全部 CLI/headless 友好，是 agentic 自动化的理想工具集——绝大多数原生支持 JSON 输出或脚本化 JSON（r2 cmdj / capa -j / Ghidra ScriptResults / YARA-X / abuse.ch API）。_

- **License**: Ghidra: Apache-2.0（可自由打包再分发）…
- **Interface**: 逐工具：(1) Ghidra — hybrid（GUI + headless analyzeHeadless CLI；PyGhidra 让 Python 直接驱动 Ghidra API），headless 100% 可用…
- **build_vs_buy**: wrap — 全部工具均已有 headless CLI 或稳定 REST/Python API，无需重建任何工具…
- **Svetovid install**: `docker image: svetovid/malware`
- **Svetovid invokes**: raw_cli (analyzeHeadless / yara / capa / r2)
- **Invoked by goals**: G02, G07, G08, G18

### `C16` — Timeline & correlation tools

_DFIR 时间线与关联工具族：把来自多源（文件系统、注册表、事件日志、浏览器、内存、云日志）的带时间戳记录聚合成统一超级时间线（super-timeline），并在其上做检测/标注/检索/关联的 CLI 与服务。本族是 PICERL 中 Analysis 阶段的核心，承上启下——上游消费 C11 镜像、C12 triage 输出、C13 内存 artifact，下游供给报告生成与 LLM 关联推理。包括：(1) Plaso / log2timeline（log2timeline/plaso，Apache-2.0，Python，~60 个 parser + 数百 plugin，覆盖 Windows/Linux/macOS/cloud artifact；CLI log2timeline.py/pinfo/psort/psteal，输出 .plaso SQLite 存储 + CSV/JSON/L2TCSV/JSONL/xlsx/OpenSearch/KML 多格式）；(2) mactime（The Sleuth Kit，CPL/IBM PL，bodyfile → ASCII 时间线 CSV，最经典的文件系统 MACB 时间线）；(3) Timesketch（Google，Apache-2.0，Web 协同时间线分析，后端 OpenSearch/Elasticsearch，REST API + Python importer/analyzer 客户端 + Sigma 规则整合 + analyzer pipeline）；(4) Hayabusa super-timeline（Yamato-Security，AGPLv3，Rust；详见 C12，csv-timeline/json-timeline 直接生成内置 Sigma 匹配的时间线，是 Timesketch/OpenSearch 的上游数据源）。统一时间线格式演进：legacy L2T CSV → Plaso .plaso 存储 → ECS（Elastic Common Schema）/OpenSearch 新趋势。全部 CLI/REST 可控，是 agentic DFIR 最理想的『wrap』对象——build_vs_buy=wrap。_

- **License**: 族多许可混合：(1) Plaso — Apache License 2.0（permissive，可自由商业再分发含专利授权；plaso/LICENSE 顶部实测）…
- **Interface**: 族整体混合（hybrid），详见 tool_detail 各工具单独说明…
- **build_vs_buy**: wrap — 全部 4 个工具均 CLI/REST-first + 结构化 JSON 输出 + 无 GUI 强依赖，直接 subprocess/REST wrap 即可，无需重建任何工具…
- **Svetovid install**: `docker image: svetovid/timeline`
- **Svetovid invokes**: raw_cli (Plaso) + Timesketch REST
- **Invoked by goals**: G01, G04, G05, G08, G12, G22

> **Replacement strategy**: Svetovid uses the open-source stack
> (TSK + Volatility 3 + iLEAPP/ALEAPP + Dissect + Chainsaw) by default.
> Wrapping a customer's already-licensed commercial install is opt-in config.

### `C17` — Open-source forensic parsing libraries

_一组开放源代码、可被脚本/AI agent 直接 import 或 subprocess 调用的取证解析库与编排框架，覆盖证据镜像格式 (E01)、文件系统/卷 (TSK)、Windows 注册表 (registry hive)、Windows 事件日志 (evtx)、Apple 文件系统 (APFS)、统一证据访问层 (Dissect) 以及分布式取证编排 (Turbinia)。它们是上层 agentic-DFIR 工具（iLEAPP/Autopsy/Plaso/Timesketch/KAPE）的底层解析骨架，agent wrapper 通过 native_lib 方式直接调用。_

- **License**: 全部开放源代码，但 license 谱系差异显著 (影响可否打包进 agentic-DFIR 产品镜像):…
- **Interface**: library (主体) — 全部 7 个均为可 import 或 subprocess 调用的库/框架，无 GUI: libewf=C 库+pyewf Python 绑定+CLI…
- **build_vs_buy**: wrap (原生) — 全部 7 个均不需要重建…
- **Svetovid install**: `pip install into backend venv`
- **Svetovid invokes**: native_lib (Python import)
- **Invoked by goals**: G01, G03, G22

> **Replacement strategy**: Svetovid uses the open-source stack
> (TSK + Volatility 3 + iLEAPP/ALEAPP + Dissect + Chainsaw) by default.
> Wrapping a customer's already-licensed commercial install is opt-in config.

### `C17a` — omerbenamram/evtx (Rust crate)

_100% safe Rust 解析器，用于 Windows EVTX (XML Event Log) 二进制格式，同时发布同名 crate (evtx@0.12.2, MIT/Apache-2.0) 与命令行工具 evtx_dump。它是 Chainsaw (WithSecure) 与 Hayabusa (Yamato-Security) 的底层解析引擎，也是 pyevtx-rs Python 绑定的 Rust 核心。对 Rust 原生 agent 或高性能取证管道，应直接依赖 crate (native_lib)，而不是 wrap CLI。8 线程下解析 30MB Security.evtx 仅 ~20.7ms，比 python-evtx 快约 7000 倍。_

- **License**: MIT/Apache-2.0 双许可 (Cargo.toml 声明 license = "MIT/Apache-2.0"；README 注明可任选其一)…
- **Interface**: library (主体，evtx crate) + CLI (附带 evtx_dump 二进制) + WASM (EVTX Web 浏览器 UI，同 Rust 核心编译)…
- **build_vs_buy**: wrap (native_lib) — 已在字段定义中被显式列为 wrap 范例 ('omerbenambar/evtx crate' 在 build_vs_buy 字段 wrap 项)…
- **Svetovid install**: `cargo add evtx (Rust core)`
- **Svetovid invokes**: native_lib (Rust crate)
- **Invoked by goals**: G01, G07

> **Replacement strategy**: Svetovid uses the open-source stack
> (TSK + Volatility 3 + iLEAPP/ALEAPP + Dissect + Chainsaw) by default.
> Wrapping a customer's already-licensed commercial install is opt-in config.

### `C17b` — Chainsaw

_Chainsaw 是 WithSecure (原 F-Secure) Countercept 团队用 Rust 编写的 Windows 取证工件快速狩猎/搜索工具，封装 omerbenamram/evtx (C17a) crate 并叠加 Sigma 规则匹配引擎 (TAU Engine)。它面向'首响应 (first-response)'快速分诊场景，让蓝队无需 ELK/Splunk 等重型基础设施即可在数十秒内对大量 EVTX/MFT/注册表 hive/SRUM 进行关键词搜索、Sigma 检测与转储。社区共识是其与 Hayabusa (C12/C16) 高度互补：Chainsaw 偏灵活查询与原始 dump，Hayabusa 偏 Sigma-driven 标准化时间线生成，实战中'两个都用'。_

- **License**: GPL-3.0-only (GPL3)…
- **Interface**: CLI (headless)…
- **build_vs_buy**: wrap。chainsaw 已是干净 headless CLI + 原生 JSON/JSONL 输出 + 跨平台预编译二进制 + 开源 (GPL3)，完全满足 'wrap' 判据 (与 Volatility 3 / iLEAPP / KAPE / omerbenamram/evtx crate / Turbinia 同类)。无需重建：agent 只需 subprocess 调用 + 读 JSON + 规范化字段名即可。唯一自建价值在 MCP server 薄包装层 (统一证据…
- **Svetovid install**: `docker image: svetovid/eztools`
- **Svetovid invokes**: raw_cli (--jsonl)
- **Invoked by goals**: G01, G02, G08

### `C17c` — Dissect (Fox-IT / NCC Group)

_Dissect 是 Fox-IT（NCC Group 旗下）开发的数字取证与应急响应（DFIR）框架与工具集，2024 年正式开源、AGPLv3 授权。其核心设计是『统一证据访问层』：通过 30+ 个解耦的 Python 子模块（dissect.evidence/dissect.hypervisor/dissect.ntfs/dissect.eventlog/dissect.regf/dissect.util/dissect.cstruct 等）把磁盘容器（E01/raw/VMDK/QCoW/VHD/AD1）、卷管理、文件系统（NTFS/ExtFS/FAT/FFS/APFS/XFS/Btrfs…）与各 OS 工件（Windows 注册表/Prefetch/Amcache/Evtx、Linux authlog/bash history、浏览器历史等）抽象为统一的 Target 对象，调查员无需手动挂载/解包即可通过 target-query / target-shell 等命令行工具用一致的插件函数语法查询任意工件。配套的 acquire 工具可在端点/hypervisor 上生成轻量采集容器，与 Timesketch（C16）衔接可构建端到端 IR 管线（Dissect 解析 → flow.record/JSON/CSV → Timesketch 上传）。被广泛视为 Plaso 的互补/竞品：Plaso 聚焦时间线生成（supertimeline），Dissect 聚焦『统一访问 + 插件化查询』，二者常组合使用。_

- **License**: AGPLv3（https://www.gnu.org/licenses/agpl-3.0.html），全部模块统一授权（dissect meta、dissect.target、dissect.evidence、dissect.hypervisor、acquire、flow.record 均为 AGPLv3）…
- **Interface**: CLI（主力）+ library（Python API）+ hybrid…
- **build_vs_buy**: wrap（build_vs_buy 语义）— 更精确为 native_lib…
- **Svetovid install**: `pip install dissect into backend venv`
- **Svetovid invokes**: native_lib + raw_cli (target-query)
- **Invoked by goals**: G04, G05, G19, G21, G22

### `C18` — Turbinia (Google)

_Google 开源的分布式取证工作负载编排框架（Apache 2.0）。它把 Plaso/Volatility/Bulk Extractor 等常见取证工具封装为可并行的 Task，由 Celery worker 池自动调度执行，用于在云端/本地规模化、自动化处理海量证据。项目自 2025 年起进入维护模式，官方建议新项目改用其继任者 OpenRelik。_

- **License**: Apache License 2.0（再分发友好，可嵌入商业 agentic-DFIR 产品镜像）…
- **Interface**: hybrid。核心是 REST API server（FastAPI，Swagger UI 在 /docs）+ turbinia-client CLI（pip 独立包）+ turbinia_api_lib Python 库…
- **build_vs_buy**: wrap。理由：Turbinia 已是现成的‘分布式取证编排基础设施’，提供干净的 REST API（FastAPI/OpenAPI）、Python 客户端库（turbinia_api_lib）和 CLI，原生 JSON 输出，完全 headless 可控。agent 应直接调用 POST /api/request/ 提交证据、轮询 GET /api/request/{request_id}、GET /api/result/request/{request_id} 取回 JS…
- **Svetovid install**: `docker-compose stack`
- **Svetovid invokes**: REST API (turbinia_api_lib)
- **Invoked by goals**: G21
