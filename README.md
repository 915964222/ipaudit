<div align="center">

# ipaudit · IP 质量检测

_输入一个 IP，输出一份「这个 IP 到底干不干净、以及为什么」的可验证报告_

![Python](https://img.shields.io/badge/Python-3.10+-3776AB?logo=python&logoColor=white)
![License](https://img.shields.io/badge/License-无许可证保留所有权利-grey)
![Tests](https://img.shields.io/badge/Tests-40%20passing-2EA043)
![标定](https://img.shields.io/badge/标定-21%2F21%20100%25-2EA043)
![依赖](https://img.shields.io/badge/依赖-零第三方-orange)

**应用** `IP 质量检测` **形态** `CLI · 本地服务 · Web 报告` **依赖** `Python 标准库零依赖`
**采集** `DNSBL · ASN · 信誉库 · 端口` **探针** `WebRTC · 时区 · 字体 · 指纹`
**输出** `终端 · JSON · HTML · Webhook` **存储** `SQLite 单文件`

**定位：卖判断力，不卖通道。**

</div>

---

## 目录

[红线](#三条红线写进了代码结构不是免责声明) ·
[快速开始](#快速开始) ·
[两个维度](#两个维度本产品的核心判断) ·
[诚实降级](#诚实降级) ·
[API](#api) ·
[监控告警](#监控告警) ·
[标定](#标定-p0-验收) ·
[打包](#打包pyinstaller) ·
[访问控制](#监听与访问控制防放大器免费扫描器)

## 三条红线（写进了代码结构，不是免责声明）

| 红线 | 落地方式 |
|---|---|
| **只检测，不代理** | 端口探测只做握手确认，确认即断开，不建立数据通道 |
| **只诊断，不伪装** | 不提供指纹伪造、UA 篡改等"通过检测"功能（指引文本有单测锁死） |
| **只存结论，不存关联** | `probe` 表刻意不存账号/店铺/备注，只有 token 和 IP |

## 快速开始

```bash
# 单 IP 终端报告（约 3-10s，全单元并行）
python -m ipaudit 8.8.8.8

# JSON / 深度模式（/24 抽样 + 端口探测）
python -m ipaudit --json --deep 8.8.8.8

# 批量出 HTML 报告
python -m ipaudit batch -f ips.txt --out report/

# 本地服务（API + 探针 + 监控循环）
python -m ipaudit serve --port 9650

# 监控
python -m ipaudit watch add 1.2.3.4 --every 6h --alert 70
python -m ipaudit watch list
```

<details>
<summary><strong>终端报告长这样</strong></summary>

```
IP 质量检测报告  8.8.8.8

  综合评分  25 / 100  不可用
  住宅判定  机房伪装

  证据链
   [身份] asn_type = AS15169 Google LLC  -40  (asn_type.json, 置信度 high)
   [身份] residence = 四路证据得分 5/100  -25  (四路投票, 置信度 medium)
   [声誉] scamalytics = Fraud Score=0   0  (Scamalytics, 置信度 medium)

  未测到（不代表干净）
   - AbuseIPDB: 未配置 ABUSEIPDB_API_KEY

  结论
   该 IP（Ashburn、United States，AS15169 Google LLC）判定为机房网段，非真住宅。
```

</details>

## 两个维度（本产品的核心判断）

| 维度 | 数据来源 | 回答的问题 |
|---|---|---|
| **IP 维度** | 服务端可查：ASN 四路证据投票、rDNS 模式、12 个 DNSBL、信誉库、端口指纹 | 这个 IP 本身干不干净？ |
| **环境维度** | 客户浏览器实测：时区、语言、字体、WebRTC 泄漏，服务端交叉比对 | 封号是不是浏览器环境造成的？ |

**只有两个维度交叉才能回答"我为什么封号"。** 典型场景：IP 是干净的真住宅，
但浏览器时区是 Asia/Shanghai——这种封号换多少 IP 都没用，报告会直接说明。

### WebRTC 四态分类（不是只有漏/不漏）

| 状态 | 含义 | 处理 |
|---|---|---|
| `leak` | 公网 IP 暴露，或内网 host candidate 外泄 | −25，最高优先级修复项 |
| `restricted` | 仅 srflx（出口 IP），无 host candidate | 合规，不扣分 |
| `disabled` | 零 candidate（已禁用） | 不扣分，但记为环境特征 |
| `blocked` | 探针被拦截（CSP/扩展） | 标 `unavailable`，不能当通过 |

### WebRTC 泄漏修复闭环

探针页检测到泄漏时，就地给出**精确到配置项**的修复方法，改完点「WebRTC 复测」
重新采集并重算环境评级。推荐顺序：**企业策略 > 启动参数 > 扩展**。

| 浏览器 | 修复方法 |
|---|---|
| 企业策略（多机管控） | 注册表 `WebRtcIPHandlingPolicy = disable_non_proxied_udp`（Chrome: `HKLM\SOFTWARE\Policies\Google\Chrome`；Edge: `HKLM\SOFTWARE\Policies\Microsoft\Edge`） |
| 指纹浏览器（AdsPower/比特等） | 环境设置 → WebRTC 选「替换」（candidate 走代理出口）或「禁用」；**设置显示已关 ≠ 真关，必须复测** |
| Chrome / Edge | 启动参数 `--webrtc-ip-handling-policy=disable_non_proxied_udp`；前提：完全退出浏览器再启动、写进快捷方式 |
| Firefox | `media.peerconnection.enabled=false`，或 `default_address_only=true` + 代理 |
| 扩展（临时补救） | uBlock Origin 仅 MV2 版有防泄漏项；只挡内网不挡公网，Lite（MV3）没有 |

```bash
python -m ipaudit serve           # 起 API
curl -X POST http://127.0.0.1:9650/api/probe/session
# → 在绑定目标 IP 的浏览器里打开返回的 /?t=token 页面，点提交
```

## 账号环境排查（clinic）

面向「为什么被封号」的会诊模式：IP 维度 + 环境探针 + 归因结论，一个店铺一次会诊。

```bash
# 就地会诊：扫 IP → 起探针服务等回传 → 输出归因清单 + HTML 报告
python -m ipaudit clinic 1.2.3.4 --serve-probe --out report/
```

归因按封号可能性排序，每条给可执行动作，并明确 **「换 IP 有没有用」**——
环境原因（WebRTC 泄漏、时区不符）换 IP 无效，报告会直接说「先别买新 IP」。

## 诚实降级

- 查不到的项目一律标 `unavailable` 并写明原因，**绝不把"查不到"当"没问题"**。
- Spamhaus 对公共解析器返回 `127.255.255.25x` 是"查询无效"，代码里已区分，不算命中。
- AbuseIPDB / IPQS 需要环境变量 `ABUSEIPDB_API_KEY` / `IPQS_API_KEY`，没配就明说。

## API

```
GET  /api/scan/{ip}            单 IP 扫描（同步，约 3–10s）
POST /api/scan                 批量 {"ips": [...]}（上限 50）
GET  /api/report/{id}.html     HTML 报告（带证据链，可直接发客户）
GET  /api/report/{id}.json     JSON
POST /api/probe/session        创建探针会话
POST /api/probe/submit         探针回传（服务端交叉比对出环境评级）
GET  /api/probe/{token}        查询比对结果
GET/POST /api/monitor          监控列表 / 新增（评分跌破阈值 webhook 告警）
GET  /api/health               存活
```

## 监控告警

```bash
python -m ipaudit watch add 1.2.3.4 --every 6h --alert 70 --webhook https://your/hook
python -m ipaudit watch run          # 立即复检全部监控并触发告警（daemon 前先验证用）
python -m ipaudit watch list
```

`serve` 启动后监控循环每 60s 检查一次到期任务；评分跌破阈值或较上次下降时
写 `alert_log` 并 POST webhook（`{ip, reason, score, fired_at}`），投递成功置
`delivered=1`。

## 代理预筛（proxy-harvest）

抓 8 个公共免费代理源 → 去重 → 并发探活 → 输出可直接粘贴进
ClaudeCN「自定义列表」的格式（每行一条 `http://ip:port` 或 `socks5://ip:port`，
按延迟排序）：

```bash
python -m ipaudit proxy-harvest --count 30 --out proxy_list.txt
```

- `--count` 目标存活条数（默认 30，给 ClaudeCN 目标 10 留 3 倍余量）
- 源失败自动重试；免费源波动大，某次全超时属正常，隔几小时重跑
- 只做连通性探测（TCP / 单次 HTTP GET），确认即断开，不建立数据通道

## 标定（P0 验收）

```bash
PYTHONIOENCODING=utf-8 python calibration/run.py
```

21 个已知类型 IP（10 真住宅 / 11 机房与公共 DNS），三分类判准率 **100%**，
明细（含每个 IP 的四路证据得分）见 `calibration/result.json`。

## 测试

```bash
python -m unittest discover -s tests -v   # 40 个离线单测
```

## 结构

```
ipaudit/
  dnsbl.py      自实现 DNS 报文 + 12 名单并发查询（含 Spamhaus 无效码语义）
  collector.py  U1–U6 采集单元，全并行、各自超时、失败不阻断
  asn_data.py   人工维护的 ASN 分类表（163 条，核心资产，一季度补一次）
  judge.py      四路证据投票 + 冲突消解 + 扣分制评分 + 结论生成
  report.py     终端 / JSON / HTML 三种渲染
  store.py      SQLite（scan / dnsbl_hit / probe / monitor / alert_log）
  server.py     ThreadingHTTPServer + 探针交叉比对 + 监控循环
  probe_page.py 单文件探针页（无依赖，客户打开即用）
  cli.py        命令行入口
calibration/    标定脚本与基准集
tests/          40 个离线单测
deploy/         unbound 配置 + 部署自检指引
```

## 打包（PyInstaller）

```bash
python -m PyInstaller --noconfirm ipaudit.spec   # 产物 dist/ipaudit.exe（约 9MB 单文件）
```

- 入口必须用 `launch.py`（顶层绝对导入）；`ipaudit/__main__.py` 的相对导入在单文件模式下没有父包，会 ImportError。
- 已实测：`dist/ipaudit.exe 8.8.8.8` 真实扫描、`--json` 机器可读、`--help` 正常。
- exe 同级生成 `data/ipaudit.db`；「我的工具大全」里以 kind=tool 挂 `ipaudit.exe`，运行按钮直接启动。

## 监听与访问控制（防放大器/免费扫描器）

解析器（unbound）与 HTTP 服务两条线都要控：

```bash
# 解析器：deploy/unbound.conf 两套方案
#   A 同机   → interface 127.0.0.1，最安全
#   B 跨机   → 只绑 WireGuard IP + access-control 白名单 + ufw 限 wg0
# 部署后必须自检：
ipaudit resolver-check                    # Spamhaus 通不通
ipaudit resolver-check --recursion-test <解析器公网IP>   # 开放递归 = 放大器，必须 REFUSED

# HTTP 服务：默认 127.0.0.1；无鉴权机制，非回环绑定直接拒绝启动
ipaudit serve                             # 本机
# 跨机访问用 SSH 隧道：ssh -L 9650:127.0.0.1:9650 <主机>
```

完整步骤与第三方验证方法见 `deploy/DEPLOY.md`。

## 数据库位置（exe 模式必读）

exe 的 SQLite 库固定在 **exe 同级** `data/ipaudit.db`（不是 %TEMP% 解包目录——
单文件模式每次启动换临时目录，写那里 = 重启丢数据）。源码模式在项目 `data/`。
要迁移历史数据，把整个 `data/` 目录跟 exe 放一起即可。

---

<div align="center">

**只检测，不代理 · 只诊断，不伪装 · 只存结论，不存关联**

</div>