# ipaudit · IP 质量检测

输入一个 IP，输出一份「这个 IP 到底干不干净、以及为什么」的可验证报告。
定位：**卖判断力，不卖通道**。设计方案见 `设计方案.md`。

## 三条红线（写进了代码结构，不是免责声明）

1. **只检测，不代理** —— 端口探测只做握手确认，确认即断开，不建立数据通道。
2. **只诊断，不伪装** —— 不提供指纹伪造、UA 篡改等"通过检测"功能。
3. **只存结论，不存关联** —— `probe` 表刻意不存账号/店铺/备注，只有 token 和 IP。

## 快速开始

```bash
# 单 IP 终端报告
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

## 两个维度（本产品的核心判断）

- **IP 维度**（服务端可查）：ASN 四路证据投票、rDNS 模式、12 个 DNSBL、信誉库、端口指纹。
- **环境维度**（必须客户浏览器实测）：在绑定了目标 IP 的浏览器里打开探针页，
  采集时区/语言/字体/WebRTC 泄漏，服务端交叉比对。

**只有两个维度交叉才能回答"我为什么封号"。** 典型场景：IP 是干净的真住宅，
但浏览器时区是 Asia/Shanghai——这种封号换多少 IP 都没用，报告会直接说明。

### WebRTC 泄漏修复闭环

探针页检测到泄漏时，就地给出**精确到配置项**的修复方法，改完点「WebRTC 复测」
重新采集并重算环境评级：

| 浏览器 | 修复方法 |
|---|---|
| 指纹浏览器（AdsPower/比特等） | 环境设置 → WebRTC 选「替换」（candidate 走代理出口）或「禁用」，优先「替换」 |
| Chrome / Edge | 启动参数 `--webrtc-ip-handling-policy=disable_non_proxied_udp`，或 uBlock 勾选防泄漏 |
| Firefox | `media.peerconnection.enabled=false`，或 `default_address_only=true` + 代理 |

报告（终端/HTML）同步输出「修复项」清单。**红线**：只指导修复真实配置、验证泄漏
闭合，不提供任何指纹伪造功能——指引文本有单测锁死。

```bash
python -m ipaudit serve           # 起 API
# 建探针会话拿 URL
curl -X POST http://127.0.0.1:9650/api/probe/session
# → 在绑定目标 IP 的浏览器里打开返回的 /?t=token 页面，点提交
```

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

## 标定（P0 验收）

```bash
PYTHONIOENCODING=utf-8 python calibration/run.py
```

21 个已知类型 IP（10 真住宅 / 11 机房与公共 DNS），三分类判准率 100%，
明细（含每个 IP 的四路证据得分）见 `calibration/result.json`。

## 测试

```bash
python -m unittest discover -s tests -v   # 26 个离线单测
```

## 结构

```
ipaudit/
  dnsbl.py      自实现 DNS 报文 + 12 名单并发查询（含 Spamhaus 无效码语义）
  collector.py  U1–U6 采集单元，全并行、各自超时、失败不阻断
  asn_data.py   人工维护的 ASN 分类表（163 条，核心资产，一季度补一次）
  judge.py      四路证据投票 + 扣分制评分 + 结论生成
  report.py     终端 / JSON / HTML 三种渲染
  store.py      SQLite（scan / dnsbl_hit / probe / monitor / alert_log）
  server.py     ThreadingHTTPServer + 探针交叉比对 + 监控循环
  probe_page.py 单文件探针页（无依赖，客户打开即用）
  cli.py        命令行入口
calibration/    标定脚本与基准集（P0 验收：21/21 = 100%）
```

## 数据库

默认 `data/ipaudit.db`，`--db` 可覆盖。监控循环随 serve 启动，每 60s 检查到期任务。

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
