"""客户端探针页（环境维度采集）。

单文件、无依赖、打开即用。客户在绑定了目标 IP 的指纹浏览器里打开，
采集结果 POST 回 /api/probe/submit。只采集环境特征，不采集任何账号信息。
关键项：WebRTC 泄漏（最常见的封号真因）、时区、语言、字体、平台一致性。

WebRTC 泄漏的修复闭环：检测到泄漏 → 页面内给出精确到配置项的修复指引
（按浏览器类型）→ 客户改配置 → 点「WebRTC 复测」重采 STUN 并重新提交
→ 服务端重算环境评级。只指导修复真实泄漏，不提供任何伪造功能。
"""

PROBE_HTML = r"""<!DOCTYPE html>
<html lang="zh-CN"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>IP 环境探针</title>
<style>
 body{font-family:'Segoe UI',system-ui,sans-serif;background:#10151c;color:#dde5ee;
      margin:0;display:flex;justify-content:center;padding:40px 16px}
 .box{max-width:680px;width:100%}
 h1{font-size:20px;font-weight:600}
 table{width:100%;border-collapse:collapse;margin:18px 0;font-size:14px}
 td{padding:8px 10px;border-bottom:1px solid #232c38}
 td:first-child{color:#8fa0b3;width:180px}
 .ok{color:#4ade80}.bad{color:#f87171}.warn{color:#fbbf24}
 button{background:#2563eb;color:#fff;border:0;border-radius:8px;padding:12px 28px;
        font-size:15px;cursor:pointer}
 button:disabled{background:#334;cursor:wait}
 button.sec{background:#334155;margin-left:8px}
 .note{color:#8fa0b3;font-size:12px;line-height:1.7;margin-top:16px}
 #fix{display:none;background:#1c2531;border:1px solid #3b4a5c;border-radius:10px;
      padding:14px 18px;margin:14px 0;font-size:13px;line-height:1.8}
 #fix h3{margin:0 0 6px;font-size:14px;color:#fbbf24}
 #fix code{background:#0d1219;padding:1px 6px;border-radius:4px;color:#7dd3fc;font-size:12px}
 #fix li{margin:4px 0}
 #status{margin-top:10px;font-size:14px;min-height:20px}
</style></head><body><div class="box">
<h1>环境探针 · 正在采集</h1>
<p>请在<strong>绑定了目标 IP 的浏览器</strong>里打开本页。采集完成后点击提交。</p>
<table id="tbl"></table>
<button id="go" onclick="doSubmit(true)">提交采集结果</button><button
 id="rtc" class="sec" onclick="retest()" disabled>WebRTC 复测</button>
<div id="status"></div>
<div id="fix">
 <h3>WebRTC 泄漏 · 修复方法（推荐顺序：企业策略 &gt; 启动参数 &gt; 扩展；改完点「WebRTC 复测」验证）</h3>
 <ul>
  <li><strong>① 企业策略（多机统一管控，用户改不掉）</strong>：注册表字符串值
      <code>WebRtcIPHandlingPolicy = disable_non_proxied_udp</code> —<br>
      Chrome：<code>HKLM\SOFTWARE\Policies\Google\Chrome</code> ｜
      Edge：<code>HKLM\SOFTWARE\Policies\Microsoft\Edge</code>。
      策略优先级高于启动参数，域内可批量下发。</li>
  <li><strong>② 启动参数（Chrome / Edge 原生）</strong>：
      <code>--webrtc-ip-handling-policy=disable_non_proxied_udp</code>
      —— 四个可选值里只有这个能同时挡内网 IP 和直连公网 IP。三个前提缺一不可：
      <strong>完全退出浏览器再启动</strong>（已有实例在跑时新参数只被当 URL 交给旧进程，
      直接丢弃——「加了参数怎么还漏」多半是这条）；<strong>写进快捷方式或启动脚本</strong>
      （手敲下次双击就丢）；装了会自建 WebRTC 连接的扩展仍需单独排查。</li>
  <li><strong>③ 扩展（临时补救，不等价）</strong>：uBlock Origin → 设置 → 隐私 →
      勾选「防止 WebRTC 泄漏本地 IP」。局限：只隐藏内网/host candidate，
      公网 IP 经 STUN 仍可能暴露；仅 Manifest V2 版有此项，
      uBlock Origin Lite（MV3）没有；多一层扩展多一层环境信号。</li>
  <li><strong>④ 指纹浏览器</strong>（AdsPower / 比特 / 紫鸟等）：环境设置的 WebRTC 选项
      （通常为 <code>real</code> / <code>replace</code> / <code>disabled</code>）选
      <code>replace</code> 或 <code>disabled</code>，不要 <code>real</code>。
      这类工具实现质量参差——<strong>设置项显示已关不等于真关了</strong>，
      改完必须点「WebRTC 复测」实检，这正是本页存在的理由。</li>
  <li><strong>Firefox</strong>：about:config →
      <code>media.peerconnection.enabled=false</code>，或
      <code>media.peerconnection.ice.default_address_only=true</code> 且走代理。</li>
  <li><strong>复测标准</strong>：WebRTC 状态变「合规：仅 srflx」或「零 candidate
      （disabled）」；提交后环境评级回升。disabled 不扣分但会被记录为环境特征。</li>
 </ul>
</div>
<div id="nosession" style="display:none;background:#2a1c1c;border:1px solid #5c3b3b;
     border-radius:10px;padding:14px 18px;margin:14px 0;font-size:13px;line-height:1.8">
 <strong style="color:#f87171">缺少探针会话</strong>：本页需要带一次性 token 打开
 （URL 形如 <code>/?t=xxxx</code>），直接打开根路径时提交会被拒绝。
 <ol style="margin:6px 0 0 18px;padding:0">
  <li>点这个按钮新建会话：
      <button class="sec" style="padding:6px 16px;margin-left:6px"
       onclick="newSession()">生成新会话链接</button></li>
  <li>浏览器会自动跳到带 <code>?t=token</code> 的新地址，重新采集提交</li>
 </ol>
 <p style="margin:6px 0 0" class="note">命令行方式（等价）：
 <code>curl -X POST http://127.0.0.1:9650/api/probe/session</code></p>
</div>
<p class="note">本页只读取浏览器环境特征（时区/语言/字体/WebRTC 等），不读取账号、
不存储任何身份信息。WebRTC 泄漏是最常见的封号真因：指纹浏览器配了代理但没关 WebRTC
时，平台一个 JS 就能拿到真实 IP。</p>
</div>
<script>
"use strict";
const $ = (id) => document.getElementById(id);
const rows = [];
function addRow(k, v, cls) {
  rows.push([k, v, cls || '']);
  const tr = document.createElement('tr');
  tr.innerHTML = `<td>${k}</td><td class="${cls||''}">${v}</td>`;
  $('tbl').appendChild(tr);
  return tr;
}

const result = { tz:'', tz_offset:null, lang:'', languages:'', platform:'',
  ua:'', ua_os:'', fonts:[], webrtc_ips:[], webrtc_candidates:[],
  webrtc_state:'', webrtc_leak:false, webrtc_has_host:false,
  webrtc_supported:true, webrtc_error:'', webrtc_timed_out:false,
  dns_leak:false, dns_servers:[], canvas_hash:'', renderer:'', gpu_sw:false,
  screen:'', hardware_concurrency:null, hc_anomaly:false };

// ---- 时区 ----
try {
  result.tz = Intl.DateTimeFormat().resolvedOptions().timeZone || '';
  result.tz_offset = new Date().getTimezoneOffset();
  addRow('IANA 时区', result.tz || '(未知)');
  addRow('本地偏移', `${-result.tz_offset/60}h (UTC${result.tz_offset<=0?'+':''}${-result.tz_offset/60})`);
} catch(e) { addRow('时区', '采集失败', 'bad'); }

// ---- 语言 ----
result.lang = navigator.language || '';
result.languages = (navigator.languages||[]).join(',');
addRow('语言', `${result.lang} (${result.languages})`);

// ---- 平台与 UA ----
result.platform = navigator.platform || '';
result.ua = navigator.userAgent || '';
const uaOs = /Windows NT/.test(result.ua) ? 'windows'
  : /Mac OS X/.test(result.ua) ? 'macos'
  : /Android/.test(result.ua) ? 'android'
  : /iPhone|iPad/.test(result.ua) ? 'ios' : /Linux/.test(result.ua) ? 'linux' : 'other';
result.ua_os = uaOs;
const platOs = /Win/.test(result.platform) ? 'windows'
  : /Mac/.test(result.platform) ? 'macos' : /Linux/.test(result.platform) ? 'linux' : 'other';
result.platform_ua_mismatch = uaOs !== 'other' && platOs !== 'other' && uaOs !== platOs;
addRow('平台/UA 一致', result.platform_ua_mismatch ? '不符 ← 风险' : '一致',
       result.platform_ua_mismatch ? 'bad' : 'ok');
addRow('UA 概要', uaOs + ' / ' + (navigator.hardwareConcurrency||'?') + ' 核');

// ---- 字体集（渲染宽度探测）----
const FONT_TEST = 'mmmmmmmmmmlli WQ@#';
const FONTS = ['Segoe UI','SF Pro Text','PingFang SC','Microsoft YaHei','Hiragino Sans',
  'Helvetica Neue','Ubuntu','Cantarell','Malgun Gothic','MS Gothic','SimSun'];
function fontWidth(f) {
  const c = document.createElement('canvas').getContext('2d');
  c.font = `20px "${f}", monospace`;
  return c.measureText(FONT_TEST).width;
}
const base = fontWidth('__no_such_font__');
for (const f of FONTS) {
  try { if (Math.abs(fontWidth(f) - base) > 0.5) result.fonts.push(f); } catch(e) {}
}
const hasWin = result.fonts.includes('Segoe UI') || result.fonts.includes('Microsoft YaHei');
const hasMac = result.fonts.includes('SF Pro Text') || result.fonts.includes('Hiragino Sans');
result.font_mismatch = (uaOs === 'windows' && hasMac && !hasWin)
                    || (uaOs === 'macos' && hasWin && !hasMac);
result.font_detail = '可用字体: ' + result.fonts.join(', ');
addRow('字体集', result.fonts.join(', ') || '默认');
addRow('字体/系统一致', result.font_mismatch ? '不符 ← 风险' : '一致',
       result.font_mismatch ? 'bad' : 'ok');

// ---- WebRTC：四态分类（leak / restricted / disabled / blocked）----
// 设计方案 3.5：不能只有"漏/不漏"。零 candidate 有两种相反原因：
// disabled（策略关闭，不扣分但记环境特征）与 blocked（探针被拦，标 unavailable）；
// 只有 srflx 且 IP==出口、无 host candidate 是 restricted（合规）。
function webrtcProbe() {
  return new Promise((resolve) => {
    result.webrtc_timed_out = false;
    let done = false;
    const finish = (timedOut) => {
      if (!done) { done = true; result.webrtc_timed_out = !!timedOut; resolve(); }
    };
    setTimeout(() => finish(true), 3500);
    try {
      if (typeof RTCPeerConnection === 'undefined') {
        result.webrtc_supported = false;
        finish(false);
        return;
      }
      result.webrtc_supported = true;
      const pcs = [];
      pcs.push(new RTCPeerConnection({iceServers:[{urls:'stun:stun.l.google.com:19302'}]}));
      pcs.push(new RTCPeerConnection({iceServers:[{urls:'stun:stun.cloudflare.com:3478'}]}));
      let n = 0;
      for (const pc of pcs) {
        pc.createDataChannel('x');
        pc.onicecandidate = (e) => {
          if (!e.candidate) { if (++n === pcs.length) finish(false); return; }
          const c = e.candidate.candidate || '';
          // candidate 类型：host / srflx / prflx / relay
          const m = c.match(/typ ([a-z]+)/);
          const typ = m ? m[1] : 'unknown';
          const ipm = c.match(/([0-9]{1,3}(\.[0-9]{1,3}){3})/);
          const ip = ipm ? ipm[1] : '';
          result.webrtc_candidates.push({typ, ip});
          if (ip && !result.webrtc_ips.includes(ip)) result.webrtc_ips.push(ip);
        };
        pc.createOffer().then(o => pc.setLocalDescription(o)).catch(()=>{});
      }
    } catch(e) { result.webrtc_error = String(e && e.message || e); finish(false); }
  });
}
const isPrivateIp = (ip) =>
  /^(10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.|127\.|100\.(6[4-9]|[7-9][0-9]|1[0-2][0-9])\.|169\.254\.)/.test(ip);
let rtcRow = null;

function classifyWebRtc() {
  // 返回 webrtc_state: leak / restricted / disabled / blocked
  if (result.webrtc_supported === false || result.webrtc_error) return 'blocked';
  if (result.webrtc_timed_out && result.webrtc_candidates.length === 0) return 'blocked';
  if (result.webrtc_candidates.length === 0) return 'disabled';
  const hasHost = result.webrtc_candidates.some(c => c.typ === 'host');
  const pub = result.webrtc_ips.filter(ip => !isPrivateIp(ip));
  if (pub.length) return 'leak';                       // 出口以外的公网 IP
  if (result.webrtc_ips.some(isPrivateIp) && hasHost) return 'leak';  // 内网 host 泄漏
  if (!hasHost) return 'restricted';                   // 只有 srflx=出口，无 host
  return 'leak';                                       // 有 host candidate 即暴露内网
}

function renderWebRtcRow() {
  const pub = result.webrtc_ips.filter(ip => !isPrivateIp(ip));
  result.webrtc_public = pub;
  result.webrtc_state = classifyWebRtc();
  result.webrtc_leak = result.webrtc_state === 'leak';
  result.webrtc_has_host = result.webrtc_candidates.some(c => c.typ === 'host');
  if (!rtcRow) rtcRow = addRow('WebRTC 采集', '…');
  const cells = {
    leak:    `<td class="bad">${result.webrtc_ips.join(', ')} ← 泄漏（公网 IP 暴露或内网 host 外泄）</td>`,
    restricted: `<td class="ok">合规：仅 srflx（出口 IP），无 host candidate</td>`,
    disabled: `<td class="warn">零 candidate（WebRTC 已禁用）——不扣分，但记为环境特征</td>`,
    blocked: `<td class="warn">探针被拦截（CSP/扩展/不支持）→ 记 unavailable，不能当通过</td>`,
  };
  rtcRow.innerHTML = '<td>WebRTC 状态</td>' + cells[result.webrtc_state];
  // 修复面板只在 leak 时展开；restricted/disabled 无需修复，blocked 给排查方向
  $('fix').style.display = result.webrtc_state === 'leak' ? 'block' : 'none';
  $('rtc').disabled = false;
}

// ---- DNS 泄漏（随机子域由服务端记录解析来源；本页先标记待服务端确认）----
result.dns_leak_token = Math.random().toString(36).slice(2, 10);

// ---- Canvas 指纹 ----
try {
  const c = document.createElement('canvas'); c.width = 240; c.height = 60;
  const g = c.getContext('2d');
  g.textBaseline = 'top';
  g.font = '16px Arial'; g.fillStyle = '#f60'; g.fillRect(0, 0, 100, 20);
  g.fillStyle = '#069'; g.fillText('ipaudit-env-probe \u2713', 2, 15);
  g.fillStyle = 'rgba(102,204,0,0.7)'; g.fillText('ipaudit-env-probe \u2713', 4, 25);
  const h = c.toDataURL().split('').reduce((a,ch)=>{a=((a<<5)-a)+ch.charCodeAt(0);
    return a & a;}, 0);
  result.canvas_hash = String(h);
  addRow('Canvas 指纹', h);
} catch(e) { addRow('Canvas 指纹', '采集失败', 'warn'); }

// ---- WebGL ----
try {
  const c = document.createElement('canvas');
  const gl = c.getContext('webgl') || c.getContext('experimental-webgl');
  const ext = gl.getExtension('WEBGL_debug_renderer_info');
  result.renderer = ext ? gl.getParameter(ext.UNMASKED_RENDERER_WEBGL) : '';
  result.gpu_sw = /swiftshader|software|llvmpipe/i.test(result.renderer);
  addRow('WebGL 渲染器', result.renderer || '(隐藏)', result.gpu_sw ? 'warn' : '');
} catch(e) { addRow('WebGL', '采集失败', 'warn'); }

// ---- 屏幕 / 硬件 ----
result.screen = `${screen.width}x${screen.height}@${screen.colorDepth}`;
result.hardware_concurrency = navigator.hardwareConcurrency || null;
result.hc_anomaly = !!navigator.hardwareConcurrency && navigator.hardwareConcurrency <= 2;
addRow('屏幕', result.screen);
addRow('时区偏移 vs IANA', '待服务端比对');

rtcRow = addRow('WebRTC 采集', '进行中…', 'warn');
webrtcProbe().then(renderWebRtcRow);
$('go').disabled = true;

function getToken() { return new URLSearchParams(location.search).get('t') || ''; }
const HAS_TOKEN = !!getToken();
if (!HAS_TOKEN) $('nosession').style.display = 'block';

async function newSession() {
  // 自愈：直接在当前页建新会话并跳转（无需 curl）
  const r = await fetch('/api/probe/session', {method: 'POST'});
  const j = await r.json();
  if (j.ok && j.url) location.href = j.url;
}

async function doSubmit(final) {
  if (!HAS_TOKEN) {
    $('status').innerHTML = '<span class="bad">无法提交：URL 缺少 ?t=token（见上方「缺少探针会话」说明）</span>';
    $('rtc').disabled = false;
    return;
  }
  const r = await fetch('/api/probe/submit', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({ token: getToken(), payload: result })
  });
  const j = await r.json();
  if (!final) {
    if (j.error && j.error.includes('会话不存在')) {
      $('nosession').style.display = 'block';
      $('status').innerHTML = '<span class="bad">会话已失效（服务重启过）——点上面「生成新会话链接」重来</span>';
      $('rtc').disabled = false;
      return;
    }
    const g = j.ok && j.checks ? `环境评级 ${j.checks.probe_grade}` : (j.error || '提交失败');
    $('status').innerHTML = j.ok
      ? `<span class="${j.checks.probe_grade==='clean'?'ok':'warn'}">复测已提交 ✓ ${g}</span>`
      : `<span class="bad">${g}</span>`;
    $('rtc').disabled = false;
    return;
  }
  document.body.innerHTML = j.ok
    ? '<div class="box"><h1>已提交 ✓</h1><p>回到检测工具页查看环境维度评级。可以关闭本页。</p></div>'
    : '<div class="box"><h1 style="color:#f87171">提交失败</h1><p>' + (j.error||'') + '</p></div>';
}

async function retest() {
  $('rtc').disabled = true;
  $('status').innerHTML = '重新采集 WebRTC…';
  result.webrtc_ips = [];
  result.webrtc_candidates = [];
  result.webrtc_state = '';
  result.webrtc_timed_out = false;
  result.webrtc_error = '';
  rtcRow.innerHTML = '<td>WebRTC 状态</td><td class="warn">复测中…</td>';
  await webrtcProbe();
  renderWebRtcRow();
  await doSubmit(false);           // 同 token 重提，服务端按更新语义重算评级
}
</script></body></html>
"""
