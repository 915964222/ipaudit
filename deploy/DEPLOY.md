# 部署：unbound 专用解析器 + ipaudit

解决两件事：Spamhaus 对公共解析器的拒绝/限流，以及**解析器自身绝不能变成
开放 DNS 放大器**。

## 一、同机部署（推荐，VPS 单机跑全套）

```bash
apt install unbound
cp deploy/unbound.conf /etc/unbound/unbound.conf.d/ipaudit.conf
unbound-check                    # 配置校验
systemctl restart unbound
```

监听 `127.0.0.1:53`，只服务本机。ipaudit 直接用默认配置即可：

```bash
ipaudit 8.8.8.8                  # 自动读系统 DNS（即本机 unbound）
ipaudit --resolver 127.0.0.1 8.8.8.8    # 显式指定更稳
```

验证 Spamhaus 通了：

```bash
ipaudit resolver-check 127.0.0.1
```

## 二、跨机部署（扫描节点与解析节点分离）

1. 两台机器之间建 WireGuard（示例网段 `10.66.0.0/24`，解析节点 `10.66.0.1`）。
2. unbound.conf 里注释掉 `127.0.0.1` 的 interface，启用 `interface: 10.66.0.1`，
   并确认 `access-control: 10.66.0.0/24 allow`。
3. 扫描节点上：`ipaudit --resolver 10.66.0.1 ...`，或 `serve --resolver 10.66.0.1`。
4. **防火墙再加一层**（ufw 示例）：

```bash
ufw default deny incoming
ufw allow in on wg0 to any port 53 proto udp    # 53 只对 wg0 网卡开放
ufw allow 22/tcp
ufw enable
```

5. 从**外部机器**验证没有开放递归（这一步必须做，别只在本机测）：

```bash
# 在第三方机器上，对着解析节点的公网 IP 查
dig @<公网IP> example.com A +timeout=5
# 期望：REFUSED 或超时。返回答案 = 开放递归 = 立刻回去查 ACL

# 放大向量专项：ANY 查询必须被拒
dig @<公网IP> example.com ANY +timeout=5 +ignore
# 期望：REFUSED
```

也可以在线验：[openresolverproject.org](https://openresolverproject.org) 输入公网 IP 检测。

## 三、开放递归的后果（为什么这步不能省）

开放递归解析器会被扫描器在几分钟内收录进放大攻击列表。后果按顺序发生：

1. 你的 VPS 出口带宽被借去打 DDoS（1:50+ 放大系数）；
2. 上游机房限速 / 下架；
3. VPS 的 IP 进 Spamhaus DROP / SBL；
4. ——你做的是 IP 质量检测生意，**自己的解析器 IP 进黑名单等于自毁招牌**。

## 四、ipaudit 侧的访问控制

HTTP 服务默认只绑 `127.0.0.1`；跨机访问时才需要 `--bind 0.0.0.0`
或内网 IP，**此时必须同时开 `--auth`**：

```bash
ipaudit serve                          # 默认 127.0.0.1:9650，本机用
ipaudit serve --bind 0.0.0.0 --auth    # 跨机：必须配 token，否则拒绝启动
```

探测页同理：跨机打开探针页时，服务会拒绝未鉴权访问；探针提交接口只收
会话 token，不开放匿名提交。

## 五、监控解析器健康

```bash
# 定期自检（可挂 cron）：Spamhaus 无效码 → 说明解析路径被限流了
ipaudit resolver-check 127.0.0.1

# unbound 自身
unbound-control status
unbound-control stats_noreset | grep total.num.queries
```
