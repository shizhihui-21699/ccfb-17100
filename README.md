# shortlink — 短链与跳转服务安全改造(Go)

把公司短链服务从"信任背书"改造成"可审计的转发工具":创建时评估目标风险、对存量短链持续巡检页面结构变化、外链跳转给中转提示页、滥用链接一键按人/按域/按活动封禁并追溯。

设计取舍、威胁模型与残余风险见 **[docs/DESIGN.md](docs/DESIGN.md)**。

## 核心防线(一句话版)

- **审批不是盖章,是结构指纹快照**:基线记录"表单提交到哪、有没有密码框、跳到哪、触及哪些第三方域";巡检比对**硬漂移**,变了就隔离。
- **点击结论每次重新算**:绝不信任"创建时是安全的";隔离/吊销优先级最高。
- **低分 ≠ 可信**:非一方落地页默认走中转页,分数只决定要不要人工介入。
- **抓取器按恶意 URL 设计**:拨号时再校验 IP(防 DNS rebinding)、限体积、逐跳校验重定向。
- **审计是哈希链**:改一条,后面全断;支持落盘与重启续链。
- **业务页开放重定向**:`internal/saferedirect` 纯白名单,不做启发式放行。

## 目录

```
cmd/shortlinkd/          进程入口 + 巡检循环
internal/dest/           建链时廉价校验(无网络)
internal/risk/           风险打分(创建期/巡检期)
internal/artifact/       页面结构指纹 + 漂移比对 + HMAC 签名
internal/htmlx/          容错 HTML 解析
internal/probe/          安全抓取器(防 SSRF/rebinding/炸弹)
internal/service/        编排:创建/点击/巡检/级联封禁
internal/saferedirect/   业务页开放重定向白名单修复
internal/audit/          哈希链审计
internal/store/          存储接口 + 内存实现
internal/httpapi/        公开路由 + 管理路由 + 中转页模板
scripts/demo.sh          真实 HTTP 端到端演示
```

## 快速开始

```bash
# 全部测试(含 approve-then-swap、token 伪造、开放重定向、审计篡改等)
go test ./...

# 端到端演示:真实起一个"合作方"站点,演示 过审→换页→隔离→封禁→追溯
./scripts/demo.sh

# 运行
go run ./cmd/shortlinkd \
  -public-addr :8080 -admin-addr 127.0.0.1:8081 \
  -base-url https://s.example.com -self-hosts s.example.com \
  -allowlist 'partner-a.com,*.partner-b.com' -first-party 'example.com' \
  -seal-key "$(head -c32 /dev/urandom | base64)" -audit-log /var/log/shortlink/audit.log
```

## 管理 API 速览

| 方法 | 路径 | 用途 |
|---|---|---|
| POST | `/api/links` | 建链(自动校验 + 打分) |
| GET  | `/api/links` | 按创建人/活动/状态/域名查询 |
| POST | `/api/links/{id}/approve` | 人工审核(**重抓当前页**后重置基线) |
| POST | `/api/links/{id}/revoke` | 封禁单条(必填 reason) |
| POST | `/api/revoke/domain` | 按注册域一键封禁全部活链 |
| POST | `/api/revoke/campaign` | 按活动封禁 |
| POST | `/api/revoke/creator` | 按账号封禁(账号被盗场景) |
| GET  | `/api/links/{id}/audit` | 追溯该链的全部事件 |
| GET  | `/api/audit/verify` | 校验审计链完整性 |
| GET/POST | `/api/allowlist` | 合作方域名白名单(支持 TTL) |

公开路由:`GET /{code}`(决策)、`GET /{code}/go?t=`(中转页同意)、`POST /{code}/report`(举报)。

## 生产注意

- 管理 API 必须在 SSO/mTLS 之后,绝不与公网路由共用中间件。
- 必须配置 `-seal-key`,否则基线不跨重启保留。
- `-allow-private-net` 仅供测试;生产开启会重新引入 SSRF。
- 审计链需同步外推到独立只写存储(WORM/SIEM),本地链用于对账。
- 业务侧所有 `redirect/next/return/...` 参数收敛到 `saferedirect.Resolve`。
