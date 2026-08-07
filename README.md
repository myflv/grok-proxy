# grok-proxy

Grok 多账号反向代理。CPA 轮询 + RT 自动续命 + SSO 复活死号。

**对客户端始终是一个端点，一个 api_key。**

## 配置

```json
{
  "listen": "0.0.0.0:5001",
  "api_key": "sk-local-fixed",
  "cpa_dir": "/data/cpa/*.json",
  "sso_file": "/data/sso/accounts.txt",
  "refresh_interval": 300,
  "refresh_lead": 600,
  "revive_enabled": true,
  "revive_interval": 600,
  "revive_concurrency": 2,
  "proxy": ""
}
```

| 字段 | 说明 |
|------|------|
| `listen` | 监听地址，默认 `:5001` |
| `api_key` | 客户端固定 key（空则不校验） |
| `cpa_dir` | CPA 通配路径，如 `/data/cpa/*.json`（**不加载** `*.json.dead`） |
| `sso_file` | 注册机 `SSO/accounts.txt`（`email:pass:sso`），或目录 |
| `refresh_interval` | 主动刷新扫描周期（秒），默认 300 |
| `refresh_lead` | 剩余 TTL ≤ 该秒数则换票。默认 **0 = 2×refresh_interval**（300→600s）。可自行改小/改大 |
| `revive_enabled` | 是否用 SSO 复活死 RT（有 `sso_file` 时默认开） |
| `revive_interval` | 限流重试扫描间隔（秒），默认 600 |
| `revive_concurrency` | 同时 SSO OAuth 数，默认 2（防 429；2000 号务必小） |
| `proxy` | 可选出站代理。支持 `http://`、`https://`、`socks5://`、`socks5h://`（含 `user:pass` 认证），如 `socks5://127.0.0.1:1080` |

## 选号策略（粘性）

**不是每个请求轮询。** 一直用当前号，直到该号不可用再切下一个：

| 触发 | 行为 |
|------|------|
| 正常 2xx | 继续用同一号 |
| 429 | 该号冷却 65s，cursor 前进，换下一号 |
| 402 额度 | 该号冷却 1h，换下一号 |
| 401/403 + RT 刷失败 | 软死/冷却，换下一号 |
| access_token 带 `bfs` claim | **不选号出站**；仍加载 + RT 续期；刷新后若 `bfs` 消失则恢复可用 |
| 单请求内 | 最多 **8 次真实上游尝试/换号**（429/402/401）；`bfs` 跳过不计入 |

```
启动
  → 只加载 *.json（跳过 *.json.dead 坟场）
  → 解析 AT JWT：带 `bfs` 的号标记为 serve-skip（仍入池）
  → 定时 refresh（每 refresh_interval）：全池判断，TTL≤refresh_lead 才换票写回
  → RT invalid_grant → 软死 + 排队 SSO（文件仍是 *.json）
  → SSO 成功 → 写新 token，复活
  → SSO 永久失败 / 无 SSO → 改名 *.json.dead（下次启动永不再碰）
  → SSO 429 → 留在队列稍后重试（不改名）
```

| 事件 | 处理 |
|------|------|
| AT 将过期 | 仅定时扫描：TTL≤`refresh_lead`（默认 2×interval）时 RT 换票写回；启动以 JWT `exp` 为准；401/空 AT 仍可应急刷 |
| AT 含 `bfs` | 不参与上游选号；RT 仍续；刷新后重检 claim |
| RT 吊销 | 软死 → **先 SSO**；成功则活，失败才 `.dead` |
| SSO 复活成功 | 写新 token，入池 |
| SSO 永久失败 | `*.json.dead`，下次启动跳过（不反复打 SSO） |
| SSO 限流 | 重试，不改名 |
| 上游 429 | 冷却 65s 切号 |
| 上游 402 | 冷却 1h 切号（额度，不是 token） |

## Docker

```bash
mkdir -p cpa sso
# CPA
cp /path/to/outputs/*/CPA/xai-*.json cpa/
# SSO（合并去重）
cat /path/to/outputs/*/SSO/accounts.txt | awk -F: '!e[$1]++' > sso/accounts.txt
# 改 api_key
cp config.json.example config.json   # 或编辑仓库里的 config.json

docker compose up -d
curl -s localhost:5001/healthz
```

镜像：`ghcr.io/myflv/grok-proxy:v0.4.5` / `latest`

## 调用

```bash
curl http://127.0.0.1:5001/v1/chat/completions \
  -H "Authorization: Bearer sk-local-fixed" \
  -H "Content-Type: application/json" \
  -d '{"model":"grok-4","messages":[{"role":"user","content":"hi"}]}'
```

```python
from openai import OpenAI
client = OpenAI(api_key="sk-local-fixed", base_url="http://127.0.0.1:5001")
```

健康检查：`GET /healthz` → `live` / `total` / `bfs` / `sso` / `revive_queue`

## 源码运行

```bash
go build -o grok-proxy .
./grok-proxy config.json
```
