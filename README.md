# mosdns

功能概述、配置方式、教程等，详见: [wiki](https://irine-sistiana.gitbook.io/mosdns-wiki/)

下载预编译文件、更新日志，详见: [release](https://github.com/IrineSistiana/mosdns/releases)

docker 镜像: [docker hub](https://hub.docker.com/r/irinesistiana/mosdns)

## 日志与请求路径

排查请求处理过程时，在现有配置中设置：

```yaml
log:
  level: debug
  production: false
  file: ./mosdns.log
```

`production: false` 使用 console 格式，包含时间、级别、插件名称、事件和结构化字段；`true` 输出 JSON。省略 `file` 时写入 stderr。

日常使用 `level: info`。需要每次请求的执行链摘要时，将下面这一项放在服务器 `entry` 所指向的 sequence 的 `args` 开头：

```yaml
- exec: query_summary
```

`debug` 会自动记录公共入口、已配置的规则和下表中的插件决策，无需在每条规则插入 `debug_print`。逐规则、逐上游日志会增加输出量和 I/O，建议排障时按需启用；日志包含客户端 IP、查询域名和匹配条件。

| 事件或字段 | 含义 |
| --- | --- |
| `query received` | 请求通过入口检查，开始执行 |
| `condition evaluated` / `rule skipped` | 条件文本、是否匹配、规则跳过原因；多个条件按原有短路逻辑求值 |
| `rule executing` / `rule returned` | 执行项和返回状态；`rule` 从 0 开始，对应该 sequence 的规则位置；`jump` / `goto` 带目标名称 |
| `cache lookup` / `cache skipped` | `miss`、`hit`、`stale hit` 或无法缓存；命中后仍按配置执行后续规则 |
| `upstream query started` / `upstream query finished` | 实际发起的上游查询、响应状态及单次 `duration` |
| `upstream response selected` / `upstream response skipped` / `upstream result ignored` | 上游结果被采用、等待其他响应或在 forward 已返回后被忽略 |
| `branch started` / `branch finished` / `branch selected` | 分支执行与最终选择，`selected` 和 `reason` 说明采用哪一路及原因 |
| `probe wait elapsed` / `secondary waiting` | 探测窗口和 fallback 等待过程 |
| `address preference decision` | IPv4/IPv6 优选放行、抑制或停止的原因 |
| `query summary` | 当前执行链的 Info 摘要，包括错误；发生在服务器最终响应处理之前 |
| `response ready` | 已打包、准备返回的响应；以 `response` 对象为准，包括服务器生成的 SERVFAIL/REFUSED、`truncated` 和字节数；不代表网络发送已完成 |

`uqid` 是进程内的请求 ID，不是 DNS 报文 ID。同一请求的并发分支保留该 ID，`branch` 表示来源，例如 `pc_dispatch/local`；嵌套分支会追加路径，缓存后台刷新使用 `cache_tag/refresh`。后台分支可能在主请求响应后继续产生日志。

`qtype_name`、`qclass_name`、`rcode_name` 分别提供 `A`/`AAAA`、`IN`、`NOERROR`/`NXDOMAIN` 等名称，保留原有数字字段。未知类型使用 DNS 库的 `TYPE数字` 表示；未知返回码保留数字且不输出空名称。`has_resp` 明确区分无响应和空答案，`answers` 是答案条数，`elapsed` 是请求开始以来的耗时。上游使用配置的 tag 标识；未设置 tag 时，通过 `upstream_index` 定位本次 forward 使用的上游列表，索引从 0 开始。

下面摘录自本机 UDP 测试上游的实际请求日志，省略时间戳和重复字段：

```text
DEBUG main        condition evaluated        {"rule": 1, "exec": "reject", "query": {"uqid": 19}, "condition": "qtype 28", "matched": false}
DEBUG cache       cache lookup               {"query": {"uqid": 19}, "result": "miss"}
DEBUG main        rule executing             {"rule": 4, "exec": "jump resolve", "query": {"uqid": 19}}
DEBUG up          upstream response selected {"uqid": 19, "upstream": "loopback", "response": {"rcode_name": "NOERROR", "answers": 1}}
INFO  main.r0     query summary              {"uqid": 19, "qname": "cached.test.", "qtype_name": "A", "has_resp": true, "rcode_name": "NOERROR", "answers": 1}
DEBUG test_server response ready             {"query": {"uqid": 19}, "response": {"rcode_name": "NOERROR", "answers": 1}, "truncated": false, "bytes": 56}
```

同次测试的分支选择记录如下，省略时间戳和重复字段。该请求在等待窗口内没有收到 probe 反馈，因此采用 local：

```json
{"logger":"pc_local","msg":"branch selected","query":{"uqid":6},"selected":"local","reason":"probe wait elapsed without feedback","response":{"rcode_name":"NOERROR","answers":1}}
```

按请求 ID 筛选 console 或 JSON 日志：

```sh
rg '"uqid":[[:space:]]*19[,}]' mosdns.log
```

## 自定义插件说明

以下为本分支新增/调整的可执行插件说明。

### 1) ip_rewrite

- **用途**: 将当前响应中的 A/AAAA 记录改写为指定 IP。
- **注意**: 该插件只改写已有响应，若当前无响应（`qCtx.R()==nil`）则不会生成新响应。

配置示例:

```yaml
- tag: gfw_ip_rewrite
  type: ip_rewrite
  args:
    ipv4: "6.6.6.6"
    ipv6: "2607:f8b0:4007:814::2004"
```

### 2) raceback

- **用途**: 并发执行 `probe_exec` 和 `local_exec`，用于“探测优先、50ms 后放行 local”的竞速调度。
- **核心逻辑**:
  - 同时启动 `probe_exec` 与 `local_exec`。
  - 在 `probe_wait` 窗口内，不直接返回 local 结果。
  - 只要 probe 返回有效响应（`resp != nil`），立即采用 probe 响应。
  - `probe_wait` 到期后，若 local 已返回且 probe 未命中，则采用 local（含空结果或 error）。

参数:

- `probe_exec` (required)
- `local_exec` (required)
- `probe_wait` (optional, 默认 50ms)
- `timeout` (optional, 默认 300ms)

配置示例:

```yaml
- tag: dynamic_race_dispatcher
  type: raceback
  args:
    probe_exec: gfw_sequence
    local_exec: local_sequence
    probe_wait: 50
    timeout: 300
```

### 3) probe_choice

- **用途**: 三路并发执行 `probe_exec` / `remote_exec` / `local_exec`，由 probe 结果决定采用 remote 或 local。
- **核心逻辑**:
  - 三个 exec 同时启动。
  - 若 probe 在 `probe_wait` 内有任意反馈（含有响应/空结果/error），最终采用 remote 的结果。
  - 若 `probe_wait` 到期仍无 probe 反馈，先按 local 结果决策。
  - 若后续 probe 才反馈，在未返回前会切换为 remote 优先。

参数:

- `probe_exec` (required)
- `remote_exec` (required)
- `local_exec` (required)
- `probe_wait` (optional, 默认 50ms)

配置示例:

```yaml
- tag: pc_dispatch
  type: probe_choice
  args:
    probe_exec: gfw_probe_seq
    remote_exec: remote_seq
    local_exec: local_seq
    probe_wait: 50
```
