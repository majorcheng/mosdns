# mosdns

功能概述、配置方式、教程等，详见: [wiki](https://irine-sistiana.gitbook.io/mosdns-wiki/)

下载预编译文件、更新日志，详见: [release](https://github.com/IrineSistiana/mosdns/releases)

docker 镜像: [docker hub](https://hub.docker.com/r/irinesistiana/mosdns)

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
