## Mosdns SOCKS5+ (Beta)

### 背景

mosdns 已支持 SOCKS5 转发 DNS over TCP 查询（TCP、DoT、DoH），但基于 UDP 的协议（DNS over UDP、DoQ、DoH3）无法经过 SOCKS5。本 Fork 补齐了全部 UDP 通路，包括 QUIC 和 HTTP/3。

```text
  mosdns 查询流程

  ┌─────────┐    ┌──────────┐    ┌─────────┐
  │ Server  │───▶│ Sequence │───▶│ Forward │   (socks5: "x.x.x.x:1080")
  │ UDP/TCP │    │  (rules) │    │         │
  └─────────┘    └──────────┘    └────┬────┘
                                      │
                       ┌──────────────┴──────────────┐
                       ▼                             ▼
                 ┌───────────┐                 ┌───────────┐
                 │UDP Path   │                 │TCP Path   │
                 │Pipeline   │                 │ReuseConn  │
                 └─────┬─────┘                 └─────┬─────┘
                       │                             │
                       │                             │
  原版 ────────────────────────────────────────────────────────
                       │                             │
                       ▼                             ▼
                    本地网络                        SOCKS5
                       │                             │
                       ▼                             ▼
                  Remote DNS                     Remote DNS
                     (直连)                      (SOCKS5转发)
           (会遇到预期外的CDN错乱等问题)
  本 Fork ──────────────────────────────────────────────────────
                       │                             │
                       ▼                             ▼
                    SOCKS5                         SOCKS5
                       │                             │
                       ▼                             ▼
                  Remote DNS                     Remote DNS
                  (SOCKS5转发)                   (SOCKS5转发)

```


### 使用

和原有配置方式完全一致（详见 [mosdns wiki](https://irine-sistiana.gitbook.io/mosdns-wiki)），只是 `socks5` 字段现在可以同时应用在 UDP 和 TCP：

```yaml
plugins:
  - tag: forward
    type: forward
    args:
      socks5: "127.0.0.1:1080"
      upstream:
        - udp: 1.1.1.1:53
```

### 协议规范

| 规范 | 状态 |
| --- | --- |
| RFC 1928 - SOCKS5 UDP ASSOCIATE | 已实现 |
| RFC 1928 - 分片（FRAG） | 未实现，DNS 场景不需要 |
| RFC 1929 - 用户名/密码认证 | 未实现，不对原版进行破坏性修改 |

### 协议支持

| 协议 | Socks5转发 |
| --- | --- |
| TCP / DoT / DoH | ✅ 原版支持 |
| DNS over UDP | ✅ 新增 |
| DoQ (QUIC) | ✅ 新增 |
| DoH3 (HTTP/3) | ✅ 新增 |
