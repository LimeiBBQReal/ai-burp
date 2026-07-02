# proxy/ — DOLA 代理模块

## 目录结构

```
proxy/
├── mini_clash.py           mihomo 控制器 (所有代理的基础)
├── node_pool.py            IP + 积分池 (生产环境用)
├── http_probe.py           DOLA 能力探测 - V2Ray 节点 (curl_cffi)
├── fetch_free_nodes.py     V2Ray 节点下载 (GitHub 源)
├── fetch_from_sources.py   HTTP/SOCKS5 代理批量采集 (32 源)
├── verify_proxies.py       批量存活验证 (curl_cffi 测 dola.com)
├── probe_http_proxies.py   HTTP 代理 DOLA 能力探测 (直接 curl_cffi)
├── multi_sample.py         多轮抽样测活 (V2Ray 节点)
├── quick_alive_test.py     快速测活 (单轮抽样)
├── merge_proxies.py        合并 CAPABLE 代理到 dola_capable.yaml
├── export_capable.py       导出 CAPABLE 节点 (旧版)
├── proxy_sources.json      32 个高质量代理源清单 (分级)
└── yaml/
    ├── dola_capable.yaml          当前 CAPABLE 节点池 (119 节点)
    ├── free_nodes_merged.yaml     V2Ray 合并池 (19000+ 节点)
    ├── proxy_alive.yaml           存活 HTTP 代理
    ├── dola_capable_proxies.yaml  DOLA 通过的 HTTP 代理 (65 个)
    ├── paid_proxies_template.yaml 付费代理配置模板
    └── proxy_raw/
        ├── http_proxies.txt       原始 HTTP 代理列表
        ├── http_alive.txt         存活 HTTP 代理
        ├── socks5_proxies.txt     原始 SOCKS5 代理列表
        └── socks5_alive.txt       存活 SOCKS5 (curl_cffi 不兼容, 0 个)
```

## 核心模块

### MiniClash (mini_clash.py)
封装 mihomo 二进制, 提供大模型友好的 API:
```python
from proxy.mini_clash import MiniClash

mc = MiniClash(config_path="yaml/dola_capable.yaml")
mc.start()
mc.switch_node("节点名")
mc.list_nodes()
mc.get_exit_ip()
mc.proxy_url()  # socks5h://127.0.0.1:{port}
mc.stop()
```

### NodePool (node_pool.py)
IP + 积分池, 并发安全:
```python
from proxy.node_pool import get_pool

pool = get_pool()      # 加载 + 预热 8 个节点
node = pool.acquire()   # 租一个有积分的节点 (预扣积分)
# ... 用 node.proxy_url 做请求 ...
pool.release(node, success=True)   # 归还
pool.stats()           # 查看统计
```

## 节点池更新流程

```bash
# V2Ray 节点 (免费)
cd proxy
python fetch_free_nodes.py                    # 下载
python multi_sample.py                        # 抽样测活
python http_probe.py --yaml yaml/free_nodes_alive_merged.yaml  # DOLA 探测

# HTTP 代理 (GitHub 免费源)
python fetch_from_sources.py                  # 下载
python verify_proxies.py                      # 存活验证
python probe_http_proxies.py                  # DOLA 探测

# HTTP 代理 (Shodan, 需要 API Key)
python fetch_shodan.py --limit 2000           # 采集
python fetch_shodan.py --country US,SG,KR     # 按国家
python verify_proxies.py                      # 验证 (会自动合并 Shodan 代理)
python probe_http_proxies.py                  # DOLA 探测

# 合并到 dola_capable.yaml
python merge_proxies.py

# 付费代理 (手动编辑 yaml/paid_proxies_template.yaml)
python http_probe.py --yaml yaml/paid_proxies_template.yaml
```

## 路径注意

从根目录调用时, dola_capable.yaml 路径需要更新:
```python
# 旧: yaml/dola_capable.yaml
# 新: proxy/yaml/dola_capable.yaml
```

`config.py` 和 `node_pool.py` 里的路径已经更新。
