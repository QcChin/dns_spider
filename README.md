# dns_spider

高性能 DNS 抓包与协议分析工具

## 项目简介

dns_spider 是一个支持多种抓包后端（pcap、XDP、DPDK）的高性能 DNS 流量采集与协议分析工具，适用于网络安全、流量监控、协议研究等场景。

## 主要功能
- 支持多种抓包方式：libpcap、XDP、DPDK
- 支持 DNS/DoT/DoH/DoQ 协议自动识别与解析
- 支持多线程高性能采集
- 支持多种输出方式（控制台、文件、Kafka、StatsD等）
- 丰富的统计信息输出
- 灵活的配置文件支持

## 依赖环境
- Rust 1.60+
- libpcap（如需pcap模式）
- DPDK/XDP 相关依赖（如需高性能模式）

## 构建方法
```bash
# 推荐使用release模式编译
cargo build --release
```

## 运行示例
```bash
# 使用默认配置（pcap模式，抓取53端口DNS流量）
dns_spider --config conf.toml
```

## 配置说明
- 配置文件位于 `config/` 目录，支持多环境（dev、prod）。
- 主要配置项：
  - `mode`: 抓包模式（pcap/xdp/dpdk）
  - `interface`: 网络接口名
  - `filter`: BPF过滤表达式
  - `output`: 输出方式及参数

## 抓包模式说明
- **pcap**：通用，易用，依赖libpcap，适合大多数环境
- **XDP**：高性能，需内核支持，适合大流量场景
- **DPDK**：极致性能，需专用驱动，适合专业网络环境

## 贡献方式
欢迎提交 issue、PR 或建议！

## License
MIT