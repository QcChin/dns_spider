dns_spirder/
├── Cargo.toml
├── build.rs # 可选：特殊构建配置
├── config/
│ ├── dev.toml # 开发环境配置
│ ├── prod.toml # 生产环境配置
│ └── mod.rs # 配置加载逻辑
├── src/
│ ├── main.rs # 主入口
│ ├── core/
│ │ ├── driver.rs # 抓包主驱动逻辑
│ │ ├── mempool.rs # 内存池实现
│ │ └── stats.rs # 统计计数器
│ ├── capture/
│ │ ├── pcap.rs # libpcap 实现
│ │ ├── xdp.rs # XDP/eBPF 实现
│ │ └── dpdk.rs # DPDK 实现（可选）
│ ├── protocols/
│ │ ├── dns/
│ │ │ ├── mod.rs # DNS 协议主逻辑
│ │ │ ├── udp.rs # UDP 协议处理
│ │ │ ├── tcp.rs # TCP 流重组
│ │ │ ├── dot.rs # DNS over TLS
│ │ │ ├── doh.rs # DNS over HTTPS
│ │ │ └── doq.rs # DNS over QUIC
│ │ └── detect.rs # 协议检测器
│ ├── output/
│ │ ├── kafka.rs # Kafka 生产者
│ │ ├── file.rs # 文件存储
│ │ ├── statsd.rs # 统计输出
│ │ └── console.rs # 控制台输出
│ ├── utils/
│ │ ├── time.rs # 高性能时间处理
│ │ ├── macros.rs # 自定义宏
│ │ └── simd.rs # SIMD 加速代码
│ ├── async_rt/
│ │ ├── executor.rs # 自定义执行器
│ │ └── scheduler.rs# 任务调度策略
│ └── error.rs # 统一错误处理
├── benches/ # 基准测试
│ └── packet_bench.rs
├── tests/ # 集成测试
│ ├── protocol_tests/
│ └── e2e_tests/
├── scripts/ # 部署/运维脚本
│ ├── setup_xdp.sh
│ └── perf_tuning.sh
├── docs/ # 文档
│ ├── ARCHITECTURE.md
│ └── PROTOCOL.md
└── .github/workflows/ # CI/CD
└── rust-ci.yml
