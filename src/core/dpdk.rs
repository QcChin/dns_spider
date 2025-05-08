//! DPDK模块实现
//! 提供高性能网络数据包处理功能

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Instant;

#[cfg(feature = "dpdk")]
use dpdk_rs::{self, Mbuf, MemPool, Port, PortConf, PortId, PortInfo};

use crate::core::stats::StatsCounter;

/// DPDK配置
pub struct DpdkConfig {
    /// EAL参数
    pub eal_args: Vec<String>,
    /// 使用的网卡端口ID
    pub port_ids: Vec<u16>,
    /// 每个端口的接收队列数
    pub rx_queues: u16,
    /// 每个端口的发送队列数
    pub tx_queues: u16,
    /// 内存池大小
    pub mempool_size: u32,
    /// 内存池缓存大小
    pub mempool_cache_size: u32,
    /// mbuf大小
    pub mbuf_size: u16,
}

impl Default for DpdkConfig {
    fn default() -> Self {
        DpdkConfig {
            eal_args: vec!["dns-spider".to_string()],
            port_ids: vec![0],
            rx_queues: 1,
            tx_queues: 1,
            mempool_size: 8192,
            mempool_cache_size: 256,
            mbuf_size: 2048,
        }
    }
}

/// DPDK实例
pub struct DpdkInstance {
    /// 配置
    config: DpdkConfig,
    /// 内存池
    #[cfg(feature = "dpdk")]
    mempool: Option<Arc<MemPool>>,
    /// 端口信息
    #[cfg(feature = "dpdk")]
    ports: HashMap<u16, Port>,
    /// 统计计数器
    stats: Arc<Mutex<StatsCounter>>,
    /// 是否已初始化
    initialized: bool,
}

impl DpdkInstance {
    /// 创建新的DPDK实例
    pub fn new(config: DpdkConfig, stats: Arc<Mutex<StatsCounter>>) -> Self {
        DpdkInstance {
            config,
            #[cfg(feature = "dpdk")]
            mempool: None,
            #[cfg(feature = "dpdk")]
            ports: HashMap::new(),
            stats,
            initialized: false,
        }
    }

    /// 初始化DPDK
    pub fn initialize(&mut self) -> crate::error::Result<()> {
        #[cfg(feature = "dpdk")]
        {
            // 已经初始化则返回
            if self.initialized {
                return Ok(());
            }

            // 初始化EAL
            let args: Vec<&str> = self.config.eal_args.iter().map(|s| s.as_str()).collect();
            match dpdk_rs::eal_init(args) {
                Ok(_) => {
                    println!("DPDK EAL初始化成功");
                }
                Err(e) => {
                    return Err(crate::error::Error::Dpdk(format!("EAL初始化失败: {}", e)));
                }
            }

            // 创建内存池
            let mempool = match MemPool::create(
                "dns_spider_mempool",
                self.config.mempool_size,
                self.config.mempool_cache_size,
                self.config.mbuf_size,
            ) {
                Ok(mp) => {
                    println!("DPDK内存池创建成功");
                    Arc::new(mp)
                }
                Err(e) => {
                    return Err(crate::error::Error::Dpdk(format!("内存池创建失败: {}", e)));
                }
            };

            self.mempool = Some(Arc::clone(&mempool));

            // 初始化端口
            for &port_id in &self.config.port_ids {
                let port_id = PortId::new(port_id);

                // 获取端口信息
                let port_info = match PortInfo::get(port_id) {
                    Ok(info) => info,
                    Err(e) => {
                        return Err(crate::error::Error::Dpdk(format!(
                            "获取端口{}信息失败: {}",
                            port_id.0, e
                        )));
                    }
                };

                println!("端口{}: {}", port_id.0, port_info.name());
                println!("  MAC地址: {}", port_info.mac_addr());
                println!("  最大接收队列: {}", port_info.max_rx_queues());
                println!("  最大发送队列: {}", port_info.max_tx_queues());

                // 配置端口
                let mut port_conf = PortConf::default();
                port_conf.rx_queues = self.config.rx_queues;
                port_conf.tx_queues = self.config.tx_queues;

                // 初始化端口
                let port = match Port::configure(port_id, &port_conf, &mempool) {
                    Ok(p) => p,
                    Err(e) => {
                        return Err(crate::error::Error::Dpdk(format!(
                            "配置端口{}失败: {}",
                            port_id.0, e
                        )));
                    }
                };

                // 启动端口
                if let Err(e) = port.start() {
                    return Err(crate::error::Error::Dpdk(format!(
                        "启动端口{}失败: {}",
                        port_id.0, e
                    )));
                }

                // 设置混杂模式
                if let Err(e) = port.promiscuous_enable() {
                    return Err(crate::error::Error::Dpdk(format!(
                        "设置端口{}混杂模式失败: {}",
                        port_id.0, e
                    )));
                }

                self.ports.insert(port_id.0, port);
                println!("端口{}初始化成功", port_id.0);
            }

            self.initialized = true;
            Ok(())
        }

        #[cfg(not(feature = "dpdk"))]
        {
            Err(crate::error::Error::Dpdk(
                "DPDK功能未启用，请在Cargo.toml中启用dpdk特性".to_string(),
            ))
        }
    }

    /// 接收数据包
    pub fn receive_packets(
        &mut self,
        port_id: u16,
        queue_id: u16,
        max_packets: u16,
    ) -> Vec<Vec<u8>> {
        let mut packets = Vec::new();

        #[cfg(feature = "dpdk")]
        {
            if !self.initialized {
                return packets;
            }

            if let Some(port) = self.ports.get(&port_id) {
                let mut mbufs = Vec::with_capacity(max_packets as usize);
                let rx_count = match port.rx_burst(queue_id, &mut mbufs) {
                    Ok(count) => count,
                    Err(_) => 0,
                };

                if rx_count > 0 {
                    // 更新统计信息
                    if let Ok(mut stats) = self.stats.lock() {
                        stats.add("dpdk.rx_packets", rx_count as u64);
                    }

                    // 处理接收到的数据包
                    for mbuf in mbufs.iter().take(rx_count) {
                        let data = mbuf.data();
                        packets.push(data.to_vec());
                    }
                }
            }
        }

        packets
    }

    /// 发送数据包
    pub fn send_packets(&mut self, port_id: u16, queue_id: u16, packets: &[Vec<u8>]) -> usize {
        #[cfg(feature = "dpdk")]
        {
            if !self.initialized || packets.is_empty() {
                return 0;
            }

            if let (Some(port), Some(mempool)) = (self.ports.get(&port_id), &self.mempool) {
                let mut mbufs = Vec::with_capacity(packets.len());

                // 创建mbuf并填充数据
                for packet in packets {
                    if let Ok(mut mbuf) = Mbuf::alloc(mempool) {
                        if mbuf.append(packet).is_ok() {
                            mbufs.push(mbuf);
                        }
                    }
                }

                // 发送数据包
                let tx_count = match port.tx_burst(queue_id, &mbufs) {
                    Ok(count) => count,
                    Err(_) => 0,
                };

                // 更新统计信息
                if tx_count > 0 {
                    if let Ok(mut stats) = self.stats.lock() {
                        stats.add("dpdk.tx_packets", tx_count as u64);
                    }
                }

                return tx_count;
            }

            0
        }

        #[cfg(not(feature = "dpdk"))]
        {
            0
        }
    }

    /// 获取端口统计信息
    pub fn get_port_stats(&self, port_id: u16) -> Option<(u64, u64)> {
        #[cfg(feature = "dpdk")]
        {
            if !self.initialized {
                return None;
            }

            if let Some(port) = self.ports.get(&port_id) {
                if let Ok(stats) = port.stats() {
                    return Some((stats.rx_packets(), stats.tx_packets()));
                }
            }

            None
        }

        #[cfg(not(feature = "dpdk"))]
        {
            None
        }
    }

    /// 关闭DPDK
    pub fn shutdown(&mut self) {
        #[cfg(feature = "dpdk")]
        {
            if !self.initialized {
                return;
            }

            // 停止所有端口
            for (port_id, port) in &self.ports {
                if let Err(e) = port.stop() {
                    eprintln!("停止端口{}失败: {}", port_id, e);
                }
            }

            // 清理资源
            self.ports.clear();
            self.mempool = None;
            self.initialized = false;

            println!("DPDK已关闭");
        }
    }
}

impl Drop for DpdkInstance {
    fn drop(&mut self) {
        self.shutdown();
    }
}
