//! DPDK捕获模块实现
//! 基于DPDK的高性能数据包捕获

use std::sync::{Arc, Mutex};

use super::{CaptureConfig, CaptureStats, PacketCapture};
use crate::core::dpdk::{DpdkConfig, DpdkInstance};
use crate::core::stats::StatsCounter;
use crate::error;

/// DPDK捕获配置
#[derive(Debug, Clone)]
pub struct DpdkCaptureConfig {
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

impl Default for DpdkCaptureConfig {
    fn default() -> Self {
        DpdkCaptureConfig {
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

/// DPDK捕获实现
pub struct DpdkCapture {
    /// 捕获配置
    config: CaptureConfig,
    /// DPDK特定配置
    dpdk_config: DpdkCaptureConfig,
    /// DPDK实例
    dpdk: Option<DpdkInstance>,
    /// 统计计数器
    stats: Arc<Mutex<StatsCounter>>,
    /// 是否正在捕获
    is_capturing: bool,
    /// 当前使用的端口ID
    current_port: u16,
    /// 当前使用的队列ID
    current_queue: u16,
    /// 捕获统计信息
    capture_stats: CaptureStats,
}

impl DpdkCapture {
    /// 创建新的DPDK捕获实例
    pub fn new(
        config: CaptureConfig,
        dpdk_config: DpdkCaptureConfig,
        stats: Arc<Mutex<StatsCounter>>,
    ) -> Self {
        DpdkCapture {
            config,
            dpdk_config,
            dpdk: None,
            stats,
            is_capturing: false,
            current_port: 0,
            current_queue: 0,
            capture_stats: CaptureStats::default(),
        }
    }

    /// 将DpdkCaptureConfig转换为DpdkConfig
    fn create_dpdk_config(&self) -> DpdkConfig {
        DpdkConfig {
            eal_args: self.dpdk_config.eal_args.clone(),
            port_ids: self.dpdk_config.port_ids.clone(),
            rx_queues: self.dpdk_config.rx_queues,
            tx_queues: self.dpdk_config.tx_queues,
            mempool_size: self.dpdk_config.mempool_size,
            mempool_cache_size: self.dpdk_config.mempool_cache_size,
            mbuf_size: self.dpdk_config.mbuf_size,
        }
    }
}

impl PacketCapture for DpdkCapture {
    fn initialize(&mut self) -> std::result::Result<(), error::Error> {
        // 创建DPDK配置
        let dpdk_config = self.create_dpdk_config();

        // 创建DPDK实例
        let mut dpdk = DpdkInstance::new(dpdk_config, Arc::clone(&self.stats));

        // 初始化DPDK
        match dpdk.initialize() {
            Ok(_) => {
                self.dpdk = Some(dpdk);
                Ok(())
            }
            Err(e) => Err(format!("DPDK初始化失败: {}", e).into()),
        }
    }

    fn start_capture(&mut self) -> std::result::Result<(), error::Error> {
        if self.dpdk.is_none() {
            return Err(format!("DPDK实例未初始化").into());
        }

        // 设置捕获状态
        self.is_capturing = true;

        // 设置当前使用的端口和队列
        if let Some(port_id) = self.dpdk_config.port_ids.first() {
            self.current_port = *port_id;
        }

        Ok(())
    }

    fn stop_capture(&mut self) {
        self.is_capturing = false;
    }

    fn receive_packets(&mut self, max_packets: usize) -> Vec<Vec<u8>> {
        if !self.is_capturing || self.dpdk.is_none() {
            return Vec::new();
        }

        let max_packets = if max_packets > u16::MAX as usize {
            u16::MAX
        } else {
            max_packets as u16
        };

        // 接收数据包
        let packets = self.dpdk.as_mut().unwrap().receive_packets(
            self.current_port,
            self.current_queue,
            max_packets,
        );

        // 更新统计信息
        self.capture_stats.rx_packets += packets.len() as u64;
        for packet in &packets {
            self.capture_stats.rx_bytes += packet.len() as u64;
        }

        packets
    }

    fn send_packets(&mut self, packets: &[Vec<u8>]) -> usize {
        if !self.is_capturing || self.dpdk.is_none() {
            return 0;
        }

        // 发送数据包
        let sent = self.dpdk.as_mut().unwrap().send_packets(
            self.current_port,
            self.current_queue,
            packets,
        );

        // 更新统计信息
        self.capture_stats.tx_packets += sent as u64;
        for i in 0..sent {
            self.capture_stats.tx_bytes += packets[i].len() as u64;
        }

        sent
    }

    fn get_stats(&self) -> CaptureStats {
        // 获取DPDK端口统计信息
        if let Some(dpdk) = &self.dpdk {
            if let Some((rx, tx)) = dpdk.get_port_stats(self.current_port) {
                // 更新丢包数量
                let mut stats = self.capture_stats.clone();
                if rx > self.capture_stats.rx_packets {
                    stats.dropped_packets = rx - self.capture_stats.rx_packets;
                }
                return stats;
            }
        }

        self.capture_stats.clone()
    }

    fn shutdown(&mut self) {
        if let Some(mut dpdk) = self.dpdk.take() {
            dpdk.shutdown();
        }
        self.is_capturing = false;
    }
}

impl Drop for DpdkCapture {
    fn drop(&mut self) {
        self.shutdown();
    }
}
