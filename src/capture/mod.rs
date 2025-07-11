//! 网络数据包捕获模块
//! 提供统一的数据包捕获接口，支持多种捕获方式

use std::fmt;
use std::sync::{Arc, Mutex};

use crate::core::stats::StatsCounter;

pub mod dpdk;
pub mod pcap;
pub mod xdp;

/// 捕获方式枚举
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CaptureMode {
    /// 使用DPDK捕获
    Dpdk,
    /// 使用libpcap捕获
    Pcap,
    /// 使用XDP捕获
    Xdp,
}

impl fmt::Display for CaptureMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CaptureMode::Dpdk => write!(f, "dpdk"),
            CaptureMode::Pcap => write!(f, "pcap"),
            CaptureMode::Xdp => write!(f, "xdp"),
        }
    }
}

impl From<&str> for CaptureMode {
    fn from(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "dpdk" => CaptureMode::Dpdk,
            "xdp" => CaptureMode::Xdp,
            _ => CaptureMode::Pcap, // 默认使用pcap
        }
    }
}

/// 捕获配置
pub struct CaptureConfig {
    /// 捕获模式
    pub mode: CaptureMode,
    /// 网络接口名称
    pub interface: String,
    /// BPF过滤器
    pub filter: String,
    /// 是否启用混杂模式
    pub promiscuous: bool,
    /// 捕获长度
    pub snaplen: i32,
    /// 超时时间(毫秒)
    pub timeout_ms: i32,
    /// 缓冲区大小
    pub buffer_size: i32,
    /// DPDK特定配置
    pub dpdk_config: Option<dpdk::DpdkCaptureConfig>,
    /// XDP特定配置
    pub xdp_config: Option<xdp::XdpCaptureConfig>,
}

impl Clone for CaptureConfig {
    fn clone(&self) -> Self {
        CaptureConfig {
            mode: self.mode,
            interface: self.interface.clone(),
            filter: self.filter.clone(),
            promiscuous: self.promiscuous,
            snaplen: self.snaplen,
            timeout_ms: self.timeout_ms,
            buffer_size: self.buffer_size,
            dpdk_config: self.dpdk_config.clone(),
            xdp_config: self.xdp_config.clone(),
        }
    }
}

impl Default for CaptureConfig {
    fn default() -> Self {
        CaptureConfig {
            mode: CaptureMode::Pcap,
            interface: "eth0".to_string(),
            filter: "udp port 53 or tcp port 53".to_string(),
            promiscuous: true,
            snaplen: 65535,
            timeout_ms: 1000,
            buffer_size: 16777216, // 16MB
            dpdk_config: None,
            xdp_config: None,
        }
    }
}

/// 数据包捕获接口
pub trait PacketCapture: Send {
    /// 初始化捕获器
    fn initialize(&mut self) -> crate::error::Result<()>;

    /// 开始捕获
    fn start_capture(&mut self) -> crate::error::Result<()>;

    /// 停止捕获
    fn stop_capture(&mut self);

    /// 接收数据包
    fn receive_packets(&mut self, max_packets: usize) -> Vec<Vec<u8>>;

    /// 发送数据包
    fn send_packets(&mut self, packets: &[Vec<u8>]) -> usize;

    /// 获取统计信息
    fn get_stats(&self) -> CaptureStats;

    /// 关闭捕获器
    fn shutdown(&mut self);
}

/// 捕获统计信息
#[derive(Debug, Clone, Default)]
pub struct CaptureStats {
    /// 接收的数据包数量
    pub rx_packets: u64,
    /// 发送的数据包数量
    pub tx_packets: u64,
    /// 丢弃的数据包数量
    pub dropped_packets: u64,
    /// 接收的字节数
    pub rx_bytes: u64,
    /// 发送的字节数
    pub tx_bytes: u64,
}

/// 创建捕获器
pub fn create_capture(
    config: CaptureConfig,
    stats: Arc<Mutex<StatsCounter>>,
) -> Box<dyn PacketCapture> {
    match config.mode {
        CaptureMode::Dpdk => {
            let cap_config = config.clone();
            let dpdk_config = config.dpdk_config.unwrap_or_default();
            Box::new(dpdk::DpdkCapture::new(cap_config, dpdk_config, stats))
        }
        CaptureMode::Pcap => Box::new(pcap::PcapCapture::new(config, stats)),
        CaptureMode::Xdp => {
            let cap_config = config.clone();
            let xdp_config = config.xdp_config.unwrap_or_default();
            Box::new(xdp::XdpCapture::new(cap_config, xdp_config, stats))
        }
    }
}
