//! libpcap捕获模块实现
//! 基于libpcap的数据包捕获

use std::sync::{Arc, Mutex};

use super::{CaptureConfig, CaptureStats, PacketCapture};
use crate::core::stats::StatsCounter;

#[cfg(feature = "pcap")]
use pcap::{Active, Capture, Device, Inactive};

/// libpcap捕获实现
pub struct PcapCapture {
    /// 捕获配置
    config: CaptureConfig,
    /// pcap捕获器
    #[cfg(feature = "pcap")]
    capture: Option<Capture<Active>>,
    /// 统计计数器
    stats: Arc<Mutex<StatsCounter>>,
    /// 是否正在捕获
    is_capturing: bool,
    /// 捕获统计信息
    capture_stats: CaptureStats,
    /// 上次统计时间
    last_stats_time: std::time::Instant,
}

impl PcapCapture {
    /// 创建新的libpcap捕获实例
    pub fn new(config: CaptureConfig, stats: Arc<Mutex<StatsCounter>>) -> Self {
        PcapCapture {
            config,
            #[cfg(feature = "pcap")]
            capture: None,
            stats,
            is_capturing: false,
            capture_stats: CaptureStats::default(),
            last_stats_time: std::time::Instant::now(),
        }
    }
}

impl PacketCapture for PcapCapture {
    fn initialize(&mut self) -> crate::error::Result<()> {
        #[cfg(feature = "pcap")]
        {
            // 查找设备
            let device = match Device::list() {
                Ok(devices) => {
                    let device = devices.into_iter().find(|d| {
                        d.name == self.config.interface
                            || d.desc
                                .as_ref()
                                .map_or(false, |desc| desc.contains(&self.config.interface))
                    });

                    match device {
                        Some(d) => d,
                        None => {
                            return Err(crate::error::Error::Capture(format!(
                                "找不到接口: {}",
                                self.config.interface
                            )))
                        }
                    }
                }
                Err(e) => {
                    return Err(crate::error::Error::Capture(format!(
                        "获取网络接口列表失败: {}",
                        e
                    )))
                }
            };

            // 创建捕获器（Inactive）
            let mut capture = match Capture::from_device(device) {
                Ok(c) => c,
                Err(e) => {
                    return Err(crate::error::Error::Capture(format!(
                        "创建捕获器失败: {}",
                        e
                    )))
                }
            };

            // 配置捕获器
            capture = capture
                .promisc(self.config.promiscuous)
                .snaplen((self.config.snaplen as u32).try_into().unwrap())
                .timeout(self.config.timeout_ms);

            if self.config.buffer_size > 0 {
                capture = capture.buffer_size(self.config.buffer_size as i32);
            }

            // 激活捕获器（变为Active）
            let mut active_capture = match capture.open() {
                Ok(c) => c,
                Err(e) => {
                    return Err(crate::error::Error::Capture(format!(
                        "激活捕获器失败: {}",
                        e
                    )))
                }
            };

            // 设置过滤器（在Active上）
            if !self.config.filter.is_empty() {
                if let Err(e) = active_capture.filter(&self.config.filter, true) {
                    return Err(crate::error::Error::Capture(format!(
                        "设置过滤器失败: {}",
                        e
                    )));
                }
            }

            // 设置非阻塞模式（在Active上）
            active_capture = match active_capture.setnonblock() {
                Ok(c) => c,
                Err(e) => {
                    return Err(crate::error::Error::Capture(format!(
                        "设置非阻塞模式失败: {}",
                        e
                    )));
                }
            };

            self.capture = Some(active_capture);
            Ok(())
        }

        #[cfg(not(feature = "pcap"))]
        {
            Err(crate::error::Error::Capture(
                "libpcap功能未启用，请在Cargo.toml中启用pcap特性".to_string(),
            ))
        }
    }

    fn start_capture(&mut self) -> crate::error::Result<()> {
        #[cfg(feature = "pcap")]
        {
            if self.capture.is_none() {
                return Err(crate::error::Error::Capture("捕获器未初始化".to_string()));
            }

            self.is_capturing = true;
            self.last_stats_time = std::time::Instant::now();
            Ok(())
        }

        #[cfg(not(feature = "pcap"))]
        {
            Err(crate::error::Error::Capture(
                "libpcap功能未启用".to_string(),
            ))
        }
    }

    fn stop_capture(&mut self) {
        self.is_capturing = false;
    }

    fn receive_packets(&mut self, max_packets: usize) -> Vec<Vec<u8>> {
        let mut packets = Vec::new();

        #[cfg(feature = "pcap")]
        {
            if !self.is_capturing || self.capture.is_none() {
                return packets;
            }

            let capture = self.capture.as_mut().unwrap();

            // 接收数据包
            for _ in 0..max_packets {
                match capture.next_packet() {
                    Ok(packet) => {
                        let data = packet.data.to_vec();
                        self.capture_stats.rx_packets += 1;
                        self.capture_stats.rx_bytes += data.len() as u64;
                        packets.push(data);
                    }
                    Err(pcap::Error::TimeoutExpired) => break,
                    Err(_) => break,
                }
            }

            // 更新统计信息
            if let Ok(mut stats) = self.stats.lock() {
                stats.add("pcap.rx_packets", packets.len() as u64);
            }
        }

        packets
    }

    fn send_packets(&mut self, packets: &[Vec<u8>]) -> usize {
        #[cfg(feature = "pcap")]
        {
            if !self.is_capturing || self.capture.is_none() || packets.is_empty() {
                return 0;
            }

            let capture = self.capture.as_mut().unwrap();
            let mut sent = 0;

            // 发送数据包
            for packet in packets {
                if capture.sendpacket(packet.as_slice()).is_ok() {
                    sent += 1;
                    self.capture_stats.tx_packets += 1;
                    self.capture_stats.tx_bytes += packet.len() as u64;
                }
            }

            // 更新统计信息
            if sent > 0 {
                if let Ok(mut stats) = self.stats.lock() {
                    stats.add("pcap.tx_packets", sent as u64);
                }
            }

            sent
        }

        #[cfg(not(feature = "pcap"))]
        {
            0
        }
    }

    fn get_stats(&self) -> CaptureStats {
        self.capture_stats.clone()
    }

    fn shutdown(&mut self) {
        #[cfg(feature = "pcap")]
        {
            self.capture = None;
        }

        self.is_capturing = false;
    }
}

impl Drop for PcapCapture {
    fn drop(&mut self) {
        self.shutdown();
    }
}
