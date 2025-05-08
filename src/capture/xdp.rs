//! XDP捕获模块实现
//! 基于XDP(eXpress Data Path)的高性能数据包捕获

use std::sync::{Arc, Mutex};

use super::{CaptureConfig, CaptureStats, PacketCapture};
use crate::core::stats::StatsCounter;

#[cfg(feature = "xdp")]
use xdp_rs::{Interface, Map, Program, Socket, UmemConfig};

/// XDP捕获配置
#[derive(Debug, Clone)]
pub struct XdpCaptureConfig {
    /// XDP程序路径
    pub program_path: String,
    /// XDP程序段名称
    pub section_name: String,
    /// XDP程序挂载标志
    pub flags: u32,
    /// 环形缓冲区大小
    pub ring_size: u32,
    /// 帧大小
    pub frame_size: u32,
    /// 帧数量
    pub frame_count: u32,
    /// 填充大小
    pub fill_size: u32,
    /// 完成大小
    pub comp_size: u32,
}

impl Default for XdpCaptureConfig {
    fn default() -> Self {
        XdpCaptureConfig {
            program_path: "xdp/dns_filter.o".to_string(),
            section_name: "dns_filter".to_string(),
            flags: 0, // XDP_FLAGS_DRV_MODE
            ring_size: 4096,
            frame_size: 2048,
            frame_count: 8192,
            fill_size: 4096,
            comp_size: 4096,
        }
    }
}

/// XDP捕获实现
pub struct XdpCapture {
    /// 捕获配置
    config: CaptureConfig,
    /// XDP特定配置
    xdp_config: XdpCaptureConfig,
    /// XDP接口
    #[cfg(feature = "xdp")]
    interface: Option<Interface>,
    /// XDP程序
    #[cfg(feature = "xdp")]
    program: Option<Program>,
    /// XDP套接字
    #[cfg(feature = "xdp")]
    socket: Option<Socket>,
    /// 统计计数器
    stats: Arc<Mutex<StatsCounter>>,
    /// 是否正在捕获
    is_capturing: bool,
    /// 捕获统计信息
    capture_stats: CaptureStats,
}

impl XdpCapture {
    /// 创建新的XDP捕获实例
    pub fn new(
        config: CaptureConfig,
        xdp_config: XdpCaptureConfig,
        stats: Arc<Mutex<StatsCounter>>,
    ) -> Self {
        XdpCapture {
            config,
            xdp_config,
            #[cfg(feature = "xdp")]
            interface: None,
            #[cfg(feature = "xdp")]
            program: None,
            #[cfg(feature = "xdp")]
            socket: None,
            stats,
            is_capturing: false,
            capture_stats: CaptureStats::default(),
        }
    }
}

impl PacketCapture for XdpCapture {
    fn initialize(&mut self) -> crate::error::Result<()> {
        #[cfg(feature = "xdp")]
        {
            // 加载XDP程序
            let program = match Program::from_file(
                &self.xdp_config.program_path,
                &self.xdp_config.section_name,
            ) {
                Ok(p) => p,
                Err(e) => return Err(crate::error::Error::Xdp(format!("加载XDP程序失败: {}", e))),
            };

            // 获取网络接口
            let interface = match Interface::from_name(&self.config.interface) {
                Ok(i) => i,
                Err(e) => return Err(crate::error::Error::Xdp(format!("获取网络接口失败: {}", e))),
            };

            // 挂载XDP程序
            if let Err(e) = interface.attach_program(&program, self.xdp_config.flags) {
                return Err(crate::error::Error::Xdp(format!("挂载XDP程序失败: {}", e)));
            }

            // 创建XDP套接字
            let umem_config = UmemConfig {
                frame_size: self.xdp_config.frame_size,
                frame_count: self.xdp_config.frame_count,
                fill_size: self.xdp_config.fill_size,
                comp_size: self.xdp_config.comp_size,
                ..Default::default()
            };

            let socket = match Socket::new(
                &interface,
                0, // 队列ID
                &umem_config,
                self.xdp_config.ring_size,
                self.xdp_config.ring_size,
            ) {
                Ok(s) => s,
                Err(e) => {
                    interface.detach_program();
                    return Err(crate::error::Error::Xdp(format!(
                        "创建XDP套接字失败: {}",
                        e
                    )));
                }
            };

            self.interface = Some(interface);
            self.program = Some(program);
            self.socket = Some(socket);

            Ok(())
        }

        #[cfg(not(feature = "xdp"))]
        {
            Err(crate::error::Error::Xdp(
                "XDP功能未启用，请在Cargo.toml中启用xdp特性".to_string(),
            ))
        }
    }

    fn start_capture(&mut self) -> crate::error::Result<()> {
        #[cfg(feature = "xdp")]
        {
            if self.socket.is_none() {
                return Err(crate::error::Error::Xdp("XDP未初始化".to_string()));
            }

            self.is_capturing = true;
            Ok(())
        }

        #[cfg(not(feature = "xdp"))]
        {
            Err(crate::error::Error::Xdp("XDP功能未启用".to_string()))
        }
    }

    fn stop_capture(&mut self) {
        self.is_capturing = false;
    }

    fn receive_packets(&mut self, max_packets: usize) -> Vec<Vec<u8>> {
        let mut packets = Vec::new();

        #[cfg(feature = "xdp")]
        {
            if !self.is_capturing || self.socket.is_none() {
                return packets;
            }

            let socket = self.socket.as_mut().unwrap();

            // 接收数据包
            for _ in 0..max_packets {
                match socket.recv() {
                    Ok(data) => {
                        let packet = data.to_vec();
                        self.capture_stats.rx_packets += 1;
                        self.capture_stats.rx_bytes += packet.len() as u64;
                        packets.push(packet);
                    }
                    Err(_) => break,
                }
            }

            // 更新统计信息
            if let Ok(mut stats) = self.stats.lock() {
                stats.add("xdp.rx_packets", packets.len() as u64);
            }
        }

        packets
    }

    fn send_packets(&mut self, packets: &[Vec<u8>]) -> usize {
        #[cfg(feature = "xdp")]
        {
            if !self.is_capturing || self.socket.is_none() || packets.is_empty() {
                return 0;
            }

            let socket = self.socket.as_mut().unwrap();
            let mut sent = 0;

            // 发送数据包
            for packet in packets {
                if socket.send(packet).is_ok() {
                    sent += 1;
                    self.capture_stats.tx_packets += 1;
                    self.capture_stats.tx_bytes += packet.len() as u64;
                }
            }

            // 更新统计信息
            if sent > 0 {
                if let Ok(mut stats) = self.stats.lock() {
                    stats.add("xdp.tx_packets", sent as u64);
                }
            }

            sent
        }

        #[cfg(not(feature = "xdp"))]
        {
            0
        }
    }

    fn get_stats(&self) -> CaptureStats {
        #[cfg(feature = "xdp")]
        {
            if let Some(socket) = &self.socket {
                if let Ok(stats) = socket.stats() {
                    let mut capture_stats = self.capture_stats.clone();
                    capture_stats.dropped_packets = stats.dropped as u64;
                    return capture_stats;
                }
            }
        }

        self.capture_stats.clone()
    }

    fn shutdown(&mut self) {
        #[cfg(feature = "xdp")]
        {
            // 关闭套接字
            self.socket = None;

            // 卸载XDP程序
            if let Some(interface) = &self.interface {
                let _ = interface.detach_program();
            }

            self.interface = None;
            self.program = None;
        }

        self.is_capturing = false;
    }
}

impl Drop for XdpCapture {
    fn drop(&mut self) {
        self.shutdown();
    }
}
