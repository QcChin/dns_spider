//! 抓包主驱动逻辑
//! 负责协调捕获、解析和输出模块

use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use crate::capture::{CaptureConfig, PacketCapture};
use crate::core::mempool::MemoryPool;
use crate::core::stats::StatsCounter;
use crate::output::{OutputConfig, OutputManager};
use crate::protocols::detect::ProtocolDetector;
use crate::protocols::dns::{DnsParser, DnsProtocol};

/// 驱动配置
pub struct DriverConfig {
    /// 捕获配置
    pub capture: CaptureConfig,
    /// 输出配置
    pub output: OutputConfig,
    /// 内存池大小
    pub mempool_size: usize,
    /// 最大包大小
    pub max_packet_size: usize,
    /// 统计输出间隔（秒）
    pub stats_interval: u64,
    /// 工作线程数
    pub worker_threads: usize,
}

/// 抓包驱动
pub struct Driver {
    config: DriverConfig,
    stats: Arc<Mutex<StatsCounter>>,
    running: Arc<Mutex<bool>>,
}

impl Driver {
    /// 创建新的驱动
    pub fn new(config: DriverConfig) -> Self {
        Driver {
            config,
            stats: Arc::new(Mutex::new(StatsCounter::new())),
            running: Arc::new(Mutex::new(false)),
        }
    }

    /// 启动抓包
    pub fn start(&mut self) -> crate::error::Result<()> {
        // 设置运行状态
        {
            let mut running = self.running.lock().unwrap();
            if *running {
                return Err(crate::error::Error::Other(
                    "Driver already running".to_string(),
                ));
            }
            *running = true;
        }

        // 创建内存池
        let mempool = Arc::new(Mutex::new(MemoryPool::new(
            self.config.mempool_size,
            self.config.max_packet_size,
        )));

        // 创建协议检测器
        let detector = Arc::new(Mutex::new(ProtocolDetector::new()));

        // 创建输出管理器
        let output_manager = Arc::new(Mutex::new(OutputManager::new(self.config.output.clone())));

        // 创建捕获实例
        let mut capture = match PacketCapture::new(self.config.capture.clone()) {
            Ok(capture) => capture,
            Err(e) => {
                let mut running = self.running.lock().unwrap();
                *running = false;
                return Err(crate::error::Error::Capture(format!(
                    "Failed to create packet capture: {}",
                    e
                )));
            }
        };

        // 创建统计线程
        let stats_clone = Arc::clone(&self.stats);
        let running_clone = Arc::clone(&self.running);
        let stats_interval = self.config.stats_interval;

        thread::spawn(move || {
            let mut last_stats = Instant::now();

            while *running_clone.lock().unwrap() {
                thread::sleep(Duration::from_secs(1));

                let now = Instant::now();
                if now.duration_since(last_stats).as_secs() >= stats_interval {
                    let stats = stats_clone.lock().unwrap();
                    stats.print_and_reset();
                    last_stats = now;
                }
            }
        });

        // 创建工作线程
        let mut worker_handles = Vec::new();

        for _ in 0..self.config.worker_threads {
            let mempool_clone = Arc::clone(&mempool);
            let detector_clone = Arc::clone(&detector);
            let output_clone = Arc::clone(&output_manager);
            let stats_clone = Arc::clone(&self.stats);
            let running_clone = Arc::clone(&self.running);

            let handle = thread::spawn(move || {
                while *running_clone.lock().unwrap() {
                    // 从内存池获取数据包
                    let packet = {
                        let mut pool = mempool_clone.lock().unwrap();
                        pool.get_next_packet()
                    };

                    if let Some(packet) = packet {
                        // 检测协议
                        let result = {
                            let detector = detector_clone.lock().unwrap();
                            detector.detect(&packet.data, packet.src_port, packet.dst_port)
                        };

                        // 处理检测结果
                        match result {
                            crate::protocols::detect::ProtocolDetectResult::Dns(protocol) => {
                                // 根据协议类型处理
                                let mut stats = stats_clone.lock().unwrap();
                                stats.increment("packet.processed");

                                // 输出结果
                                let mut output = output_clone.lock().unwrap();
                                output.output_packet(&packet, &protocol);
                            }
                            crate::protocols::detect::ProtocolDetectResult::NeedMoreData => {
                                // 需要更多数据，放回内存池
                                let mut pool = mempool_clone.lock().unwrap();
                                pool.return_packet(packet);
                            }
                            crate::protocols::detect::ProtocolDetectResult::Unknown => {
                                // 未知协议，丢弃
                                let mut stats = stats_clone.lock().unwrap();
                                stats.increment("packet.unknown");
                            }
                        }
                    } else {
                        // 没有数据包，等待
                        thread::sleep(Duration::from_millis(1));
                    }
                }
            });

            worker_handles.push(handle);
        }

        // 启动捕获
        if let Err(e) = capture.start(mempool) {
            let mut running = self.running.lock().unwrap();
            *running = false;
            return Err(format!("Failed to start capture: {}", e));
        }

        // 等待所有工作线程完成
        for handle in worker_handles {
            let _ = handle.join();
        }

        Ok(())
    }

    /// 停止抓包
    pub fn stop(&mut self) {
        let mut running = self.running.lock().unwrap();
        *running = false;
    }

    /// 获取统计信息
    pub fn get_stats(&self) -> StatsCounter {
        self.stats.lock().unwrap().clone()
    }
}
