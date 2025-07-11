//! 抓包主驱动逻辑
//! 负责协调捕获、解析和输出模块

use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use crate::capture::{CaptureConfig, create_capture};
use crate::core::stats::StatsCounter;
use crate::output::{OutputConfig, OutputManager};
use crate::protocols::detect::ProtocolDetector;
use crate::protocols::dns::{DnsParser, UdpDnsParser};

/// 驱动配置
pub struct DriverConfig {
    /// 捕获配置
    pub capture: CaptureConfig,
    /// 输出配置
    pub output: OutputConfig,
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

        // 创建协议检测器
        let detector = Arc::new(Mutex::new(ProtocolDetector::new()));

        // 创建DNS解析器
        let dns_parser = Arc::new(Mutex::new(UdpDnsParser::new(65535)));

        // 创建输出管理器
        let output_manager = Arc::new(Mutex::new(OutputManager::new(self.config.output.clone())));

        // 创建捕获实例
        let capture = create_capture(self.config.capture.clone(), Arc::clone(&self.stats));

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
                    let mut stats = stats_clone.lock().unwrap();
                    stats.print_and_reset();
                    last_stats = now;
                }
            }
        });

        // 创建工作线程
        let mut worker_handles = Vec::new();

        // 将capture包装在Arc<Mutex<>>中以便多线程共享
        let capture = Arc::new(Mutex::new(capture));

        for _ in 0..self.config.worker_threads {
            let detector_clone = Arc::clone(&detector);
            let dns_parser_clone = Arc::clone(&dns_parser);
            let output_clone = Arc::clone(&output_manager);
            let stats_clone = Arc::clone(&self.stats);
            let running_clone = Arc::clone(&self.running);
            let capture_clone = Arc::clone(&capture);

            let handle = thread::spawn(move || {
                while *running_clone.lock().unwrap() {
                    // 从捕获器获取数据包
                    let packets = {
                        let mut capture = capture_clone.lock().unwrap();
                        capture.receive_packets(10)
                    };

                    for packet_data in packets {
                        // 检测协议
                        let result = {
                            let detector = detector_clone.lock().unwrap();
                            detector.detect(&packet_data, 53, 53) // 简化：假设都是DNS端口
                        };

                        // 处理检测结果
                        match result {
                            crate::protocols::detect::ProtocolDetectResult::Dns(protocol) => {
                                // 解析DNS消息
                                let dns_message = {
                                    let mut parser = dns_parser_clone.lock().unwrap();
                                    let mut stats = stats_clone.lock().unwrap();
                                    parser.parse(&packet_data, &mut stats)
                                };

                                if let Some(message) = dns_message {
                                    // 更新统计
                                    {
                                        let mut stats = stats_clone.lock().unwrap();
                                        stats.increment("packet.processed");
                                    }

                                    // 输出结果
                                    {
                                        let mut output = output_clone.lock().unwrap();
                                        let _ = output.output(&message);
                                    }
                                }
                            }
                            crate::protocols::detect::ProtocolDetectResult::NeedMoreData => {
                                // 需要更多数据，暂时跳过
                                let mut stats = stats_clone.lock().unwrap();
                                stats.increment("packet.need_more_data");
                            }
                            crate::protocols::detect::ProtocolDetectResult::Unknown => {
                                // 未知协议，丢弃
                                let mut stats = stats_clone.lock().unwrap();
                                stats.increment("packet.unknown");
                            }
                        }
                    }

                    // 短暂休眠避免CPU占用过高
                    thread::sleep(Duration::from_millis(1));
                }
            });

            worker_handles.push(handle);
        }

        // 启动捕获
        if let Err(e) = {
            let mut capture = capture.lock().unwrap();
            capture.initialize()
        } {
            let mut running = self.running.lock().unwrap();
            *running = false;
            return Err(crate::error::Error::Capture(format!(
                "Failed to initialize capture: {}", e
            )));
        }
        if let Err(e) = {
            let mut capture = capture.lock().unwrap();
            capture.start_capture()
        } {
            let mut running = self.running.lock().unwrap();
            *running = false;
            return Err(crate::error::Error::Capture(format!(
                "Failed to start capture: {}", e
            )));
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
