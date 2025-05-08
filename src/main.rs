//! DNS Spider主入口
//! 负责初始化和启动抓包系统

use std::process;

use crate::capture::CaptureConfig;
use crate::core::driver::{Driver, DriverConfig};
use crate::output::{ConsoleConfig, FileConfig, KafkaConfig, OutputConfig, StatsdConfig};

mod async_rt;
mod capture;
mod core;
mod error;
mod output;
mod protocols;
mod utils;

fn main() {
    println!("启动DNS Spider...");

    // 创建配置
    let config = create_config();

    // 创建驱动
    let mut driver = Driver::new(config);

    // 启动抓包
    match driver.start() {
        Ok(_) => {
            println!("DNS Spider已启动，按Ctrl+C停止...");

            // 等待中断信号
            ctrlc::set_handler(move || {
                println!("接收到停止信号，正在关闭...");
                process::exit(0);
            })
            .expect("设置中断处理器失败");

            // 阻塞主线程
            loop {
                std::thread::sleep(std::time::Duration::from_secs(1));
            }
        }
        Err(e) => {
            eprintln!("启动失败: {}", e);
            process::exit(1);
        }
    }
}

/// 创建配置
fn create_config() -> DriverConfig {
    // 捕获配置
    let capture_config = CaptureConfig {
        interface: "eth0".to_string(),
        filter: "udp port 53 or tcp port 53".to_string(),
        promiscuous: true,
        snaplen: 65535,
        timeout_ms: 1000,
        buffer_size: 16777216, // 16MB
    };

    // Kafka配置
    let kafka_config = KafkaConfig {
        brokers: "localhost:9092".to_string(),
        topic: "dns-events".to_string(),
        client_id: "dns-spider".to_string(),
    };

    // 文件配置
    let file_config = FileConfig {
        output_dir: "./logs".to_string(),
        file_prefix: "dns-".to_string(),
        file_suffix: "".to_string(),
        rotation_interval: 3600, // 1小时
    };

    // Statsd配置
    let statsd_config = StatsdConfig {
        host: "localhost".to_string(),
        port: 8125,
        prefix: "dns.spider".to_string(),
    };

    // 控制台配置
    let console_config = ConsoleConfig {
        verbose: true,
        color: true,
    };

    // 输出配置
    let output_config = OutputConfig {
        enable_kafka: false, // 默认禁用Kafka
        kafka_config,
        enable_file: true,
        file_config,
        enable_statsd: false, // 默认禁用Statsd
        statsd_config,
        enable_console: true,
        console_config,
    };

    // 驱动配置
    DriverConfig {
        capture: capture_config,
        output: output_config,
        mempool_size: 1024,
        max_packet_size: 65535,
        stats_interval: 10,
        worker_threads: 4,
    }
}
