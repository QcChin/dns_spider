//! DNS Spider主入口
//! 负责初始化和启动抓包系统

use std::process;

use crate::capture::{CaptureConfig, CaptureMode};
use crate::core::driver::{Driver, DriverConfig};
use crate::output::{ConsoleConfig, FileConfig, KafkaConfig, OutputConfig, StatsdConfig};

mod capture;
mod core;
mod error;
mod output;
mod protocols;

fn main() {
    println!("启动DNS Spider...");

    // 检查权限
    #[cfg(target_os = "macos")]
    {
        println!("注意: 在macOS上抓包可能需要管理员权限");
        println!("如果抓不到包，请尝试: sudo ./target/release/dns_spider");
    }

    // 创建配置
    let config = create_config();

    println!("配置信息:");
    println!("  接口: {}", config.capture.interface);
    println!("  过滤器: {}", config.capture.filter);
    println!("  混杂模式: {}", config.capture.promiscuous);
    println!("  工作线程: {}", config.worker_threads);

    // 创建驱动
    let mut driver = Driver::new(config);

    // 启动抓包
    match driver.start() {
        Ok(_) => {
            println!("DNS Spider已启动，按Ctrl+C停止...");
            println!("正在监听网络流量...");

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
            eprintln!("可能的解决方案:");
            eprintln!("  1. 使用 sudo 运行程序");
            eprintln!("  2. 检查网络接口是否可用");
            eprintln!("  3. 确认防火墙设置");
            process::exit(1);
        }
    }
}

/// 创建配置
fn create_config() -> DriverConfig {
    // 自动检测网络接口
    let interface = detect_network_interface();

    // 捕获配置
    let capture_config = CaptureConfig {
        interface,
        filter: "udp or tcp".to_string(), // 更宽松的过滤器，抓取所有UDP和TCP流量
        promiscuous: true,
        snaplen: 65535,
        timeout_ms: 1000,
        buffer_size: 16_777_216, // 16MB
        mode: CaptureMode::Pcap,
        dpdk_config: Default::default(),
        xdp_config: Default::default(),
    };

    println!("使用BPF过滤器: {}", capture_config.filter);
    println!("注意: 如果仍然抓不到包，请尝试使用 sudo 运行程序");

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
        stats_interval: 10,
        worker_threads: 4,
    }
}

/// 自动检测网络接口
fn detect_network_interface() -> String {
    #[cfg(feature = "pcap")]
    {
        use pcap::Device;
        
        match Device::list() {
            Ok(devices) => {
                println!("可用网络接口:");
                for device in &devices {
                    println!("  - {}: {}", device.name, device.desc.as_deref().unwrap_or("无描述"));
                }
                
                // 优先选择活跃的网络接口
                let preferred_interfaces = ["en0", "en1", "en2", "en3", "en4"];
                for preferred in &preferred_interfaces {
                    for device in &devices {
                        if device.name == *preferred {
                            println!("选择优先网络接口: {} ({})", device.name, device.desc.as_deref().unwrap_or("无描述"));
                            return device.name.clone();
                        }
                    }
                }
                
                // 优先选择物理网络接口（排除VPN、loopback等）
                for device in &devices {
                    let name = &device.name;
                    let desc = device.desc.as_deref().unwrap_or("");
                    
                    // 排除VPN、loopback、虚拟接口
                    if !name.contains("utun") && 
                       !name.contains("lo") && 
                       !name.contains("loopback") &&
                       !name.contains("vmnet") &&
                       !name.contains("vbox") &&
                       !name.contains("ap") &&  // 排除接入点接口
                       !name.contains("bridge") &&  // 排除桥接接口
                       !desc.to_lowercase().contains("vpn") &&
                       !desc.to_lowercase().contains("virtual") {
                        println!("选择网络接口: {} ({})", name, desc);
                        return name.clone();
                    }
                }
                
                // 如果没有找到合适的接口，使用第一个非loopback接口
                for device in &devices {
                    if !device.name.contains("lo") && !device.name.contains("loopback") {
                        println!("使用备选网络接口: {}", device.name);
                        return device.name.clone();
                    }
                }
                
                // 最后使用第一个可用接口
                if let Some(first_device) = devices.first() {
                    println!("使用默认网络接口: {}", first_device.name);
                    return first_device.name.clone();
                }
            }
            Err(e) => {
                eprintln!("警告: 无法获取网络接口列表: {}", e);
            }
        }
    }
    
    // 默认接口名称（根据操作系统调整）
    #[cfg(target_os = "macos")]
    {
        println!("使用默认网络接口: en0");
        "en0".to_string()
    }
    
    #[cfg(target_os = "linux")]
    {
        println!("使用默认网络接口: eth0");
        "eth0".to_string()
    }
    
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        println!("使用默认网络接口: eth0");
        "eth0".to_string()
    }
}
