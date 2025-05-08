//! 输出模块
//! 负责将解析结果输出到不同目标

mod console;
mod file;
mod kafka;
mod statsd;

pub use console::ConsoleOutput;
pub use file::FileOutput;
pub use kafka::KafkaOutput;
pub use statsd::StatsdOutput;

use crate::protocols::dns::DnsMessage;
use std::sync::{Arc, Mutex};

/// 输出配置
#[derive(Clone)]
pub struct OutputConfig {
    /// 是否启用Kafka输出
    pub enable_kafka: bool,
    /// Kafka配置
    pub kafka_config: KafkaConfig,
    /// 是否启用文件输出
    pub enable_file: bool,
    /// 文件输出配置
    pub file_config: FileConfig,
    /// 是否启用Statsd输出
    pub enable_statsd: bool,
    /// Statsd配置
    pub statsd_config: StatsdConfig,
    /// 是否启用控制台输出
    pub enable_console: bool,
    /// 控制台输出配置
    pub console_config: ConsoleConfig,
}

/// Kafka配置
#[derive(Clone)]
pub struct KafkaConfig {
    /// Kafka服务器地址
    pub brokers: String,
    /// 主题
    pub topic: String,
    /// 客户端ID
    pub client_id: String,
}

/// 文件输出配置
#[derive(Clone)]
pub struct FileConfig {
    /// 输出目录
    pub output_dir: String,
    /// 文件前缀
    pub file_prefix: String,
    /// 文件后缀
    pub file_suffix: String,
    /// 轮转间隔（秒）
    pub rotation_interval: u64,
}

/// Statsd配置
#[derive(Clone)]
pub struct StatsdConfig {
    /// Statsd服务器地址
    pub host: String,
    /// 端口
    pub port: u16,
    /// 前缀
    pub prefix: String,
}

/// 控制台输出配置
#[derive(Clone)]
pub struct ConsoleConfig {
    /// 是否启用详细模式
    pub verbose: bool,
    /// 是否启用彩色输出
    pub color: bool,
}

/// 输出接口
pub trait Output {
    /// 输出DNS消息
    fn output(&mut self, message: &DnsMessage) -> Result<(), String>;
    /// 关闭输出
    fn close(&mut self) -> Result<(), String>;
}

/// 输出管理器
pub struct OutputManager {
    /// 配置
    config: OutputConfig,
    /// 输出列表
    outputs: Vec<Box<dyn Output + Send>>,
}

impl OutputManager {
    /// 创建新的输出管理器
    pub fn new(config: OutputConfig) -> Self {
        let mut manager = OutputManager {
            config,
            outputs: Vec::new(),
        };

        manager.init();
        manager
    }

    /// 初始化输出
    fn init(&mut self) {
        // 初始化Kafka输出
        if self.config.enable_kafka {
            match KafkaOutput::new(self.config.kafka_config.clone()) {
                Ok(output) => self.outputs.push(Box::new(output)),
                Err(e) => eprintln!("Failed to initialize Kafka output: {}", e),
            }
        }

        // 初始化文件输出
        if self.config.enable_file {
            match FileOutput::new(self.config.file_config.clone()) {
                Ok(output) => self.outputs.push(Box::new(output)),
                Err(e) => eprintln!("Failed to initialize file output: {}", e),
            }
        }

        // 初始化Statsd输出
        if self.config.enable_statsd {
            match StatsdOutput::new(self.config.statsd_config.clone()) {
                Ok(output) => self.outputs.push(Box::new(output)),
                Err(e) => eprintln!("Failed to initialize Statsd output: {}", e),
            }
        }

        // 初始化控制台输出
        if self.config.enable_console {
            match ConsoleOutput::new(self.config.console_config.clone()) {
                Ok(output) => self.outputs.push(Box::new(output)),
                Err(e) => eprintln!("Failed to initialize console output: {}", e),
            }
        }
    }

    /// 输出DNS消息
    pub fn output(&mut self, message: &DnsMessage) -> Result<(), String> {
        for output in &mut self.outputs {
            if let Err(e) = output.output(message) {
                eprintln!("Output error: {}", e);
            }
        }

        Ok(())
    }

    /// 关闭所有输出
    pub fn close(&mut self) -> Result<(), String> {
        for output in &mut self.outputs {
            if let Err(e) = output.close() {
                eprintln!("Close output error: {}", e);
            }
        }

        Ok(())
    }
}
