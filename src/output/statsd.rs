//! Statsd输出实现
//! 将DNS统计信息输出到Statsd

use std::io::Error;
use std::net::UdpSocket;
use std::time::Instant;

use crate::output::{Output, StatsdConfig};
use crate::protocols::dns::{DnsMessage, DnsMessageType, DnsRecordType};

/// Statsd输出
pub struct StatsdOutput {
    /// 配置
    config: StatsdConfig,
    /// UDP套接字
    socket: UdpSocket,
    /// 上次发送时间
    last_send: Instant,
    /// 计数器
    counters: std::collections::HashMap<String, u64>,
}

impl StatsdOutput {
    /// 创建新的Statsd输出
    pub fn new(config: StatsdConfig) -> Result<Self, String> {
        // 创建UDP套接字
        let socket = UdpSocket::bind("0.0.0.0:0")
            .map_err(|e| format!("Failed to bind UDP socket: {}", e))?;

        Ok(StatsdOutput {
            config,
            socket,
            last_send: Instant::now(),
            counters: std::collections::HashMap::new(),
        })
    }

    /// 发送计数器到Statsd
    fn send_counter(&self, name: &str, value: u64) -> Result<(), Error> {
        let metric = format!("{}.{}:{}|c\n", self.config.prefix, name, value);
        let addr = format!("{}{}", self.config.host, self.config.port);
        self.socket.send_to(metric.as_bytes(), addr)?;
        Ok(())
    }

    /// 发送计时器到Statsd
    fn send_timer(&self, name: &str, value_ms: u64) -> Result<(), Error> {
        let metric = format!("{}.{}:{}|ms\n", self.config.prefix, name, value_ms);
        let addr = format!("{}{}", self.config.host, self.config.port);
        self.socket.send_to(metric.as_bytes(), addr)?;
        Ok(())
    }

    /// 发送所有统计信息
    fn flush_stats(&mut self) -> Result<(), String> {
        for (name, value) in &self.counters {
            self.send_counter(name, *value)
                .map_err(|e| format!("Failed to send counter: {}", e))?;
        }

        // 重置计数器
        self.counters.clear();
        self.last_send = Instant::now();

        Ok(())
    }

    /// 更新DNS消息统计信息
    fn update_stats(&mut self, message: &DnsMessage) {
        // 更新总消息计数
        *self
            .counters
            .entry("messages.total".to_string())
            .or_insert(0) += 1;

        // 按消息类型计数
        match message.message_type {
            DnsMessageType::Query => {
                *self
                    .counters
                    .entry("messages.query".to_string())
                    .or_insert(0) += 1;
            }
            DnsMessageType::Response => {
                *self
                    .counters
                    .entry("messages.response".to_string())
                    .or_insert(0) += 1;
            }
        }

        // 按协议类型计数
        let protocol_key = format!("protocol.{:?}", message.protocol).to_lowercase();
        *self.counters.entry(protocol_key).or_insert(0) += 1;

        // 按记录类型计数
        for question in &message.questions {
            let record_type_key = format!("record_type.{:?}", question.record_type).to_lowercase();
            *self.counters.entry(record_type_key).or_insert(0) += 1;
        }

        // 每分钟刷新一次统计信息
        if self.last_send.elapsed().as_secs() >= 60 {
            if let Err(e) = self.flush_stats() {
                eprintln!("Failed to flush stats: {}", e);
            }
        }
    }
}

impl Output for StatsdOutput {
    fn output(&mut self, message: &DnsMessage) -> Result<(), String> {
        // 更新统计信息
        self.update_stats(message);
        Ok(())
    }

    fn close(&mut self) -> Result<(), String> {
        // 刷新所有统计信息
        self.flush_stats()
    }
}
