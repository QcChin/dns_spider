//! 控制台输出实现
//! 将DNS消息输出到控制台

use crate::output::{ConsoleConfig, Output};
use crate::protocols::dns::{DnsMessage, DnsMessageType, DnsRecordType};
use colored::*;

/// 控制台输出
pub struct ConsoleOutput {
    /// 配置
    config: ConsoleConfig,
}

impl ConsoleOutput {
    /// 创建新的控制台输出
    pub fn new(config: ConsoleConfig) -> Result<Self, String> {
        Ok(ConsoleOutput { config })
    }

    /// 格式化DNS消息
    fn format_message(&self, message: &DnsMessage) -> String {
        let mut result = String::new();

        // 消息头
        let msg_type = match message.message_type {
            DnsMessageType::Query => "查询",
            DnsMessageType::Response => "响应",
        };

        result.push_str(&format!(
            "[DNS {}] ID: {:04X} | 协议: {:?}\n",
            msg_type, message.transaction_id, message.protocol
        ));

        // 问题部分
        if !message.questions.is_empty() {
            result.push_str("问题:\n");
            for (i, q) in message.questions.iter().enumerate() {
                result.push_str(&format!(
                    "  {}. {} (类型: {:?}, 类: {})\n",
                    i + 1,
                    q.name,
                    q.record_type,
                    q.class
                ));
            }
        }

        // 详细模式下显示应答
        if self.config.verbose && !message.answers.is_empty() {
            result.push_str("应答:\n");
            for (i, a) in message.answers.iter().enumerate() {
                result.push_str(&format!(
                    "  {}. {} (类型: {:?}, TTL: {}s)\n",
                    i + 1,
                    a.name,
                    a.record_type,
                    a.ttl
                ));

                // 根据记录类型格式化数据
                match a.record_type {
                    DnsRecordType::A | DnsRecordType::AAAA => {
                        result.push_str(&format!("     IP: {}\n", a.data_str));
                    }
                    DnsRecordType::CNAME | DnsRecordType::NS | DnsRecordType::PTR => {
                        result.push_str(&format!("     域名: {}\n", a.data_str));
                    }
                    DnsRecordType::MX => {
                        result.push_str(&format!("     邮件服务器: {}\n", a.data_str));
                    }
                    DnsRecordType::TXT => {
                        result.push_str(&format!("     文本: {}\n", a.data_str));
                    }
                    _ => {
                        result.push_str(&format!("     数据: {}\n", a.data_str));
                    }
                }
            }
        }

        result
    }
}

impl Output for ConsoleOutput {
    fn output(&mut self, message: &DnsMessage) -> Result<(), String> {
        let formatted = self.format_message(message);

        // 根据配置决定是否使用彩色输出
        if self.config.color {
            let colored_output = match message.message_type {
                DnsMessageType::Query => formatted.blue(),
                DnsMessageType::Response => formatted.green(),
            };
            println!("{}", colored_output);
        } else {
            println!("{}", formatted);
        }

        Ok(())
    }

    fn close(&mut self) -> Result<(), String> {
        // 控制台输出不需要特殊关闭操作
        Ok(())
    }
}
