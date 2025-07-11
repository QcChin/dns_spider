//! Kafka输出实现
//! 将DNS消息输出到Kafka

use std::time::Duration;

use crate::output::KafkaConfig;
use crate::output::Output;
use crate::protocols::dns::DnsMessage;
use kafka::client::RequiredAcks;
use kafka::producer::Record;
use kafka::producer::{Producer};

/// Kafka输出
pub struct KafkaOutput {
    /// 配置
    config: KafkaConfig,
    /// Kafka生产者
    producer: Producer,
}

impl KafkaOutput {
    /// 创建新的Kafka输出
    pub fn new(config: KafkaConfig) -> Result<Self, String> {
        // 创建Kafka生产者
        let producer: Producer = Producer::from_hosts(vec![config.brokers.clone()])
            .with_ack_timeout(Duration::from_secs(5))
            .with_required_acks(RequiredAcks::One)
            .create()
            .map_err(|e| format!("Failed to create Kafka producer: {}", e))?;

        Ok(KafkaOutput { config, producer })
    }

    /// 格式化DNS消息为JSON
    fn format_message_json(&self, message: &DnsMessage) -> String {
        // 简单实现，实际项目中可能需要更复杂的JSON序列化
        let mut json = String::new();

        json.push_str("{\n");
        json.push_str(&format!("  \"timestamp\": {},\n", message.timestamp));
        json.push_str(&format!(
            "  \"transaction_id\": {},\n",
            message.transaction_id
        ));
        json.push_str(&format!(
            "  \"message_type\": \"{:?}\",\n",
            message.message_type
        ));
        json.push_str(&format!("  \"protocol\": \"{:?}\",\n", message.protocol));

        // 问题
        json.push_str("  \"questions\": [\n");
        for (i, q) in message.questions.iter().enumerate() {
            json.push_str("    {\n");
            json.push_str(&format!("      \"name\": \"{}\",\n", q.name));
            json.push_str(&format!(
                "      \"record_type\": \"{:?}\",\n",
                q.record_type
            ));
            json.push_str(&format!("      \"class\": {}\n", q.class));
            json.push_str("    }");
            if i < message.questions.len() - 1 {
                json.push_str(",\n");
            } else {
                json.push_str("\n");
            }
        }
        json.push_str("  ],\n");

        // 应答
        json.push_str("  \"answers\": [\n");
        for (i, a) in message.answers.iter().enumerate() {
            json.push_str("    {\n");
            json.push_str(&format!("      \"name\": \"{}\",\n", a.name));
            json.push_str(&format!(
                "      \"record_type\": \"{:?}\",\n",
                a.record_type
            ));
            json.push_str(&format!("      \"class\": {},\n", a.class));
            json.push_str(&format!("      \"ttl\": {},\n", a.ttl));
            json.push_str(&format!("      \"data\": \"{}\"\n", a.data_str));
            json.push_str("    }");
            if i < message.answers.len() - 1 {
                json.push_str(",\n");
            } else {
                json.push_str("\n");
            }
        }
        json.push_str("  ]\n");

        json.push_str("}\n");

        json
    }
}

impl Output for KafkaOutput {
    fn output(&mut self, message: &DnsMessage) -> Result<(), String> {
        // 格式化消息
        let formatted = self.format_message_json(message);
        let key = format!("{}", message.transaction_id);

        let topic = self.config.topic.clone();
        // 发送到Kafka
        let record = Record::from_value(&topic, formatted);

        // 异步发送，但这里简单等待结果
        match self.producer.send(&record) {
            Ok(_) => Ok(()),
            Err(e) => Err(format!("Failed to send message to Kafka: {}", e)),
        }
    }

    fn close(&mut self) -> Result<(), String> {
        // Kafka生产者会在析构时自动关闭
        Ok(())
    }
}
