//! 文件输出实现
//! 将DNS消息输出到文件

use std::fs::{File, OpenOptions};
use std::io::{self, Write};
use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::output::{FileConfig, Output};
use crate::protocols::dns::DnsMessage;

/// 文件输出
pub struct FileOutput {
    /// 配置
    config: FileConfig,
    /// 当前文件
    current_file: Option<File>,
    /// 当前文件路径
    current_path: String,
    /// 上次轮转时间
    last_rotation: SystemTime,
}

impl FileOutput {
    /// 创建新的文件输出
    pub fn new(config: FileConfig) -> Result<Self, String> {
        // 确保输出目录存在
        let output_dir = Path::new(&config.output_dir);
        if !output_dir.exists() {
            std::fs::create_dir_all(output_dir)
                .map_err(|e| format!("Failed to create output directory: {}", e))?;
        }

        let mut output = FileOutput {
            config,
            current_file: None,
            current_path: String::new(),
            last_rotation: SystemTime::now(),
        };

        // 初始化文件
        output.rotate_file()?;

        Ok(output)
    }

    /// 轮转文件
    fn rotate_file(&mut self) -> Result<(), String> {
        // 生成新文件名
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| format!("Time error: {}", e))?
            .as_secs();

        let filename = format!(
            "{}{}{}.{}",
            self.config.file_prefix, timestamp, self.config.file_suffix, "log"
        );

        let path = Path::new(&self.config.output_dir).join(filename);
        let path_str = path.to_str().ok_or_else(|| "Invalid path".to_string())?;

        // 打开新文件
        let file = OpenOptions::new()
            .create(true)
            .write(true)
            .append(true)
            .open(&path)
            .map_err(|e| format!("Failed to open file: {}", e))?;

        // 更新状态
        self.current_file = Some(file);
        self.current_path = path_str.to_string();
        self.last_rotation = SystemTime::now();

        println!("Rotated to new file: {}", path_str);

        Ok(())
    }

    /// 检查是否需要轮转文件
    fn check_rotation(&mut self) -> Result<(), String> {
        if let Ok(duration) = SystemTime::now().duration_since(self.last_rotation) {
            if duration.as_secs() >= self.config.rotation_interval {
                self.rotate_file()?;
            }
        }

        Ok(())
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

impl Output for FileOutput {
    fn output(&mut self, message: &DnsMessage) -> Result<(), String> {
        // 检查是否需要轮转文件
        self.check_rotation()?;

        // 格式化消息
        let formatted = self.format_message_json(message);

        // 写入文件
        if let Some(file) = &mut self.current_file {
            file.write_all(formatted.as_bytes())
                .map_err(|e| format!("Failed to write to file: {}", e))?;
            file.flush()
                .map_err(|e| format!("Failed to flush file: {}", e))?;
        }

        Ok(())
    }

    fn close(&mut self) -> Result<(), String> {
        // 关闭文件
        self.current_file = None;
        Ok(())
    }
}
