//! UDP DNS协议解析实现
//! 处理标准DNS消息解析

use crate::core::stats::StatsCounter;
use crate::protocols::dns::{DnsAnswer, DnsMessage, DnsMessageType, DnsParser, DnsProtocol, DnsQuestion, DnsRecordType};

/// UDP DNS解析器
pub struct UdpDnsParser {
    // 配置
    max_packet_size: usize,
}

impl UdpDnsParser {
    /// 创建新的UDP DNS解析器
    pub fn new(max_packet_size: usize) -> Self {
        UdpDnsParser {
            max_packet_size,
        }
    }

    /// 解析域名
    fn parse_domain_name(&self, data: &[u8], offset: usize) -> Option<(String, usize)> {
        let mut name = String::new();
        let mut pos = offset;
        let mut jumped = false;
        let mut jump_count = 0;
        let max_jumps = 10; // 防止无限循环
        let mut next_pos = pos;

        while pos < data.len() {
            // 检查是否是指针
            if (data[pos] & 0xC0) == 0xC0 {
                if pos + 1 >= data.len() {
                    return None; // 数据不足
                }

                if !jumped {
                    next_pos = pos + 2;
                }

                // 计算指针位置
                let pointer = ((data[pos] as usize & 0x3F) << 8) | data[pos + 1] as usize;
                pos = pointer;
                jumped = true;
                jump_count += 1;

                if jump_count > max_jumps {
                    return None; // 防止无限循环
                }
            } else {
                // 标准标签
                let len = data[pos] as usize;
                if len == 0 {
                    break; // 域名结束
                }

                pos += 1;
                if pos + len > data.len() {
                    return None; // 数据不足
                }

                // 添加标签到域名
                if !name.is_empty() {
                    name.push('.');
                }

                // 将标签添加到域名
                name.push_str(
                    &String::from_utf8_lossy(&data[pos..pos + len]).to_string()
                );

                pos += len;
            }
        }

        // 如果没有跳转，更新下一个位置
        if !jumped {
            next_pos = pos + 1;
        }

        Some((name, next_pos))
    }

    /// 解析DNS问题部分
    fn parse_question(&self, data: &[u8], offset: usize) -> Option<(DnsQuestion, usize)> {
        // 解析域名
        let (name, offset) = self.parse_domain_name(data, offset)?;

        // 确保有足够的数据
        if offset + 4 > data.len() {
            return None;
        }

        // 解析类型和类
        let record_type = u16::from_be_bytes([data[offset], data[offset + 1]]);
        let class = u16::from_be_bytes([data[offset + 2], data[offset + 3]]);

        Some((
            DnsQuestion {
                name,
                record_type: DnsRecordType::from(record_type),
                class,
            },
            offset + 4,
        ))
    }

    /// 解析DNS应答部分
    fn parse_answer(&self, data: &[u8], offset: usize) -> Option<(DnsAnswer, usize)> {
        // 解析域名
        let (name, offset) = self.parse_domain_name(data, offset)?;

        // 确保有足够的数据
        if offset + 10 > data.len() {
            return None;
        }

        // 解析类型、类、TTL和数据长度
        let record_type = u16::from_be_bytes([data[offset], data[offset + 1]]);
        let class = u16::from_be_bytes([data[offset + 2], data[offset + 3]]);
        let ttl = u32::from_be_bytes([
            data[offset + 4],
            data[offset + 5],
            data[offset + 6],
            data[offset + 7],
        ]);
        let data_len = u16::from_be_bytes([data[offset + 8], data[offset + 9]]) as usize;

        // 确保有足够的数据
        if offset + 10 + data_len > data.len() {
            return None;
        }

        // 提取数据
        let record_data = data[offset + 10..offset + 10 + data_len].to_vec();
        
        // 尝试将数据转换为字符串表示
        let data_str = match DnsRecordType::from(record_type) {
            DnsRecordType::A => {
                if record_data.len() == 4 {
                    format!("{}.{}.{}.{}", record_data[0], record_data[1], record_data[2], record_data[3])
                } else {
                    String::from("Invalid A record")
                }
            },
            DnsRecordType::AAAA => {
                if record_data.len() == 16 {
                    let mut parts = Vec::new();
                    for i in 0..8 {
                        let value = u16::from_be_bytes([record_data[i*2], record_data[i*2+1]]);
                        parts.push(format!("{:x}", value));
                    }
                    parts.join(":")
                } else {
                    String::from("Invalid AAAA record")
                }
            },
            DnsRecordType::CNAME | DnsRecordType::NS | DnsRecordType::PTR => {
                if let Some((domain, _)) = self.parse_domain_name(&data, offset + 10) {
                    domain
                } else {
                    String::from("Invalid domain name")
                }
            },
            _ => format!("<{} bytes of data>", record_data.len()),
        };

        Some((
            DnsAnswer {
                name,
                record_type: DnsRecordType::from(record_type),
                class,
                ttl,
                data: record_data,
                data_str,
            },
            offset + 10 + data_len,
        ))
    }
}

impl DnsParser for UdpDnsParser {
    fn parse(&mut self, data: &[u8], stats: &mut StatsCounter) -> Option<DnsMessage> {
        // 检查数据长度
        if data.len() < 12 || data.len() > self.max_packet_size {
            stats.increment("dns.udp.invalid_size");
            return None;
        }

        // 解析DNS头部
        let transaction_id = u16::from_be_bytes([data[0], data[1]]);
        let flags = u16::from_be_bytes([data[2], data[3]]);
        let questions_count = u16::from_be_bytes([data[4], data[5]]) as usize;
        let answers_count = u16::from_be_bytes([data[6], data[7]]) as usize;
        let authority_count = u16::from_be_bytes([data[8], data[9]]) as usize;
        let additional_count = u16::from_be_bytes([data[10], data[11]]) as usize;

        // 确定消息类型
        let message_type = if (flags & 0x8000) != 0 {
            DnsMessageType::Response
        } else {
            DnsMessageType::Query
        };

        // 解析问题部分
        let mut offset = 12;
        let mut questions = Vec::with_capacity(questions_count);

        for _ in 0..questions_count {
            if let Some((question, new_offset)) = self.parse_question(data, offset) {
                questions.push(question);
                offset = new_offset;
            } else {
                stats.increment("dns.udp.parse_question_failed");
                return None;
            }
        }

        // 解析应答部分
        let mut answers = Vec::with_capacity(answers_count);

        for _ in 0..answers_count {
            if let Some((answer, new_offset)) = self.parse_answer(data, offset) {
                answers.push(answer);
                offset = new_offset;
            } else {
                // 如果解析应答失败，但至少有问题部分，仍然返回消息
                if !questions.is_empty() {
                    stats.increment("dns.udp.parse_answer_failed");
                    break;
                } else {
                    stats.increment("dns.udp.parse_failed");
                    return None;
                }
            }
        }

        // 忽略权威和附加部分

        // 统计
        stats.increment("dns.udp.parsed");
        if message_type == DnsMessageType::Query {
            stats.increment("dns.udp.query");
        } else {
            stats.increment("dns.udp.response");
        }

        // 返回解析结果
        Some(DnsMessage {
            transaction_id,
            message_type,
            questions,
            answers,
            timestamp: 0, // 时间戳需要在调用处设置
            protocol: DnsProtocol::Udp,
        })
    }

    fn protocol_type(&self) -> DnsProtocol {
        DnsProtocol::Udp
    }
}