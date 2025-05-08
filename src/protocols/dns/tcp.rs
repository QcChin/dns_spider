//! TCP DNS协议解析实现
//! 处理TCP流重组和DNS消息提取

use crate::core::stats::StatsCounter;
use crate::protocols::dns::{DnsMessage, DnsParser, DnsProtocol};
use std::collections::HashMap;

/// TCP会话状态
struct TcpSession {
    buffer: Vec<u8>,
    last_seen: u64,
}

/// TCP DNS解析器
pub struct TcpDnsParser {
    // 内部UDP解析器用于解析DNS消息
    udp_parser: super::udp::UdpDnsParser,
    // TCP会话跟踪
    tcp_sessions: HashMap<(u32, u32, u16, u16), TcpSession>, // (src_ip, dst_ip, src_port, dst_port)
    // 配置
    max_packet_size: usize,
    max_sessions: usize,
    session_timeout_ms: u64,
    current_time_ms: u64,
}

impl TcpDnsParser {
    /// 创建新的TCP DNS解析器
    pub fn new(max_packet_size: usize, max_sessions: usize, session_timeout_ms: u64) -> Self {
        TcpDnsParser {
            udp_parser: super::udp::UdpDnsParser::new(max_packet_size),
            tcp_sessions: HashMap::with_capacity(max_sessions),
            max_packet_size,
            max_sessions,
            session_timeout_ms,
            current_time_ms: 0,
        }
    }

    /// 更新当前时间
    pub fn update_time(&mut self, time_ms: u64) {
        self.current_time_ms = time_ms;
        self.cleanup_sessions();
    }

    /// 清理过期会话
    fn cleanup_sessions(&mut self) {
        let expired_time = self.current_time_ms.saturating_sub(self.session_timeout_ms);
        self.tcp_sessions.retain(|_, session| session.last_seen > expired_time);
    }

    /// 处理TCP段
    pub fn process_tcp_segment(&mut self, 
                              src_ip: u32, 
                              dst_ip: u32, 
                              src_port: u16, 
                              dst_port: u16, 
                              data: &[u8], 
                              stats: &mut StatsCounter) -> Vec<DnsMessage> {
        let mut results = Vec::new();
        
        // 会话标识
        let session_id = (src_ip, dst_ip, src_port, dst_port);
        
        // 获取或创建会话
        let session = self.tcp_sessions.entry(session_id).or_insert_with(|| {
            // 如果超过最大会话数，清理最旧的会话
            if self.tcp_sessions.len() >= self.max_sessions {
                self.cleanup_sessions();
                
                // 如果仍然超过限制，移除最旧的会话
                if self.tcp_sessions.len() >= self.max_sessions {
                    let oldest = self.tcp_sessions.iter()
                        .min_by_key(|(_, s)| s.last_seen)
                        .map(|(k, _)| *k);
                    
                    if let Some(key) = oldest {
                        self.tcp_sessions.remove(&key);
                    }
                }
            }
            
            TcpSession {
                buffer: Vec::new(),
                last_seen: self.current_time_ms,
            }
        });
        
        // 更新最后见到时间
        session.last_seen = self.current_time_ms;
        
        // 添加数据到缓冲区
        session.buffer.extend_from_slice(data);
        
        // 检查缓冲区大小
        if session.buffer.len() > self.max_packet_size {
            stats.increment("dns.tcp.buffer_overflow");
            session.buffer.clear();
            return results;
        }
        
        // 处理缓冲区中的所有完整DNS消息
        while session.buffer.len() >= 2 {
            // TCP中的DNS消息前两个字节是长度
            let message_length = u16::from_be_bytes([session.buffer[0], session.buffer[1]]) as usize;
            
            // 检查是否有完整的消息
            if session.buffer.len() >= message_length + 2 {
                // 提取DNS消息
                let dns_data = &session.buffer[2..message_length + 2];
                
                // 解析DNS消息
                if let Some(mut message) = self.udp_parser.parse(dns_data, stats) {
                    // 修改协议类型
                    message.protocol = DnsProtocol::Tcp;
                    results.push(message);
                }
                
                // 移除已处理的数据
                session.buffer.drain(0..message_length + 2);
            } else {
                // 没有完整的消息，等待更多数据
                break;
            }
        }
        
        results
    }
}

impl DnsParser for TcpDnsParser {
    fn parse(&mut self, data: &[u8], stats: &mut StatsCounter) -> Option<DnsMessage> {
        // 注意：TCP解析器需要通过process_tcp_segment方法处理TCP段
        // 这个方法主要用于兼容DnsParser特征
        stats.increment("dns.tcp.direct_parse_attempt");
        None
    }

    fn protocol_type(&self) -> DnsProtocol {
        DnsProtocol::Tcp
    }
}