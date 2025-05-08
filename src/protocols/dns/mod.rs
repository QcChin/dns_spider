//! DNS协议解析模块
//! 支持标准DNS、DoT、DoH和DoQ协议

mod udp;
mod tcp;
mod dot;
mod doh;
mod doq;

pub use doh::DohParser;
pub use doq::DoqParser;
pub use dot::DotParser;
pub use tcp::TcpDnsParser;
pub use udp::UdpDnsParser;

use crate::core::stats::StatsCounter;

/// DNS消息类型
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DnsMessageType {
    Query,
    Response,
}

/// DNS记录类型
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DnsRecordType {
    A,
    AAAA,
    CNAME,
    MX,
    NS,
    PTR,
    SOA,
    SRV,
    TXT,
    Other(u16),
}

impl From<u16> for DnsRecordType {
    fn from(value: u16) -> Self {
        match value {
            1 => DnsRecordType::A,
            28 => DnsRecordType::AAAA,
            5 => DnsRecordType::CNAME,
            15 => DnsRecordType::MX,
            2 => DnsRecordType::NS,
            12 => DnsRecordType::PTR,
            6 => DnsRecordType::SOA,
            33 => DnsRecordType::SRV,
            16 => DnsRecordType::TXT,
            other => DnsRecordType::Other(other),
        }
    }
}

/// DNS解析结果
#[derive(Debug)]
pub struct DnsMessage {
    pub transaction_id: u16,
    pub message_type: DnsMessageType,
    pub questions: Vec<DnsQuestion>,
    pub answers: Vec<DnsAnswer>,
    pub timestamp: u64,
    pub protocol: DnsProtocol,
}

/// DNS协议类型
#[derive(Debug, Clone, Copy)]
pub enum DnsProtocol {
    Udp,
    Tcp,
    Dot,
    Doh,
    Doq,
}

/// DNS问题记录
#[derive(Debug)]
pub struct DnsQuestion {
    pub name: String,
    pub record_type: DnsRecordType,
    pub class: u16,
}

/// DNS应答记录
#[derive(Debug)]
pub struct DnsAnswer {
    pub name: String,
    pub record_type: DnsRecordType,
    pub class: u16,
    pub ttl: u32,
    pub data: Vec<u8>,
    pub data_str: String,
}

/// DNS解析器特征
pub trait DnsParser {
    fn parse(&mut self, data: &[u8], stats: &mut StatsCounter) -> Option<DnsMessage>;
    fn protocol_type(&self) -> DnsProtocol;
}