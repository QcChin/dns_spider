//! 协议检测器
//! 用于识别不同类型的DNS协议

use crate::protocols::dns::{DnsParser, DnsProtocol};

/// 协议检测结果
pub enum ProtocolDetectResult {
    Dns(DnsProtocol),
    Unknown,
    NeedMoreData,
}

/// 协议检测器
pub struct ProtocolDetector {
    // 配置
    dns_ports: Vec<u16>,
    dot_ports: Vec<u16>,
    doh_ports: Vec<u16>,
    doq_ports: Vec<u16>,
}

impl ProtocolDetector {
    /// 创建新的协议检测器
    pub fn new() -> Self {
        ProtocolDetector {
            dns_ports: vec![53],
            dot_ports: vec![853],
            doh_ports: vec![443],
            doq_ports: vec![853, 8853],
        }
    }

    /// 自定义DNS端口
    pub fn with_dns_ports(mut self, ports: Vec<u16>) -> Self {
        self.dns_ports = ports;
        self
    }

    /// 自定义DoT端口
    pub fn with_dot_ports(mut self, ports: Vec<u16>) -> Self {
        self.dot_ports = ports;
        self
    }

    /// 自定义DoH端口
    pub fn with_doh_ports(mut self, ports: Vec<u16>) -> Self {
        self.doh_ports = ports;
        self
    }

    /// 自定义DoQ端口
    pub fn with_doq_ports(mut self, ports: Vec<u16>) -> Self {
        self.doq_ports = ports;
        self
    }

    /// 检测数据包所属的协议类型
    /// 
    /// # 参数
    /// 
    /// * `data` - 数据包内容
    /// * `src_port` - 源端口
    /// * `dst_port` - 目标端口
    /// 
    /// # 返回值
    /// 
    /// 返回检测结果，可能是已知协议、未知协议或需要更多数据
    pub fn detect(&self, data: &[u8], src_port: u16, dst_port: u16) -> ProtocolDetectResult {
        // 检查是否是标准DNS协议
        if self.dns_ports.contains(&src_port) || self.dns_ports.contains(&dst_port) {
            return ProtocolDetectResult::Dns(DnsProtocol::Udp); // 或其它合适的类型
        }

        // 检查是否是DoT协议
        if self.dot_ports.contains(&src_port) || self.dot_ports.contains(&dst_port) {
            // DoT协议检测逻辑
            // 由于DoT是基于TLS的，这里需要更复杂的TLS解析
            // 简单实现可以先返回需要更多数据
            return ProtocolDetectResult::NeedMoreData;
        }

        // 检查是否是DoH协议
        if self.doh_ports.contains(&src_port) || self.doh_ports.contains(&dst_port) {
            // DoH协议检测逻辑
            // 由于DoH是基于HTTP的，这里需要HTTP解析
            // 简单实现可以先返回需要更多数据
            return ProtocolDetectResult::NeedMoreData;
        }

        // 检查是否是DoQ协议
        if self.doq_ports.contains(&src_port) || self.doq_ports.contains(&dst_port) {
            // DoQ协议检测逻辑
            // 由于DoQ是基于QUIC的，这里需要QUIC解析
            // 简单实现可以先返回需要更多数据
            return ProtocolDetectResult::NeedMoreData;
        }

        // 尝试通用DNS检测
        // 直接返回 ProtocolDetectResult::Dns(DnsProtocol::Udp) 即可
        ProtocolDetectResult::Dns(DnsProtocol::Udp)
    }

    /// 判断端口是否为DNS相关端口
    pub fn is_dns_related_port(&self, port: u16) -> bool {
        self.dns_ports.contains(&port) || 
        self.dot_ports.contains(&port) || 
        self.doh_ports.contains(&port) || 
        self.doq_ports.contains(&port)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detector_creation() {
        let detector = ProtocolDetector::new();
        assert!(detector.dns_ports.contains(&53));
        assert!(detector.dot_ports.contains(&853));
        assert!(detector.doh_ports.contains(&443));
        assert!(detector.doq_ports.contains(&853));
    }

    #[test]
    fn test_custom_ports() {
        let detector = ProtocolDetector::new()
            .with_dns_ports(vec![5353])
            .with_dot_ports(vec![8853])
            .with_doh_ports(vec![8443])
            .with_doq_ports(vec![8853, 9853]);
        
        assert!(detector.dns_ports.contains(&5353));
        assert!(detector.dot_ports.contains(&8853));
        assert!(detector.doh_ports.contains(&8443));
        assert!(detector.doq_ports.contains(&9853));
    }

    #[test]
    fn test_is_dns_related_port() {
        let detector = ProtocolDetector::new();
        assert!(detector.is_dns_related_port(53));
        assert!(detector.is_dns_related_port(853));
        assert!(detector.is_dns_related_port(443));
        assert!(!detector.is_dns_related_port(80));
    }
}