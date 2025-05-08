//! 错误处理模块
//! 定义项目中使用的错误类型

use std::fmt;
use std::io;
use std::result;

/// 项目结果类型别名
pub type Result<T> = result::Result<T, Error>;

/// DNS Spider错误类型
#[derive(Debug)]
pub enum Error {
    /// IO错误
    Io(io::Error),
    /// 配置错误
    Config(String),
    /// 捕获错误
    Capture(String),
    /// 解析错误
    Parse(String),
    /// DPDK错误
    Dpdk(String),
    /// XDP错误
    Xdp(String),
    /// 协议错误
    Protocol(String),
    /// 输出错误
    Output(String),
    /// 其他错误
    Other(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Io(err) => write!(f, "IO错误: {}", err),
            Error::Config(msg) => write!(f, "配置错误: {}", msg),
            Error::Capture(msg) => write!(f, "捕获错误: {}", msg),
            Error::Parse(msg) => write!(f, "解析错误: {}", msg),
            Error::Dpdk(msg) => write!(f, "DPDK错误: {}", msg),
            Error::Xdp(msg) => write!(f, "XDP错误: {}", msg),
            Error::Protocol(msg) => write!(f, "协议错误: {}", msg),
            Error::Output(msg) => write!(f, "输出错误: {}", msg),
            Error::Other(msg) => write!(f, "其他错误: {}", msg),
        }
    }
}

impl std::error::Error for Error {}

impl From<io::Error> for Error {
    fn from(err: io::Error) -> Self {
        Error::Io(err)
    }
}

impl From<String> for Error {
    fn from(err: String) -> Self {
        Error::Other(err)
    }
}

impl From<&str> for Error {
    fn from(err: &str) -> Self {
        Error::Other(err.to_string())
    }
}
