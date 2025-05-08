//! 高性能时间处理
//! 提供精确的时间戳和计时功能

use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// 获取当前时间戳（微秒）
pub fn current_time_micros() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::from_secs(0))
        .as_micros() as u64
}

/// 获取当前时间戳（毫秒）
pub fn current_time_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::from_secs(0))
        .as_millis() as u64
}

/// 获取当前时间戳（秒）
pub fn current_time_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::from_secs(0))
        .as_secs()
}

/// 高精度计时器
pub struct HighResTimer {
    /// 开始时间
    start: Instant,
    /// 标记点
    marks: Vec<(String, Duration)>,
}

impl HighResTimer {
    /// 创建新的计时器
    pub fn new() -> Self {
        HighResTimer {
            start: Instant::now(),
            marks: Vec::new(),
        }
    }

    /// 添加标记点
    pub fn mark(&mut self, name: &str) {
        let elapsed = self.start.elapsed();
        self.marks.push((name.to_string(), elapsed));
    }

    /// 获取总耗时（纳秒）
    pub fn elapsed_nanos(&self) -> u64 {
        self.start.elapsed().as_nanos() as u64
    }

    /// 获取总耗时（微秒）
    pub fn elapsed_micros(&self) -> u64 {
        self.start.elapsed().as_micros() as u64
    }

    /// 获取总耗时（毫秒）
    pub fn elapsed_millis(&self) -> u64 {
        self.start.elapsed().as_millis() as u64
    }

    /// 获取标记点之间的耗时
    pub fn intervals(&self) -> Vec<(String, u64)> {
        let mut result = Vec::new();
        let mut prev = Duration::from_secs(0);

        for (name, time) in &self.marks {
            let interval = time.saturating_sub(prev);
            result.push((name.clone(), interval.as_nanos() as u64));
            prev = *time;
        }

        result
    }

    /// 打印计时结果
    pub fn print_results(&self) {
        println!("=== 计时结果 ====");
        println!("总耗时: {:.3}毫秒", self.elapsed_millis() as f64 / 1000.0);

        if !self.marks.is_empty() {
            println!("标记点:");
            let intervals = self.intervals();
            for (i, (name, nanos)) in intervals.iter().enumerate() {
                let micros = *nanos as f64 / 1000.0;
                let millis = micros / 1000.0;
                println!("  {}: {} - {:.3}毫秒", i + 1, name, millis);
            }
        }

        println!("=================");
    }

    /// 重置计时器
    pub fn reset(&mut self) {
        self.start = Instant::now();
        self.marks.clear();
    }
}

/// 创建一个作用域计时器，在离开作用域时自动打印耗时
pub struct ScopedTimer {
    /// 名称
    name: String,
    /// 开始时间
    start: Instant,
}

impl ScopedTimer {
    /// 创建新的作用域计时器
    pub fn new(name: &str) -> Self {
        println!("[{}] 开始计时", name);
        ScopedTimer {
            name: name.to_string(),
            start: Instant::now(),
        }
    }
}

impl Drop for ScopedTimer {
    fn drop(&mut self) {
        let elapsed = self.start.elapsed();
        println!(
            "[{}] 结束计时: {:.3}毫秒",
            self.name,
            elapsed.as_millis() as f64 / 1000.0
        );
    }
}
