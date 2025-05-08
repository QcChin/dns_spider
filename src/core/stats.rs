//! 统计计数器
//! 用于收集和报告性能指标

use std::collections::HashMap;
use std::time::{Duration, Instant};

/// 统计计数器
#[derive(Clone)]
pub struct StatsCounter {
    /// 计数器映射
    counters: HashMap<String, u64>,
    /// 计时器映射
    timers: HashMap<String, Duration>,
    /// 开始时间
    start_time: Instant,
}

impl StatsCounter {
    /// 创建新的统计计数器
    pub fn new() -> Self {
        StatsCounter {
            counters: HashMap::new(),
            timers: HashMap::new(),
            start_time: Instant::now(),
        }
    }
    
    /// 增加计数器值
    pub fn increment(&mut self, key: &str) {
        *self.counters.entry(key.to_string()).or_insert(0) += 1;
    }
    
    /// 增加计数器指定值
    pub fn add(&mut self, key: &str, value: u64) {
        *self.counters.entry(key.to_string()).or_insert(0) += value;
    }
    
    /// 设置计数器值
    pub fn set(&mut self, key: &str, value: u64) {
        self.counters.insert(key.to_string(), value);
    }
    
    /// 获取计数器值
    pub fn get(&self, key: &str) -> u64 {
        *self.counters.get(key).unwrap_or(&0)
    }
    
    /// 开始计时
    pub fn start_timer(&mut self, key: &str) {
        self.timers.insert(key.to_string(), Duration::from_secs(0));
    }
    
    /// 停止计时
    pub fn stop_timer(&mut self, key: &str, start: Instant) {
        let duration = start.elapsed();
        if let Some(timer) = self.timers.get_mut(key) {
            *timer += duration;
        } else {
            self.timers.insert(key.to_string(), duration);
        }
    }
    
    /// 获取计时器值（毫秒）
    pub fn get_timer_ms(&self, key: &str) -> u64 {
        self.timers.get(key).map_or(0, |d| d.as_millis() as u64)
    }
    
    /// 打印统计信息并重置
    pub fn print_and_reset(&mut self) {
        let elapsed = self.start_time.elapsed().as_secs_f64();
        
        println!("=== 统计信息 (运行时间: {:.2}秒) ===", elapsed);
        
        // 打印计数器
        let mut sorted_counters: Vec<_> = self.counters.iter().collect();
        sorted_counters.sort_by(|a, b| a.0.cmp(b.0));
        
        for (key, value) in sorted_counters {
            let rate = *value as f64 / elapsed;
            println!("{}: {} ({:.2}/秒)", key, value, rate);
        }
        
        // 打印计时器
        let mut sorted_timers: Vec<_> = self.timers.iter().collect();
        sorted_timers.sort_by(|a, b| a.0.cmp(b.0));
        
        for (key, duration) in sorted_timers {
            println!("{}: {:.2}毫秒", key, duration.as_millis());
        }
        
        println!("===========================");
        
        // 重置
        self.counters.clear();
        self.timers.clear();
        self.start_time = Instant::now();
    }
    
    /// 合并另一个计数器的统计信息
    pub fn merge(&mut self, other: &StatsCounter) {
        for (key, value) in &other.counters {
            *self.counters.entry(key.clone()).or_insert(0) += value;
        }
        
        for (key, duration) in &other.timers {
            *self.timers.entry(key.clone()).or_insert(Duration::from_secs(0)) += *duration;
        }
    }
}