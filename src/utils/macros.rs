//! 自定义宏
//! 提供各种实用宏来简化代码

/// 计时宏，用于测量代码块执行时间
#[macro_export]
macro_rules! time_it {
    ($name:expr, $block:block) => {{
        use $crate::utils::time::HighResTimer;
        let mut timer = HighResTimer::new();
        let result = $block;
        println!(
            "[{}] 执行耗时: {:.3}毫秒",
            $name,
            timer.elapsed_millis() as f64 / 1000.0
        );
        result
    }};
}

/// 重试宏，用于自动重试可能失败的操作
#[macro_export]
macro_rules! retry {
    ($op:expr, $attempts:expr) => {{
        let mut attempts_left = $attempts;
        let mut last_err = None;

        while attempts_left > 0 {
            match $op {
                Ok(result) => break Ok(result),
                Err(err) => {
                    attempts_left -= 1;
                    last_err = Some(err);
                    if attempts_left > 0 {
                        std::thread::sleep(std::time::Duration::from_millis(100));
                    }
                }
            }
        }

        if let Some(err) = last_err {
            Err(err)
        } else {
            Err("Unknown error".into())
        }
    }};
    ($op:expr, $attempts:expr, $delay_ms:expr) => {{
        let mut attempts_left = $attempts;
        let mut last_err = None;

        while attempts_left > 0 {
            match $op {
                Ok(result) => break Ok(result),
                Err(err) => {
                    attempts_left -= 1;
                    last_err = Some(err);
                    if attempts_left > 0 {
                        std::thread::sleep(std::time::Duration::from_millis($delay_ms));
                    }
                }
            }
        }

        if let Some(err) = last_err {
            Err(err)
        } else {
            Err("Unknown error".into())
        }
    }};
}

/// 日志宏，用于统一日志格式
#[macro_export]
macro_rules! log {
    (error, $($arg:tt)*) => {
        eprintln!("[ERROR] {}", format!($($arg)*));
    };
    (warn, $($arg:tt)*) => {
        eprintln!("[WARN] {}", format!($($arg)*));
    };
    (info, $($arg:tt)*) => {
        println!("[INFO] {}", format!($($arg)*));
    };
    (debug, $($arg:tt)*) => {
        #[cfg(debug_assertions)]
        println!("[DEBUG] {}", format!($($arg)*));
    };
    (trace, $($arg:tt)*) => {
        #[cfg(feature = "trace")]
        println!("[TRACE] {}", format!($($arg)*));
    };
}

/// 测量内存使用宏
#[macro_export]
macro_rules! measure_memory {
    ($block:block) => {{
        let before = std::mem::size_of_val(&$block);
        let result = $block;
        let after = std::mem::size_of_val(&result);
        println!("内存使用: {}字节", after - before);
        result
    }};
}

/// 解析或返回宏，用于简化错误处理
#[macro_export]
macro_rules! parse_or_return {
    ($expr:expr, $default:expr) => {
        match $expr {
            Ok(val) => val,
            Err(_) => return $default,
        }
    };
}
