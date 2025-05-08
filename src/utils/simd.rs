//! SIMD加速代码
//! 使用SIMD指令集优化性能关键路径

#[cfg(target_arch = "x86_64")]
use std::arch::x86_64::*;

/// 使用SIMD加速的内存比较
///
/// # 安全性
///
/// 这个函数使用了不安全的SIMD指令，调用者必须确保：
/// 1. CPU支持SSE2指令集
/// 2. 输入数据对齐正确
pub unsafe fn simd_memcmp(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }

    #[cfg(target_arch = "x86_64")]
    {
        // 检查是否有足够的数据进行SIMD比较
        if a.len() >= 16 {
            let chunks = a.len() / 16;

            for i in 0..chunks {
                let offset = i * 16;
                let a_ptr = a.as_ptr().add(offset) as *const __m128i;
                let b_ptr = b.as_ptr().add(offset) as *const __m128i;

                let a_chunk = _mm_loadu_si128(a_ptr);
                let b_chunk = _mm_loadu_si128(b_ptr);

                let cmp = _mm_cmpeq_epi8(a_chunk, b_chunk);
                let mask = _mm_movemask_epi8(cmp);

                if mask != 0xFFFF {
                    return false;
                }
            }

            // 比较剩余字节
            let remaining_start = chunks * 16;
            for i in remaining_start..a.len() {
                if a[i] != b[i] {
                    return false;
                }
            }

            return true;
        }
    }

    // 回退到标准比较
    a == b
}

/// 使用SIMD加速的字节查找
pub unsafe fn simd_find_byte(data: &[u8], byte: u8) -> Option<usize> {
    #[cfg(target_arch = "x86_64")]
    {
        if data.len() >= 16 {
            // 创建包含目标字节的向量
            let target = _mm_set1_epi8(byte as i8);
            let chunks = data.len() / 16;

            for i in 0..chunks {
                let offset = i * 16;
                let data_ptr = data.as_ptr().add(offset) as *const __m128i;

                let data_chunk = _mm_loadu_si128(data_ptr);
                let cmp = _mm_cmpeq_epi8(data_chunk, target);
                let mask = _mm_movemask_epi8(cmp);

                if mask != 0 {
                    // 找到匹配，确定具体位置
                    let trailing_zeros = mask.trailing_zeros() as usize;
                    return Some(offset + trailing_zeros);
                }
            }

            // 检查剩余字节
            let remaining_start = chunks * 16;
            for i in remaining_start..data.len() {
                if data[i] == byte {
                    return Some(i);
                }
            }

            return None;
        }
    }

    // 回退到标准查找
    data.iter().position(|&b| b == byte)
}

/// 使用SIMD加速的内存复制
pub unsafe fn simd_memcpy(dst: &mut [u8], src: &[u8]) -> usize {
    let len = std::cmp::min(dst.len(), src.len());

    #[cfg(target_arch = "x86_64")]
    {
        if len >= 16 {
            let chunks = len / 16;

            for i in 0..chunks {
                let offset = i * 16;
                let src_ptr = src.as_ptr().add(offset) as *const __m128i;
                let dst_ptr = dst.as_mut_ptr().add(offset) as *mut __m128i;

                let data = _mm_loadu_si128(src_ptr);
                _mm_storeu_si128(dst_ptr, data);
            }

            // 复制剩余字节
            let remaining_start = chunks * 16;
            for i in remaining_start..len {
                dst[i] = src[i];
            }

            return len;
        }
    }

    // 回退到标准复制
    dst[..len].copy_from_slice(&src[..len]);
    len
}

/// 使用SIMD加速的字符串解析
/// 快速查找分隔符并分割字符串
pub unsafe fn simd_split_at_byte(data: &[u8], delimiter: u8) -> Vec<&[u8]> {
    let mut result = Vec::new();
    let mut start = 0;

    #[cfg(target_arch = "x86_64")]
    {
        if data.len() >= 16 {
            // 创建包含分隔符的向量
            let target = _mm_set1_epi8(delimiter as i8);

            let mut pos = 0;
            while pos + 16 <= data.len() {
                let data_ptr = data.as_ptr().add(pos) as *const __m128i;
                let data_chunk = _mm_loadu_si128(data_ptr);

                let cmp = _mm_cmpeq_epi8(data_chunk, target);
                let mask = _mm_movemask_epi8(cmp);

                if mask != 0 {
                    // 处理所有匹配
                    let mut mask_copy = mask;
                    while mask_copy != 0 {
                        let trailing_zeros = mask_copy.trailing_zeros() as usize;
                        let delimiter_pos = pos + trailing_zeros;

                        result.push(&data[start..delimiter_pos]);
                        start = delimiter_pos + 1;

                        // 清除已处理的位
                        mask_copy &= mask_copy - 1;
                    }
                }

                pos += 16;
            }
        }
    }

    // 处理剩余部分或回退到标准方法
    let mut i = start.max(data.len() / 16 * 16);
    while i < data.len() {
        if data[i] == delimiter {
            result.push(&data[start..i]);
            start = i + 1;
        }
        i += 1;
    }

    // 添加最后一段
    if start < data.len() {
        result.push(&data[start..]);
    }

    result
}
