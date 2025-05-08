//! 内存池实现
//! 提供高效的内存分配和回收机制

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

/// 内存块
#[derive(Clone)]
pub struct MemoryBlock {
    /// 内存数据
    pub data: Vec<u8>,
    /// 已使用的大小
    pub used: usize,
}

impl MemoryBlock {
    /// 创建新的内存块
    pub fn new(size: usize) -> Self {
        MemoryBlock {
            data: vec![0; size],
            used: 0,
        }
    }

    /// 重置内存块
    pub fn reset(&mut self) {
        self.used = 0;
    }

    /// 获取可用空间
    pub fn available(&self) -> usize {
        self.data.len() - self.used
    }

    /// 写入数据
    pub fn write(&mut self, data: &[u8]) -> Option<usize> {
        if self.available() < data.len() {
            return None;
        }

        let start = self.used;
        let end = start + data.len();
        self.data[start..end].copy_from_slice(data);
        self.used = end;

        Some(start)
    }

    /// 读取数据
    pub fn read(&self, offset: usize, len: usize) -> Option<&[u8]> {
        if offset + len > self.used {
            return None;
        }

        Some(&self.data[offset..offset + len])
    }
}

/// 内存池
pub struct MemoryPool {
    /// 空闲内存块
    free_blocks: VecDeque<MemoryBlock>,
    /// 已分配内存块
    allocated_blocks: VecDeque<MemoryBlock>,
    /// 内存块大小
    block_size: usize,
    /// 内存池大小（块数）
    pool_size: usize,
}

impl MemoryPool {
    /// 创建新的内存池
    pub fn new(pool_size: usize, block_size: usize) -> Self {
        let mut free_blocks = VecDeque::with_capacity(pool_size);

        // 预分配内存块
        for _ in 0..pool_size {
            free_blocks.push_back(MemoryBlock::new(block_size));
        }

        MemoryPool {
            free_blocks,
            allocated_blocks: VecDeque::with_capacity(pool_size),
            block_size,
            pool_size,
        }
    }

    /// 分配内存块
    pub fn allocate(&mut self) -> Option<MemoryBlock> {
        if let Some(mut block) = self.free_blocks.pop_front() {
            block.reset();
            self.allocated_blocks.push_back(block);
            return self.allocated_blocks.back().cloned();
        }

        // 如果没有空闲块，创建新的
        if self.allocated_blocks.len() < self.pool_size * 2 {
            let block = MemoryBlock::new(self.block_size);
            self.allocated_blocks.push_back(block);
            return self.allocated_blocks.back().cloned();
        }

        None
    }

    /// 释放内存块
    pub fn free(&mut self, block: MemoryBlock) {
        // 查找并移除已分配块
        for i in 0..self.allocated_blocks.len() {
            if std::ptr::eq(self.allocated_blocks[i].data.as_ptr(), block.data.as_ptr()) {
                let mut block = self.allocated_blocks.remove(i).unwrap();
                block.reset();
                self.free_blocks.push_back(block);
                return;
            }
        }
    }

    /// 获取统计信息
    pub fn stats(&self) -> MemoryPoolStats {
        MemoryPoolStats {
            total_blocks: self.free_blocks.len() + self.allocated_blocks.len(),
            free_blocks: self.free_blocks.len(),
            allocated_blocks: self.allocated_blocks.len(),
            block_size: self.block_size,
        }
    }
}

/// 内存池统计信息
#[derive(Debug, Clone, Copy)]
pub struct MemoryPoolStats {
    /// 总块数
    pub total_blocks: usize,
    /// 空闲块数
    pub free_blocks: usize,
    /// 已分配块数
    pub allocated_blocks: usize,
    /// 块大小
    pub block_size: usize,
}

impl Clone for MemoryBlock {
    fn clone(&self) -> Self {
        MemoryBlock {
            data: self.data.clone(),
            used: self.used,
        }
    }
}
