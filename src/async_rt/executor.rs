pub struct DnsExecutor {
    local_queues: Vec<LocalQueue>,
    global_queue: Arc<ConcurrentQueue>,
}
