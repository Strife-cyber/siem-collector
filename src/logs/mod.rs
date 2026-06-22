use crate::types::CollectorLogRecord;
use async_trait::async_trait;
use tokio::sync::mpsc;

pub mod windows;

#[async_trait]
pub trait Collector: Send {
    async fn run(&mut self, sender: mpsc::Sender<CollectorLogRecord>) -> anyhow::Result<()>;
}
