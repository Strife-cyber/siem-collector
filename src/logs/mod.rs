use tokio::sync::mpsc;
use async_trait::async_trait;
use crate::types::CollectorLogRecord;

pub mod windows;

#[async_trait]
pub trait Collector {
    async fn run(
        &mut self,
        sender: mpsc::Sender<CollectorLogRecord>
    ) -> anyhow::Result<()>;
}
