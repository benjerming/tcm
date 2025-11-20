mod app;
mod netlink;
mod runtime;
mod tcm;
mod undo;

use crate::app::App;
use crate::runtime::{RuntimeBootstrap, bootstrap};
use crate::tcm::*;
use anyhow::{Context, Result};
use log::{info, warn};
use std::sync::Arc;

#[tokio::main]
async fn main() -> Result<()> {
    dotenvy::dotenv().ok();
    env_logger::init();

    let handler: Arc<dyn TcmEventHandler> = Arc::new(LoggingEventHandler);
    let runtime = bootstrap(Arc::clone(&handler)).await?;
    let RuntimeBootstrap {
        mut client,
        listener,
        guard,
    } = runtime;

    let auth_key = std::env::var("TCM_AUTH_KEY").unwrap_or_else(|_| {
        warn!("TCM_AUTH_KEY 未设置，将使用默认测试密钥");
        "1234567890".to_owned()
    });

    info!("logging in to TCM");
    client.login(&auth_key).await.context("failed to login")?;
    info!("  success");

    let mut app = App::new(client, listener, handler);
    app.run().await?;

    let listener = app.into_listener();
    guard.shutdown(listener).await;

    info!("userspace listener terminated");
    Ok(())
}

struct LoggingEventHandler;

impl TcmEventHandler for LoggingEventHandler {
    fn on_proc(&self, event: TcmProcEvent) {
        info!("{event:?}");
    }

    fn on_file(&self, event: TcmFileEvent) {
        info!("{event:?}");
    }

    fn on_file_stats(&self, event: TcmFileMonitorStats) {
        info!(
            "file stats: pid_table_size={} pid_entries={} file_entries={} top_pid_count={}",
            event.pid_table_size,
            event.pid_entry_count,
            event.file_entry_count,
            event.top_pid_count
        );

        if event.top_pids.is_empty() {
            info!("  no processes tracked");
            return;
        }

        for (idx, stat) in event.top_pids.iter().enumerate() {
            info!(
                "  top #{idx}: pid={} file_count={}",
                stat.pid, stat.file_count
            );
        }
    }
}
