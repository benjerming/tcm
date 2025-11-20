use crate::netlink::TcmGenlClient;
use anyhow::{Result, anyhow};

#[derive(Debug, Clone)]
pub enum TrustAction {
    TrustFileAdd(String),
    TrustFileRemove(String),
    TrustProcAdd(i32),
    TrustProcRemove(i32),
}

impl TrustAction {
    pub fn describe(&self) -> String {
        match self {
            TrustAction::TrustFileAdd(path) => format!("添加信任文件: {path}"),
            TrustAction::TrustFileRemove(path) => format!("移除信任文件: {path}"),
            TrustAction::TrustProcAdd(pid) => format!("添加信任进程: {pid}"),
            TrustAction::TrustProcRemove(pid) => format!("移除信任进程: {pid}"),
        }
    }

    async fn apply(&self, client: &mut TcmGenlClient) -> Result<()> {
        match self {
            TrustAction::TrustFileAdd(path) => client.put_trust_path(path).await,
            TrustAction::TrustFileRemove(path) => client.distrust_path(path).await,
            TrustAction::TrustProcAdd(pid) => client.put_trust_proc_list(vec![*pid]).await,
            TrustAction::TrustProcRemove(pid) => client.distrust_proc(*pid).await,
        }
    }

    async fn revert(&self, client: &mut TcmGenlClient) -> Result<()> {
        match self {
            TrustAction::TrustFileAdd(path) => client.distrust_path(path).await,
            TrustAction::TrustFileRemove(path) => client.put_trust_path(path).await,
            TrustAction::TrustProcAdd(pid) => client.distrust_proc(*pid).await,
            TrustAction::TrustProcRemove(pid) => client.put_trust_proc_list(vec![*pid]).await,
        }
    }
}

#[derive(Default)]
pub struct UndoRedoManager {
    undo_stack: Vec<TrustAction>,
    redo_stack: Vec<TrustAction>,
}

impl UndoRedoManager {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn stack_descriptions(&self) -> (Vec<String>, Vec<String>) {
        let undo = self
            .undo_stack
            .iter()
            .rev()
            .map(TrustAction::describe)
            .collect();
        let redo = self
            .redo_stack
            .iter()
            .rev()
            .map(TrustAction::describe)
            .collect();
        (undo, redo)
    }

    pub fn record(&mut self, action: TrustAction) {
        self.undo_stack.push(action);
        self.redo_stack.clear();
    }

    pub async fn undo(&mut self, client: &mut TcmGenlClient) -> Result<TrustAction> {
        let Some(action) = self.undo_stack.pop() else {
            return Err(anyhow!("没有可撤销的操作"));
        };
        action.revert(client).await?;
        let description = action.clone();
        self.redo_stack.push(action);
        Ok(description)
    }

    pub async fn redo(&mut self, client: &mut TcmGenlClient) -> Result<TrustAction> {
        let Some(action) = self.redo_stack.pop() else {
            return Err(anyhow!("没有可重做的操作"));
        };
        action.apply(client).await?;
        let description = action.clone();
        self.undo_stack.push(action);
        Ok(description)
    }
}
