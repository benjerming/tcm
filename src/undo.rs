use anyhow::{Result, anyhow};

use crate::netlink::TcmGenlClient;

#[derive(Debug, Clone)]
pub enum WhitelistAction {
    FileAdd(String),
    FileRemove(String),
    ProcAdd { pid: i32, include_children: bool },
    ProcRemove { pid: i32, include_children: bool },
}

impl WhitelistAction {
    pub fn describe(&self) -> String {
        match self {
            WhitelistAction::FileAdd(path) => format!("文件白名单 +{path}"),
            WhitelistAction::FileRemove(path) => format!("文件白名单 -{path}"),
            WhitelistAction::ProcAdd {
                pid,
                include_children,
            } => {
                let scope = if *include_children {
                    "含子进程"
                } else {
                    "仅自身"
                };
                format!("进程白名单 +PID({pid}) [{scope}]")
            }
            WhitelistAction::ProcRemove {
                pid,
                include_children,
            } => {
                let scope = if *include_children {
                    "含子进程"
                } else {
                    "仅自身"
                };
                format!("进程白名单 -PID({pid}) [{scope}]")
            }
        }
    }

    async fn apply(&self, client: &mut TcmGenlClient) -> Result<()> {
        match self {
            WhitelistAction::FileAdd(path) => client.put_trust_path(path).await,
            WhitelistAction::FileRemove(path) => client.distrust_path(path).await,
            WhitelistAction::ProcAdd {
                pid,
                include_children,
            } => {
                client
                    .put_trust_proc_list(vec![*pid], *include_children)
                    .await
            }
            WhitelistAction::ProcRemove {
                pid,
                include_children,
            } => client.distrust_proc(*pid, *include_children).await,
        }
    }

    async fn revert(&self, client: &mut TcmGenlClient) -> Result<()> {
        match self {
            WhitelistAction::FileAdd(path) => client.distrust_path(path).await,
            WhitelistAction::FileRemove(path) => client.put_trust_path(path).await,
            WhitelistAction::ProcAdd {
                pid,
                include_children,
            } => client.distrust_proc(*pid, *include_children).await,
            WhitelistAction::ProcRemove {
                pid,
                include_children,
            } => {
                client
                    .put_trust_proc_list(vec![*pid], *include_children)
                    .await
            }
        }
    }
}

#[derive(Default)]
pub struct UndoRedoManager {
    undo_stack: Vec<WhitelistAction>,
    redo_stack: Vec<WhitelistAction>,
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
            .map(WhitelistAction::describe)
            .collect();
        let redo = self
            .redo_stack
            .iter()
            .rev()
            .map(WhitelistAction::describe)
            .collect();
        (undo, redo)
    }

    pub fn record(&mut self, action: WhitelistAction) {
        self.undo_stack.push(action);
        self.redo_stack.clear();
    }

    pub async fn undo(&mut self, client: &mut TcmGenlClient) -> Result<WhitelistAction> {
        let Some(action) = self.undo_stack.pop() else {
            return Err(anyhow!("没有可撤销的操作"));
        };
        action.revert(client).await?;
        let description = action.clone();
        self.redo_stack.push(action);
        Ok(description)
    }

    pub async fn redo(&mut self, client: &mut TcmGenlClient) -> Result<WhitelistAction> {
        let Some(action) = self.redo_stack.pop() else {
            return Err(anyhow!("没有可重做的操作"));
        };
        action.apply(client).await?;
        let description = action.clone();
        self.undo_stack.push(action);
        Ok(description)
    }
}
