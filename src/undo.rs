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

    pub fn pop_undo(&mut self) -> Result<TrustAction> {
        self.undo_stack
            .pop()
            .ok_or_else(|| anyhow!("没有可撤销的操作"))
    }

    pub fn pop_redo(&mut self) -> Result<TrustAction> {
        self.redo_stack
            .pop()
            .ok_or_else(|| anyhow!("没有可重做的操作"))
    }

    pub fn push_undo(&mut self, action: TrustAction) {
        self.undo_stack.push(action);
    }

    pub fn push_redo(&mut self, action: TrustAction) {
        self.redo_stack.push(action);
    }
}
