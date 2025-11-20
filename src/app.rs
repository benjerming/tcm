use crate::netlink::{TcmGenlBroadcastListener, TcmGenlClient};
use crate::tcm::TcmEventHandler;
use crate::undo::{TrustAction, UndoRedoManager};
use anyhow::{Result, anyhow};
use log::{info, warn};
use std::path::{Component, Path};
use std::sync::Arc;
use tokio::io::{self, AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::signal;

pub struct App {
    client: TcmGenlClient,
    listener: Option<TcmGenlBroadcastListener>,
    handler: Arc<dyn TcmEventHandler>,
    undo_redo: UndoRedoManager,
    stdin: BufReader<io::Stdin>,
    stdout: io::Stdout,
    input: String,
}

enum LoopControl {
    Continue,
    Exit,
}

#[derive(Copy, Clone)]
enum MenuCommand {
    ShowStats,
    ListenBroadcast,
    AddTrustPath,
    RemoveTrustPath,
    AddTrustProc,
    RemoveTrustProc,
    Undo,
    Redo,
    PrintStacks,
    Exit,
}

impl MenuCommand {
    fn from_input(choice: &str) -> Option<Self> {
        match choice {
            "1" => Some(MenuCommand::ShowStats),
            "2" => Some(MenuCommand::ListenBroadcast),
            "3" => Some(MenuCommand::AddTrustPath),
            "4" => Some(MenuCommand::RemoveTrustPath),
            "5" => Some(MenuCommand::AddTrustProc),
            "6" => Some(MenuCommand::RemoveTrustProc),
            "7" => Some(MenuCommand::Undo),
            "8" => Some(MenuCommand::Redo),
            "9" => Some(MenuCommand::PrintStacks),
            "q" | "Q" => Some(MenuCommand::Exit),
            _ => None,
        }
    }
}

impl App {
    pub fn new(
        client: TcmGenlClient,
        listener: TcmGenlBroadcastListener,
        handler: Arc<dyn TcmEventHandler>,
    ) -> Self {
        Self {
            client,
            listener: Some(listener),
            handler,
            undo_redo: UndoRedoManager::new(),
            stdin: BufReader::new(io::stdin()),
            stdout: io::stdout(),
            input: String::new(),
        }
    }

    pub async fn run(&mut self) -> Result<()> {
        loop {
            self.print_menu().await?;
            self.input.clear();
            let bytes = self.stdin.read_line(&mut self.input).await?;
            if bytes == 0 {
                info!("标准输入已关闭，准备退出");
                break;
            }

            let choice = self.input.trim().to_owned();
            match self.handle_choice(choice.as_str()).await? {
                LoopControl::Continue => {}
                LoopControl::Exit => break,
            }
        }

        Ok(())
    }

    pub fn into_listener(mut self) -> TcmGenlBroadcastListener {
        self.listener
            .take()
            .expect("listener should exist when taking ownership from App")
    }

    async fn print_menu(&mut self) -> Result<()> {
        self.stdout.write_all("\n".as_bytes()).await?;
        self.stdout
            .write_all("请选择工作模式:\n".as_bytes())
            .await?;
        self.stdout
            .write_all("1. 统计文件监控信息\n".as_bytes())
            .await?;
        self.stdout
            .write_all("2. 接收内核广播消息 (CTRL+C 返回)\n".as_bytes())
            .await?;
        self.stdout
            .write_all("3. 添加信任文件[夹]\n".as_bytes())
            .await?;
        self.stdout
            .write_all("4. 移除信任文件[夹]\n".as_bytes())
            .await?;
        self.stdout
            .write_all("5. 添加信任进程[组]\n".as_bytes())
            .await?;
        self.stdout
            .write_all("6. 移除信任进程[组]\n".as_bytes())
            .await?;
        self.stdout
            .write_all("7. 撤销上一次操作\n".as_bytes())
            .await?;
        self.stdout
            .write_all("8. 重做上一次撤销\n".as_bytes())
            .await?;
        self.stdout
            .write_all("9. 打印撤销/重做栈\n".as_bytes())
            .await?;
        self.stdout.write_all("q. 退出程序\n".as_bytes()).await?;
        self.stdout.write_all("> ".as_bytes()).await?;
        self.stdout.flush().await?;
        Ok(())
    }

    async fn handle_choice(&mut self, choice: &str) -> Result<LoopControl> {
        match MenuCommand::from_input(choice) {
            Some(cmd) => self.execute_command(cmd).await,
            None => {
                if choice.is_empty() {
                    Ok(LoopControl::Continue)
                } else {
                    self.stdout.write_all("无效输入\n".as_bytes()).await?;
                    Ok(LoopControl::Continue)
                }
            }
        }
    }

    async fn execute_command(&mut self, cmd: MenuCommand) -> Result<LoopControl> {
        match cmd {
            MenuCommand::ShowStats => {
                self.show_file_stats().await?;
                Ok(LoopControl::Continue)
            }
            MenuCommand::ListenBroadcast => {
                self.listen_for_broadcasts().await?;
                Ok(LoopControl::Continue)
            }
            MenuCommand::AddTrustPath => self.add_trust_path().await,
            MenuCommand::RemoveTrustPath => self.remove_trust_path().await,
            MenuCommand::AddTrustProc => self.add_trust_proc().await,
            MenuCommand::RemoveTrustProc => self.remove_trust_proc().await,
            MenuCommand::Undo => {
                self.undo_last_action().await?;
                Ok(LoopControl::Continue)
            }
            MenuCommand::Redo => {
                self.redo_last_action().await?;
                Ok(LoopControl::Continue)
            }
            MenuCommand::PrintStacks => {
                self.print_stacks().await?;
                Ok(LoopControl::Continue)
            }
            MenuCommand::Exit => {
                info!("用户选择退出程序");
                Ok(LoopControl::Exit)
            }
        }
    }

    async fn show_file_stats(&mut self) -> Result<()> {
        info!("requesting file listener stats via Generic Netlink");
        match self.client.get_file_monitor_stats().await {
            Ok(stats) => {
                info!("received on-demand file stats response");
                self.handler.on_file_stats(stats);
            }
            Err(err) => {
                warn!("failed to request file stats: {err:?}");
            }
        }
        Ok(())
    }

    async fn listen_for_broadcasts(&mut self) -> Result<()> {
        self.listener().enable();

        match signal::ctrl_c().await {
            Ok(()) => {
                self.stdout.write_all("\nCTRL + C\n".as_bytes()).await?;
            }
            Err(err) => {
                self.stdout
                    .write_all(format!("\n错误: {err:?}\n").as_bytes())
                    .await?;
            }
        }

        self.listener().disable();
        Ok(())
    }

    async fn add_trust_path(&mut self) -> Result<LoopControl> {
        let Some(path) = self.prompt_path("请输入信任文件[夹](以/结尾): ").await? else {
            info!("标准输入已关闭，准备退出");
            return Ok(LoopControl::Exit);
        };

        match self.client.put_trust_path(&path).await {
            Ok(()) => {
                self.undo_redo
                    .record(TrustAction::TrustFileAdd(path.clone()));
                self.stdout
                    .write_all("信任文件[夹]已更新\n".as_bytes())
                    .await?;
            }
            Err(err) => {
                warn!("添加信任文件[夹]失败: {err:?}");
                self.stdout
                    .write_all(format!("错误: {err:?}\n").as_bytes())
                    .await?;
            }
        }

        Ok(LoopControl::Continue)
    }

    async fn remove_trust_path(&mut self) -> Result<LoopControl> {
        let Some(path) = self
            .prompt_path("请输入要移除的信任文件[夹](以/结尾): ")
            .await?
        else {
            info!("标准输入已关闭，准备退出");
            return Ok(LoopControl::Exit);
        };

        match self.client.distrust_path(&path).await {
            Ok(()) => {
                self.undo_redo
                    .record(TrustAction::TrustFileRemove(path.clone()));
                self.stdout
                    .write_all("信任文件[夹]已更新\n".as_bytes())
                    .await?;
            }
            Err(err) => {
                warn!("移除信任文件[夹]失败: {err:?}");
                self.stdout
                    .write_all(format!("错误: {err:?}\n").as_bytes())
                    .await?;
            }
        }

        Ok(LoopControl::Continue)
    }

    async fn add_trust_proc(&mut self) -> Result<LoopControl> {
        let Some(pid) = self
            .prompt_pid("请输入要添加信任的进程 PID(负数表示单个进程，正数表示进程树): ")
            .await?
        else {
            info!("标准输入已关闭，准备退出");
            return Ok(LoopControl::Exit);
        };

        match self.client.put_trust_proc_list(vec![pid]).await {
            Ok(()) => {
                self.undo_redo.record(TrustAction::TrustProcAdd(pid));
                self.stdout
                    .write_all("信任进程[组]已更新\n".as_bytes())
                    .await?;
            }
            Err(err) => {
                warn!("添加信任进程[组]失败: {err:?}");
                self.stdout
                    .write_all(format!("错误: {err:?}\n").as_bytes())
                    .await?;
            }
        }

        Ok(LoopControl::Continue)
    }

    async fn remove_trust_proc(&mut self) -> Result<LoopControl> {
        let Some(pid) = self
            .prompt_pid("请输入要移除的进程 PID(负数表示单个进程，正数表示进程树): ")
            .await?
        else {
            info!("标准输入已关闭，准备退出");
            return Ok(LoopControl::Exit);
        };

        match self.client.distrust_proc(pid).await {
            Ok(()) => {
                self.stdout
                    .write_all("信任进程[组]已更新\n".as_bytes())
                    .await?;
                self.undo_redo.record(TrustAction::TrustProcRemove(pid));
            }
            Err(err) => {
                warn!("移除信任进程[组]失败: {err:?}");
                self.stdout
                    .write_all(format!("错误: {err:?}\n").as_bytes())
                    .await?;
            }
        }

        Ok(LoopControl::Continue)
    }

    async fn undo_last_action(&mut self) -> Result<()> {
        match self.undo_redo.pop_undo() {
            Ok(action) => {
                let description = action.describe();
                match self.revert_trust_action(&action).await {
                    Ok(()) => {
                        self.undo_redo.push_redo(action);
                        let msg = format!("已撤销: {description}\n");
                        self.stdout.write_all(msg.as_bytes()).await?;
                    }
                    Err(err) => {
                        self.undo_redo.push_undo(action);
                        self.stdout
                            .write_all(format!("错误: {err:?}\n").as_bytes())
                            .await?;
                    }
                }
            }
            Err(err) => {
                self.stdout
                    .write_all(format!("错误: {err:?}\n").as_bytes())
                    .await?;
            }
        }
        Ok(())
    }

    async fn redo_last_action(&mut self) -> Result<()> {
        match self.undo_redo.pop_redo() {
            Ok(action) => {
                let description = action.describe();
                match self.apply_trust_action(&action).await {
                    Ok(()) => {
                        self.undo_redo.push_undo(action);
                        let msg = format!("已重做: {description}\n");
                        self.stdout.write_all(msg.as_bytes()).await?;
                    }
                    Err(err) => {
                        self.undo_redo.push_redo(action);
                        self.stdout
                            .write_all(format!("错误: {err:?}\n").as_bytes())
                            .await?;
                    }
                }
            }
            Err(err) => {
                self.stdout
                    .write_all(format!("错误: {err:?}\n").as_bytes())
                    .await?;
            }
        }
        Ok(())
    }

    async fn print_stacks(&mut self) -> Result<()> {
        let (undo_stack, redo_stack) = self.undo_redo.stack_descriptions();
        let mut message = String::from("\n撤销栈 (栈顶在上):\n");
        if undo_stack.is_empty() {
            message.push_str("  <空>\n");
        } else {
            for (idx, entry) in undo_stack.iter().enumerate() {
                message.push_str(&format!("  {}. {}\n", idx + 1, entry));
            }
        }
        message.push_str("重做栈 (栈顶在上):\n");
        if redo_stack.is_empty() {
            message.push_str("  <空>\n");
        } else {
            for (idx, entry) in redo_stack.iter().enumerate() {
                message.push_str(&format!("  {}. {}\n", idx + 1, entry));
            }
        }
        self.stdout.write_all(message.as_bytes()).await?;
        Ok(())
    }

    fn listener(&self) -> &TcmGenlBroadcastListener {
        self.listener
            .as_ref()
            .expect("listener should exist while App is running")
    }

    async fn prompt_path(&mut self, prompt: &str) -> Result<Option<String>> {
        loop {
            match self.prompt_line(prompt).await? {
                None => return Ok(None),
                Some(input) => match normalize_path(&input) {
                    Ok(path) => return Ok(Some(path)),
                    Err(err) => {
                        self.stdout
                            .write_all(format!("错误: {err}\n").as_bytes())
                            .await?;
                    }
                },
            }
        }
    }

    async fn prompt_pid(&mut self, prompt: &str) -> Result<Option<i32>> {
        loop {
            match self.prompt_line(prompt).await? {
                None => return Ok(None),
                Some(input) if input.is_empty() => {
                    self.stdout.write_all("PID 不能为空\n".as_bytes()).await?;
                }
                Some(input) => match input.parse::<i32>() {
                    Ok(pid) if pid != 0 => return Ok(Some(pid)),
                    _ => {
                        self.stdout.write_all("PID 无效\n".as_bytes()).await?;
                    }
                },
            }
        }
    }

    async fn prompt_line(&mut self, prompt: &str) -> Result<Option<String>> {
        self.stdout.write_all(prompt.as_bytes()).await?;
        self.stdout.flush().await?;

        let mut buf = String::new();
        let bytes = self.stdin.read_line(&mut buf).await?;
        if bytes == 0 {
            return Ok(None);
        }

        Ok(Some(buf.trim().to_owned()))
    }

    async fn apply_trust_action(&mut self, action: &TrustAction) -> Result<()> {
        match action {
            TrustAction::TrustFileAdd(path) => self.client.put_trust_path(path).await,
            TrustAction::TrustFileRemove(path) => self.client.distrust_path(path).await,
            TrustAction::TrustProcAdd(pid) => self.client.put_trust_proc_list(vec![*pid]).await,
            TrustAction::TrustProcRemove(pid) => self.client.distrust_proc(*pid).await,
        }
    }

    async fn revert_trust_action(&mut self, action: &TrustAction) -> Result<()> {
        match action {
            TrustAction::TrustFileAdd(path) => self.client.distrust_path(path).await,
            TrustAction::TrustFileRemove(path) => self.client.put_trust_path(path).await,
            TrustAction::TrustProcAdd(pid) => self.client.distrust_proc(*pid).await,
            TrustAction::TrustProcRemove(pid) => self.client.put_trust_proc_list(vec![*pid]).await,
        }
    }
}

fn normalize_path(raw: &str) -> Result<String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(anyhow!("路径不能为空"));
    }

    let has_trailing_slash = trimmed.ends_with('/');
    let path = Path::new(trimmed);
    let mut normalized_segments: Vec<String> = Vec::new();
    let mut is_absolute = path.is_absolute();

    for component in path.components() {
        match component {
            Component::Prefix(_) => {
                return Err(anyhow!("不支持包含磁盘前缀的路径"));
            }
            Component::RootDir => {
                is_absolute = true;
                normalized_segments.clear();
            }
            Component::CurDir => {}
            Component::ParentDir => {
                if normalized_segments.pop().is_none() && !is_absolute {
                    return Err(anyhow!("路径越界: 包含无法解析的 .."));
                }
            }
            Component::Normal(segment) => {
                let segment_str = segment.to_string_lossy();
                if segment_str.is_empty() {
                    continue;
                }
                normalized_segments.push(segment_str.into_owned());
            }
        }
    }

    let mut normalized = String::new();
    if is_absolute {
        normalized.push('/');
    }
    normalized.push_str(&normalized_segments.join("/"));

    if normalized.is_empty() {
        normalized = if is_absolute { "/".into() } else { ".".into() };
    }

    if has_trailing_slash && !normalized.ends_with('/') {
        normalized.push('/');
    }

    Ok(normalized)
}
