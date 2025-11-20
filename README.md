# TCM

## Cargo 子命令

本项目提供 `cargo tcm` 以管理内核模块：

- `cargo tcm build`：在 `k/` 目录中执行 `make` 并生成 `build/tcm.ko`
- `cargo tcm load`：默认先编译再使用 `sudo insmod` 加载模块（可加 `--skip-build`、`--force`）
- `cargo tcm unload`：卸载已加载的 `tcm` 模块
- `cargo tcm reload`: 卸载并重新编译安装 `tcm` 模块
- `cargo tcm status`：查看 `tcm` 模块是否已加载

若未安装该子命令，可在仓库根目录运行 `cargo run --bin cargo-tcm -- <命令>` 进行调试，或执行
`cargo install --path . --bin cargo-tcm` 以在全局环境中使用 `cargo tcm`。
