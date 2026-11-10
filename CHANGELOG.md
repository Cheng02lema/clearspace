# 更新记录

## 0.1.1-preview

- 增加 macOS 源码启动入口和 Finder 启动器，仍需本机 Python 与 Node.js。
- macOS 扫描范围默认限制为当前用户主目录与显式配置目录，并隐藏 Windows 专用操作。
- 区分 macOS 的钥匙串、Safari、网络恢复及一键恢复限制。
- 加入 Apple Silicon / Intel 的 macOS 持续集成检查；图形界面尚待真实 Mac 验证。

## 0.1.0-preview

- 提供面向 Claude 本地数据清理的 Python / Tkinter 界面。
- 分离浏览器设置、系统设置与网络恢复，加入可关闭的动态效果。
- 提供扫描、逐项确认、一键执行和有限范围的一键恢复。
- 暂时保留原 JavaScript 安全核心，仍需要 Node.js。
- 清理不创建备份；浏览器清理可影响所有网站。
