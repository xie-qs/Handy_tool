# 刘组YYDS (Handy_tool)

一款专为 Android 开发与逆向分析打造的高性能集成工具箱：集成了 Android 日志查看器 (Logcat)、透明网络抓包与修改 (Charles Proxy / WinDivert 透明劫持)、以及低延迟屏幕投屏控制 (Scrcpy)。

## 🌟 核心功能

- **📱 Android Logcat 查看器**
  - 多设备自动发现与连接切换。
  - 支持按日志级别 (Verbose/Debug/Info/Warn/Error/Fatal)、进程名、Tag 实时高亮筛选。
  - 智能解析 JSON 格式日志并美化展示。

- **🌐 全功能网络抓包与接口修改 (Charles / Fiddler 替代品)**
  - **透明代理与驱动级拦截**：基于 WinDivert 驱动，透明劫持电脑应用（如微信小程序、各类加速器、PC 客户端）的 TCP/TLS 请求，无感免配置系统代理。
  - **HTTPS MITM 动态解密**：动态签发泛域名及多 SAN 证书，无缝解密 HTTPS 流量。
  - **HTTPDNS / 纯 IP 直连智能纠偏**：自动识别请求头真实 Host 域名，维护 IP ↔ 域名双向映射记忆库，支持纯 IP 嗅探解密，无需重复为动态 IP 加白名单。
  - **断点拦截与参数修改**：支持针对特定域名/接口的请求断点、响应断点、修改 Query / 请求体、修改响应内容、本地直接 Mock 等高级调试功能。
  - **多进程来源精准识别**：精确标注请求来源进程（如 `💻 leigod_launcher.exe`、`📱 手机设备`），支持按来源与域名多级过滤。

- **🖥️ 实时高清投屏 (Scrcpy 集成)**
  - 免安装内置 Scrcpy，一键唤醒 Android 设备实时画面投屏与触控交互。

## 🚀 快速启动

### 方式一：直接运行已打包的单文件版
直接运行根目录下的 `刘组YYDS.exe` 即可（建议右键以管理员身份运行以启用透明驱动级抓包功能）。

### 方式二：通过 Python 源码运行
1. 安装依赖：
   ```bash
   pip install cryptography psutil pillow pygame
   ```
2. 启动程序：
   ```bash
   python logcat_viewer.py
   ```

### 方式三：重新打包
```bash
pyinstaller --noconfirm 刘组YYDS.spec
```
