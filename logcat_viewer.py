#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Android Logcat 桌面可视化工具 (Python + Tkinter 零依赖单文件版)
功能特性：
1. 实时连接 Android 设备 (ADB) 抓取日志，支持设备选择、暂停/继续、清屏、断流自动重连
2. 支持按日志级别 (V/D/I/W/E/F) 过滤与 Android Studio 风格颜色高亮
3. 支持按 Tag、PID/应用包名、关键词、排除词、正则表达式实时过滤
4. 支持导入本地 .log / .txt 日志文件（自动识别 UTF-8 / GBK 等编码）与导出过滤结果
5. 底部详情面板支持长日志查看、调用栈阅读及 JSON 自动格式化高亮
6. 内置模拟日志生成器，无手机连接时也可一键体验全部功能
"""

import json
import os
import queue
import re
import subprocess
import sys
import threading
import time
import tkinter as tk
from datetime import datetime
from tkinter import filedialog, messagebox, ttk

from charles_proxy import CharlesCaptureWindow, auto_fit_dialog


# ==================== 日志解析正则与常量 ====================

LEVEL_ORDER = {"V": 0, "D": 1, "I": 2, "W": 3, "E": 4, "F": 5, "A": 5}

# Android Studio Darcula 风格配色
LEVEL_COLORS = {
    "V": {"fg": "#A9B7C6", "bg": None, "name": "Verbose"},
    "D": {"fg": "#389FD6", "bg": None, "name": "Debug"},
    "I": {"fg": "#6A8759", "bg": None, "name": "Info"},
    "W": {"fg": "#D6BF55", "bg": None, "name": "Warn"},
    "E": {"fg": "#FF6B68", "bg": None, "name": "Error"},
    "F": {"fg": "#FFFFFF", "bg": "#7A1C1C", "name": "Fatal"},
}

# 1. threadtime 格式: 10-29 16:30:01.123  1234  5678 D ActivityManager: Start proc...
RE_THREADTIME = re.compile(
    r"^(\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}\.\d{3})\s+(\d+)\s+(\d+)\s+([VDIWEFA])\s+(.*?)\s*:\s(.*)$"
)

# 2. time 格式: 10-29 16:30:01.123 D/ActivityManager( 1234): Start proc...
RE_TIME = re.compile(
    r"^(\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}\.\d{3})\s+([VDIWEFA])/([^\(]+)\(\s*(\d+)\):\s(.*)$"
)

# 3. brief 格式: D/ActivityManager( 1234): Start proc...
RE_BRIEF = re.compile(r"^([VDIWEFA])/([^\(]+)\(\s*(\d+)\):\s(.*)$")


class LogEntry:
    """单条结构化日志对象"""
    __slots__ = ("index", "timestamp", "pid", "tid", "level", "tag", "message", "raw")

    def __init__(self, index, timestamp, pid, tid, level, tag, message, raw):
        self.index = index
        self.timestamp = timestamp
        self.pid = pid
        self.tid = tid
        self.level = "F" if level == "A" else level
        self.tag = tag.strip()
        self.message = message
        self.raw = raw

    def format_line(self):
        if self.timestamp or self.pid or self.tag:
            pid_tid = f"{self.pid:>5}-{self.tid:<5}" if self.tid else f"{self.pid:>5}"
            tag_str = f"{self.tag:<22}" if len(self.tag) <= 22 else self.tag[:21] + "…"
            return f"{self.timestamp:<18} {pid_tid} {self.level}/{tag_str}: {self.message}"
        return self.raw


def parse_log_line(raw_line: str, index: int, prev_entry: LogEntry = None) -> LogEntry:
    """解析单行日志，支持多种 logcat 格式；若为未格式化的多行堆栈，则继承上一条属性"""
    line = raw_line.rstrip("\r\n")

    m = RE_THREADTIME.match(line)
    if m:
        ts, pid, tid, level, tag, msg = m.groups()
        return LogEntry(index, ts, pid, tid, level, tag, msg, line)

    m = RE_TIME.match(line)
    if m:
        ts, level, tag, pid, msg = m.groups()
        return LogEntry(index, ts, pid, "", level, tag, msg, line)

    m = RE_BRIEF.match(line)
    if m:
        level, tag, pid, msg = m.groups()
        return LogEntry(index, "", pid, "", level, tag, msg, line)

    # 若是多行日志（如异常堆栈 \tat xxx 或 Caused by:），继承上一条的元数据以便同组过滤和高亮
    if prev_entry is not None and (
        line.startswith("\t")
        or line.startswith("    ")
        or line.startswith("Caused by:")
        or line.startswith("  ")
    ):
        return LogEntry(
            index,
            prev_entry.timestamp,
            prev_entry.pid,
            prev_entry.tid,
            prev_entry.level,
            prev_entry.tag,
            line,
            line,
        )

    return LogEntry(index, "", "", "", "I", "System", line, line)


# ==================== 主界面类 ====================

class LogcatApp:
    def __init__(self, root: tk.Tk):
        self.root = root
        self._apply_app_icon(self.root)

        # Logcat 独立窗口（默认隐藏，点击主页面「📜 Logcat日志」按钮时弹出）
        self.logcat_win = tk.Toplevel(self.root)
        self.logcat_win.withdraw()
        self.logcat_win.title("📜 RMYYDS - Android Logcat 日志查看器")
        self.logcat_win.geometry("1320x820")
        self.logcat_win.minsize(980, 620)
        self.logcat_win.configure(bg="#1E1F22")
        self._apply_app_icon(self.logcat_win)

        # 核心数据状态
        self._is_closing = False
        self._queue_after_id = None
        self.all_logs: list[LogEntry] = []          # 内存中保存的全部日志
        self.filtered_logs: list[LogEntry] = []     # 当前满足过滤条件的日志
        self.max_keep_logs = 100000                 # 内存最大保留条数
        self.max_display_lines = 4000               # 文本框最大渲染行数（保证流畅不卡顿）
        self.log_counter = 0
        self.last_parsed_entry = None

        # ADB 与后台线程状态
        self.adb_process = None
        self.capture_session_id = 0                 # 抓包会话ID，区分主动停止与异常退出重连
        self.is_capturing = False
        self.is_paused = False
        self.auto_scroll = tk.BooleanVar(value=True)
        self.log_queue = queue.Queue()
        self.ui_event_queue = queue.Queue()         # 线程安全的 UI 状态更新队列（严禁子线程直接调用 Tkinter）
        self.sim_running = False
        self.package_pid_map: dict[str, str] = {}   # 正在运行的包名 -> PID 映射 (支持多进程 1234|5678)
        self.installed_packages: set[str] = set()   # 设备已安装的所有包名集合
        self.pkg_popup: tk.Toplevel = None          # 包名模糊搜索下拉浮层
        self.pkg_listbox: tk.Listbox = None
        self.pkg_matched_items: list[str] = []      # 浮层列表每行对应的真实包名

        # 投屏配置状态
        self.scrcpy_proc = None
        self.mirror_res_var = tk.StringVar(value="1080 (高清推荐)")
        self.mirror_fps_var = tk.StringVar(value="60")
        self.mirror_stay_awake_var = tk.BooleanVar(value=True)
        self.mirror_topmost_var = tk.BooleanVar(value=False)
        self.mirror_screen_off_var = tk.BooleanVar(value=False)
        self.mirror_audio_var = tk.BooleanVar(value=False)

        # 过滤变量
        self.device_var = tk.StringVar(value="")
        self.pkg_var = tk.StringVar(value="")
        self.min_level_var = tk.StringVar(value="V - Verbose (全部)")
        self.tag_filter_var = tk.StringVar(value="")
        self.pid_filter_var = tk.StringVar(value="")
        self.search_var = tk.StringVar(value="")
        self.exclude_var = tk.StringVar(value="")
        self.use_regex_var = tk.BooleanVar(value=False)
        self.case_sensitive_var = tk.BooleanVar(value=False)

        # 级别独立开关
        self.level_toggles = {
            lvl: tk.BooleanVar(value=True) for lvl in ["V", "D", "I", "W", "E", "F"]
        }

        self._filter_after_id = None

        self._setup_styles()
        self._build_ui()
        self._bind_events()

        # 将「接口抓包」直接构建为主窗口界面（打开 exe 即为接口抓包主页面）
        self._charles_win_ctrl = CharlesCaptureWindow(self, is_main_window=True)

        # 启动队列消费循环与初始设备检测
        self.root.after(40, self._process_log_queue)
        self.root.after(200, self.refresh_devices)

    # -------------------- 样式配置 --------------------
    def _setup_styles(self):
        style = ttk.Style()
        try:
            style.theme_use("clam")
        except tk.TclError:
            pass

        bg_dark = "#1E1F22"
        bg_panel = "#2B2D30"
        fg_main = "#DFE1E5"
        accent = "#3574F0"

        style.configure(".", background=bg_panel, foreground=fg_main, font=("Microsoft YaHei UI", 9))
        style.configure("TFrame", background=bg_panel)
        style.configure("Dark.TFrame", background=bg_dark)
        style.configure("TLabel", background=bg_panel, foreground=fg_main)
        style.configure("Status.TLabel", background="#18191B", foreground="#9DA0A8", font=("Consolas", 9))

        style.configure(
            "TButton",
            background="#393B40",
            foreground=fg_main,
            borderwidth=1,
            focusthickness=0,
            padding=(12, 4),
        )
        style.map(
            "TButton",
            background=[("active", "#4E5157"), ("pressed", "#2D2F33")],
            foreground=[("disabled", "#6F737A")],
        )

        style.configure(
            "Primary.TButton",
            background=accent,
            foreground="#FFFFFF",
            font=("Microsoft YaHei UI", 9, "bold"),
            padding=(12, 4),
        )
        style.map("Primary.TButton", background=[("active", "#4682FA"), ("pressed", "#295FCC")])

        style.configure(
            "Danger.TButton",
            background="#C75450",
            foreground="#FFFFFF",
            font=("Microsoft YaHei UI", 9, "bold"),
            padding=(12, 4),
        )
        style.map("Danger.TButton", background=[("active", "#DE635E"), ("pressed", "#A8423E")])

        style.configure(
            "TCombobox",
            fieldbackground="#1E1F22",
            background="#393B40",
            foreground=fg_main,
            arrowcolor=fg_main,
        )
        style.map(
            "TCombobox",
            fieldbackground=[("readonly", "#1E1F22")],
            selectbackground=[("readonly", "#2E436E")],
            selectforeground=[("readonly", "#FFFFFF")],
        )

        style.configure("TCheckbutton", background=bg_panel, foreground=fg_main)
        style.map("TCheckbutton", background=[("active", bg_panel)])

    # -------------------- 构建 Logcat 窗口 UI --------------------
    def _build_ui(self):
        # 1. 顶部工具栏：ADB 控制 + 文件导入导出
        top_bar = ttk.Frame(self.logcat_win, padding=(10, 8))
        top_bar.pack(side=tk.TOP, fill=tk.X, padx=6, pady=(6, 3))

        ttk.Label(top_bar, text="设备:").pack(side=tk.LEFT, padx=(0, 4))
        self.device_combo = ttk.Combobox(top_bar, textvariable=self.device_var, width=22, state="readonly")
        self.device_combo.pack(side=tk.LEFT, padx=(0, 4))

        ttk.Button(top_bar, text="刷新设备", command=self.refresh_devices).pack(side=tk.LEFT, padx=2)
        ttk.Button(top_bar, text="📶 WiFi连接", command=self.open_wifi_adb_dialog).pack(side=tk.LEFT, padx=2)
        ttk.Button(top_bar, text="📱 手机投屏", command=self.start_screen_mirror).pack(side=tk.LEFT, padx=2)
        ttk.Button(top_bar, text="🎮 遥控/设置", command=self.open_mirror_control_dialog).pack(side=tk.LEFT, padx=2)
        ttk.Button(top_bar, text="🌐 回到接口抓包主界面", command=self.open_network_sniffer).pack(side=tk.LEFT, padx=2)

        self.btn_start = ttk.Button(
            top_bar, text="▶ 开始抓日志", style="Primary.TButton", command=self.toggle_capture
        )
        self.btn_start.pack(side=tk.LEFT, padx=(6, 2))

        self.btn_pause = ttk.Button(
            top_bar, text="⏸ 暂停", command=self.toggle_pause, state=tk.DISABLED
        )
        self.btn_pause.pack(side=tk.LEFT, padx=2)

        ttk.Button(top_bar, text="🗑 清屏", command=self.clear_logs).pack(side=tk.LEFT, padx=2)
        ttk.Button(top_bar, text="🧹 清空设备缓存", command=self.clear_adb_buffer).pack(side=tk.LEFT, padx=2)

        # 分隔线
        ttk.Separator(top_bar, orient=tk.VERTICAL).pack(side=tk.LEFT, fill=tk.Y, padx=10, pady=2)

        ttk.Button(top_bar, text="📂 打开日志文件", command=self.open_log_file).pack(side=tk.LEFT, padx=2)
        ttk.Button(top_bar, text="💾 导出当前日志", command=self.export_logs).pack(side=tk.LEFT, padx=2)
        self.btn_sim = ttk.Button(top_bar, text="🧪 模拟实时日志", command=self.toggle_simulation)
        self.btn_sim.pack(side=tk.LEFT, padx=(6, 2))

        ttk.Button(top_bar, text="⬇ 滚到底部", command=self.scroll_to_bottom).pack(side=tk.RIGHT, padx=2)
        ttk.Checkbutton(
            top_bar, text="自动滚底", variable=self.auto_scroll, command=self._on_autoscroll_toggled
        ).pack(side=tk.RIGHT, padx=4)

        # 2. 第二栏：过滤控制栏 (级别、包名/PID、Tag、关键词、排除词)
        filter_bar = ttk.Frame(self.logcat_win, padding=(10, 6))
        filter_bar.pack(side=tk.TOP, fill=tk.X, padx=6, pady=3)

        # 第一行过滤：最低级别 + 独立级别彩色按钮 + 包名/PID + Tag
        row1 = ttk.Frame(filter_bar)
        row1.pack(side=tk.TOP, fill=tk.X, pady=(0, 6))

        ttk.Label(row1, text="最低级别:").pack(side=tk.LEFT, padx=(0, 4))
        self.level_combo = ttk.Combobox(
            row1,
            textvariable=self.min_level_var,
            values=[
                "V - Verbose (全部)",
                "D - Debug",
                "I - Info",
                "W - Warn",
                "E - Error",
                "F - Fatal",
            ],
            width=16,
            state="readonly",
        )
        self.level_combo.pack(side=tk.LEFT, padx=(0, 8))

        # 彩色级别快捷勾选
        lvl_frame = ttk.Frame(row1)
        lvl_frame.pack(side=tk.LEFT, padx=(0, 10))
        for lvl in ["V", "D", "I", "W", "E", "F"]:
            fg_col = LEVEL_COLORS[lvl]["fg"]
            cb = tk.Checkbutton(
                lvl_frame,
                text=lvl,
                variable=self.level_toggles[lvl],
                command=self.schedule_refilter,
                bg="#2B2D30",
                fg=fg_col,
                activebackground="#2B2D30",
                activeforeground=fg_col,
                selectcolor="#1E1F22",
                font=("Consolas", 9, "bold"),
                bd=0,
                padx=3,
            )
            cb.pack(side=tk.LEFT)

        ttk.Label(row1, text="应用包名:").pack(side=tk.LEFT, padx=(4, 4))
        pkg_box = tk.Frame(row1, bg="#1E1F22", highlightthickness=1, highlightbackground="#393B40")
        pkg_box.pack(side=tk.LEFT, padx=(0, 2))
        self.pkg_entry = self._create_dark_entry(
            pkg_box, self.pkg_var, width=25, placeholder="输入关键词模糊匹配包名..."
        )
        self.pkg_entry.config(highlightthickness=0)
        self.pkg_entry.pack(side=tk.LEFT, padx=(4, 0), pady=2)
        tk.Button(
            pkg_box,
            text="✕",
            command=self._clear_pkg_selection,
            bg="#1E1F22",
            fg="#8C9099",
            activebackground="#2B2D30",
            activeforeground="#FFFFFF",
            bd=0,
            padx=3,
            pady=0,
            font=("Microsoft YaHei UI", 8),
            cursor="hand2",
        ).pack(side=tk.LEFT)
        tk.Button(
            pkg_box,
            text="▼",
            command=self._toggle_pkg_popup,
            bg="#2B2D30",
            fg="#DFE1E5",
            activebackground="#393B40",
            activeforeground="#FFFFFF",
            bd=0,
            padx=5,
            pady=1,
            font=("Microsoft YaHei UI", 8),
            cursor="hand2",
        ).pack(side=tk.LEFT)
        ttk.Button(row1, text="🎯 当前应用", command=self.select_foreground_package).pack(side=tk.LEFT, padx=(2, 2))
        ttk.Button(row1, text="刷新进程", command=self.refresh_packages).pack(side=tk.LEFT, padx=(0, 8))

        ttk.Label(row1, text="PID:").pack(side=tk.LEFT, padx=(0, 4))
        self.pid_entry = self._create_dark_entry(row1, self.pid_filter_var, width=8, placeholder="如 1234")
        self.pid_entry.pack(side=tk.LEFT, padx=(0, 8))

        ttk.Label(row1, text="Tag过滤:").pack(side=tk.LEFT, padx=(0, 4))
        self.tag_entry = self._create_dark_entry(
            row1, self.tag_filter_var, width=20, placeholder="支持多个: TagA|TagB"
        )
        self.tag_entry.pack(side=tk.LEFT, fill=tk.X, expand=True)

        # 第二行过滤：搜索关键词 + 排除词 + 正则/大小写 + 重置
        row2 = ttk.Frame(filter_bar)
        row2.pack(side=tk.TOP, fill=tk.X)

        ttk.Label(row2, text="🔍 搜索内容:").pack(side=tk.LEFT, padx=(0, 4))
        self.search_entry = self._create_dark_entry(
            row2, self.search_var, width=35, placeholder="输入关键词或正则表达式过滤并高亮 (Ctrl+F)"
        )
        self.search_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 10))

        ttk.Label(row2, text="🚫 排除词:").pack(side=tk.LEFT, padx=(0, 4))
        self.exclude_entry = self._create_dark_entry(
            row2, self.exclude_var, width=22, placeholder="排除包含此词的日志 (用 | 分隔)"
        )
        self.exclude_entry.pack(side=tk.LEFT, padx=(0, 10))

        ttk.Checkbutton(
            row2, text="正则表达式 (Regex)", variable=self.use_regex_var, command=self.schedule_refilter
        ).pack(side=tk.LEFT, padx=4)
        ttk.Checkbutton(
            row2, text="区分大小写", variable=self.case_sensitive_var, command=self.schedule_refilter
        ).pack(side=tk.LEFT, padx=4)

        ttk.Button(row2, text="重置过滤", command=self.reset_filters).pack(side=tk.LEFT, padx=(6, 0))

        # 3. 中部主分栏窗口（上方日志列表 + 下方详情/JSON格式化查看器）
        paned = tk.PanedWindow(
            self.logcat_win, orient=tk.VERTICAL, bg="#1E1F22", sashwidth=5, sashrelief=tk.RAISED, bd=0
        )
        paned.pack(side=tk.TOP, fill=tk.BOTH, expand=True, padx=6, pady=2)

        # 上半部分：主日志视图
        log_container = ttk.Frame(paned)
        paned.add(log_container, minsize=320, stretch="always")

        # 表头说明条
        header_bar = tk.Frame(log_container, bg="#25262A", height=24)
        header_bar.pack(side=tk.TOP, fill=tk.X)
        tk.Label(
            header_bar,
            text=" 时间戳             PID-TID     级别/Tag                 日志消息内容 (点击任意行在下方查看完整详情与 JSON 格式化)",
            bg="#25262A",
            fg="#8C9099",
            font=("Consolas", 9, "bold"),
            anchor="w",
        ).pack(side=tk.LEFT, fill=tk.X, padx=4, pady=2)

        # 日志文本框 + 滚动条
        text_frame = ttk.Frame(log_container, style="Dark.TFrame")
        text_frame.pack(side=tk.TOP, fill=tk.BOTH, expand=True)

        self.v_scroll = ttk.Scrollbar(text_frame, orient=tk.VERTICAL, command=self._on_vertical_scroll)
        self.h_scroll = ttk.Scrollbar(text_frame, orient=tk.HORIZONTAL)

        self.log_text = tk.Text(
            text_frame,
            bg="#1E1F22",
            fg="#A9B7C6",
            insertbackground="#FFFFFF",
            selectbackground="#2E436E",
            selectforeground="#FFFFFF",
            font=("Consolas", 10),
            wrap=tk.NONE,
            undo=False,
            yscrollcommand=self._on_text_yscroll,
            xscrollcommand=self.h_scroll.set,
            padx=6,
            pady=4,
            bd=0,
            highlightthickness=0,
            cursor="arrow",
        )
        self.h_scroll.config(command=self.log_text.xview)

        self.v_scroll.pack(side=tk.RIGHT, fill=tk.Y)
        self.h_scroll.pack(side=tk.BOTTOM, fill=tk.X)
        self.log_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        # 配置各级别颜色 Tag
        for lvl, cfg in LEVEL_COLORS.items():
            tag_kwargs = {"foreground": cfg["fg"]}
            if cfg["bg"]:
                tag_kwargs["background"] = cfg["bg"]
            self.log_text.tag_configure(f"LVL_{lvl}", **tag_kwargs)

        # 搜索关键词高亮与选中行高亮
        self.log_text.tag_configure("SEARCH_HIT", background="#F9A825", foreground="#000000")
        self.log_text.tag_configure("SELECTED_LINE", background="#2B313A")

        # 下半部分：日志详情与 JSON 格式化面板
        detail_container = ttk.Frame(paned)
        paned.add(detail_container, minsize=130, stretch="never")

        detail_header = tk.Frame(detail_container, bg="#2B2D30")
        detail_header.pack(side=tk.TOP, fill=tk.X, padx=4, pady=2)

        self.detail_info_label = tk.Label(
            detail_header,
            text="📋 日志详情面板（点击上方任意一条日志查看完整内容、自动解析 JSON）",
            bg="#2B2D30",
            fg="#A9B7C6",
            font=("Microsoft YaHei UI", 9, "bold"),
            anchor="w",
        )
        self.detail_info_label.pack(side=tk.LEFT, padx=4)

        ttk.Button(detail_header, text="复制该条日志", command=self.copy_selected_detail).pack(
            side=tk.RIGHT, padx=4
        )
        ttk.Button(detail_header, text="按此 Tag 过滤", command=self.filter_by_selected_tag).pack(
            side=tk.RIGHT, padx=4
        )
        ttk.Button(detail_header, text="按此 PID 过滤", command=self.filter_by_selected_pid).pack(
            side=tk.RIGHT, padx=4
        )

        detail_text_frame = ttk.Frame(detail_container, style="Dark.TFrame")
        detail_text_frame.pack(side=tk.TOP, fill=tk.BOTH, expand=True)

        detail_scroll = ttk.Scrollbar(detail_text_frame, orient=tk.VERTICAL)
        self.detail_text = tk.Text(
            detail_text_frame,
            bg="#18191B",
            fg="#DFE1E5",
            insertbackground="#FFFFFF",
            selectbackground="#2E436E",
            font=("Consolas", 10),
            wrap=tk.WORD,
            height=7,
            yscrollcommand=detail_scroll.set,
            padx=8,
            pady=6,
            bd=0,
            highlightthickness=0,
        )
        detail_scroll.config(command=self.detail_text.yview)
        detail_scroll.pack(side=tk.RIGHT, fill=tk.Y)
        self.detail_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        # 4. 底部状态栏
        status_frame = tk.Frame(self.logcat_win, bg="#18191B", height=26)
        status_frame.pack(side=tk.BOTTOM, fill=tk.X)

        self.status_label = ttk.Label(
            status_frame, text="就绪 | 提示：可连接手机点击“开始抓日志”，或点击“模拟实时日志”立即体验", style="Status.TLabel"
        )
        self.status_label.pack(side=tk.LEFT, padx=10, pady=3)

        self.count_label = ttk.Label(
            status_frame, text="总计: 0 条 | 显示: 0 条", style="Status.TLabel"
        )
        self.count_label.pack(side=tk.RIGHT, padx=10, pady=3)

        # 右键菜单
        self.context_menu = tk.Menu(self.logcat_win, tearoff=0, bg="#2B2D30", fg="#DFE1E5", activebackground="#3574F0")
        self.context_menu.add_command(label="复制选中内容 (Ctrl+C)", command=self.copy_selection)
        self.context_menu.add_command(label="仅看该 Tag 的日志", command=self.filter_by_selected_tag)
        self.context_menu.add_command(label="仅看该 PID 的日志", command=self.filter_by_selected_pid)
        self.context_menu.add_separator()
        self.context_menu.add_command(label="滚到底部并恢复自动滚动", command=self.scroll_to_bottom)
        self.context_menu.add_command(label="清屏 (Ctrl+L)", command=self.clear_logs)

        self.selected_entry: LogEntry = None

    def _create_dark_entry(self, parent, textvariable, width=15, placeholder=""):
        entry = tk.Entry(
            parent,
            textvariable=textvariable,
            width=width,
            bg="#1E1F22",
            fg="#DFE1E5",
            insertbackground="#FFFFFF",
            relief=tk.FLAT,
            highlightthickness=1,
            highlightbackground="#393B40",
            highlightcolor="#3574F0",
            font=("Microsoft YaHei UI", 9),
        )
        entry.placeholder = placeholder
        entry.is_placeholder = False

        def on_focus_in(event):
            if entry.is_placeholder:
                entry.delete(0, tk.END)
                entry.config(fg="#DFE1E5")
                entry.is_placeholder = False

        def on_focus_out(event):
            if not textvariable.get():
                entry.is_placeholder = True
                entry.insert(0, placeholder)
                entry.config(fg="#6F737A")

        if placeholder and not textvariable.get():
            entry.is_placeholder = True
            entry.insert(0, placeholder)
            entry.config(fg="#6F737A")

        entry.bind("<FocusIn>", on_focus_in)
        entry.bind("<FocusOut>", on_focus_out)
        return entry

    def _get_clean_var(self, entry_widget, tk_var) -> str:
        if getattr(entry_widget, "is_placeholder", False):
            return ""
        return tk_var.get().strip()

    # -------------------- 事件绑定 --------------------
    def _bind_events(self):
        self.level_combo.bind("<<ComboboxSelected>>", lambda e: self._on_min_level_changed())

        # 应用包名输入框：输入模糊搜索 + 方向键选择 + 回车确认
        self.pkg_entry.bind("<KeyRelease>", self._on_pkg_key_release)
        self.pkg_entry.bind("<Down>", self._on_pkg_arrow_down)
        self.pkg_entry.bind("<Up>", self._on_pkg_arrow_up)
        self.pkg_entry.bind("<Return>", self._on_pkg_enter)
        self.pkg_entry.bind("<Escape>", lambda e: self._hide_pkg_popup())
        self.pkg_entry.bind("<Button-1>", lambda e: self.root.after(50, self._show_pkg_popup))

        for entry in [self.pid_entry, self.tag_entry, self.search_entry, self.exclude_entry]:
            entry.bind("<KeyRelease>", lambda e: self.schedule_refilter())

        # 点击 Logcat 窗口其它区域或移动窗口时关闭包名下拉浮层
        self.logcat_win.bind("<Button-1>", self._on_root_click, add="+")
        self.logcat_win.bind("<Configure>", lambda e: self._hide_pkg_popup(), add="+")

        # 点击日志行查看详情
        self.log_text.bind("<ButtonRelease-1>", self._on_log_click)
        self.log_text.bind("<Button-3>", self._show_context_menu)

        # 防止用户直接在主日志窗口打字修改，但允许复制快捷键
        self.log_text.bind("<Key>", self._on_log_text_key)

        # 鼠标滚轮事件
        self.log_text.bind("<MouseWheel>", self._on_mousewheel)

        # Logcat 窗口快捷键与关闭隐藏事件
        self.logcat_win.bind("<Control-f>", lambda e: self._focus_search())
        self.logcat_win.bind("<Control-F>", lambda e: self._focus_search())
        self.logcat_win.bind("<Control-l>", lambda e: self.clear_logs())
        self.logcat_win.bind("<Control-L>", lambda e: self.clear_logs())
        self.logcat_win.bind("<Control-o>", lambda e: self.open_log_file())
        self.logcat_win.bind("<Control-s>", lambda e: self.export_logs())
        self.logcat_win.protocol("WM_DELETE_WINDOW", self.hide_logcat_window)

    def _focus_search(self):
        self.search_entry.focus_set()
        if not getattr(self.search_entry, "is_placeholder", False):
            self.search_entry.select_range(0, tk.END)

    def _on_log_text_key(self, event):
        if (event.state & 0x4) and event.keysym.lower() in ("c", "a"):
            return
        if event.keysym in ("Up", "Down", "Left", "Right", "Prior", "Next", "Home", "End"):
            return
        return "break"

    def scroll_to_bottom(self):
        self.auto_scroll.set(True)
        self._rebuild_view()
        self.log_text.see(tk.END)

    def _on_autoscroll_toggled(self):
        if self.auto_scroll.get():
            self._rebuild_view()
            self.log_text.see(tk.END)

    def _on_vertical_scroll(self, *args):
        self.log_text.yview(*args)
        _, bottom = self.log_text.yview()
        # 拖动滚动条到底部时恢复自动滚动，拖离底部较远时暂停自动滚底
        if bottom >= 0.98:
            self.auto_scroll.set(True)
        elif bottom < 0.92:
            self.auto_scroll.set(False)

    def _on_text_yscroll(self, first, last):
        self.v_scroll.set(first, last)

    def _on_mousewheel(self, event):
        # 仅当用户明显向上滚离底部区域时才关闭自动滚底；滚回底部附近立即恢复
        def check_pos():
            _, bottom = self.log_text.yview()
            if event.delta > 0 and bottom < 0.94:
                self.auto_scroll.set(False)
            elif bottom >= 0.97:
                self.auto_scroll.set(True)

        self.root.after(10, check_pos)

    # -------------------- ADB 设备与进程管理 --------------------
    def _apply_app_icon(self, win):
        """设置窗口与任务栏自定义图标"""
        candidates = []
        if hasattr(sys, "_MEIPASS"):
            candidates.append(os.path.join(sys._MEIPASS, "app_icon.ico"))
        if getattr(sys, "frozen", False):
            candidates.append(os.path.join(os.path.dirname(os.path.abspath(sys.executable)), "app_icon.ico"))
        candidates.append(os.path.join(os.path.dirname(os.path.abspath(__file__)), "app_icon.ico"))
        for ico in candidates:
            if os.path.isfile(ico):
                try:
                    win.iconbitmap(ico)
                except Exception:
                    pass
                break

    def _find_bundled_tool(self, exe_name: str) -> str:
        """在 PyInstaller 解包目录 (_MEIPASS)、exe 同级目录、脚本目录中查找内置组件"""
        candidates = []
        if hasattr(sys, "_MEIPASS"):
            candidates.append(os.path.join(sys._MEIPASS, "scrcpy", exe_name))
        if getattr(sys, "frozen", False):
            candidates.append(os.path.join(os.path.dirname(os.path.abspath(sys.executable)), "scrcpy", exe_name))
        candidates.append(os.path.join(os.path.dirname(os.path.abspath(__file__)), "scrcpy", exe_name))
        for p in candidates:
            if os.path.isfile(p):
                return p
        return ""

    def _get_adb_exe(self) -> str:
        """优先使用环境变量中的 adb，若无则自动使用打包内置的 scrcpy/adb.exe"""
        if getattr(self, "_cached_adb_exe", None):
            return self._cached_adb_exe
        import shutil
        sys_adb = shutil.which("adb")
        if sys_adb:
            self._cached_adb_exe = sys_adb
            return sys_adb
        bundled_adb = self._find_bundled_tool("adb.exe")
        self._cached_adb_exe = bundled_adb or "adb"
        return self._cached_adb_exe

    def _run_adb_cmd(self, args: list[str], timeout=5) -> tuple[bool, str]:
        try:
            creation_flags = subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0
            proc = subprocess.run(
                [self._get_adb_exe()] + args,
                stdin=subprocess.DEVNULL,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=timeout,
                creationflags=creation_flags,
            )
            return proc.returncode == 0, proc.stdout
        except FileNotFoundError:
            return False, "未找到 adb 命令，请确认 Android SDK platform-tools 已加入环境变量 PATH"
        except Exception as e:
            return False, str(e)

    def refresh_devices(self):
        """在后台线程检测设备列表，避免主界面卡顿或关闭无响应"""
        def task():
            ok, out = self._run_adb_cmd(["devices", "-l"], timeout=4)
            self.ui_event_queue.put(("devices_list", (ok, out)))

        threading.Thread(target=task, daemon=True).start()

    def _apply_devices_list(self, ok: bool, out: str):
        if not ok:
            self.status_label.config(text=f"⚠ ADB 检测提示: {out}")
            self.device_combo["values"] = []
            return

        devices = []
        for line in out.splitlines()[1:]:
            line = line.strip()
            if not line or line.startswith("*"):
                continue
            parts = line.split()
            if len(parts) >= 2 and parts[1] == "device":
                serial = parts[0]
                model = ""
                for p in parts[2:]:
                    if p.startswith("model:"):
                        model = p.split(":", 1)[1]
                        break
                display = f"{serial} ({model})" if model else serial
                devices.append(display)

        self.device_combo["values"] = devices
        ctrl = getattr(self, "_charles_win_ctrl", None)
        if ctrl is not None:
            ctrl.sync_devices_combo(devices)
        if devices:
            pending_prefix = getattr(self, "_pending_select_device_prefix", "")
            if pending_prefix:
                self._pending_select_device_prefix = ""
                for item in devices:
                    if item.startswith(pending_prefix):
                        self.device_var.set(item)
                        break
            if self.device_var.get() not in devices:
                self.device_var.set(devices[0])
            if not self.is_capturing:
                self.status_label.config(text=f"✅ 已检测到 {len(devices)} 台 Android 设备")
            self.refresh_packages()
        else:
            self.device_var.set("")
            if not self.is_capturing:
                self.status_label.config(
                    text="ℹ 当前未检测到连接设备（可连接手机开启 USB 调试，或打开本地文件 / 点击“模拟实时日志”）"
                )

    def _get_selected_serial(self) -> str:
        val = self.device_var.get().strip()
        if not val:
            return ""
        return val.split()[0]

    def _get_device_wlan_ip(self, serial: str) -> str:
        """从已连接的设备自动读取 wlan0 局域网 IP 地址"""
        if not serial:
            return ""
        if ":" in serial and re.match(r"^\d+\.\d+\.\d+\.\d+:\d+$", serial):
            return serial.split(":", 1)[0]

        for cmd in [
            ["-s", serial, "shell", "ip", "-f", "inet", "addr", "show", "wlan0"],
            ["-s", serial, "shell", "ip", "route"],
            ["-s", serial, "shell", "ifconfig", "wlan0"],
        ]:
            ok, out = self._run_adb_cmd(cmd, timeout=3)
            if ok and out:
                m = re.search(r"inet\s+(\d+\.\d+\.\d+\.\d+)", out)
                if m and not m.group(1).startswith("127."):
                    return m.group(1)
                m2 = re.search(r"src\s+(\d+\.\d+\.\d+\.\d+)", out)
                if m2 and not m2.group(1).startswith("127."):
                    return m2.group(1)
        return ""

    def open_wifi_adb_dialog(self):
        """打开 ADB WiFi 无线调试连接管理窗口"""
        if getattr(self, "_wifi_win", None) is not None and self._wifi_win.winfo_exists():
            self._wifi_win.lift()
            self._wifi_win.focus_force()
            return

        win = tk.Toplevel(self.root)
        self._wifi_win = win
        win.title("📶 ADB WiFi 无线连接管理")
        win.geometry("540x470")
        auto_fit_dialog(win)
        win.configure(bg="#2B2D30")
        win.transient(self.root)
        self._apply_app_icon(win)

        serial = self._get_selected_serial()
        default_ip = getattr(self, "_last_wifi_ip", "192.168.1.")

        # 1. 区域一：USB 一键转无线连接
        sec1 = tk.LabelFrame(
            win,
            text=" ⚡ 方式一：USB 一键转 WiFi 连接（最省心，连好后即可拔掉数据线） ",
            bg="#2B2D30",
            fg="#73C991",
            font=("Microsoft YaHei UI", 9, "bold"),
            padx=12,
            pady=10,
        )
        sec1.pack(fill=tk.X, padx=14, pady=(12, 8))

        usb_info_var = tk.StringVar(
            value=f"当前设备: {serial} (正在读取手机 WiFi IP...)"
            if serial
            else "当前未检测到 USB 设备（若首次开启 5555 端口请先插上 USB 数据线）"
        )
        lbl_usb_info = tk.Label(
            sec1, textvariable=usb_info_var, bg="#2B2D30", fg="#DFE1E5", font=("Microsoft YaHei UI", 9), anchor="w"
        )
        lbl_usb_info.pack(fill=tk.X, pady=(0, 8))

        # 2. 区域二：输入 IP:端口 直接连接
        sec2 = tk.LabelFrame(
            win,
            text=" 🔗 方式二：通过 IP + 端口直接连接 (adb connect) ",
            bg="#2B2D30",
            fg="#56A8F5",
            font=("Microsoft YaHei UI", 9, "bold"),
            padx=12,
            pady=10,
        )
        sec2.pack(fill=tk.X, padx=14, pady=8)

        row_ip = ttk.Frame(sec2)
        row_ip.pack(fill=tk.X, pady=4)
        ttk.Label(row_ip, text="手机 IP:").pack(side=tk.LEFT, padx=(0, 4))
        ip_var = tk.StringVar(value=default_ip)
        ip_entry = tk.Entry(
            row_ip,
            textvariable=ip_var,
            width=18,
            bg="#1E1F22",
            fg="#DFE1E5",
            insertbackground="#FFFFFF",
            relief=tk.FLAT,
            font=("Consolas", 10),
        )
        ip_entry.pack(side=tk.LEFT, padx=(0, 10), ipady=3)

        ttk.Label(row_ip, text="端口:").pack(side=tk.LEFT, padx=(0, 4))
        port_var = tk.StringVar(value="5555")
        port_entry = tk.Entry(
            row_ip,
            textvariable=port_var,
            width=8,
            bg="#1E1F22",
            fg="#DFE1E5",
            insertbackground="#FFFFFF",
            relief=tk.FLAT,
            font=("Consolas", 10),
        )
        port_entry.pack(side=tk.LEFT, padx=(0, 10), ipady=3)

        # 后台异步读取手机 IP，避免打开窗口时卡顿
        if serial:
            def detect_ip_bg():
                ip = self._get_device_wlan_ip(serial)
                self.ui_event_queue.put(("wifi_ip_detected", (serial, ip, usb_info_var, ip_var)))

            threading.Thread(target=detect_ip_bg, daemon=True).start()

        # 3. 区域三：Android 11+ 无线调试配对码配对
        sec3 = tk.LabelFrame(
            win,
            text=" 🔐 方式三：Android 11+ 无线调试配对码配对 (免数据线 adb pair) ",
            bg="#2B2D30",
            fg="#D6BF55",
            font=("Microsoft YaHei UI", 9, "bold"),
            padx=12,
            pady=10,
        )
        sec3.pack(fill=tk.X, padx=14, pady=8)

        tk.Label(
            sec3,
            text="路径：开发者选项 -> 无线调试 -> 使用配对码配对设备（注意配对端口与连接端口不同）",
            bg="#2B2D30",
            fg="#9DA0A8",
            font=("Microsoft YaHei UI", 8),
            anchor="w",
        ).pack(fill=tk.X, pady=(0, 6))

        row_pair = ttk.Frame(sec3)
        row_pair.pack(fill=tk.X, pady=2)
        ttk.Label(row_pair, text="配对端口:").pack(side=tk.LEFT, padx=(0, 4))
        pair_port_var = tk.StringVar(value="")
        pair_port_entry = tk.Entry(
            row_pair,
            textvariable=pair_port_var,
            width=8,
            bg="#1E1F22",
            fg="#DFE1E5",
            insertbackground="#FFFFFF",
            relief=tk.FLAT,
            font=("Consolas", 10),
        )
        pair_port_entry.pack(side=tk.LEFT, padx=(0, 10), ipady=3)

        ttk.Label(row_pair, text="6位配对码:").pack(side=tk.LEFT, padx=(0, 4))
        pair_code_var = tk.StringVar(value="")
        pair_code_entry = tk.Entry(
            row_pair,
            textvariable=pair_code_var,
            width=10,
            bg="#1E1F22",
            fg="#DFE1E5",
            insertbackground="#FFFFFF",
            relief=tk.FLAT,
            font=("Consolas", 10),
        )
        pair_code_entry.pack(side=tk.LEFT, padx=(0, 10), ipady=3)

        # 底部状态反馈标签
        msg_var = tk.StringVar(value="💡 提示：电脑与手机需处于同一局域网 / WiFi 下")
        lbl_msg = tk.Label(
            win,
            textvariable=msg_var,
            bg="#1E1F22",
            fg="#DFE1E5",
            font=("Microsoft YaHei UI", 9),
            anchor="w",
            padx=10,
            pady=8,
        )
        lbl_msg.pack(fill=tk.X, padx=14, pady=(6, 10))

        def do_usb_to_wifi():
            cur_serial = self._get_selected_serial()
            if not cur_serial:
                msg_var.set("❌ 未检测到已连接的 USB 设备，请先插上数据线并刷新设备")
                return
            target_ip = ip_var.get().strip()
            target_port = port_var.get().strip() or "5555"
            msg_var.set(f"⏳ 正在开启设备 [{cur_serial}] 端口 {target_port} 并无线连接...")

            def bg():
                real_ip = target_ip if (target_ip and not target_ip.endswith(".")) else self._get_device_wlan_ip(cur_serial)
                if not real_ip or real_ip.endswith("."):
                    self.ui_event_queue.put(("wifi_result", (False, "", "未能自动获取手机 IP，请在「手机 IP」框手动输入")))
                    return
                self._last_wifi_ip = real_ip
                ok1, out1 = self._run_adb_cmd(["-s", cur_serial, "tcpip", target_port], timeout=6)
                time.sleep(1.0)
                addr = f"{real_ip}:{target_port}"
                ok2, out2 = self._run_adb_cmd(["connect", addr], timeout=6)
                combined = (out1.strip() + " | " + out2.strip()).strip(" |")
                success = ("connected to" in out2.lower()) or ("already connected" in out2.lower())
                self.ui_event_queue.put(("wifi_result", (success, addr, combined)))

            threading.Thread(target=bg, daemon=True).start()

        def do_direct_connect():
            target_ip = ip_var.get().strip()
            target_port = port_var.get().strip() or "5555"
            if not target_ip or target_ip.endswith("."):
                msg_var.set("❌ 请先输入有效的手机 IP 地址")
                return
            self._last_wifi_ip = target_ip
            addr = f"{target_ip}:{target_port}" if ":" not in target_ip else target_ip
            msg_var.set(f"⏳ 正在无线连接 {addr} ...")

            def bg():
                ok, out = self._run_adb_cmd(["connect", addr], timeout=6)
                success = ok and (("connected to" in out.lower()) or ("already connected" in out.lower()))
                self.ui_event_queue.put(("wifi_result", (success, addr, out.strip())))

            threading.Thread(target=bg, daemon=True).start()

        def do_disconnect_all():
            msg_var.set("⏳ 正在断开无线调试设备...")

            def bg():
                ok, out = self._run_adb_cmd(["disconnect"], timeout=5)
                self.ui_event_queue.put(("wifi_result", (True, "", f"已断开无线连接 ({out.strip() or 'OK'})")))

            threading.Thread(target=bg, daemon=True).start()

        def do_pair():
            target_ip = ip_var.get().strip()
            p_port = pair_port_var.get().strip()
            p_code = pair_code_var.get().strip()
            if not target_ip or not p_port or not p_code:
                msg_var.set("❌ 请填写「手机 IP」、「配对端口」和「6位配对码」")
                return
            pair_addr = f"{target_ip}:{p_port}"
            msg_var.set(f"⏳ 正在向 {pair_addr} 发送配对码 {p_code} ...")

            def bg():
                ok, out = self._run_adb_cmd(["pair", pair_addr, p_code], timeout=8)
                success = ok and ("successfully paired" in out.lower() or "成功" in out)
                self.ui_event_queue.put(("wifi_pair_result", (success, out.strip())))

            threading.Thread(target=bg, daemon=True).start()

        # 绑定各区域按钮
        ttk.Button(
            sec1,
            text="⚡ 一键开启当前手机 5555 端口并连接 WiFi",
            style="Primary.TButton",
            command=do_usb_to_wifi,
        ).pack(anchor="w")

        ttk.Button(row_ip, text="🔗 立即连接", style="Primary.TButton", command=do_direct_connect).pack(
            side=tk.LEFT, padx=4
        )
        ttk.Button(row_ip, text="🔌 断开无线", command=do_disconnect_all).pack(side=tk.LEFT, padx=4)

        ttk.Button(row_pair, text="🔐 配对设备", command=do_pair).pack(side=tk.LEFT, padx=4)

        self._wifi_msg_var = msg_var

    # -------------------- 手机投屏与电脑反控 (基于内置 scrcpy) --------------------
    def _find_scrcpy_exe(self) -> str:
        """优先查找内置或同级目录的 scrcpy.exe，其次查找系统环境变量"""
        bundled = self._find_bundled_tool("scrcpy.exe")
        if bundled:
            return bundled
        import shutil
        return shutil.which("scrcpy") or ""

    def _ensure_active_serial(self) -> str:
        """获取当前选中设备的序列号"""
        return self._get_selected_serial()

    def start_screen_mirror(self):
        """一键启动 60FPS 手机投屏窗口（支持电脑鼠标点击/滑动、键盘输入、右键返回、中键桌面）"""
        serial = self._ensure_active_serial()
        if not serial:
            messagebox.showwarning("未检测到设备", "请先通过 USB 或「📶 WiFi连接」连接并选择一台 Android 设备！")
            return

        scrcpy_exe = self._find_scrcpy_exe()
        if not scrcpy_exe:
            messagebox.showerror("未找到投屏组件", "未找到 scrcpy.exe，请确认目录下的 scrcpy 文件夹完整。")
            return

        # 如果已有正在运行的投屏窗口，先关闭旧窗口再按最新参数启动
        if self.scrcpy_proc is not None and self.scrcpy_proc.poll() is None:
            try:
                self.scrcpy_proc.kill()
            except Exception:
                pass

        cmd = [scrcpy_exe, "-s", serial, "--window-title", f"📱 手机投屏反控 - {serial}"]

        # 分辨率限制
        res_val = self.mirror_res_var.get().split()[0]
        if res_val.isdigit():
            cmd.append(f"--max-size={res_val}")

        # 帧率
        fps_val = self.mirror_fps_var.get().strip()
        if fps_val.isdigit():
            cmd.append(f"--max-fps={fps_val}")

        if not self.mirror_audio_var.get():
            cmd.append("--no-audio")
        if self.mirror_stay_awake_var.get():
            cmd.append("--stay-awake")
        if self.mirror_topmost_var.get():
            cmd.append("--always-on-top")
        if self.mirror_screen_off_var.get():
            cmd.append("--turn-screen-off")

        try:
            env = os.environ.copy()
            env["ADB"] = self._get_adb_exe()
            creation_flags = subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0
            self.scrcpy_proc = subprocess.Popen(
                cmd,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                env=env,
                close_fds=True,
                creationflags=creation_flags,
            )
            self.status_label.config(
                text=f"📱 已启动手机投屏窗口 [{serial}] | 鼠标左键:点击滑动 | 右键:返回 | 中键:桌面 | 滚轮:上下翻页"
            )
        except Exception as e:
            messagebox.showerror("启动投屏失败", f"无法启动投屏:\n{e}")

    def _send_keyevent(self, keycode: str, desc: str = ""):
        serial = self._ensure_active_serial()
        if not serial:
            return

        def bg():
            self._run_adb_cmd(["-s", serial, "shell", "input", "keyevent", str(keycode)], timeout=3)
            if desc:
                self.ui_event_queue.put(("status", f"🎮 已发送按键指令: {desc}"))

        threading.Thread(target=bg, daemon=True).start()

    def take_device_screenshot(self):
        """一键截取手机当前屏幕并保存到电脑"""
        serial = self._ensure_active_serial()
        if not serial:
            messagebox.showinfo("提示", "请先连接一台 Android 设备")
            return

        default_name = f"screenshot_{datetime.now().strftime('%Y%m%d_%H%M%S')}.png"
        save_path = filedialog.asksaveasfilename(
            title="保存手机截屏到电脑",
            initialfile=default_name,
            defaultextension=".png",
            filetypes=[("PNG 图片", "*.png")],
        )
        if not save_path:
            return

        self.status_label.config(text="📸 正在截取手机屏幕...")

        def bg():
            try:
                creation_flags = subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0
                proc = subprocess.run(
                    [self._get_adb_exe(), "-s", serial, "exec-out", "screencap", "-p"],
                    stdin=subprocess.DEVNULL,
                    capture_output=True,
                    timeout=8,
                    creationflags=creation_flags,
                )
                if proc.returncode == 0 and proc.stdout.startswith(b"\x89PNG"):
                    with open(save_path, "wb") as f:
                        f.write(proc.stdout)
                    self.ui_event_queue.put(
                        ("status", f"📸 手机截屏已保存至: {os.path.basename(save_path)}")
                    )
                else:
                    self.ui_event_queue.put(("status", "❌ 截屏失败，请检查设备连接状态"))
            except Exception as e:
                self.ui_event_queue.put(("status", f"❌ 截屏出错: {e}"))

        threading.Thread(target=bg, daemon=True).start()

    def open_mirror_control_dialog(self):
        """打开投屏参数设置与手机快捷遥控器面板"""
        if getattr(self, "_mirror_win", None) is not None and self._mirror_win.winfo_exists():
            self._mirror_win.lift()
            self._mirror_win.focus_force()
            return

        win = tk.Toplevel(self.root)
        self._mirror_win = win
        win.title("🎮 手机投屏设置与快捷遥控器")
        win.geometry("500x410")
        auto_fit_dialog(win)
        win.configure(bg="#2B2D30")
        win.transient(self.root)
        self._apply_app_icon(win)

        # 1. 快捷物理按键遥控区
        sec_ctrl = tk.LabelFrame(
            win,
            text=" 🎮 电脑远程控制手机快捷按键 ",
            bg="#2B2D30",
            fg="#73C991",
            font=("Microsoft YaHei UI", 9, "bold"),
            padx=12,
            pady=10,
        )
        sec_ctrl.pack(fill=tk.X, padx=14, pady=(12, 8))

        btn_row1 = ttk.Frame(sec_ctrl)
        btn_row1.pack(fill=tk.X, pady=3)
        ttk.Button(btn_row1, text="🏠 桌面 (Home)", command=lambda: self._send_keyevent(3, "Home 桌面")).pack(
            side=tk.LEFT, padx=3, expand=True, fill=tk.X
        )
        ttk.Button(btn_row1, text="🔙 返回 (Back)", command=lambda: self._send_keyevent(4, "Back 返回")).pack(
            side=tk.LEFT, padx=3, expand=True, fill=tk.X
        )
        ttk.Button(btn_row1, text="🗂 多任务切换", command=lambda: self._send_keyevent(187, "多任务菜单")).pack(
            side=tk.LEFT, padx=3, expand=True, fill=tk.X
        )

        btn_row2 = ttk.Frame(sec_ctrl)
        btn_row2.pack(fill=tk.X, pady=3)
        ttk.Button(btn_row2, text="🔆 电源 (亮/熄屏)", command=lambda: self._send_keyevent(26, "电源键")).pack(
            side=tk.LEFT, padx=3, expand=True, fill=tk.X
        )
        ttk.Button(btn_row2, text="🔊 音量 +", command=lambda: self._send_keyevent(24, "音量+")).pack(
            side=tk.LEFT, padx=3, expand=True, fill=tk.X
        )
        ttk.Button(btn_row2, text="🔉 音量 -", command=lambda: self._send_keyevent(25, "音量-")).pack(
            side=tk.LEFT, padx=3, expand=True, fill=tk.X
        )
        ttk.Button(btn_row2, text="📸 截屏存电脑", command=self.take_device_screenshot).pack(
            side=tk.LEFT, padx=3, expand=True, fill=tk.X
        )

        # 2. 投屏画质与功能设置区
        sec_cfg = tk.LabelFrame(
            win,
            text=" ⚙ 投屏画质与窗口参数设置 ",
            bg="#2B2D30",
            fg="#56A8F5",
            font=("Microsoft YaHei UI", 9, "bold"),
            padx=12,
            pady=10,
        )
        sec_cfg.pack(fill=tk.X, padx=14, pady=8)

        cfg_row1 = ttk.Frame(sec_cfg)
        cfg_row1.pack(fill=tk.X, pady=4)
        ttk.Label(cfg_row1, text="最大分辨率:").pack(side=tk.LEFT, padx=(0, 6))
        ttk.Combobox(
            cfg_row1,
            textvariable=self.mirror_res_var,
            values=["1080 (高清推荐)", "720 (极速省流)", "1440 (超清)", "原始分辨率 (不限制)"],
            width=18,
            state="readonly",
        ).pack(side=tk.LEFT, padx=(0, 16))

        ttk.Label(cfg_row1, text="最大帧率:").pack(side=tk.LEFT, padx=(0, 6))
        ttk.Combobox(
            cfg_row1,
            textvariable=self.mirror_fps_var,
            values=["30", "60", "90", "120"],
            width=8,
            state="readonly",
        ).pack(side=tk.LEFT)

        cfg_row2 = ttk.Frame(sec_cfg)
        cfg_row2.pack(fill=tk.X, pady=6)
        ttk.Checkbutton(cfg_row2, text="保持手机常亮", variable=self.mirror_stay_awake_var).pack(
            side=tk.LEFT, padx=(0, 12)
        )
        ttk.Checkbutton(cfg_row2, text="投屏窗口置顶", variable=self.mirror_topmost_var).pack(
            side=tk.LEFT, padx=(0, 12)
        )
        ttk.Checkbutton(cfg_row2, text="熄灭手机屏幕投屏", variable=self.mirror_screen_off_var).pack(
            side=tk.LEFT
        )

        cfg_row3 = ttk.Frame(sec_cfg)
        cfg_row3.pack(fill=tk.X, pady=2)
        ttk.Checkbutton(cfg_row3, text="同步播放手机声音到电脑", variable=self.mirror_audio_var).pack(
            side=tk.LEFT
        )

        # 3. 操作说明与启动按钮
        tips = (
            "💡 投屏窗口鼠标/键盘操作秘籍：\n"
            "  • 鼠标左键：点击 / 拖拽滑动屏幕      • 鼠标右键：返回键 (Back)\n"
            "  • 鼠标中键：回到桌面 (Home)          • 双击黑边：去除黑边自适应\n"
            "  • 电脑键盘：直接在手机输入框打字 / Ctrl+V 粘贴电脑剪贴板到手机"
        )
        tk.Label(
            win, text=tips, bg="#1E1F22", fg="#9DA0A8", font=("Microsoft YaHei UI", 8), justify=tk.LEFT, padx=10, pady=8
        ).pack(fill=tk.X, padx=14, pady=(4, 10))

        ttk.Button(
            win, text="📱 应用设置并启动/重启手机投屏", style="Primary.TButton", command=self.start_screen_mirror
        ).pack(pady=2)

    def refresh_packages(self):
        serial = self._get_selected_serial()
        if not serial:
            return

        def task():
            # 1. 获取当前正在运行的进程与对应 PID
            ok, out = self._run_adb_cmd(["-s", serial, "shell", "ps", "-A", "-o", "PID,NAME"])
            if not ok or not out.strip():
                ok, out = self._run_adb_cmd(["-s", serial, "shell", "ps"])

            pkg_pids: dict[str, list[str]] = {}
            if ok and out:
                for line in out.splitlines()[1:]:
                    parts = line.strip().split()
                    if len(parts) >= 2:
                        pid = (
                            parts[0]
                            if parts[0].isdigit()
                            else (parts[1] if len(parts) > 1 and parts[1].isdigit() else "")
                        )
                        name = parts[-1]
                        if pid and "." in name and not name.startswith("/"):
                            pkg_pids.setdefault(name, []).append(pid)
                            # 若是子进程 (如 com.example.app:remote)，同时把 PID 归集到主包名下
                            base_pkg = name.split(":", 1)[0]
                            if base_pkg != name:
                                pkg_pids.setdefault(base_pkg, []).append(pid)

            pkg_map = {k: "|".join(dict.fromkeys(v)) for k, v in pkg_pids.items()}

            # 2. 获取设备上已安装的所有应用包名 (便于模糊搜索尚未启动或刚启动的应用)
            installed = set()
            ok_pm, out_pm = self._run_adb_cmd(["-s", serial, "shell", "pm", "list", "packages"])
            if ok_pm and out_pm:
                for line in out_pm.splitlines():
                    line = line.strip()
                    if line.startswith("package:"):
                        installed.add(line.split("package:", 1)[1].strip())

            self.ui_event_queue.put(("packages", (pkg_map, installed)))

        threading.Thread(target=task, daemon=True).start()

    def select_foreground_package(self):
        """一键检测手机当前屏幕前台应用包名并自动过滤"""
        serial = self._get_selected_serial()
        if not serial:
            messagebox.showinfo("提示", "请先连接并选择一台 Android 设备")
            return

        self.status_label.config(text="🔍 正在获取手机当前前台应用包名...")

        def task():
            pkg = ""
            # 1. 通过 dumpsys window 查找 mCurrentFocus / mFocusedApp
            ok, out = self._run_adb_cmd(["-s", serial, "shell", "dumpsys", "window", "windows"], timeout=4)
            if ok and out:
                for pattern in [
                    r"mCurrentFocus=Window\{[^\}]*\s+([a-zA-Z0-9_\.]+)/",
                    r"mFocusedApp=ActivityRecord\{[^\}]*\s+([a-zA-Z0-9_\.]+)/",
                ]:
                    m = re.search(pattern, out)
                    if m:
                        pkg = m.group(1).strip()
                        break

            # 2. 备选：通过 dumpsys activity top 查找顶层 ACTIVITY
            if not pkg:
                ok2, out2 = self._run_adb_cmd(["-s", serial, "shell", "dumpsys", "activity", "top"], timeout=4)
                if ok2 and out2:
                    matches = re.findall(r"ACTIVITY\s+([a-zA-Z0-9_\.]+)/[^\s]+\s+[0-9a-fA-F]+\s+pid=(\d+)", out2)
                    if matches:
                        pkg = matches[-1][0].strip()

            self.ui_event_queue.put(("foreground_pkg", pkg))

        threading.Thread(target=task, daemon=True).start()

    # -------------------- 应用包名模糊匹配与下拉浮层 --------------------
    def _fuzzy_match_packages(self, query: str) -> list[tuple[str, str]]:
        """
        根据输入的关键词模糊匹配包名。
        返回 [(真实包名, 显示文本), ...]
        支持：
        - 不分大小写子串匹配 (如输入 setting 匹配 com.android.settings)
        - 空格分词多关键词匹配 (如输入 miui home 匹配 com.miui.home)
        - 首字母/跳跃字符模糊匹配 (如输入 cas 匹配 com.android.settings)
        """
        q = query.strip().lower()
        all_pkgs = set(self.package_pid_map.keys()) | self.installed_packages
        if not all_pkgs:
            return []

        results = []
        if not q:
            # 无关键词时：优先展示正在运行的包名，其次展示已安装包名
            for pkg in sorted(all_pkgs):
                pid = self.package_pid_map.get(pkg, "")
                if pid:
                    results.append((0, pkg, f"● {pkg}   [PID: {pid}]"))
                else:
                    results.append((1, pkg, f"○ {pkg}"))
            results.sort(key=lambda x: (x[0], x[1]))
            return [("", "★ (全部应用 - 不限包名)")] + [(r[1], r[2]) for r in results[:250]]

        tokens = [t for t in q.split() if t]
        for pkg in all_pkgs:
            pkg_lower = pkg.lower()
            pid = self.package_pid_map.get(pkg, "")
            is_running = 0 if pid else 1
            last_seg = pkg_lower.rsplit(".", 1)[-1]

            # 优先级 1：包名末段以关键词开头 或 完全相等
            if last_seg.startswith(q) or pkg_lower == q:
                rank = 1
            # 优先级 2：完整包含关键词子串
            elif q in pkg_lower:
                rank = 2
            # 优先级 3：多词同时包含 (如 "miui cam")
            elif len(tokens) > 1 and all(t in pkg_lower for t in tokens):
                rank = 3
            else:
                # 优先级 4：按点号分段首字母或字符顺序模糊匹配 (如 "cas" -> com.android.settings)
                it = iter(pkg_lower)
                if all(ch in it for ch in q.replace(" ", "")):
                    rank = 4
                else:
                    continue

            disp = f"● {pkg}   [PID: {pid}]" if pid else f"○ {pkg}"
            results.append((rank, is_running, len(pkg), pkg, disp))

        results.sort(key=lambda x: (x[0], x[1], x[2], x[3]))
        return [(r[3], r[4]) for r in results[:150]]

    def _ensure_pkg_popup(self):
        if self.pkg_popup is not None and self.pkg_popup.winfo_exists():
            return
        self.pkg_popup = tk.Toplevel(self.root)
        self.pkg_popup.withdraw()
        self.pkg_popup.overrideredirect(True)
        self.pkg_popup.configure(bg="#3574F0", bd=1)
        try:
            self.pkg_popup.wm_attributes("-topmost", True)
        except Exception:
            pass

        frame = tk.Frame(self.pkg_popup, bg="#1E1F22")
        frame.pack(fill=tk.BOTH, expand=True)

        scroll = ttk.Scrollbar(frame, orient=tk.VERTICAL)
        self.pkg_listbox = tk.Listbox(
            frame,
            bg="#1E1F22",
            fg="#DFE1E5",
            selectbackground="#2E436E",
            selectforeground="#FFFFFF",
            font=("Consolas", 9),
            height=12,
            bd=0,
            highlightthickness=0,
            activestyle="none",
            yscrollcommand=scroll.set,
            exportselection=False,
        )
        scroll.config(command=self.pkg_listbox.yview)
        scroll.pack(side=tk.RIGHT, fill=tk.Y)
        self.pkg_listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        self.pkg_listbox.bind("<ButtonRelease-1>", self._on_pkg_listbox_click)
        self.pkg_listbox.bind("<Return>", self._on_pkg_listbox_click)
        self.pkg_listbox.bind("<Motion>", self._on_pkg_listbox_hover)

    def _show_pkg_popup(self, filter_query: str = None):
        if not self.package_pid_map and not self.installed_packages:
            self.refresh_packages()

        if filter_query is None:
            filter_query = self._get_clean_var(self.pkg_entry, self.pkg_var)

        matches = self._fuzzy_match_packages(filter_query)
        self._ensure_pkg_popup()
        self.pkg_listbox.delete(0, tk.END)
        self.pkg_matched_items = []

        if not matches:
            self.pkg_listbox.insert(tk.END, "  (未匹配到包名，可按「刷新进程」或直接回车动态查找)")
            self.pkg_matched_items.append(None)
        else:
            for idx, (pkg_name, disp_text) in enumerate(matches):
                self.pkg_listbox.insert(tk.END, f" {disp_text}")
                self.pkg_matched_items.append(pkg_name)
                if disp_text.startswith("●"):
                    self.pkg_listbox.itemconfig(idx, fg="#73C991")
                elif disp_text.startswith("○"):
                    self.pkg_listbox.itemconfig(idx, fg="#9DA0A8")
            self.pkg_listbox.selection_clear(0, tk.END)
            self.pkg_listbox.selection_set(0)
            self.pkg_listbox.activate(0)

        # 定位在 pkg_entry 正下方
        self.root.update_idletasks()
        x = self.pkg_entry.winfo_rootx() - 4
        y = self.pkg_entry.winfo_rooty() + self.pkg_entry.winfo_height() + 3
        width = max(self.pkg_entry.winfo_width() + 140, 380)
        rows = min(max(len(self.pkg_matched_items), 1), 12)
        height = rows * 21 + 6

        self.pkg_popup.geometry(f"{width}x{height}+{x}+{y}")
        self.pkg_popup.deiconify()
        self.pkg_popup.lift()

    def _hide_pkg_popup(self):
        if self.pkg_popup is not None and self.pkg_popup.winfo_exists():
            self.pkg_popup.withdraw()

    def _toggle_pkg_popup(self):
        if self.pkg_popup is not None and self.pkg_popup.winfo_exists() and self.pkg_popup.state() == "normal":
            self._hide_pkg_popup()
        else:
            self.pkg_entry.focus_set()
            if getattr(self.pkg_entry, "is_placeholder", False):
                self.pkg_entry.delete(0, tk.END)
                self.pkg_entry.config(fg="#DFE1E5")
                self.pkg_entry.is_placeholder = False
            # 点击 ▼ 按钮时展示基于当前输入（或全部）的列表
            self._show_pkg_popup(self._get_clean_var(self.pkg_entry, self.pkg_var))

    def _on_root_click(self, event):
        if self.pkg_popup is None or not self.pkg_popup.winfo_exists() or self.pkg_popup.state() != "normal":
            return
        w = event.widget
        if w in (self.pkg_entry, self.pkg_listbox) or str(w).startswith(str(self.pkg_popup)):
            return
        self._hide_pkg_popup()

    def _on_pkg_key_release(self, event):
        if event.keysym in ("Up", "Down", "Return", "Escape", "Left", "Right", "Shift_L", "Shift_R", "Control_L", "Control_R"):
            return
        q = self._get_clean_var(self.pkg_entry, self.pkg_var)
        self._show_pkg_popup(q)
        if not q:
            # 清空包名时同步清空自动关联的 PID
            self._set_pid_filter("")
            self.schedule_refilter()

    def _on_pkg_arrow_down(self, event):
        if self.pkg_popup is None or not self.pkg_popup.winfo_exists() or self.pkg_popup.state() != "normal":
            self._show_pkg_popup()
            return "break"
        size = self.pkg_listbox.size()
        if size > 0:
            cur = self.pkg_listbox.curselection()
            nxt = (cur[0] + 1) % size if cur else 0
            self.pkg_listbox.selection_clear(0, tk.END)
            self.pkg_listbox.selection_set(nxt)
            self.pkg_listbox.activate(nxt)
            self.pkg_listbox.see(nxt)
        return "break"

    def _on_pkg_arrow_up(self, event):
        if self.pkg_popup is None or not self.pkg_popup.winfo_exists() or self.pkg_popup.state() != "normal":
            self._show_pkg_popup()
            return "break"
        size = self.pkg_listbox.size()
        if size > 0:
            cur = self.pkg_listbox.curselection()
            prv = (cur[0] - 1) % size if cur else size - 1
            self.pkg_listbox.selection_clear(0, tk.END)
            self.pkg_listbox.selection_set(prv)
            self.pkg_listbox.activate(prv)
            self.pkg_listbox.see(prv)
        return "break"

    def _on_pkg_enter(self, event):
        if self.pkg_popup is not None and self.pkg_popup.winfo_exists() and self.pkg_popup.state() == "normal":
            cur = self.pkg_listbox.curselection()
            if cur and cur[0] < len(self.pkg_matched_items):
                chosen = self.pkg_matched_items[cur[0]]
                if chosen is not None:
                    self._apply_selected_package(chosen)
                    return "break"
        # 直接按回车时尝试用输入的内容作为包名
        raw_q = self._get_clean_var(self.pkg_entry, self.pkg_var)
        self._apply_selected_package(raw_q)
        return "break"

    def _on_pkg_listbox_hover(self, event):
        idx = self.pkg_listbox.nearest(event.y)
        if 0 <= idx < self.pkg_listbox.size():
            self.pkg_listbox.selection_clear(0, tk.END)
            self.pkg_listbox.selection_set(idx)

    def _on_pkg_listbox_click(self, event=None):
        cur = self.pkg_listbox.curselection()
        if not cur or cur[0] >= len(self.pkg_matched_items):
            return
        chosen = self.pkg_matched_items[cur[0]]
        if chosen is not None:
            self._apply_selected_package(chosen)

    def _clear_pkg_selection(self):
        self._hide_pkg_popup()
        self.pkg_var.set("")
        self.pkg_entry.delete(0, tk.END)
        if self.pkg_entry.placeholder:
            self.pkg_entry.is_placeholder = True
            self.pkg_entry.insert(0, self.pkg_entry.placeholder)
            self.pkg_entry.config(fg="#6F737A")
        self._set_pid_filter("")
        self.schedule_refilter()

    def _set_pid_filter(self, pid_str: str):
        self.pid_entry.delete(0, tk.END)
        if pid_str:
            self.pid_entry.is_placeholder = False
            self.pid_entry.config(fg="#DFE1E5")
            self.pid_filter_var.set(pid_str)
        else:
            self.pid_filter_var.set("")
            if self.pid_entry.placeholder and self.root.focus_get() != self.pid_entry:
                self.pid_entry.is_placeholder = True
                self.pid_entry.insert(0, self.pid_entry.placeholder)
                self.pid_entry.config(fg="#6F737A")

    def _apply_selected_package(self, pkg: str):
        self._hide_pkg_popup()
        pkg = (pkg or "").strip()
        if not pkg:
            self._clear_pkg_selection()
            return

        self.pkg_entry.is_placeholder = False
        self.pkg_entry.config(fg="#DFE1E5")
        self.pkg_var.set(pkg)

        # 1. 先从缓存映射中快速设置 PID
        pid = self.package_pid_map.get(pkg, "")
        if pid:
            self._set_pid_filter(pid)
            self.status_label.config(text=f"🎯 已选择包名: {pkg} (PID: {pid})")
        else:
            self._set_pid_filter("")
            self.status_label.config(text=f"🔍 正在查询包名 [{pkg}] 的实时进程 PID...")

        self.schedule_refilter()

        # 2. 异步向设备实时查询最新 PID (防止应用刚启动或重启后 PID 变化)
        serial = self._get_selected_serial()
        if serial:
            def resolve_pid():
                ok, out = self._run_adb_cmd(["-s", serial, "shell", "pidof", pkg], timeout=3)
                pids = [p for p in out.strip().split() if p.isdigit()] if ok and out else []
                if not pids:
                    # 兼容部分旧机型无 pidof 或子进程查找
                    ok2, out2 = self._run_adb_cmd(["-s", serial, "shell", "ps", "-A", "-o", "PID,NAME"], timeout=3)
                    if ok2 and out2:
                        for line in out2.splitlines()[1:]:
                            parts = line.strip().split()
                            if len(parts) >= 2 and parts[0].isdigit():
                                proc_name = parts[-1]
                                if proc_name == pkg or proc_name.startswith(pkg + ":"):
                                    pids.append(parts[0])
                if pids:
                    pid_joined = "|".join(dict.fromkeys(pids))
                    self.ui_event_queue.put(("resolved_pkg_pid", (pkg, pid_joined)))
                elif not pid:
                    self.ui_event_queue.put(
                        ("status", f"⚠ 应用 [{pkg}] 当前未运行 (尚未产生进程 PID)，启动应用后点「刷新进程」或重新选择即可")
                    )

            threading.Thread(target=resolve_pid, daemon=True).start()

    # -------------------- 实时抓包与断流自动重连 --------------------
    def toggle_capture(self):
        if self.is_capturing:
            self.stop_capture()
        else:
            self.start_capture()

    def start_capture(self):
        if self.sim_running:
            self.toggle_simulation()

        serial = self._ensure_active_serial()
        if not serial:
            messagebox.showwarning(
                "未检测到设备",
                "未检测到连接的 Android 设备！\n\n"
                "1. 请确认手机已开启「USB 调试」并授权电脑\n"
                "2. 或点击顶部「📂 打开日志文件」分析本地日志\n"
                "3. 或点击「🧪 模拟实时日志」测试软件功能",
            )
            return

        self.is_capturing = True
        self.is_paused = False
        self.auto_scroll.set(True)
        self.capture_session_id += 1
        session_id = self.capture_session_id

        self.btn_start.config(text="⏹ 停止抓包", style="Danger.TButton")
        self.btn_pause.config(state=tk.NORMAL, text="⏸ 暂停")
        self.status_label.config(text=f"🟢 正在实时抓取设备 [{serial}] 的 Logcat 日志...")

        threading.Thread(
            target=self._adb_reader_loop, args=(serial, session_id), daemon=True
        ).start()

    def _adb_reader_loop(self, serial: str, session_id: int):
        """
        持续读取 adb logcat。
        注意：部分高负载 Android 机型 logd 环形缓冲区溢出时会导致 adb logcat 以 code 255 (unexpected EOF) 退出。
        此循环在用户未主动点击“停止抓包”时会自动无缝重连继续抓取，彻底解决自动中断问题。
        """
        first_connect = True
        creation_flags = subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0

        while self.is_capturing and session_id == self.capture_session_id:
            # 首次连接读取最近 300 条历史并开始实时流；断流重连时用 -T 1 仅衔接最新实时日志，避免重复刷屏
            tail_count = "300" if first_connect else "1"
            first_connect = False
            cmd = [self._get_adb_exe(), "-s", serial, "logcat", "-v", "threadtime", "-T", tail_count]

            try:
                proc = subprocess.Popen(
                    cmd,
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    creationflags=creation_flags,
                    close_fds=True,
                )
                self.adb_process = proc

                for raw_bytes in iter(proc.stdout.readline, b""):
                    if not self.is_capturing or session_id != self.capture_session_id:
                        break
                    line = raw_bytes.decode("utf-8", errors="replace")
                    if line.strip() and not line.startswith("--------- beginning of"):
                        self.log_queue.put(line)

                try:
                    proc.kill()
                except Exception:
                    pass
            except Exception:
                pass

            # 如果用户并未主动停止，说明是 adb 缓冲区 EOF 或瞬时断流，等待 0.2 秒后自动重连继续抓
            if self.is_capturing and session_id == self.capture_session_id:
                ok, out = self._run_adb_cmd(["devices"], timeout=3)
                if not ok or serial not in out:
                    self.ui_event_queue.put(
                        ("status", f"⏳ 设备 [{serial}] 连接中断，正在等待设备重连...")
                    )
                    time.sleep(1.0)
                else:
                    self.ui_event_queue.put(
                        ("status", f"🟢 正在实时抓取设备 [{serial}] 的 Logcat 日志 (已自动续接缓冲区)...")
                    )
                    time.sleep(0.15)

    def stop_capture(self):
        self.is_capturing = False
        self.is_paused = False
        self.capture_session_id += 1
        if self.adb_process:
            try:
                self.adb_process.kill()
            except Exception:
                pass
            self.adb_process = None

        self.btn_start.config(text="▶ 开始抓包", style="Primary.TButton")
        self.btn_pause.config(state=tk.DISABLED, text="⏸ 暂停")
        self.status_label.config(text="⏹ 已停止实时抓包")

    def toggle_pause(self):
        if not self.is_capturing and not self.sim_running:
            return
        self.is_paused = not self.is_paused
        if self.is_paused:
            self.btn_pause.config(text="▶ 继续")
            self.status_label.config(text="⏸ 已暂停视图刷新（后台仍在缓存新日志）")
        else:
            self.btn_pause.config(text="⏸ 暂停")
            self.status_label.config(text="🟢 已恢复实时刷新")
            self.refilter_all()

    def clear_adb_buffer(self):
        serial = self._get_selected_serial()
        if not serial:
            messagebox.showinfo("提示", "请先连接并选择一台 Android 设备")
            return
        self.clear_logs()
        self.status_label.config(text=f"⏳ 正在清空设备 [{serial}] 缓存...")

        def _worker():
            ok, out = self._run_adb_cmd(["-s", serial, "logcat", "-c"], timeout=5)
            if ok:
                self.ui_event_queue.put(("status", f"🧹 已清空设备 [{serial}] 缓存及当前屏幕"))
            else:
                self.ui_event_queue.put(("status", f"⚠ 清空设备 [{serial}] 缓存失败: {out}"))

        threading.Thread(target=_worker, daemon=True).start()

    # -------------------- 模拟日志生成（方便无设备时测试） --------------------
    def toggle_simulation(self):
        if self.sim_running:
            self.sim_running = False
            self.btn_sim.config(text="🧪 模拟实时日志")
            self.btn_pause.config(state=tk.DISABLED, text="⏸ 暂停")
            self.status_label.config(text="⏹ 已停止模拟日志")
        else:
            if self.is_capturing:
                self.stop_capture()
            self.sim_running = True
            self.is_paused = False
            self.auto_scroll.set(True)
            self.btn_sim.config(text="⏹ 停止模拟")
            self.btn_pause.config(state=tk.NORMAL, text="⏸ 暂停")
            self.status_label.config(text="🧪 正在生成模拟 Android 实时日志（可测试级别、Tag、搜索、JSON详情等功能）...")
            threading.Thread(target=self._simulation_loop, daemon=True).start()

    def _simulation_loop(self):
        import random

        samples = [
            ("D", "NetworkClient", "1842", "1860", 'GET https://api.example.com/v1/user/profile -> 200 OK {"code":0,"data":{"uid":10086,"nickname":"AndroidDev","vip":true,"tags":["kotlin","jetpack","compose"]},"cost_ms":42}'),
            ("I", "ActivityTaskManager", "1024", "1055", "Displayed com.example.demo/.ui.MainActivity: +268ms"),
            ("V", "RenderThread", "1842", "1899", "DrawFrame complete: vsync_jitter=0.4ms, gpu_time=3.1ms"),
            ("W", "Glide", "1842", "1910", "Load failed for [https://cdn.example.com/avatar_hd.png] with dimensions [200x200], falling back to local cache"),
            ("D", "BluetoothGatt", "1420", "1433", "onClientConnectionState() - status=0 clientIf=6 device=AA:BB:CC:11:22:33"),
            ("I", "OkHttp", "1842", "1861", 'POST /v1/order/submit {"orderId":"ORD-20261029-9981","amount":199.00,"currency":"CNY","items":[{"sku":"PRO-01","qty":1}]}'),
            ("E", "AndroidRuntime", "1842", "1842", "FATAL EXCEPTION: main\n    Process: com.example.demo, PID: 1842\n    java.lang.NullPointerException: Attempt to invoke virtual method 'int java.lang.String.length()' on a null object reference\n        at com.example.demo.ui.OrderViewModel.submitOrder(OrderViewModel.kt:84)\n        at com.example.demo.ui.MainActivity$onCreate$2.onClick(MainActivity.kt:47)\n        at android.view.View.performClick(View.java:7892)"),
            ("W", "Choreographer", "1842", "1842", "Skipped 38 frames!  The application may be doing too much work on its main thread."),
            ("F", "libc", "2910", "2915", "Fatal signal 11 (SIGSEGV), code 1 (SEGV_MAPERR), fault addr 0x0 in tid 2915 (NativeCodec), pid 2910 (com.example.media)"),
        ]

        while self.sim_running:
            lvl, tag, pid, tid, msg = random.choice(samples)
            now_str = datetime.now().strftime("%m-%d %H:%M:%S.%f")[:-3]
            for idx, subline in enumerate(msg.split("\n")):
                if idx == 0:
                    raw = f"{now_str}  {pid}  {tid} {lvl} {tag}: {subline}"
                else:
                    raw = subline
                self.log_queue.put(raw)
            time.sleep(random.uniform(0.12, 0.45))

    # -------------------- 队列消费与高性能批量渲染 --------------------
    def _process_log_queue(self):
        if getattr(self, "_is_closing", False):
            return
        try:
            # 1. 处理后台线程发来的 UI 状态更新事件
            while True:
                try:
                    evt_type, payload = self.ui_event_queue.get_nowait()
                except queue.Empty:
                    break
                if evt_type == "status":
                    self.status_label.config(text=payload)
                elif evt_type == "devices_list":
                    ok, out = payload
                    self._apply_devices_list(ok, out)
                elif evt_type == "wifi_ip_detected":
                    serial, ip, usb_info_var, ip_var = payload
                    try:
                        if getattr(self, "_wifi_win", None) is not None and self._wifi_win.winfo_exists():
                            usb_info_var.set(
                                f"当前选中设备: {serial}   |   自动检测手机局域网 IP: {ip or '未获取到 (请手填手机 Wi-Fi IP)'}"
                            )
                            if ip and not ip_var.get().strip():
                                ip_var.set(ip)
                    except Exception:
                        pass
                elif evt_type == "packages":
                    pkg_map, installed = payload
                    self.package_pid_map = pkg_map
                    self.installed_packages = installed
                    # 若下拉浮层正在打开，实时刷新其中的匹配项
                    if self.pkg_popup is not None and self.pkg_popup.winfo_exists() and self.pkg_popup.state() == "normal":
                        self._show_pkg_popup(self._get_clean_var(self.pkg_entry, self.pkg_var))
                elif evt_type == "resolved_pkg_pid":
                    pkg_name, pid_joined = payload
                    self.package_pid_map[pkg_name] = pid_joined
                    if self._get_clean_var(self.pkg_entry, self.pkg_var) == pkg_name:
                        self._set_pid_filter(pid_joined)
                        self.status_label.config(text=f"🎯 已选择包名: {pkg_name} (实时 PID: {pid_joined})")
                        self.schedule_refilter()
                elif evt_type == "foreground_pkg":
                    if payload:
                        self._apply_selected_package(payload)
                    else:
                        self.status_label.config(text="⚠ 未能识别当前前台应用（请确认手机屏幕处于亮屏解锁状态）")
                elif evt_type == "wifi_result":
                    success, addr, detail = payload
                    if addr and success:
                        self._pending_select_device_prefix = addr
                        msg = f"✅ 无线连接成功: {addr} ({detail})，现在可以拔掉 USB 数据线了！"
                    elif success:
                        msg = f"✅ {detail}"
                    else:
                        msg = f"❌ 连接失败: {detail}"
                    self.refresh_devices()
                    self.status_label.config(text=msg)
                    if getattr(self, "_wifi_msg_var", None) is not None:
                        try:
                            self._wifi_msg_var.set(msg)
                        except Exception:
                            pass
                elif evt_type == "wifi_pair_result":
                    success, detail = payload
                    msg = (
                        f"✅ 配对成功: {detail}！现在请在上方填写无线调试页面显示的「端口」点立即连接"
                        if success
                        else f"❌ 配对失败: {detail}"
                    )
                    self.status_label.config(text=msg)
                    if getattr(self, "_wifi_msg_var", None) is not None:
                        try:
                            self._wifi_msg_var.set(msg)
                        except Exception:
                            pass

            # 2. 一次性取出队列中所有积压日志，避免高吞吐量下队列堆积延迟
            batch = []
            while True:
                try:
                    raw_line = self.log_queue.get_nowait()
                except queue.Empty:
                    break
                self.log_counter += 1
                entry = parse_log_line(raw_line, self.log_counter, self.last_parsed_entry)
                self.last_parsed_entry = entry
                batch.append(entry)

            if batch:
                self.all_logs.extend(batch)
                if len(self.all_logs) > self.max_keep_logs:
                    overflow = len(self.all_logs) - self.max_keep_logs
                    del self.all_logs[:overflow]

                if not self.is_paused:
                    matched = [e for e in batch if self._matches_filter(e)]
                    if matched:
                        self.filtered_logs.extend(matched)
                        # 若单帧新增超过 max_display_lines，直接重建视图更快
                        if len(matched) >= self.max_display_lines:
                            self._rebuild_view()
                        else:
                            self._append_entries_to_view(matched)
                    self._update_counts()
        except Exception:
            pass
        finally:
            # 确保定时器循环永远不会因为任何异常而中断，但在关闭窗口时不再续订
            if not getattr(self, "_is_closing", False):
                self._queue_after_id = self.root.after(40, self._process_log_queue)

    def _on_min_level_changed(self):
        val = self.min_level_var.get()
        min_lvl = val[0] if val else "V"
        min_order = LEVEL_ORDER.get(min_lvl, 0)
        for lvl, var in self.level_toggles.items():
            var.set(LEVEL_ORDER[lvl] >= min_order)
        self.schedule_refilter()

    def schedule_refilter(self):
        if self._filter_after_id:
            self.root.after_cancel(self._filter_after_id)
        self._filter_after_id = self.root.after(150, self.refilter_all)

    def _compile_filter_criteria(self):
        """预编译当前过滤条件，提升数万条日志过滤速度"""
        active_levels = {lvl for lvl, var in self.level_toggles.items() if var.get()}
        pid_q = self._get_clean_var(self.pid_entry, self.pid_filter_var)
        tag_q = self._get_clean_var(self.tag_entry, self.tag_filter_var)
        search_q = self._get_clean_var(self.search_entry, self.search_var)
        exclude_q = self._get_clean_var(self.exclude_entry, self.exclude_var)
        use_regex = self.use_regex_var.get()
        case_sens = self.case_sensitive_var.get()
        flags = 0 if case_sens else re.IGNORECASE

        tag_regex = None
        if tag_q:
            try:
                tag_regex = re.compile(tag_q, flags)
            except re.error:
                tag_regex = re.compile(re.escape(tag_q), flags)

        search_regex = None
        if search_q:
            try:
                pattern = search_q if use_regex else re.escape(search_q)
                search_regex = re.compile(pattern, flags)
            except re.error:
                search_regex = re.compile(re.escape(search_q), flags)

        exclude_regex = None
        if exclude_q:
            try:
                pattern = (
                    exclude_q
                    if use_regex
                    else "|".join(re.escape(p.strip()) for p in exclude_q.split("|") if p.strip())
                )
                if pattern:
                    exclude_regex = re.compile(pattern, flags)
            except re.error:
                pass

        pid_set = {p.strip() for p in re.split(r"[|,;\s]+", pid_q) if p.strip()} if pid_q else None

        self._compiled_criteria = (active_levels, pid_set, tag_regex, search_regex, exclude_regex)
        return self._compiled_criteria

    def _matches_filter(self, entry: LogEntry) -> bool:
        if not hasattr(self, "_compiled_criteria"):
            self._compile_filter_criteria()
        active_levels, pid_set, tag_regex, search_regex, exclude_regex = self._compiled_criteria

        if entry.level not in active_levels:
            return False
        if pid_set and entry.pid not in pid_set:
            return False
        if tag_regex and not tag_regex.search(entry.tag):
            return False
        if exclude_regex and (exclude_regex.search(entry.message) or exclude_regex.search(entry.tag)):
            return False
        if search_regex and not (
            search_regex.search(entry.message)
            or search_regex.search(entry.tag)
            or search_regex.search(entry.raw)
        ):
            return False
        return True

    def refilter_all(self):
        self._compile_filter_criteria()
        self.filtered_logs = [e for e in self.all_logs if self._matches_filter(e)]
        self._rebuild_view()
        self._update_counts()

    def _rebuild_view(self):
        self.log_text.delete("1.0", tk.END)
        display_slice = self.filtered_logs[-self.max_display_lines :]
        self._append_entries_to_view(display_slice, force_scroll=self.auto_scroll.get())

    def _append_entries_to_view(self, entries: list[LogEntry], force_scroll: bool = None):
        if not entries:
            return

        _, _, _, search_regex, _ = getattr(self, "_compiled_criteria", self._compile_filter_criteria())

        # 将相邻同级别的日志合并为单次 insert 调用，大幅降低 Tkinter 高频刷新开销
        if not search_regex:
            grouped_chunks = []
            cur_tag = None
            cur_lines = []
            for entry in entries:
                lvl_tag = f"LVL_{entry.level}" if entry.level in LEVEL_COLORS else "LVL_I"
                line_str = entry.format_line() + "\n"
                if lvl_tag == cur_tag:
                    cur_lines.append(line_str)
                else:
                    if cur_lines:
                        grouped_chunks.append(("".join(cur_lines), (cur_tag,)))
                    cur_tag = lvl_tag
                    cur_lines = [line_str]
            if cur_lines:
                grouped_chunks.append(("".join(cur_lines), (cur_tag,)))

            for chunk_text, tags in grouped_chunks:
                self.log_text.insert(tk.END, chunk_text, tags)
        else:
            for entry in entries:
                line_text = entry.format_line() + "\n"
                lvl_tag = f"LVL_{entry.level}" if entry.level in LEVEL_COLORS else "LVL_I"
                start_idx = self.log_text.index("end-1c")
                self.log_text.insert(tk.END, line_text, (lvl_tag,))
                line_no = int(start_idx.split(".")[0])
                for m in search_regex.finditer(line_text[:-1]):
                    s_col, e_col = m.span()
                    if s_col < e_col:
                        self.log_text.tag_add("SEARCH_HIT", f"{line_no}.{s_col}", f"{line_no}.{e_col}")

        should_scroll = self.auto_scroll.get() if force_scroll is None else force_scroll
        # 仅在开启自动滚底时裁剪顶部超长行数，避免用户向上翻阅历史时行号跳动
        if should_scroll:
            total_lines = int(self.log_text.index("end-1c").split(".")[0])
            if total_lines > self.max_display_lines + 400:
                excess = total_lines - self.max_display_lines
                self.log_text.delete("1.0", f"{excess + 1}.0")
            self.log_text.see(tk.END)

    def _update_counts(self):
        total = len(self.all_logs)
        shown = len(self.filtered_logs)
        if shown > self.max_display_lines:
            self.count_label.config(
                text=f"总计: {total:,} 条 | 匹配: {shown:,} 条 (仅渲染最新 {self.max_display_lines:,} 条以保流畅)"
            )
        else:
            self.count_label.config(text=f"总计: {total:,} 条 | 显示: {shown:,} 条")

    # -------------------- 详情查看与 JSON 格式化 --------------------
    def _on_log_click(self, event=None):
        try:
            index = self.log_text.index(f"@{event.x},{event.y}" if event else tk.INSERT)
            line_no = int(index.split(".")[0])
        except Exception:
            return

        self.log_text.tag_remove("SELECTED_LINE", "1.0", tk.END)
        self.log_text.tag_add("SELECTED_LINE", f"{line_no}.0", f"{line_no}.end+1c")

        total_lines_in_widget = int(self.log_text.index("end-1c").split(".")[0]) - 1
        if total_lines_in_widget <= 0:
            return
        display_slice = self.filtered_logs[-total_lines_in_widget:]
        if 1 <= line_no <= len(display_slice):
            entry = display_slice[line_no - 1]
            self.selected_entry = entry
            self._show_entry_detail(entry)

    def _show_entry_detail(self, entry: LogEntry):
        lvl_name = LEVEL_COLORS.get(entry.level, {}).get("name", entry.level)
        self.detail_info_label.config(
            text=f"📋 详情 | 时间: {entry.timestamp or 'N/A'} | PID-TID: {entry.pid}-{entry.tid} | 级别: {entry.level} ({lvl_name}) | Tag: {entry.tag}"
        )

        self.detail_text.delete("1.0", tk.END)
        formatted_msg = self._try_pretty_json(entry.message)
        header = f"[原始行] {entry.raw}\n" + ("-" * 90) + "\n"
        self.detail_text.insert("1.0", header + formatted_msg)

    def _try_pretty_json(self, text: str) -> str:
        """自动检测日志消息中是否嵌入了 JSON 对象或数组，若有则美化缩进展示"""
        for open_ch, close_ch in [("{", "}"), ("[", "]")]:
            start = text.find(open_ch)
            end = text.rfind(close_ch)
            if start != -1 and end > start:
                candidate = text[start : end + 1]
                try:
                    parsed = json.loads(candidate)
                    pretty = json.dumps(parsed, indent=2, ensure_ascii=False)
                    prefix = text[:start].strip()
                    suffix = text[end + 1 :].strip()
                    parts = []
                    if prefix:
                        parts.append(prefix)
                    parts.append("✨ [自动识别并格式化 JSON]:\n" + pretty)
                    if suffix:
                        parts.append(suffix)
                    return "\n\n".join(parts)
                except Exception:
                    pass
        return text

    # -------------------- 快捷过滤与文件导入导出 --------------------
    def filter_by_selected_tag(self):
        if not self.selected_entry or not self.selected_entry.tag:
            messagebox.showinfo("提示", "请先在日志列表中点击选择一条日志")
            return
        self.tag_entry.is_placeholder = False
        self.tag_entry.config(fg="#DFE1E5")
        self.tag_filter_var.set(f"^{re.escape(self.selected_entry.tag)}$")
        self.refilter_all()

    def filter_by_selected_pid(self):
        if not self.selected_entry or not self.selected_entry.pid:
            messagebox.showinfo("提示", "请先在日志列表中点击选择一条带 PID 的日志")
            return
        self.pid_entry.is_placeholder = False
        self.pid_entry.config(fg="#DFE1E5")
        self.pid_filter_var.set(self.selected_entry.pid)
        self.refilter_all()

    def reset_filters(self):
        self._hide_pkg_popup()
        self.min_level_var.set("V - Verbose (全部)")
        for var in self.level_toggles.values():
            var.set(True)
        self.use_regex_var.set(False)
        self.case_sensitive_var.set(False)

        for entry, var in [
            (self.pkg_entry, self.pkg_var),
            (self.pid_entry, self.pid_filter_var),
            (self.tag_entry, self.tag_filter_var),
            (self.search_entry, self.search_var),
            (self.exclude_entry, self.exclude_var),
        ]:
            var.set("")
            entry.delete(0, tk.END)
            if entry.placeholder:
                entry.is_placeholder = True
                entry.insert(0, entry.placeholder)
                entry.config(fg="#6F737A")

        self.refilter_all()
        self.status_label.config(text="🔄 已重置所有过滤条件")

    def clear_logs(self):
        self.all_logs.clear()
        self.filtered_logs.clear()
        self.log_counter = 0
        self.last_parsed_entry = None
        self.selected_entry = None
        self.log_text.delete("1.0", tk.END)
        self.detail_text.delete("1.0", tk.END)
        self._update_counts()
        self.status_label.config(text="🗑 已清空日志列表")

    def open_log_file(self):
        file_path = filedialog.askopenfilename(
            title="打开本地 Logcat 日志文件",
            filetypes=[("日志文件", "*.log *.txt"), ("所有文件", "*.*")],
        )
        if not file_path:
            return

        if self.is_capturing:
            self.stop_capture()
        if self.sim_running:
            self.toggle_simulation()

        self.status_label.config(text=f"⏳ 正在读取文件: {os.path.basename(file_path)} ...")
        self.root.update_idletasks()

        lines = []
        for enc in ("utf-8", "utf-8-sig", "gb18030", "latin-1"):
            try:
                with open(file_path, "r", encoding=enc) as f:
                    lines = f.readlines()
                break
            except UnicodeDecodeError:
                continue
            except Exception as e:
                messagebox.showerror("读取失败", f"无法打开文件:\n{e}")
                return

        self.clear_logs()
        prev = None
        entries = []
        for i, raw in enumerate(lines, 1):
            if raw.strip():
                entry = parse_log_line(raw, i, prev)
                prev = entry
                entries.append(entry)

        self.log_counter = len(entries)
        self.all_logs = entries
        self.refilter_all()
        self.status_label.config(
            text=f"📂 已加载本地文件: {os.path.basename(file_path)} (共 {len(entries):,} 条日志)"
        )

    def export_logs(self):
        if not self.filtered_logs:
            messagebox.showinfo("提示", "当前没有可导出的日志内容")
            return

        default_name = f"logcat_export_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
        file_path = filedialog.asksaveasfilename(
            title="导出当前过滤后的日志",
            initialfile=default_name,
            defaultextension=".log",
            filetypes=[("Log 文件", "*.log"), ("文本文件", "*.txt"), ("所有文件", "*.*")],
        )
        if not file_path:
            return

        try:
            with open(file_path, "w", encoding="utf-8") as f:
                for entry in self.filtered_logs:
                    f.write(entry.raw + "\n")
            self.status_label.config(
                text=f"💾 已成功导出 {len(self.filtered_logs):,} 条日志至: {os.path.basename(file_path)}"
            )
            messagebox.showinfo("导出成功", f"已导出 {len(self.filtered_logs):,} 条日志到:\n{file_path}")
        except Exception as e:
            messagebox.showerror("导出失败", f"保存文件时出错:\n{e}")

    # -------------------- 复制与右键菜单 --------------------
    def _show_context_menu(self, event):
        self._on_log_click(event)
        try:
            self.context_menu.tk_popup(event.x_root, event.y_root)
        finally:
            self.context_menu.grab_release()

    def copy_selection(self):
        try:
            sel = self.log_text.get(tk.SEL_FIRST, tk.SEL_LAST)
            self.root.clipboard_clear()
            self.root.clipboard_append(sel)
            self.status_label.config(text="📋 已复制选中文本到剪贴板")
        except tk.TclError:
            self.copy_selected_detail()

    def copy_selected_detail(self):
        if self.selected_entry:
            self.root.clipboard_clear()
            self.root.clipboard_append(self.selected_entry.raw)
            self.status_label.config(text="📋 已复制该条日志到剪贴板")

    def open_logcat_window(self):
        """从接口抓包主界面点击按钮弹出 Logcat 日志查看器窗口"""
        if self.logcat_win and self.logcat_win.winfo_exists():
            self.logcat_win.deiconify()
            self.logcat_win.lift()
            self.logcat_win.focus_force()

    def hide_logcat_window(self):
        """关闭 Logcat 子窗口时仅隐藏窗口，保持后台与主抓包窗口正常运行"""
        self._hide_pkg_popup()
        if self.logcat_win and self.logcat_win.winfo_exists():
            self.logcat_win.withdraw()

    def open_network_sniffer(self):
        """将接口抓包主界面置顶激活"""
        ctrl = getattr(self, "_charles_win_ctrl", None)
        if ctrl is not None and ctrl.win.winfo_exists():
            ctrl.win.deiconify()
            ctrl.win.lift()
            ctrl.win.focus_force()
            return
        self._charles_win_ctrl = CharlesCaptureWindow(self, is_main_window=True)

    def _on_close(self):
        self._is_closing = True
        self.sim_running = False
        self.is_capturing = False
        self.capture_session_id += 1
        try:
            ctrl = getattr(self, "_charles_win_ctrl", None)
            if ctrl is not None:
                ctrl.shutdown_cleanly()
        except Exception:
            pass
        try:
            self.root.unbind("<Configure>")
        except Exception:
            pass
        for after_id in (getattr(self, "_queue_after_id", None), getattr(self, "_filter_after_id", None)):
            if after_id:
                try:
                    self.root.after_cancel(after_id)
                except Exception:
                    pass
        try:
            self.root.withdraw()
        except Exception:
            pass
        for proc in (self.adb_process, self.scrcpy_proc):
            if proc is not None:
                try:
                    proc.kill()
                except Exception:
                    pass
        try:
            self.root.quit()
        except Exception:
            pass
        os._exit(0)


def main():
    if sys.platform == "win32":
        try:
            import ctypes
            ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID("liuzu.yyds.proxy.viewer.2.0")
        except Exception:
            pass
        try:
            import ctypes
            ctypes.windll.shcore.SetProcessDpiAwareness(1)
        except Exception:
            pass

    root = tk.Tk()
    root.withdraw()
    holder = {}

    # 启动动画与主窗口使用同一个初始大小，并居中显示在屏幕上
    win_w, win_h = 1380, 840
    scr_w, scr_h = root.winfo_screenwidth(), root.winfo_screenheight()
    win_w, win_h = min(win_w, scr_w), min(win_h, scr_h - 40)
    pos_x, pos_y = max(0, (scr_w - win_w) // 2), max(0, (scr_h - win_h) // 2 - 20)
    box = (win_w, win_h, pos_x, pos_y)

    def _build_app():
        holder["app"] = LogcatApp(root)
        root.withdraw()  # 启动动画结束前保持主窗口隐藏

    def _show_main():
        root.geometry(f"{win_w}x{win_h}+{pos_x}+{pos_y}")
        root.deiconify()
        root.lift()
        root.focus_force()

    if not _show_splash(root, on_ready=_build_app, on_finish=_show_main, box=box):
        _build_app()
        _show_main()
    root.mainloop()


def _find_resource(name: str) -> str:
    """在 PyInstaller 解包目录、exe 同级目录、脚本目录中查找资源文件"""
    candidates = []
    if hasattr(sys, "_MEIPASS"):
        candidates.append(os.path.join(sys._MEIPASS, name))
    if getattr(sys, "frozen", False):
        candidates.append(os.path.join(os.path.dirname(os.path.abspath(sys.executable)), name))
    candidates.append(os.path.join(os.path.dirname(os.path.abspath(__file__)), name))
    for p in candidates:
        if os.path.isfile(p):
            return p
    return ""


def _show_splash(root: tk.Tk, on_ready, on_finish, box: tuple, duration_ms: int = 2000) -> bool:
    """启动动画：在与主窗口初始大小相同的居中框内，LOGO 由小放大铺满并淡入，约 2 秒后淡出进入主界面。返回 False 表示无法显示动画"""
    logo_path = _find_resource("splash_logo.jpg")
    if not logo_path:
        return False
    try:
        from PIL import Image, ImageTk
    except Exception:
        return False

    try:
        src = Image.open(logo_path).convert("RGB")
    except Exception:
        return False

    splash = tk.Toplevel(root)
    splash.overrideredirect(True)
    splash.configure(bg="#000000")
    sw, sh, bx, by = box
    splash.geometry(f"{sw}x{sh}+{bx}+{by}")
    splash.attributes("-topmost", True)
    try:
        splash.attributes("-alpha", 0.0)
    except Exception:
        pass

    canvas = tk.Canvas(splash, width=sw, height=sh, bg="#000000", highlightthickness=0, bd=0)
    canvas.pack(fill=tk.BOTH, expand=True)
    img_item = canvas.create_image(sw // 2, sh // 2, anchor="center")

    iw, ih = src.size
    final_scale = max(sw / iw, sh / ih)   # 最终铺满全屏 (cover)
    start_scale = final_scale * 0.55
    zoom_ms = 1400
    fade_in_ms = 500
    fade_out_ms = 300
    frame_ms = 16
    state = {"t0": None, "photo": None, "app_built": False, "done": False}

    def _render(scale: float):
        w, h = max(1, int(iw * scale)), max(1, int(ih * scale))
        frame = src.resize((w, h), Image.BILINEAR)
        # 超出屏幕的部分裁掉，避免创建超大位图
        if w > sw or h > sh:
            left, top = max(0, (w - sw) // 2), max(0, (h - sh) // 2)
            frame = frame.crop((left, top, left + min(w, sw), top + min(h, sh)))
        photo = ImageTk.PhotoImage(frame)
        canvas.itemconfig(img_item, image=photo)
        state["photo"] = photo  # 保持引用防止被回收

    def _finish():
        if state["done"]:
            return
        state["done"] = True
        try:
            splash.destroy()
        except Exception:
            pass
        on_finish()

    def _tick():
        now = time.time() * 1000
        if state["t0"] is None:
            state["t0"] = now
        t = now - state["t0"]

        # 1. 缩放：ease-out-cubic 从 55% 放大到铺满全屏
        p = min(1.0, t / zoom_ms)
        ease = 1 - (1 - p) ** 3
        if p < 1.0 or state.get("last_p", 0) < 1.0:
            _render(start_scale + (final_scale - start_scale) * ease)
            state["last_p"] = p

        # 2. 透明度：淡入 -> 保持 -> 淡出
        if t < fade_in_ms:
            alpha = t / fade_in_ms
        elif t < duration_ms:
            alpha = 1.0
        else:
            alpha = max(0.0, 1.0 - (t - duration_ms) / fade_out_ms)
        try:
            splash.attributes("-alpha", alpha)
        except Exception:
            pass

        # 3. 动画放大完成后再在后台构建主界面（此时画面静止，构建造成的短暂卡顿不可见）
        if p >= 1.0 and not state["app_built"]:
            state["app_built"] = True
            splash.update_idletasks()
            try:
                on_ready()
            except Exception:
                _finish()
                raise
            splash.lift()

        if t >= duration_ms + fade_out_ms:
            _finish()
            return
        splash.after(frame_ms, _tick)

    _render(start_scale)
    splash.after(10, _tick)
    return True


if __name__ == "__main__":
    main()
