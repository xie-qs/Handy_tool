#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
刘组YYDS - 内置类 Charles HTTP/HTTPS 抓包代理与可视化分析模块
支持：
1. 本地 HTTP / HTTPS (MITM 动态签发域名证书) 代理服务器
2. 树形域名导航 (Structure) + 实时请求序列列表 (Sequence)
3. Request / Response Headers、Query 参数、JSON 自动解压与美化、cURL 一键生成
4. ADB 一键自动挂载/清除手机全局代理（防断网自动还原）
5. ADB 一键推送 CA 根证书到手机 / 手机浏览器访问 http://yyds.ca 在线安装证书
"""

import atexit
import base64
import binascii
import ctypes
import ctypes.wintypes as wt
import datetime
import gzip
import io
import ipaddress
import json
import os
import queue
import re
import select
import socket
import ssl
import struct
import subprocess
import sys
import threading
import time
import tkinter as tk
import urllib.parse
import zlib
from tkinter import filedialog, messagebox, ttk


# ==================== Windows 本机进程名反查 & 系统代理自动挂载 ====================

class _MIB_TCPROW_OWNER_PID(ctypes.Structure):
    _fields_ = [
        ("dwState", wt.DWORD),
        ("dwLocalAddr", wt.DWORD),
        ("dwLocalPort", wt.DWORD),
        ("dwRemoteAddr", wt.DWORD),
        ("dwRemotePort", wt.DWORD),
        ("dwOwningPid", wt.DWORD),
    ]


_PID_NAME_CACHE: dict[int, tuple[float, str]] = {}
_LOCAL_IP_SET: set[str] = {"127.0.0.1", "::1", "localhost"}
_WIN_PROXY_ACTIVE = False
_SELF_PID = os.getpid()
_PROXY_OUTBOUND_PORTS: set[int] = set()
_OUTBOUND_LOCK = threading.Lock()

# 不对其做透明流量劫持的底层系统/加速通道/开发工具/企业微信进程白名单（仅排除企业微信，绝不排除普通微信与微信小程序）
_BYPASS_EXE_NAMES: set[str] = {
    "xptool.exe",
    "wxwork.exe",
    "wxworkweb.exe",
    "wxdrive_x64.exe",
    "wxdrive.exe",
    "wxworktpplayer.exe",
    "wxworkhelper.exe",
    "wework.exe",
    "wecom-agent.exe",
    "wemail.exe",
    "wemailnode_x64.exe",
    "httpdebuggersvc.exe",
    "httpdebuggerui.exe",
    "httpdebuggerui_cn.exe",
    "charles.exe",
    "fiddler.exe",
    "antigravity.exe",
    "antigravity ide.exe",
    "language_server_windows_x64.exe",
    "code.exe",
    "adb.exe",
    "scrcpy.exe",
    "svchost.exe",
    "system",
    "lsass.exe",
    "services.exe",
    "wininit.exe",
    "csrss.exe",
    "smss.exe",
    "spoolsv.exe",
    "navicat.exe",
    "mysqld.exe",
    "redis-server.exe",
    "xshell.exe",
    "git.exe",
    "ssh.exe",
    "hipsdaemon.exe",
    "usysdiag.exe",
    "gameviewerserver.exe",
    "gameviewerservice.exe",
    "gameviewer.exe",
}


def register_local_pc_ip(ip: str):
    if ip:
        _LOCAL_IP_SET.add(ip.strip())


_OUTBOUND_PORT_MIN = 28000
_OUTBOUND_PORT_MAX = 28999
_outbound_port_cursor = _OUTBOUND_PORT_MIN


def _create_outbound_socket(host: str, port: int, timeout: float = 15.0) -> socket.socket:
    """创建代理向上游服务器发出的 TCP 连接，绑定 28000..28999 专用豁免端口段，在 WinDivert 内核层 100% 零开销直通"""
    global _outbound_port_cursor
    last_err = None
    for res in socket.getaddrinfo(host, port, socket.AF_INET, socket.SOCK_STREAM):
        af, socktype, proto, _, sa = res
        for _ in range(120):
            s = None
            try:
                s = socket.socket(af, socktype, proto)
                s.settimeout(timeout)
                with _OUTBOUND_LOCK:
                    bind_port = _outbound_port_cursor
                    _outbound_port_cursor += 1
                    if _outbound_port_cursor > _OUTBOUND_PORT_MAX:
                        _outbound_port_cursor = _OUTBOUND_PORT_MIN
                    _PROXY_OUTBOUND_PORTS.add(bind_port)
                try:
                    s.bind(("0.0.0.0", bind_port))
                except OSError:
                    s.close()
                    continue
                s.connect(sa)
                return s
            except OSError as e:
                last_err = e
                if s is not None:
                    try:
                        s.close()
                    except Exception:
                        pass
                # 若 connect 时该源端口与目标地址的四元组处于 TIME_WAIT (WinError 10048/10013)，继续尝试下一个端口
                if getattr(e, "winerror", 0) in (10048, 10013) or getattr(e, "errno", 0) in (10048, 10013):
                    continue
                break
            except Exception as e:
                last_err = e
                if s is not None:
                    try:
                        s.close()
                    except Exception:
                        pass
                break
    if last_err:
        raise last_err
    raise OSError(f"无法解析或连接目标主机: {host}:{port}")


def _peer_ip_of(sock) -> str:
    try:
        return sock.getpeername()[0]
    except Exception:
        return ""


def _get_exe_name_by_pid(pid: int) -> str:
    if not pid or pid <= 4:
        return ""
    now = time.time()
    cached = _PID_NAME_CACHE.get(pid)
    if cached and (now - cached[0]) < 30.0:
        return cached[1]
    name = ""
    if sys.platform == "win32":
        try:
            kernel32 = ctypes.windll.kernel32
            h = kernel32.OpenProcess(0x1000, False, int(pid))
            if h:
                try:
                    buf = ctypes.create_unicode_buffer(512)
                    sz = wt.DWORD(512)
                    if kernel32.QueryFullProcessImageNameW(h, 0, buf, ctypes.byref(sz)):
                        name = os.path.basename(buf.value)
                finally:
                    kernel32.CloseHandle(h)
        except Exception:
            pass
    if not name:
        name = f"PID:{pid}"
    _PID_NAME_CACHE[pid] = (now, name)
    return name


# 仅针对企业微信 (WXWork) 专属域名后缀免除 MITM 假证书（绝不包含 servicewechat.com / qpic.cn 等微信小程序域名）
_WXWORK_BYPASS_DOMAIN_SUFFIXES = (
    "work.weixin.qq.com",
    "wework.cn",
    "wework.qpic.cn",
)


def _is_tencent_bypass_domain(host: str) -> bool:
    h = (host or "").split(":")[0].strip().lower()
    if not h:
        return False
    for suf in _WXWORK_BYPASS_DOMAIN_SUFFIXES:
        if h == suf or h.endswith("." + suf):
            return True
    return False


def _resolve_pid_and_exe_by_port(client_port: int) -> tuple[int, str]:
    """根据本机 TCP 源端口查询所属 (PID, 进程名.exe)"""
    if sys.platform != "win32" or not client_port:
        return 0, ""
    try:
        iphlpapi = ctypes.windll.iphlpapi
        target_net_port = socket.htons(int(client_port)) & 0xFFFF
        row_size = ctypes.sizeof(_MIB_TCPROW_OWNER_PID)
        # 5 = TCP_TABLE_OWNER_PID_ALL (包含刚 bind 尚未完成握手的 SYN 连接及所有活动连接)
        for tbl_class in (5, 4):
            size = wt.DWORD(0)
            iphlpapi.GetExtendedTcpTable(None, ctypes.byref(size), False, 2, tbl_class, 0)
            if size.value <= 0:
                continue
            alloc_size = size.value + 8192
            size = wt.DWORD(alloc_size)
            buf = ctypes.create_string_buffer(alloc_size)
            if iphlpapi.GetExtendedTcpTable(buf, ctypes.byref(size), False, 2, tbl_class, 0) != 0:
                continue
            num_entries = struct.unpack_from("<I", buf, 0)[0]
            offset = 4
            limit = min(alloc_size, size.value)
            for _ in range(num_entries):
                if offset + row_size > limit:
                    break
                row = _MIB_TCPROW_OWNER_PID.from_buffer_copy(buf, offset)
                offset += row_size
                if (row.dwLocalPort & 0xFFFF) == target_net_port and row.dwOwningPid:
                    pid = int(row.dwOwningPid)
                    exe = _get_exe_name_by_pid(pid)
                    return pid, exe
    except Exception:
        pass
    return 0, ""


def _resolve_client_process_name(client_ip: str, client_port: int) -> str:
    """根据客户端 IP 与端口毫秒级识别是本机哪个 .exe 程序还是手机设备"""
    if client_ip not in _LOCAL_IP_SET and not client_ip.startswith("127."):
        return f"📱 手机 ({client_ip})"
    _, exe = _resolve_pid_and_exe_by_port(client_port)
    if exe:
        return f"💻 {exe}"
    return "💻 本机程序"


def _parse_sni_from_tls_client_hello(data: bytes) -> str:
    """从原生 TLS ClientHello 二进制握手中直接提取明文 SNI 域名（用于透明 HTTPS 抓包）"""
    try:
        if len(data) < 43 or data[0] != 0x16:
            return ""
        pos = 5
        if data[pos] != 0x01:  # Handshake Type 1 = ClientHello
            return ""
        pos += 4 + 2 + 32  # Handshake hdr(4) + TLS version(2) + Random(32)
        if pos >= len(data):
            return ""
        sid_len = data[pos]
        pos += 1 + sid_len
        if pos + 2 > len(data):
            return ""
        cs_len = struct.unpack("!H", data[pos : pos + 2])[0]
        pos += 2 + cs_len
        if pos >= len(data):
            return ""
        comp_len = data[pos]
        pos += 1 + comp_len
        if pos + 2 > len(data):
            return ""
        ext_total_len = struct.unpack("!H", data[pos : pos + 2])[0]
        pos += 2
        end = min(len(data), pos + ext_total_len)
        while pos + 4 <= end:
            ext_type, ext_len = struct.unpack("!HH", data[pos : pos + 4])
            pos += 4
            if ext_type == 0x0000 and pos + 2 <= end:  # server_name extension
                p2 = pos + 2
                while p2 + 3 <= pos + ext_len and p2 + 3 <= end:
                    name_type = data[p2]
                    name_len = struct.unpack("!H", data[p2 + 1 : p2 + 3])[0]
                    p2 += 3
                    if name_type == 0 and p2 + name_len <= end:
                        return data[p2 : p2 + name_len].decode("ascii", errors="ignore").strip()
                    p2 += name_len
            pos += ext_len
    except Exception:
        pass
    return ""


class _WINDIVERT_ADDRESS(ctypes.Structure):
    _fields_ = [
        ("Timestamp", ctypes.c_int64),
        ("Flags", ctypes.c_uint32),
        ("Reserved2", ctypes.c_uint32),
        ("Data", ctypes.c_uint8 * 64),
    ]


class WinDivertTransparentRedirector:
    """
    类似 HTTP Debugger / Proxifier 的 Windows 驱动级透明 TCP 流量劫持器：
    将本机应用程序（如雷神客户端 leigod.exe、微信小程序 WeChatAppEx.exe 等不走系统代理的软件）
    发往外网 80/443（或本地透明网关 10091）的 TCP 连接，透明重定向到本地抓包端口。
    """

    def __init__(self):
        self.dll = None
        self.handle = None
        self.running = False
        self.proxy_port = 8888
        # client_port -> (orig_src_ip_bytes, orig_dst_ip_bytes, orig_dst_port, proc_label, ts)
        self.nat_table: dict[int, tuple[bytes, bytes, int, str, float]] = {}
        self.bypass_ports: set[int] = set()
        self._lock = threading.Lock()
        self._load_dll()

    def _load_dll(self):
        if sys.platform != "win32":
            return
        candidates = []
        if getattr(sys, "frozen", False) and hasattr(sys, "_MEIPASS"):
            candidates.append(os.path.join(sys._MEIPASS, "windivert", "WinDivert.dll"))
        base_dir = os.path.dirname(os.path.abspath(__file__))
        candidates.append(os.path.join(base_dir, "windivert", "WinDivert.dll"))
        try:
            import mitmproxy_windows
            candidates.append(os.path.join(os.path.dirname(mitmproxy_windows.__file__), "WinDivert.dll"))
        except Exception:
            pass

        for path in candidates:
            if os.path.exists(path):
                try:
                    dll = ctypes.WinDLL(path, use_last_error=True)
                    dll.WinDivertOpen.argtypes = [
                        ctypes.c_char_p,
                        ctypes.c_int,
                        ctypes.c_int16,
                        ctypes.c_uint64,
                    ]
                    dll.WinDivertOpen.restype = ctypes.c_void_p
                    dll.WinDivertRecv.argtypes = [
                        ctypes.c_void_p,
                        ctypes.c_void_p,
                        ctypes.c_uint32,
                        ctypes.POINTER(ctypes.c_uint32),
                        ctypes.POINTER(_WINDIVERT_ADDRESS),
                    ]
                    dll.WinDivertRecv.restype = ctypes.c_bool
                    dll.WinDivertSend.argtypes = [
                        ctypes.c_void_p,
                        ctypes.c_void_p,
                        ctypes.c_uint32,
                        ctypes.POINTER(ctypes.c_uint32),
                        ctypes.POINTER(_WINDIVERT_ADDRESS),
                    ]
                    dll.WinDivertSend.restype = ctypes.c_bool
                    dll.WinDivertHelperCalcChecksums.argtypes = [
                        ctypes.c_void_p,
                        ctypes.c_uint32,
                        ctypes.POINTER(_WINDIVERT_ADDRESS),
                        ctypes.c_uint64,
                    ]
                    dll.WinDivertHelperCalcChecksums.restype = ctypes.c_bool
                    dll.WinDivertClose.argtypes = [ctypes.c_void_p]
                    dll.WinDivertClose.restype = ctypes.c_bool
                    self.dll = dll
                    break
                except Exception:
                    continue

    def start(self, proxy_port: int = 8888) -> tuple[bool, str]:
        if self.running:
            self.stop()
        if not self.dll:
            return False, "未找到 WinDivert.dll 驱动组件"
        self.proxy_port = int(proxy_port)
        # 保持原版拦截范围（兼容微信小程序与 xptool 加速器），仅豁免 8080 端口（企业微信 gap.work.weixin.qq.com:8080 主信令长连接）
        flt = (
            f"outbound and ip and tcp "
            f"and (tcp.SrcPort < {_OUTBOUND_PORT_MIN} or tcp.SrcPort > {_OUTBOUND_PORT_MAX}) "
            f"and (tcp.DstPort < {_OUTBOUND_PORT_MIN} or tcp.DstPort > {_OUTBOUND_PORT_MAX}) "
            f"and (tcp.DstPort == 80 or tcp.DstPort == 443 or tcp.DstPort == 8443 "
            f"or tcp.DstPort == 10091 or tcp.SrcPort == {self.proxy_port})"
        ).encode("ascii")
        h = self.dll.WinDivertOpen(flt, 0, 0, 0)
        if not h or h == ctypes.c_void_p(-1).value or h == 0xFFFFFFFFFFFFFFFF:
            err = ctypes.get_last_error()
            return False, f"WinDivertOpen 失败 (WinError {err}，请以管理员权限运行)"
        self.handle = h
        self.running = True
        with self._lock:
            self.nat_table.clear()
            self.bypass_ports.clear()
        threading.Thread(target=self._packet_loop, daemon=True).start()
        return True, "WinDivert 驱动级透明劫持已启动"

    def stop(self):
        self.running = False
        h = self.handle
        self.handle = None
        if h and self.dll:
            try:
                self.dll.WinDivertClose(h)
            except Exception:
                pass
        with self._lock:
            self.nat_table.clear()
            self.bypass_ports.clear()

    def get_nat_info(self, client_port: int) -> tuple[str, int, str] | None:
        """返回被透明重定向连接的 (原始目标IP, 原始目标端口, 进程显示名)"""
        with self._lock:
            item = self.nat_table.get(int(client_port))
        if not item:
            return None
        _, orig_dst_ip_b, orig_dst_port, proc_label, _ = item
        return socket.inet_ntoa(orig_dst_ip_b), orig_dst_port, proc_label

    def _check_port_action(self, src_port: int, tcp_flags: int) -> tuple[str, str]:
        """返回 (action, exe_name)"""
        if _OUTBOUND_PORT_MIN <= src_port <= _OUTBOUND_PORT_MAX:
            return "pass", ""
        with _OUTBOUND_LOCK:
            if src_port in _PROXY_OUTBOUND_PORTS:
                return "pass", ""

        is_syn = (tcp_flags & 0x02) != 0 and (tcp_flags & 0x10) == 0
        if not is_syn:
            with self._lock:
                if src_port in self.nat_table:
                    return "divert", ""
                if src_port in self.bypass_ports:
                    return "pass", ""

        pid, exe = _resolve_pid_and_exe_by_port(src_port)
        if pid == _SELF_PID:
            with _OUTBOUND_LOCK:
                _PROXY_OUTBOUND_PORTS.add(src_port)
            with self._lock:
                self.nat_table.pop(src_port, None)
                self.bypass_ports.add(src_port)
            return "pass", exe

        exe_lower = (exe or "").lower()
        # 若明确属于企业微信等白名单进程，无论是新连接(SYN)还是旧连接，一律清理旧 nat_table 并在内核层直通放行
        if exe_lower in _BYPASS_EXE_NAMES:
            with self._lock:
                self.nat_table.pop(src_port, None)
                self.bypass_ports.add(src_port)
            return "pass", exe

        if is_syn:
            with self._lock:
                self.bypass_ports.discard(src_port)
            return "divert", exe

        # 抓包开启前已存在的旧连接：保留直通，不注入 RST 破坏企业微信存量连接
        with self._lock:
            self.bypass_ports.add(src_port)
        return "pass", exe

    def _packet_loop(self):
        buf = (ctypes.c_uint8 * 65535)()
        addr = _WINDIVERT_ADDRESS()
        recv_len = ctypes.c_uint32(0)
        send_len = ctypes.c_uint32(0)
        p_port = self.proxy_port
        last_clean = time.time()

        while self.running and self.handle:
            ok = self.dll.WinDivertRecv(
                self.handle,
                ctypes.byref(buf),
                65535,
                ctypes.byref(recv_len),
                ctypes.byref(addr),
            )
            if not ok:
                break
            n = recv_len.value
            if n < 40:
                self.dll.WinDivertSend(self.handle, ctypes.byref(buf), n, ctypes.byref(send_len), ctypes.byref(addr))
                continue

            raw = bytearray(ctypes.string_at(buf, n))
            ihl = (raw[0] & 0x0F) * 4
            if n < ihl + 20:
                self.dll.WinDivertSend(self.handle, ctypes.byref(buf), n, ctypes.byref(send_len), ctypes.byref(addr))
                continue

            src_ip = bytes(raw[12:16])
            dst_ip = bytes(raw[16:20])
            src_port, dst_port = struct.unpack("!HH", raw[ihl : ihl + 4])
            tcp_flags = raw[ihl + 13]
            is_loopback = bool(addr.Flags & 0x40000)

            modified = False
            if src_port == p_port:
                with self._lock:
                    nat_entry = self.nat_table.get(dst_port)
                if nat_entry:
                    orig_src_ip, orig_dst_ip, orig_dst_port, _, _ = nat_entry
                    raw[12:16] = orig_dst_ip
                    raw[16:20] = orig_src_ip
                    struct.pack_into("!H", raw, ihl, orig_dst_port)
                    if not is_loopback:
                        addr.Flags &= ~0x20000  # Outbound = 0 (Inbound)
                    modified = True
            elif dst_port != p_port:
                action, exe = self._check_port_action(src_port, tcp_flags)
                if action == "divert":
                    now = time.time()
                    is_syn = (tcp_flags & 0x02) != 0 and (tcp_flags & 0x10) == 0
                    with self._lock:
                        if is_syn or src_port not in self.nat_table:
                            proc_label = f"💻 {exe}" if exe else "💻 本机程序"
                            self.nat_table[src_port] = (src_ip, dst_ip, dst_port, proc_label, now)
                        else:
                            orig_s, orig_d, orig_dp, pl, _ = self.nat_table[src_port]
                            self.nat_table[src_port] = (orig_s, orig_d, orig_dp, pl, now)
                        if now - last_clean > 30.0:
                            last_clean = now
                            expired = [k for k, v in self.nat_table.items() if now - v[4] > 180.0]
                            for k in expired:
                                self.nat_table.pop(k, None)
                            if len(self.bypass_ports) > 4000:
                                self.bypass_ports.clear()

                    raw[12:16] = dst_ip
                    raw[16:20] = src_ip
                    struct.pack_into("!H", raw, ihl + 2, p_port)
                    if not is_loopback:
                        addr.Flags &= ~0x20000  # Outbound = 0 (Inbound)
                    modified = True

            if modified:
                ctypes.memmove(buf, bytes(raw), n)
                self.dll.WinDivertHelperCalcChecksums(ctypes.byref(buf), n, ctypes.byref(addr), 0)
            self.dll.WinDivertSend(self.handle, ctypes.byref(buf), n, ctypes.byref(send_len), ctypes.byref(addr))


_GLOBAL_DIVERT = WinDivertTransparentRedirector()


def _set_windows_system_proxy(enable: bool, port: int = 8888) -> tuple[bool, str]:
    """开启或关闭 Windows 电脑程序抓包（优先使用类 HTTP Debugger 的纯 WinDivert 驱动透明劫持，不污染注册表系统代理）"""
    global _WIN_PROXY_ACTIVE
    if sys.platform != "win32":
        return False, "当前非 Windows 系统"
    divert_msg = ""
    ok_d = False
    try:
        if enable:
            ok_d, msg_d = _GLOBAL_DIVERT.start(proxy_port=port)
            divert_msg = f" + {msg_d}" if ok_d else f" (透明驱动未启用: {msg_d})"
        else:
            _GLOBAL_DIVERT.stop()
    except Exception as e:
        divert_msg = f" ({e})"

    try:
        import winreg
        reg_path = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings"
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, reg_path, 0, winreg.KEY_SET_VALUE) as key:
            # 恢复开启系统代理（确保微信小程序 WeChatAppEx.exe 与浏览器 100% 正常启动并抓包），
            # 同时将企业微信域名加入系统级 ProxyOverride 绕过列表，配合代理层白名单双重保障企业微信发图直通！
            if enable:
                winreg.SetValueEx(key, "ProxyEnable", 0, winreg.REG_DWORD, 1)
                winreg.SetValueEx(key, "ProxyServer", 0, winreg.REG_SZ, f"127.0.0.1:{port}")
                winreg.SetValueEx(
                    key,
                    "ProxyOverride",
                    0,
                    winreg.REG_SZ,
                    "localhost;127.0.0.1;*.work.weixin.qq.com;*.wework.cn;wework.qpic.cn;182.254.116.117;182.254.118.119;<local>",
                )
                _WIN_PROXY_ACTIVE = True
            else:
                winreg.SetValueEx(key, "ProxyEnable", 0, winreg.REG_DWORD, 0)
                _WIN_PROXY_ACTIVE = False

        try:
            wininet = ctypes.windll.wininet
            wininet.InternetSetOptionW(0, 39, 0, 0)  # INTERNET_OPTION_SETTINGS_CHANGED
            wininet.InternetSetOptionW(0, 37, 0, 0)  # INTERNET_OPTION_REFRESH
        except Exception:
            pass
        return True, f"OK{divert_msg}"
    except Exception as e:
        return False, str(e)


def check_and_restore_residual_proxy(default_port: int = 8888) -> tuple[bool, str]:
    """
    启动防呆自检：检测 Windows 注册表系统代理是否残留指向本地抓包端口（如 127.0.0.1:8888 / 8899）。
    如果发现残留（通常因上次程序被任务管理器强杀、崩溃或断电所致），自动重置为直连模式，防止电脑持续断网。
    返回: (是否执行了修复, 说明信息)
    """
    if sys.platform != "win32":
        return False, "非 Windows 系统"
    try:
        import winreg
        reg_path = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings"
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, reg_path, 0, winreg.KEY_READ) as key:
            try:
                enabled, _ = winreg.QueryValueEx(key, "ProxyEnable")
            except Exception:
                enabled = 0
            try:
                server, _ = winreg.QueryValueEx(key, "ProxyServer")
            except Exception:
                server = ""

        srv_str = str(server or "")
        is_local_residual = any(
            f"127.0.0.1:{p}" in srv_str or f"localhost:{p}" in srv_str
            for p in (default_port, 8888, 8899, 8898, 9888, 18888, 8880, 8889)
        )
        if is_local_residual and (enabled == 1 or srv_str):
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, reg_path, 0, winreg.KEY_SET_VALUE) as key:
                winreg.SetValueEx(key, "ProxyEnable", 0, winreg.REG_DWORD, 0)
                winreg.SetValueEx(key, "ProxyServer", 0, winreg.REG_SZ, "")
            try:
                wininet = ctypes.windll.wininet
                wininet.InternetSetOptionW(0, 39, 0, 0)
                wininet.InternetSetOptionW(0, 37, 0, 0)
            except Exception:
                pass
            return True, f"检测到上次残留的本地代理配置 ({srv_str})，已自动为您安全清理，电脑网络已恢复正常！"
        return False, "系统网络正常"
    except Exception as e:
        return False, f"自检代理失败: {e}"


def force_reset_system_proxy() -> tuple[bool, str]:
    """一键重置/恢复电脑系统代理为直连模式，确保网络完全通畅"""
    global _WIN_PROXY_ACTIVE
    _WIN_PROXY_ACTIVE = False
    try:
        _GLOBAL_DIVERT.stop()
    except Exception:
        pass
    if sys.platform != "win32":
        return False, "非 Windows 系统"
    try:
        import winreg
        reg_path = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings"
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, reg_path, 0, winreg.KEY_SET_VALUE) as key:
            winreg.SetValueEx(key, "ProxyEnable", 0, winreg.REG_DWORD, 0)
        try:
            wininet = ctypes.windll.wininet
            wininet.InternetSetOptionW(0, 39, 0, 0)
            wininet.InternetSetOptionW(0, 37, 0, 0)
        except Exception:
            pass
        return True, "已成功将电脑系统代理重置为直连模式，网络已恢复通畅！"
    except Exception as e:
        return False, f"重置代理失败: {e}"


def _atexit_restore_win_proxy():
    try:
        _GLOBAL_DIVERT.stop()
    except Exception:
        pass
    if _WIN_PROXY_ACTIVE:
        _set_windows_system_proxy(False)


atexit.register(_atexit_restore_win_proxy)


def auto_fit_dialog(win, delay_ms: int = 60):
    """弹窗内容构建完成后，按控件实际所需尺寸自动放大窗口（解决高 DPI / 字体缩放导致文字显示不全），并居中到父窗口"""
    def _fit():
        try:
            if not win.winfo_exists():
                return
            win.update_idletasks()
            cur_w, cur_h = win.winfo_width(), win.winfo_height()
            req_w, req_h = win.winfo_reqwidth(), win.winfo_reqheight()
            sw, sh = win.winfo_screenwidth(), win.winfo_screenheight()
            w = min(max(cur_w, req_w + 8), int(sw * 0.95))
            h = min(max(cur_h, req_h + 8), int(sh * 0.9))
            win.resizable(True, True)
            win.minsize(min(req_w, w), min(req_h, h))
            master = win.master if win.master is not None else win
            try:
                mx, my = master.winfo_rootx(), master.winfo_rooty()
                mw, mh = master.winfo_width(), master.winfo_height()
                x = mx + (mw - w) // 2 if mw > 1 else (sw - w) // 2
                y = my + (mh - h) // 2 if mh > 1 else (sh - h) // 2
            except Exception:
                x, y = (sw - w) // 2, (sh - h) // 2
            x = max(0, min(x, sw - w))
            y = max(0, min(y, sh - h - 40))
            win.geometry(f"{w}x{h}+{x}+{y}")
        except Exception:
            pass

    try:
        win.after(delay_ms, _fit)
    except Exception:
        pass


# ==================== 内置业务 Payload 加解密算法 (Base64 + RC4("abc") + zlib) ====================

_RC4_DEFAULT_KEY = b"abc"
_ZLIB_COMPRESS_LEVEL = 6
_ZLIB_DEFAULT_MEMLEVEL = 9


def _rc4_keystream(length: int, key: bytes = _RC4_DEFAULT_KEY) -> bytes:
    """生成 RC4 密钥流（KSA + PRGA）"""
    state = list(range(256))
    j = 0
    for i in range(256):
        j = (j + state[i] + key[i % len(key)]) & 0xFF
        state[i], state[j] = state[j], state[i]

    out = bytearray(length)
    i = j = 0
    for index in range(length):
        i = (i + 1) & 0xFF
        j = (j + state[i]) & 0xFF
        state[i], state[j] = state[j], state[i]
        out[index] = state[(state[i] + state[j]) & 0xFF]
    return bytes(out)


def _xor_stream(data: bytes, keystream: bytes) -> bytes:
    return bytes(value ^ keystream[index] for index, value in enumerate(data))


def decrypt_leigod_payload(encoded: str, pretty_json: bool = True) -> str:
    """
    使用 decrypt_payload.py 相同算法解密 Base64 密文：
    密文 = Base64( zlib.compress(明文, level=6) XOR RC4(key=b"abc") 密钥流 )
    支持智能剥离首尾多余的双引号、单引号、逗号与空白字符。
    """
    cleaned = encoded.strip()
    # 如果用户框选时带上了 JSON 字符串两端的引号或末尾逗号，自动剥离
    if cleaned.endswith(","):
        cleaned = cleaned[:-1].strip()
    if (cleaned.startswith('"') and cleaned.endswith('"')) or (
        cleaned.startswith("'") and cleaned.endswith("'")
    ):
        cleaned = cleaned[1:-1].strip()
    # 处理 JSON 转义斜杠（如 \/）
    cleaned = cleaned.replace("\\/", "/")
    cleaned = "".join(cleaned.split())
    if not cleaned:
        raise ValueError("未检测到需要解密的密文内容")

    padded = cleaned + "=" * (-len(cleaned) % 4)
    try:
        ciphertext = base64.b64decode(padded, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise ValueError(f"Base64 格式错误：{exc}") from exc

    keystream = _rc4_keystream(len(ciphertext))
    compressed = _xor_stream(ciphertext, keystream)
    if compressed[:2] not in (b"\x78\x01", b"\x78\x5e", b"\x78\x9c", b"\x78\xda"):
        raise ValueError(
            f"解密后不是有效的 zlib 数据（头两字节 {compressed[:2].hex()}），请确认选中的是完整的加密字符串"
        )

    decompressor = zlib.decompressobj()
    try:
        plaintext_bytes = decompressor.decompress(compressed) + decompressor.flush()
    except zlib.error as exc:
        raise ValueError(f"zlib 解压失败：{exc}") from exc

    plaintext = plaintext_bytes.decode("utf-8")
    if pretty_json:
        try:
            obj = json.loads(plaintext)
            return json.dumps(obj, ensure_ascii=False, indent=2)
        except Exception:
            pass
    return plaintext


def encrypt_leigod_payload(plaintext: str, memlevel: int = _ZLIB_DEFAULT_MEMLEVEL) -> str:
    """将明文字符串/JSON 加密回 Base64(zlib + RC4("abc")) 密文"""
    text = plaintext.strip()
    # 若输入是美化后的多行 JSON，先压缩为紧凑单行 JSON 再加密，保持与服务端/客户端一致
    if (text.startswith("{") and text.endswith("}")) or (text.startswith("[") and text.endswith("]")):
        try:
            obj = json.loads(text)
            text = json.dumps(obj, ensure_ascii=False, separators=(",", ":"))
        except Exception:
            pass
    compressor = zlib.compressobj(
        _ZLIB_COMPRESS_LEVEL, zlib.DEFLATED, 15, memlevel, zlib.Z_DEFAULT_STRATEGY
    )
    raw = text.encode("utf-8")
    compressed = compressor.compress(raw) + compressor.flush()
    return base64.b64encode(_xor_stream(compressed, _rc4_keystream(len(compressed)))).decode("ascii")


# ==================== CA 根证书与动态域名证书管理 ====================

class CertManager:
    """管理 Root CA 证书并按目标域名动态签发 MITM 证书 (带内存缓存)"""

    def __init__(self):
        self.ca_dir = os.path.join(os.path.expanduser("~"), ".liuzu_yyds_ca")
        os.makedirs(self.ca_dir, exist_ok=True)
        self.ca_cert_path = os.path.join(self.ca_dir, "liuzu_yyds_ca.crt")
        self.ca_key_path = os.path.join(self.ca_dir, "liuzu_yyds_ca.key")
        self.domain_dir = os.path.join(self.ca_dir, "domains")
        os.makedirs(self.domain_dir, exist_ok=True)

        self._lock = threading.Lock()
        self._ssl_ctx_cache = {}
        self._ca_key = None
        self._ca_cert = None
        self.available = False
        self.init_error = ""

        try:
            self._ensure_ca()
            self.available = True
        except Exception as e:
            self.init_error = str(e)

    def _ensure_ca(self):
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.x509.oid import NameOID

        if os.path.exists(self.ca_cert_path) and os.path.exists(self.ca_key_path):
            try:
                with open(self.ca_key_path, "rb") as f:
                    self._ca_key = serialization.load_pem_private_key(f.read(), password=None)
                with open(self.ca_cert_path, "rb") as f:
                    self._ca_cert = x509.load_pem_x509_certificate(f.read())
                return
            except Exception:
                pass

        # 生成全新 2048 位 RSA 根证书
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        subject = issuer = x509.Name(
            [
                x509.NameAttribute(NameOID.COUNTRY_NAME, "CN"),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, "LiuZu YYDS Proxy"),
                x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "Mobile QA Security"),
                x509.NameAttribute(NameOID.COMMON_NAME, "RM YYDS Root CA"),
            ]
        )
        now = datetime.datetime.now(datetime.timezone.utc)
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(days=7))
            .not_valid_after(now + datetime.timedelta(days=3650))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    content_commitment=False,
                    key_encipherment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=True,
                    crl_sign=True,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
            .sign(key, hashes.SHA256())
        )

        with open(self.ca_key_path, "wb") as f:
            f.write(
                key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.TraditionalOpenSSL,
                    encryption_algorithm=serialization.NoEncryption(),
                )
            )
        with open(self.ca_cert_path, "wb") as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))

        self._ca_key = key
        self._ca_cert = cert

    def get_ca_pem_bytes(self) -> bytes:
        if os.path.exists(self.ca_cert_path):
            with open(self.ca_cert_path, "rb") as f:
                return f.read()
        return b""

    def get_domain_ssl_context(self, host: str, extra_names: list[str] | None = None) -> ssl.SSLContext:
        """为指定域名或 IP 动态签发叶子证书并返回服务端 SSLContext"""
        clean_host = host.split(":")[0].strip().lower()
        with self._lock:
            if clean_host in self._ssl_ctx_cache:
                return self._ssl_ctx_cache[clean_host]

            from cryptography import x509
            from cryptography.hazmat.primitives import hashes, serialization
            from cryptography.hazmat.primitives.asymmetric import rsa
            from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

            safe_name = re.sub(r"[^a-zA-Z0-9._-]", "_", clean_host)[:80]
            cert_file = os.path.join(self.domain_dir, f"{safe_name}.pem")

            if not os.path.exists(cert_file):
                leaf_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
                subject = x509.Name(
                    [
                        x509.NameAttribute(NameOID.COUNTRY_NAME, "CN"),
                        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "LiuZu YYDS Proxy"),
                        x509.NameAttribute(NameOID.COMMON_NAME, clean_host[:64]),
                    ]
                )
                san_items = []
                try:
                    ip_obj = ipaddress.ip_address(clean_host)
                    san_items.append(x509.IPAddress(ip_obj))
                except ValueError:
                    san_items.append(x509.DNSName(clean_host))

                if extra_names:
                    for ename in extra_names:
                        ename_clean = (ename or "").split(":")[0].strip().lower()
                        if ename_clean and ename_clean != clean_host:
                            try:
                                extra_ip = ipaddress.ip_address(ename_clean)
                                san_items.append(x509.IPAddress(extra_ip))
                            except ValueError:
                                san_items.append(x509.DNSName(ename_clean))

                san = x509.SubjectAlternativeName(san_items)

                now = datetime.datetime.now(datetime.timezone.utc)
                # Android / Chrome 要求叶子证书有效期不超过 398 天
                leaf_cert = (
                    x509.CertificateBuilder()
                    .subject_name(subject)
                    .issuer_name(self._ca_cert.subject)
                    .public_key(leaf_key.public_key())
                    .serial_number(x509.random_serial_number())
                    .not_valid_before(now - datetime.timedelta(days=2))
                    .not_valid_after(now + datetime.timedelta(days=365))
                    .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
                    .add_extension(san, critical=False)
                    .add_extension(
                        x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]),
                        critical=False,
                    )
                    .add_extension(
                        x509.AuthorityKeyIdentifier.from_issuer_public_key(self._ca_key.public_key()),
                        critical=False,
                    )
                    .sign(self._ca_key, hashes.SHA256())
                )

                with open(cert_file, "wb") as f:
                    f.write(leaf_cert.public_bytes(serialization.Encoding.PEM))
                    f.write(
                        leaf_key.private_bytes(
                            encoding=serialization.Encoding.PEM,
                            format=serialization.PrivateFormat.TraditionalOpenSSL,
                            encryption_algorithm=serialization.NoEncryption(),
                        )
                    )

            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ctx.load_cert_chain(certfile=cert_file)
            self._ssl_ctx_cache[clean_host] = ctx
            return ctx


# ==================== 单条抓包数据模型 ====================

class HttpFlow:
    """表示一条完整的 HTTP/HTTPS 请求与响应记录"""

    def __init__(
        self,
        flow_id: int,
        scheme: str,
        method: str,
        host: str,
        port: int,
        path: str,
        client_addr: str,
    ):
        self.flow_id = flow_id
        self.timestamp = datetime.datetime.now().strftime("%H:%M:%S.%f")[:-3]
        self.scheme = scheme  # http / https / tunnel
        self.method = method
        self.host = host
        self.port = port
        self.path = path
        self.client_addr = client_addr

        self.req_headers = {}
        self.req_body_raw = b""
        self.status_code = 0
        self.reason = ""
        self.resp_headers = {}
        self.resp_body_raw = b""
        self.content_type = ""
        self.duration_ms = 0
        self.size_bytes = 0
        self.error = ""
        self.notes = ""
        self.process_name = ""
        self.server_ip = ""

    @property
    def full_url(self) -> str:
        if self.method == "CONNECT":
            return f"https://{self.host}:{self.port}"
        default_port = 443 if self.scheme == "https" else 80
        port_part = "" if self.port == default_port else f":{self.port}"
        path_part = self.path if self.path.startswith("/") else f"/{self.path}"
        return f"{self.scheme}://{self.host}{port_part}{path_part}"

    @property
    def short_type(self) -> str:
        ct = self.content_type.lower()
        if "json" in ct:
            return "JSON"
        if "html" in ct:
            return "HTML"
        if "javascript" in ct or "ecmascript" in ct:
            return "JS"
        if "css" in ct:
            return "CSS"
        if "image/" in ct:
            return ct.split("image/", 1)[1].split(";")[0].upper()[:6]
        if "xml" in ct:
            return "XML"
        if "form" in ct:
            return "FORM"
        if "text/plain" in ct:
            return "TEXT"
        if self.method == "CONNECT":
            return "TLS隧道"
        return ct.split(";")[0][:12] if ct else "-"

    def format_size(self) -> str:
        b = self.size_bytes
        if b < 1024:
            return f"{b} B"
        if b < 1024 * 1024:
            return f"{b / 1024:.1f} KB"
        return f"{b / (1024 * 1024):.2f} MB"

    def get_decoded_body(self, is_request: bool = False) -> str:
        raw = self.req_body_raw if is_request else self.resp_body_raw
        headers = self.req_headers if is_request else self.resp_headers
        if not raw:
            return ""

        data = raw
        enc = ""
        for k, v in headers.items():
            if k.lower() == "content-encoding":
                enc = v.lower().strip()
                break

        try:
            if "gzip" in enc or (len(data) >= 2 and data[:2] == b"\x1f\x8b"):
                data = gzip.decompress(data)
            elif "deflate" in enc:
                try:
                    data = zlib.decompress(data)
                except zlib.error:
                    data = zlib.decompress(data, -zlib.MAX_WBITS)
            elif "br" in enc:
                try:
                    import brotli
                    data = brotli.decompress(data)
                except Exception:
                    pass
            elif "zstd" in enc:
                try:
                    import zstandard
                    data = zstandard.ZstdDecompressor().decompress(data)
                except Exception:
                    pass
        except Exception:
            pass

        ct = ""
        for k, v in headers.items():
            if k.lower() == "content-type":
                ct = v.lower()
                break
        if any(BinaryTag in ct for BinaryTag in ("image/", "audio/", "video/", "application/octet-stream", "font/")):
            return f"[二进制数据 ({ct})，共 {len(raw):,} 字节，已省略文本预览]"

        for charset in ("utf-8", "gb18030", "latin-1"):
            try:
                text = data.decode(charset)
                break
            except Exception:
                text = data.decode("utf-8", errors="replace")

        # 尝试自动美化 JSON
        stripped = text.strip()
        if (stripped.startswith("{") and stripped.endswith("}")) or (
            stripped.startswith("[") and stripped.endswith("]")
        ):
            try:
                obj = json.loads(stripped)
                return json.dumps(obj, indent=2, ensure_ascii=False)
            except Exception:
                pass
        return text


# ==================== HTTP 报文底层读写辅助函数 ====================

def _recv_line(sock: socket.socket, max_len: int = 65536) -> bytes:
    buf = bytearray()
    while len(buf) < max_len:
        ch = sock.recv(1)
        if not ch:
            break
        buf.extend(ch)
        if buf.endswith(b"\n"):
            break
    return bytes(buf)


def _read_http_message(sock: socket.socket, is_request: bool = True):
    """
    从 socket 流中完整读取一条 HTTP/1.x 请求或响应。
    返回: (first_line_str, headers_dict, raw_headers_bytes, raw_body_bytes, raw_wire_body_bytes)
    其中 raw_body_bytes 为解除了 chunked 包装后的实体内容，raw_wire_body_bytes 为原始传输层字节。
    """
    first_line_bytes = _recv_line(sock)
    if not first_line_bytes:
        return None
    first_line = first_line_bytes.decode("latin-1", errors="replace").strip()
    if not first_line:
        return None

    headers = {}
    header_lines = [first_line_bytes]
    while True:
        line = _recv_line(sock)
        if not line:
            break
        header_lines.append(line)
        if line in (b"\r\n", b"\n"):
            break
        decoded = line.decode("latin-1", errors="replace").strip()
        if ":" in decoded:
            k, v = decoded.split(":", 1)
            headers[k.strip()] = v.strip()

    raw_headers_bytes = b"".join(header_lines)

    # 判断是否有 Body 及 Expect: 100-continue
    transfer_encoding = ""
    content_length = None
    expect_continue = False
    for k, v in headers.items():
        kl = k.lower()
        if kl == "transfer-encoding":
            transfer_encoding = v.lower()
        elif kl == "content-length":
            try:
                content_length = int(v.strip())
            except ValueError:
                pass
        elif kl == "expect" and "100-continue" in v.lower():
            expect_continue = True

    if is_request and expect_continue:
        try:
            sock.sendall(b"HTTP/1.1 100 Continue\r\n\r\n")
        except Exception:
            pass

    if is_request and content_length is None and "chunked" not in transfer_encoding:
        return first_line, headers, raw_headers_bytes, b"", b""

    if not is_request:
        # 1xx / 204 / 304 响应无 body
        parts = first_line.split(None, 2)
        if len(parts) >= 2:
            try:
                code = int(parts[1])
                if 100 <= code < 200 or code in (204, 304):
                    return first_line, headers, raw_headers_bytes, b"", b""
            except ValueError:
                pass

    if "chunked" in transfer_encoding:
        assembled = bytearray()
        wire_bytes = bytearray()
        while True:
            size_line = _recv_line(sock)
            if not size_line:
                break
            wire_bytes.extend(size_line)
            size_str = size_line.split(b";", 1)[0].strip()
            try:
                chunk_size = int(size_str, 16)
            except ValueError:
                break
            if chunk_size == 0:
                # 读取结尾 CRLF
                trailer = _recv_line(sock)
                wire_bytes.extend(trailer)
                break
            chunk_data = bytearray()
            while len(chunk_data) < chunk_size:
                part = sock.recv(min(65536, chunk_size - len(chunk_data)))
                if not part:
                    break
                chunk_data.extend(part)
            assembled.extend(chunk_data)
            wire_bytes.extend(chunk_data)
            crlf = _recv_line(sock)
            wire_bytes.extend(crlf)
        return first_line, headers, raw_headers_bytes, bytes(assembled), bytes(wire_bytes)

    if content_length is not None:
        body = bytearray()
        while len(body) < content_length:
            part = sock.recv(min(65536, content_length - len(body)))
            if not part:
                break
            body.extend(part)
        b_body = bytes(body)
        return first_line, headers, raw_headers_bytes, b_body, b_body

    if not is_request:
        # 无 Content-Length 且非 chunked，读取至对端关闭连接
        body = bytearray()
        while True:
            try:
                part = sock.recv(16384)
                if not part:
                    break
                body.extend(part)
            except Exception:
                break
        b_body = bytes(body)
        return first_line, headers, raw_headers_bytes, b_body, b_body

    return first_line, headers, raw_headers_bytes, b"", b""


# ==================== 代理服务器核心引擎 ====================

def _is_ip_address(host: str) -> bool:
    """判断字符串是否为合法 IPv4 或 IPv6 地址"""
    if not host:
        return False
    h = host.split(":")[0].strip().strip("[]")
    if not h:
        return False
    try:
        ipaddress.ip_address(h)
        return True
    except ValueError:
        return False


class IpDomainMapper:
    """管理 IP 与真实域名的双向映射库，用于将 HTTPDNS/透明代理拦截到的纯 IP 自动纠正为真实域名"""
    def __init__(self, cache_file: str):
        self.cache_file = cache_file
        self._lock = threading.Lock()
        self.ip_to_domain: dict[str, str] = {}
        self.domain_to_ips: dict[str, set[str]] = {}
        self._load()

    def _load(self):
        if os.path.exists(self.cache_file):
            try:
                with open(self.cache_file, "r", encoding="utf-8") as f:
                    data = json.load(f)
                if isinstance(data, dict):
                    with self._lock:
                        for ip, dom in data.items():
                            if isinstance(ip, str) and isinstance(dom, str):
                                ip_clean = ip.strip()
                                dom_clean = dom.strip().lower()
                                if ip_clean and dom_clean and _is_ip_address(ip_clean) and not _is_ip_address(dom_clean):
                                    self.ip_to_domain[ip_clean] = dom_clean
                                    self.domain_to_ips.setdefault(dom_clean, set()).add(ip_clean)
                                    root = _extract_root_domain(dom_clean)
                                    if root and root != dom_clean:
                                        self.domain_to_ips.setdefault(f"*.{root}", set()).add(ip_clean)
            except Exception:
                pass

    def save(self):
        try:
            with self._lock:
                to_save = dict(self.ip_to_domain)
            with open(self.cache_file, "w", encoding="utf-8") as f:
                json.dump(to_save, f, ensure_ascii=False, indent=2)
        except Exception:
            pass

    def record(self, ip: str, domain: str):
        ip = (ip or "").split(":")[0].strip().strip("[]")
        domain = (domain or "").split(":")[0].strip().lower()
        if not ip or not domain:
            return
        if not _is_ip_address(ip) or _is_ip_address(domain):
            return
        need_save = False
        with self._lock:
            old = self.ip_to_domain.get(ip)
            if old != domain:
                self.ip_to_domain[ip] = domain
                self.domain_to_ips.setdefault(domain, set()).add(ip)
                root = _extract_root_domain(domain)
                if root and root != domain:
                    self.domain_to_ips.setdefault(f"*.{root}", set()).add(ip)
                need_save = True
        if need_save:
            threading.Thread(target=self.save, daemon=True).start()

    def get_domain(self, ip: str) -> str:
        ip = (ip or "").split(":")[0].strip().strip("[]")
        with self._lock:
            return self.ip_to_domain.get(ip, "")

    def matches_rules(self, ip: str, capture_rules: set[str]) -> bool:
        dom = self.get_domain(ip)
        if not dom:
            return False
        if "*" in capture_rules or dom in capture_rules or f"*.{dom}" in capture_rules:
            return True
        for rule in capture_rules:
            if rule.startswith("*."):
                suf = rule[2:]
                if dom == suf or dom.endswith("." + suf):
                    return True
        return False


def _extract_root_domain(host: str) -> str:
    """提取根域名，例如 play.fe.googleapis.com -> googleapis.com"""
    h = host.split(":")[0].strip().lower()
    try:
        ipaddress.ip_address(h)
        return h
    except ValueError:
        pass
    parts = h.split(".")
    if len(parts) >= 3 and parts[-2] in ("com", "net", "org", "gov", "edu", "co") and len(parts[-1]) == 2:
        return ".".join(parts[-3:])
    if len(parts) >= 2:
        return ".".join(parts[-2:])
    return h


def _clean_api_path(path: str) -> str:
    """提取不带 Query 参数的纯净接口路径，例如 /v1/order/submit?a=1 -> /v1/order/submit"""
    if not path:
        return "/"
    base = path.split("?", 1)[0].strip()
    return base if base.startswith("/") else "/" + base


_HTTP_REASON_MAP = {
    200: "OK",
    201: "Created",
    204: "No Content",
    400: "Bad Request",
    401: "Unauthorized",
    403: "Forbidden",
    404: "Not Found",
    429: "Too Many Requests",
    500: "Internal Server Error",
    502: "Bad Gateway",
    503: "Service Unavailable",
    504: "Gateway Timeout",
}


class InterceptRule:
    """单条接口断点 / 参数篡改 / 固定状态码规则"""

    def __init__(
        self,
        host: str,
        path: str,
        enabled: bool = True,
        breakpoint_req: bool = False,
        breakpoint_resp: bool = False,
        modify_req_enabled: bool = False,
        fixed_query: str = "",
        fixed_req_body: str = "",
        fixed_status_enabled: bool = False,
        fixed_status_code: int = 500,
        modify_resp_enabled: bool = False,
        fixed_resp_body: str = "",
        mock_direct: bool = False,
    ):
        self.host = host.split(":")[0].strip().lower()
        self.path = _clean_api_path(path)
        self.enabled = enabled
        self.breakpoint_req = breakpoint_req
        self.breakpoint_resp = breakpoint_resp
        self.modify_req_enabled = modify_req_enabled
        self.fixed_query = fixed_query
        self.fixed_req_body = fixed_req_body
        self.fixed_status_enabled = fixed_status_enabled
        self.fixed_status_code = int(fixed_status_code or 500)
        self.modify_resp_enabled = modify_resp_enabled
        self.fixed_resp_body = fixed_resp_body
        self.mock_direct = mock_direct

    @property
    def key(self) -> str:
        return f"{self.host}{self.path}"

    def to_dict(self) -> dict:
        return {
            "host": self.host,
            "path": self.path,
            "enabled": self.enabled,
            "breakpoint_req": self.breakpoint_req,
            "breakpoint_resp": self.breakpoint_resp,
            "modify_req_enabled": self.modify_req_enabled,
            "fixed_query": self.fixed_query,
            "fixed_req_body": self.fixed_req_body,
            "fixed_status_enabled": self.fixed_status_enabled,
            "fixed_status_code": self.fixed_status_code,
            "modify_resp_enabled": self.modify_resp_enabled,
            "fixed_resp_body": self.fixed_resp_body,
            "mock_direct": self.mock_direct,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "InterceptRule":
        return cls(
            host=d.get("host", ""),
            path=d.get("path", "/"),
            enabled=bool(d.get("enabled", True)),
            breakpoint_req=bool(d.get("breakpoint_req", False)),
            breakpoint_resp=bool(d.get("breakpoint_resp", False)),
            modify_req_enabled=bool(d.get("modify_req_enabled", False)),
            fixed_query=str(d.get("fixed_query", "")),
            fixed_req_body=str(d.get("fixed_req_body", "")),
            fixed_status_enabled=bool(d.get("fixed_status_enabled", False)),
            fixed_status_code=int(d.get("fixed_status_code", 500)),
            modify_resp_enabled=bool(d.get("modify_resp_enabled", False)),
            fixed_resp_body=str(d.get("fixed_resp_body", "")),
            mock_direct=bool(d.get("mock_direct", False)),
        )

    def summary_tags(self) -> str:
        tags = []
        if self.breakpoint_req or self.breakpoint_resp:
            bp_part = "请求+响应" if (self.breakpoint_req and self.breakpoint_resp) else ("请求" if self.breakpoint_req else "响应")
            tags.append(f"🛑断点({bp_part})")
        if self.fixed_status_enabled:
            tags.append(f"⚡状态码={self.fixed_status_code}")
        if self.modify_req_enabled:
            tags.append("✏️改请求参数")
        if self.modify_resp_enabled:
            tags.append("✏️改响应体")
        return " | ".join(tags) if tags else "未启用子项"


class BreakpointSession:
    """表示一次挂起等待用户在 UI 弹窗确认放行的实时断点会话"""

    def __init__(
        self,
        stage: str,  # "request" 或 "response"
        scheme: str,
        method: str,
        host: str,
        port: int,
        path: str,
        req_headers: dict,
        req_body_text: str,
        status_code: int = 200,
        resp_headers: dict = None,
        resp_body_text: str = "",
    ):
        self.stage = stage
        self.scheme = scheme
        self.method = method
        self.host = host
        self.port = port
        self.path = path
        self.req_headers = dict(req_headers or {})
        self.req_body_text = req_body_text
        self.status_code = status_code
        self.resp_headers = dict(resp_headers or {})
        self.resp_body_text = resp_body_text
        self.abort_with_500 = False
        self.event = threading.Event()


class CharlesProxyEngine:
    """多线程 HTTP / HTTPS (按需对选中域名 MITM 解密) 抓包代理服务"""

    def __init__(self, flow_queue: queue.Queue, cert_mgr: CertManager):
        self.flow_queue = flow_queue
        self.cert_mgr = cert_mgr
        self.running = False
        self.port = 8888
        self.mitm_enabled = True
        self.pc_auto_mitm = False
        self.user_excluded_hosts: set[str] = set()
        self.tls_passthrough_hosts: set[str] = set()
        self.capture_file = os.path.join(self.cert_mgr.ca_dir, "capture_targets.json")
        self.capture_rules: set[str] = self._load_capture_rules()
        self.ip_cache_file = os.path.join(self.cert_mgr.ca_dir, "ip_domain_cache.json")
        self.ip_mapper = IpDomainMapper(self.ip_cache_file)
        self.intercept_file = os.path.join(self.cert_mgr.ca_dir, "intercept_rules.json")
        self.intercept_rules: dict[str, InterceptRule] = self._load_intercept_rules()
        # 电脑内网无法连通的海外域名（非抓包目标时自动加入手机直连排除列表，保证谷歌商店等正常使用）
        self.auto_direct_rules: set[str] = {
            "google.com",
            "*.google.com",
            "googleapis.com",
            "*.googleapis.com",
            "gstatic.com",
            "*.gstatic.com",
            "ggpht.com",
            "*.ggpht.com",
            "googleusercontent.com",
            "*.googleusercontent.com",
            "gvt1.com",
            "*.gvt1.com",
            "gvt2.com",
            "*.gvt2.com",
        }
        self._server_sock = None
        self._flow_seq = 0
        self._seq_lock = threading.Lock()

    def _load_intercept_rules(self) -> dict[str, InterceptRule]:
        res = {}
        if os.path.exists(self.intercept_file):
            try:
                with open(self.intercept_file, "r", encoding="utf-8") as f:
                    data = json.load(f)
                if isinstance(data, list):
                    for item in data:
                        if isinstance(item, dict):
                            r = InterceptRule.from_dict(item)
                            res[r.key] = r
            except Exception:
                pass
        return res

    def save_intercept_rules(self):
        try:
            with open(self.intercept_file, "w", encoding="utf-8") as f:
                json.dump(
                    [r.to_dict() for r in self.intercept_rules.values()],
                    f,
                    ensure_ascii=False,
                    indent=2,
                )
        except Exception:
            pass

    def set_intercept_rule(self, rule: InterceptRule):
        # 添加接口规则时，自动将该域名加入 HTTPS 抓包解密列表，确保规则能直接拦截到明文接口
        if rule.host:
            self.add_capture_rule(rule.host)
        if not (
            rule.breakpoint_req
            or rule.breakpoint_resp
            or rule.modify_req_enabled
            or rule.fixed_status_enabled
            or rule.modify_resp_enabled
        ):
            self.intercept_rules.pop(rule.key, None)
        else:
            self.intercept_rules[rule.key] = rule
        self.save_intercept_rules()

    def remove_intercept_rule(self, key: str):
        self.intercept_rules.pop(key, None)
        self.save_intercept_rules()

    def match_intercept_rule(self, host: str, path: str) -> InterceptRule | None:
        h = host.split(":")[0].strip().lower()
        clean_p = _clean_api_path(path)
        rule = self.intercept_rules.get(f"{h}{clean_p}")
        if rule and rule.enabled:
            return rule
        for r in list(self.intercept_rules.values()):
            if not r.enabled:
                continue
            if (r.host == "*" or r.host == h) and (r.path == "*" or r.path == clean_p):
                return r
        return None

    def _load_capture_rules(self) -> set[str]:
        if os.path.exists(self.capture_file):
            try:
                with open(self.capture_file, "r", encoding="utf-8") as f:
                    data = json.load(f)
                if isinstance(data, list):
                    return {str(x).strip().lower() for x in data if str(x).strip()}
            except Exception:
                pass
        return set()

    def save_capture_rules(self):
        try:
            with open(self.capture_file, "w", encoding="utf-8") as f:
                json.dump(sorted(self.capture_rules), f, ensure_ascii=False, indent=2)
        except Exception:
            pass

    def _warmup_domain_ips(self, domain_rule: str):
        """异步预热解析域名的当前 DNS IP，填充进 IP-域名映射表，让 HTTPDNS 直连时立即命中白名单"""
        clean = domain_rule.lstrip("*.").strip().lower()
        if not clean or _is_ip_address(clean):
            return
        domains_to_test = [clean]
        if "leigod" in clean:
            domains_to_test.extend([
                f"geoip.{clean}",
                f"geoip3.{clean}",
                f"api11.{clean}",
                f"secapiv11.{clean}",
                f"update.{clean}",
                f"webapi.{clean}",
                f"picture.{clean}",
                f"quicktracking-api.{clean}",
            ])
        else:
            domains_to_test.extend([f"api.{clean}", f"www.{clean}"])
        for d in domains_to_test:
            try:
                infos = socket.getaddrinfo(d, 443, socket.AF_INET, socket.SOCK_STREAM)
                for item in infos:
                    ip = item[4][0]
                    if ip and _is_ip_address(ip):
                        self.ip_mapper.record(ip, d)
            except Exception:
                pass

    def add_capture_rule(self, rule: str):
        r = rule.split(":")[0].strip().lower()
        if r:
            self.capture_rules.add(r)
            self.tls_passthrough_hosts.discard(r)
            self.auto_direct_rules.discard(r)
            root = _extract_root_domain(r.lstrip("*."))
            self.auto_direct_rules.discard(root)
            self.auto_direct_rules.discard(f"*.{root}")
            self.save_capture_rules()
            if not _is_ip_address(r):
                threading.Thread(target=self._warmup_domain_ips, args=(r,), daemon=True).start()

    def remove_capture_rule(self, rule: str):
        r = rule.split(":")[0].strip().lower()
        self.capture_rules.discard(r)
        root = _extract_root_domain(r.lstrip("*."))
        self.capture_rules.discard(f"*.{root}")
        # 若移除的是通配符如 *.leigod.com，同步移除该根域名下的子域名规则
        if r.startswith("*."):
            suf = r[2:]
            for item in list(self.capture_rules):
                if item == suf or item.endswith("." + suf):
                    self.capture_rules.discard(item)
        self.save_capture_rules()

    def should_mitm_host(self, host: str, process_name: str = "", allow_ip_probe: bool = True) -> bool:
        """判断是否应当对该域名进行 HTTPS MITM 解密抓包（支持纯 IP 自动查映射与智能解密嗅探）"""
        if not self.mitm_enabled or not self.cert_mgr.available:
            return False
        h = host.split(":")[0].strip().lower()
        if not h:
            return False
        exe_part = ""
        if process_name.startswith("💻 "):
            exe_part = process_name[2:].strip().lower()
            if exe_part in _BYPASS_EXE_NAMES:
                return False
        if h in self.tls_passthrough_hosts:
            return False
        # 腾讯/企微/微信专属域名与 HTTPDNS IP（如 oss.work.weixin.qq.com、i.work.weixin.qq.com、wework.qpic.cn 等）
        # 除非用户显式将该具体域名加入 capture_rules，否则一律不签发自签名假证书，100% 走原始 TLS 隧道透传！
        if _is_tencent_bypass_domain(h) and h not in self.capture_rules:
            return False

        # 检查是否直接命中抓包目标（包括 IP 已映射到目标域名的情况）
        if self.is_target_captured(h):
            return True

        # 若是纯 IP 且来源非系统内置旁路进程（如雷神客户端 HTTPDNS 直连 IP）：
        # 恢复原版探测性解密逻辑，但排除企业微信进程
        if allow_ip_probe and _is_ip_address(h):
            return True

        return False

    def is_target_captured(self, host: str) -> bool:
        """判断该域名或 IP 是否被用户加入了『🎯 目标抓包解密列表』"""
        h = host.split(":")[0].strip().lower()
        if not h:
            return False
        if "*" in self.capture_rules or h in self.capture_rules or f"*.{h}" in self.capture_rules:
            return True
        for rule in list(self.capture_rules):
            if rule.startswith("*."):
                suf = rule[2:]
                if h == suf or h.endswith("." + suf):
                    return True
        # 若 h 是纯 IP，检查该 IP 是否映射到已捕获的域名
        if _is_ip_address(h):
            if self.ip_mapper.matches_rules(h, self.capture_rules):
                return True
        return False

    def next_flow_id(self) -> int:
        with self._seq_lock:
            self._flow_seq += 1
            return self._flow_seq

    def start(self, port: int = 8888, mitm_enabled: bool = True) -> tuple[bool, str]:
        if self.running:
            self.stop()
        self.port = port
        self.mitm_enabled = mitm_enabled
        try:
            srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            srv.bind(("0.0.0.0", port))
            srv.listen(128)
            self._server_sock = srv
            self.running = True
            threading.Thread(target=self._accept_loop, daemon=True).start()
            return True, f"监听 0.0.0.0:{port} 成功"
        except Exception as e:
            self.running = False
            return False, str(e)

    def stop(self):
        self.running = False
        if self._server_sock:
            try:
                self._server_sock.close()
            except Exception:
                pass
            self._server_sock = None

    def _accept_loop(self):
        while self.running and self._server_sock:
            try:
                client_sock, client_addr = self._server_sock.accept()
                threading.Thread(
                    target=self._handle_client,
                    args=(client_sock, client_addr),
                    daemon=True,
                ).start()
            except Exception:
                if not self.running:
                    break

    def _serve_cert_portal(self, client_sock: socket.socket, path: str):
        """响应手机浏览器访问 http://yyds.ca 或 http://chls.pro/ssl 下载证书"""
        pem_bytes = self.cert_mgr.get_ca_pem_bytes()
        if path.endswith(".crt") or path.endswith(".cer") or path.endswith(".pem") or path == "/ssl":
            headers = (
                "HTTP/1.1 200 OK\r\n"
                "Content-Type: application/x-x509-ca-cert\r\n"
                'Content-Disposition: attachment; filename="liuzu_yyds_ca.crt"\r\n'
                f"Content-Length: {len(pem_bytes)}\r\n"
                "Connection: close\r\n\r\n"
            ).encode("utf-8")
            client_sock.sendall(headers + pem_bytes)
            return

        html = """<!DOCTYPE html>
<html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>RMYYDS 抓包证书安装</title>
<style>
body{font-family:sans-serif;background:#1E1F22;color:#DFE1E5;padding:24px;text-align:center;}
.card{background:#2B2D30;border-radius:12px;padding:24px;max-width:420px;margin:0 auto;box-shadow:0 4px 16px rgba(0,0,0,.4);}
a.btn{display:block;background:#3574F0;color:#fff;text-decoration:none;padding:14px 20px;border-radius:8px;font-weight:bold;margin:16px 0;}
ol{text-align:left;line-height:1.8;font-size:14px;color:#A9B7C6;}
</style></head><body>
<div class="card">
<h2>🛡️ 刘组YYDS 抓包根证书</h2>
<p>安装此证书后即可解密手机 HTTPS 接口请求</p>
<a class="btn" href="/liuzu_yyds_ca.crt">📥 点击下载安装 CA 证书 (.crt)</a>
<ol>
<li>点击上方按钮下载 <b>liuzu_yyds_ca.crt</b></li>
<li>若系统未自动弹出安装窗口，请打开手机：<br><b>设置 → 安全与隐私 → 更多安全设置 → 加密与凭据 → 安装证书 → CA 证书</b></li>
<li>选择刚下载的 <b>liuzu_yyds_ca.crt</b> 完成安装</li>
</ol>
</div></body></html>""".encode("utf-8")
        resp = (
            "HTTP/1.1 200 OK\r\n"
            "Content-Type: text/html; charset=utf-8\r\n"
            f"Content-Length: {len(html)}\r\n"
            "Connection: close\r\n\r\n"
        ).encode("utf-8") + html
        client_sock.sendall(resp)

    def _bridge_raw_socket(self, client_sock: socket.socket, dst_ip: str, dst_port: int):
        """对白名单进程或非 HTTP / 非标准 TLS 的私有二进制协议连接直接透传回原始目标，确保企业微信发图/游戏隧道不断线"""
        if not dst_ip or not dst_port or dst_port == self.port:
            return
        upstream = None
        try:
            upstream = _create_outbound_socket(dst_ip, dst_port, timeout=12)
            sockets = [client_sock, upstream]
            while self.running:
                rlist, _, xlist = select.select(sockets, [], sockets, 60)
                if xlist or not rlist:
                    break
                eof = False
                for s in rlist:
                    data = s.recv(65536)
                    if not data:
                        eof = True
                        break
                    other = upstream if s is client_sock else client_sock
                    other.sendall(data)
                if eof:
                    break
        except Exception:
            pass
        finally:
            if upstream:
                try:
                    upstream.close()
                except Exception:
                    pass

    def _handle_client(self, client_sock: socket.socket, client_addr):
        client_sock.settimeout(20)
        client_ip = f"{client_addr[0]}:{client_addr[1]}"
        nat_info = _GLOBAL_DIVERT.get_nat_info(client_addr[1])
        if nat_info:
            orig_dst_ip, orig_dst_port, proc_name = nat_info
            # 若 SYN 瞬间尚未解析出具体 .exe，在 ESTABLISHED 后直接按源端口补查本机 PID（注意此时 client_addr[0] 是伪装的远端 IP，不可用 _resolve_client_process_name）
            if not proc_name or proc_name == "💻 本机程序" or proc_name.lower().startswith("💻 pid:"):
                _, exe = _resolve_pid_and_exe_by_port(client_addr[1])
                proc_name = f"💻 {exe}" if exe else "💻 本机程序"
        else:
            orig_dst_ip, orig_dst_port = "", 0
            proc_name = _resolve_client_process_name(client_addr[0], client_addr[1])

        exe_clean = proc_name[2:].strip().lower() if proc_name.startswith("💻 ") else ""
        # 若该连接来自企业微信等白名单进程且带有原始目标地址，不嗅探、不解析、不抓包，直接 100% 原始 TCP 透传
        if exe_clean in _BYPASS_EXE_NAMES and orig_dst_ip and orig_dst_port:
            try:
                self._bridge_raw_socket(client_sock, orig_dst_ip, orig_dst_port)
            finally:
                try:
                    client_sock.close()
                except Exception:
                    pass
            return

        try:
            # 先通过 MSG_PEEK 嗅探首包：区分 1) 原生 TLS ClientHello (0x16) 2) HTTP/CONNECT 3) 私有二进制协议
            try:
                peek = client_sock.recv(16, socket.MSG_PEEK)
            except Exception:
                return
            if not peek:
                return

            # 情况 A：首字节为 0x16 -> 被 WinDivert 驱动透明劫持进来的原生 TLS (HTTPS) 直连请求（如雷神客户端/微信小程序）
            if peek[0] == 0x16:
                try:
                    hello_peek = client_sock.recv(4096, socket.MSG_PEEK)
                except Exception:
                    hello_peek = peek
                sni_host = _parse_sni_from_tls_client_hello(hello_peek)
                host = sni_host or (orig_dst_ip if orig_dst_ip and not orig_dst_ip.startswith("127.") else "")
                port = orig_dst_port if (orig_dst_port and orig_dst_port not in (10091, self.port)) else 443

                if not host:
                    self._bridge_raw_socket(client_sock, orig_dst_ip, orig_dst_port)
                    return

                if self.should_mitm_host(host, proc_name):
                    self._handle_https_mitm(
                        client_sock,
                        client_ip,
                        host,
                        port,
                        {"Host": f"{host}:{port}", "X-Capture-Mode": "Transparent-TLS-SNI"},
                        proc_name,
                        orig_dst_ip=orig_dst_ip,
                    )
                else:
                    # 若属于后台白名单进程或未启用解密的域名，直接通过豁免端口段透传到目标域名/IP
                    exe_clean = proc_name[2:].strip().lower() if proc_name.startswith("💻 ") else ""
                    if exe_clean in _BYPASS_EXE_NAMES or _is_tencent_bypass_domain(host):
                        self._bridge_raw_socket(client_sock, orig_dst_ip or host, port)
                    else:
                        self._handle_connect_tunnel(
                            client_sock,
                            client_ip,
                            host,
                            port,
                            {"Host": f"{host}:{port}"},
                            proc_name,
                            connect_ip=orig_dst_ip,
                            connect_port=port,
                        )
                return

            # 情况 B：检查是否为标准 HTTP 方法开头；若不是（例如微信 MMTLS 或游戏私有二进制流），直接无损桥接透传
            upper_peek = peek.upper()
            if not upper_peek.startswith(
                (b"GET ", b"POST ", b"PUT ", b"DELETE ", b"HEAD ", b"OPTIONS ", b"PATCH ", b"CONNECT ")
            ):
                if orig_dst_ip and orig_dst_port:
                    self._bridge_raw_socket(client_sock, orig_dst_ip, orig_dst_port)
                return

            msg = _read_http_message(client_sock, is_request=True)
            if not msg:
                return
            first_line, req_headers, raw_req_headers, req_body, _ = msg
            parts = first_line.split(None, 2)
            if len(parts) < 2:
                return
            method, target = parts[0].upper(), parts[1]
            version = parts[2] if len(parts) > 2 else "HTTP/1.1"

            # 1. 处理 HTTPS CONNECT 隧道/MITM 请求
            if method == "CONNECT":
                if ":" in target:
                    host, port_s = target.rsplit(":", 1)
                    try:
                        port = int(port_s)
                    except ValueError:
                        port = 443
                else:
                    host, port = target, 443

                # 通知客户端连接已建立
                client_sock.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")

                if exe_clean in _BYPASS_EXE_NAMES or _is_tencent_bypass_domain(host):
                    self._bridge_raw_socket(client_sock, host, port)
                    return

                # 若 CONNECT 目标是纯 IP，通过 MSG_PEEK 嗅探客户端紧接着发来的首包：
                # 1) 若非 TLS 握手 (0x16)，说明是 MMTLS 等私有协议，直接走隧道透传
                # 2) 若是 TLS 握手且带有明文 SNI (如 oss.work.weixin.qq.com)，用真实 SNI 域名判断是否需要 MITM 解密，避免对企微纯 IP 误做探测解密
                check_host = host
                connect_ip = orig_dst_ip or (host if _is_ip_address(host) else "")
                if _is_ip_address(host):
                    try:
                        c_peek = client_sock.recv(4096, socket.MSG_PEEK)
                        if c_peek:
                            if c_peek[0] != 0x16:
                                self._handle_connect_tunnel(
                                    client_sock, client_ip, host, port, req_headers, proc_name, connect_ip=connect_ip, connect_port=port
                                )
                                return
                            sni = _parse_sni_from_tls_client_hello(c_peek)
                            if sni:
                                check_host = sni
                    except Exception:
                        pass

                if self.should_mitm_host(check_host, proc_name):
                    self._handle_https_mitm(client_sock, client_ip, check_host, port, req_headers, proc_name, orig_dst_ip=connect_ip)
                else:
                    self._handle_connect_tunnel(
                        client_sock, client_ip, check_host, port, req_headers, proc_name, connect_ip=connect_ip, connect_port=port
                    )
                return

            # 2. 处理普通明文 HTTP 请求或在线证书下载门户（支持 Keep-Alive 多分片长连接复用）
            while self.running:
                host_header = ""
                for k, v in req_headers.items():
                    if k.lower() == "host":
                        host_header = v.strip()
                        break

                if target.startswith("http://") or target.startswith("https://"):
                    parsed = urllib.parse.urlsplit(target)
                    scheme = parsed.scheme or "http"
                    host = parsed.hostname or host_header.split(":")[0]
                    port = parsed.port or (443 if scheme == "https" else 80)
                    path = parsed.path or "/"
                    if parsed.query:
                        path += "?" + parsed.query
                else:
                    scheme = "http"
                    if ":" in host_header:
                        host, p_str = host_header.rsplit(":", 1)
                        try:
                            port = int(p_str)
                        except ValueError:
                            port = 80
                    else:
                        host, port = host_header, 80
                    path = target

                # 检查是否访问内置证书安装页面
                if host in ("yyds.ca", "chls.pro", "127.0.0.1", "localhost") or (
                    port == self.port and path in ("/", "/ssl", "/ca.crt", "/liuzu_yyds_ca.crt")
                ):
                    self._serve_cert_portal(client_sock, path)
                    return

                actual_server_ip = orig_dst_ip or (host if _is_ip_address(host) else "")
                display_host = host
                clean_hdr_host = host_header.split(":")[0].strip()
                if _is_ip_address(host) and clean_hdr_host and not _is_ip_address(clean_hdr_host):
                    display_host = clean_hdr_host
                    if actual_server_ip:
                        self.ip_mapper.record(actual_server_ip, clean_hdr_host)

                should_record = (
                    (exe_clean not in _BYPASS_EXE_NAMES)
                    and not (_is_tencent_bypass_domain(display_host) and display_host not in self.capture_rules)
                    and (self.is_target_captured(display_host) or not self.capture_rules)
                )

                keep_going = self._forward_http_exchange(
                    client_sock=client_sock,
                    client_ip=client_ip,
                    scheme=scheme,
                    method=method,
                    host=display_host,
                    port=port,
                    path=path,
                    version=version,
                    req_headers=req_headers,
                    req_body=req_body,
                    use_tls=False,
                    process_name=proc_name,
                    server_ip=actual_server_ip,
                    should_record_flow=should_record,
                )
                if not keep_going:
                    break
                next_msg = _read_http_message(client_sock, is_request=True)
                if not next_msg:
                    break
                first_line, req_headers, raw_req_headers, req_body, _ = next_msg
                parts = first_line.split(None, 2)
                if len(parts) < 2:
                    break
                method, target = parts[0].upper(), parts[1]
                version = parts[2] if len(parts) > 2 else "HTTP/1.1"
                if method == "CONNECT":
                    break
        except Exception:
            pass
        finally:
            try:
                client_sock.close()
            except Exception:
                pass

    def _handle_https_mitm(
        self,
        client_sock: socket.socket,
        client_ip: str,
        host: str,
        port: int,
        connect_headers: dict,
        process_name: str = "",
        orig_dst_ip: str = "",
    ):
        """对 CONNECT 隧道或透明 TLS 直连执行动态证书签发与 TLS 解密抓包"""
        t0 = time.time()
        mapped_dom = self.ip_mapper.get_domain(host or orig_dst_ip)
        extra_san = [mapped_dom] if (mapped_dom and mapped_dom != host) else None
        try:
            ctx = self.cert_mgr.get_domain_ssl_context(host, extra_names=extra_san)
            tls_client = ctx.wrap_socket(client_sock, server_side=True)
        except Exception as e:
            # 若电脑客户端某个特殊域名启用了强证书绑定 (SSL Pinning)，自动将其加入本次会话直通列表，保证软件不卡死
            if (process_name.startswith("💻") or _is_ip_address(host)) and host:
                self.tls_passthrough_hosts.add(host.split(":")[0].strip().lower())
            flow = HttpFlow(self.next_flow_id(), "https", "CONNECT", host, port, "/", client_ip)
            flow.process_name = process_name
            flow.server_ip = orig_dst_ip or host
            flow.req_headers = connect_headers
            flow.status_code = 495
            flow.reason = "TLS Handshake Rejected"
            flow.duration_ms = int((time.time() - t0) * 1000)
            flow.error = f"客户端未信任抓包证书或启用了 SSL Pinning ({e})"
            flow.resp_body_raw = (
                f"⚠️ HTTPS 解密握手未完成：{host}:{port}\n\n"
                "可能原因：\n"
                "1. 若抓电脑程序：请点击顶部『📲 安装证书』→ 点击『💻 一键安装证书到本机电脑』\n"
                "2. 若抓手机应用：手机尚未安装「RM YYDS Root CA」证书，或应用启用了 SSL Pinning\n"
            ).encode("utf-8")
            if self.is_target_captured(host) or (mapped_dom and self.is_target_captured(mapped_dom)):
                self.flow_queue.put(flow)
            return

        # 握手成功后，可能复用同一 TLS 连接发送多个 HTTP 请求
        try:
            tls_client.settimeout(20)
            while self.running:
                msg = _read_http_message(tls_client, is_request=True)
                if not msg:
                    break
                first_line, req_headers, _, req_body, _ = msg
                parts = first_line.split(None, 2)
                if len(parts) < 2:
                    break
                method, path = parts[0].upper(), parts[1]
                version = parts[2] if len(parts) > 2 else "HTTP/1.1"
                if path.startswith("https://"):
                    parsed = urllib.parse.urlsplit(path)
                    path = (parsed.path or "/") + (("?" + parsed.query) if parsed.query else "")

                # 提取 HTTP 请求头中的真实 Host 域名
                req_host = ""
                for k, v in req_headers.items():
                    if k.lower() == "host":
                        req_host = v.strip().split(":")[0].strip()
                        break

                display_host = host
                actual_server_ip = orig_dst_ip or (host if _is_ip_address(host) else "")

                # 智能域名纠正与绑定
                if req_host and not _is_ip_address(req_host):
                    display_host = req_host
                    if actual_server_ip:
                        self.ip_mapper.record(actual_server_ip, req_host)
                elif not req_host and mapped_dom:
                    display_host = mapped_dom

                # 白名单判定：若配置了白名单，只有命中白名单的主机才放入 UI 列表
                should_record = True
                if self.capture_rules:
                    if not self.is_target_captured(display_host):
                        should_record = False

                keep_going = self._forward_http_exchange(
                    client_sock=tls_client,
                    client_ip=client_ip,
                    scheme="https",
                    method=method,
                    host=display_host,
                    port=port,
                    path=path,
                    version=version,
                    req_headers=req_headers,
                    req_body=req_body,
                    use_tls=True,
                    process_name=process_name,
                    server_ip=actual_server_ip,
                    should_record_flow=should_record,
                )
                if not keep_going:
                    break
        except Exception:
            pass
        finally:
            try:
                tls_client.close()
            except Exception:
                pass

    def _forward_http_exchange(
        self,
        client_sock: socket.socket,
        client_ip: str,
        scheme: str,
        method: str,
        host: str,
        port: int,
        path: str,
        version: str,
        req_headers: dict,
        req_body: bytes,
        use_tls: bool,
        process_name: str = "",
        server_ip: str = "",
        should_record_flow: bool = True,
    ) -> bool:
        """向目标服务器转发一条 HTTP/HTTPS 请求，支持断点拦截、修改请求参数、修改响应体及固定返回状态码"""
        t0 = time.time()

        # 再次兜底检查请求头中的 Host 字段
        req_host_hdr = ""
        for k, v in req_headers.items():
            if k.lower() == "host":
                req_host_hdr = v.strip().split(":")[0].strip()
                break

        display_host = host
        target_connect_ip = server_ip
        if _is_ip_address(host) and req_host_hdr and not _is_ip_address(req_host_hdr):
            display_host = req_host_hdr
            target_connect_ip = host
            self.ip_mapper.record(host, req_host_hdr)

        # 规则匹配统一按真实域名匹配
        rule = self.match_intercept_rule(display_host, path)
        note_tags = []

        # -------- 阶段 1：请求发出前（自动改参 + 请求断点） --------
        if rule:
            if rule.modify_req_enabled:
                base_p = _clean_api_path(path)
                if rule.fixed_query.strip():
                    q_clean = rule.fixed_query.strip().lstrip("?")
                    path = f"{base_p}?{q_clean}"
                elif "?" in path and rule.fixed_query == "":
                    # 保持原 query 或按用户配置
                    pass
                if rule.fixed_req_body.strip():
                    req_body = rule.fixed_req_body.encode("utf-8")
                note_tags.append("✏️改参")

            if rule.breakpoint_req:
                temp_flow = HttpFlow(0, scheme, method, display_host, port, path, client_ip)
                temp_flow.req_headers = dict(req_headers)
                temp_flow.req_body_raw = req_body
                bp_req = BreakpointSession(
                    stage="request",
                    scheme=scheme,
                    method=method,
                    host=display_host,
                    port=port,
                    path=path,
                    req_headers=req_headers,
                    req_body_text=temp_flow.get_decoded_body(is_request=True),
                )
                self.flow_queue.put(("__BREAKPOINT__", bp_req))
                bp_req.event.wait(timeout=300)
                method = bp_req.method.strip().upper() or method
                path = bp_req.path.strip() or path
                req_headers = dict(bp_req.req_headers)
                req_body = bp_req.req_body_text.encode("utf-8")
                note_tags.append("🛑断请求")
                if bp_req.abort_with_500:
                    flow = HttpFlow(self.next_flow_id(), scheme, method, display_host, port, path, client_ip)
                    flow.process_name = process_name
                    flow.server_ip = target_connect_ip or ""
                    flow.req_headers = dict(req_headers)
                    flow.req_body_raw = req_body
                    flow.status_code = 500
                    flow.reason = "Internal Server Error (Breakpoint Aborted)"
                    flow.notes = " ".join(note_tags + ["⚡断点返回500"])
                    err_bytes = json.dumps(
                        {"code": 500, "msg": "Breakpoint Mock 500 Internal Server Error"},
                        ensure_ascii=False,
                    ).encode("utf-8")
                    flow.resp_headers = {"Content-Type": "application/json; charset=utf-8"}
                    flow.resp_body_raw = err_bytes
                    flow.content_type = "application/json; charset=utf-8"
                    flow.size_bytes = len(err_bytes)
                    flow.duration_ms = int((time.time() - t0) * 1000)
                    raw_resp = (
                        b"HTTP/1.1 500 Internal Server Error\r\n"
                        b"Content-Type: application/json; charset=utf-8\r\n"
                        + f"Content-Length: {len(err_bytes)}\r\nConnection: close\r\n\r\n".encode("latin-1")
                        + err_bytes
                    )
                    client_sock.sendall(raw_resp)
                    if should_record_flow:
                        self.flow_queue.put(flow)
                    return False

        flow = HttpFlow(self.next_flow_id(), scheme, method, display_host, port, path, client_ip)
        flow.process_name = process_name
        flow.server_ip = target_connect_ip or ""
        flow.req_headers = dict(req_headers)
        flow.req_body_raw = req_body

        # -------- 阶段 2：若勾选了『本地直接 Mock（不请求真实后端）』 --------
        if rule and rule.mock_direct and (rule.fixed_status_enabled or rule.modify_resp_enabled):
            code = rule.fixed_status_code if rule.fixed_status_enabled else 200
            reason = _HTTP_REASON_MAP.get(code, "Mock Response")
            body_str = (
                rule.fixed_resp_body
                if rule.modify_resp_enabled and rule.fixed_resp_body
                else json.dumps({"code": code, "msg": f"Mock Fixed Status {code}"}, ensure_ascii=False)
            )
            resp_body = body_str.encode("utf-8")
            resp_headers = {
                "Content-Type": "application/json; charset=utf-8",
                "X-Mock-By": "LiuZu-YYDS-Proxy",
            }
            note_tags.append(f"⚡Mock({code})")
            flow.server_ip = "本地 Mock"
            status_line = f"HTTP/1.1 {code} {reason}"
        else:
            # -------- 阶段 2B：正常向源站发起请求 --------
            upstream = None
            try:
                connect_addr = target_connect_ip if (_is_ip_address(target_connect_ip)) else display_host
                raw_up = _create_outbound_socket(connect_addr, port, timeout=15)
                flow.server_ip = _peer_ip_of(raw_up) or target_connect_ip or connect_addr
                if use_tls:
                    up_ctx = ssl._create_unverified_context()
                    upstream = up_ctx.wrap_socket(raw_up, server_hostname=display_host)
                else:
                    upstream = raw_up
                upstream.settimeout(20)

                out_lines = [f"{method} {path} HTTP/1.1\r\n"]
                has_host = False
                for k, v in req_headers.items():
                    kl = k.lower()
                    if kl in (
                        "proxy-connection",
                        "proxy-authorization",
                        "connection",
                        "transfer-encoding",
                        "content-length",
                    ):
                        continue
                    if kl == "accept-encoding":
                        # 统一协商为 gzip, deflate，避免源站返回 br / zstd 导致未安装扩展时显示乱码
                        out_lines.append("Accept-Encoding: gzip, deflate\r\n")
                        continue
                    if kl == "host":
                        has_host = True
                    out_lines.append(f"{k}: {v}\r\n")
                if not has_host:
                    default_p = 443 if use_tls else 80
                    h_val = host if port == default_p else f"{host}:{port}"
                    out_lines.append(f"Host: {h_val}\r\n")
                if req_body:
                    out_lines.append(f"Content-Length: {len(req_body)}\r\n")
                out_lines.append("Connection: close\r\n\r\n")

                upstream.sendall("".join(out_lines).encode("latin-1", errors="replace") + req_body)

                resp_msg = _read_http_message(upstream, is_request=False)
                if not resp_msg:
                    flow.status_code = 502
                    flow.reason = "Empty Upstream Response"
                    flow.duration_ms = int((time.time() - t0) * 1000)
                    self.flow_queue.put(flow)
                    return False

                status_line, resp_headers, _, resp_body, _ = resp_msg
            except Exception as e:
                flow.status_code = 502
                flow.reason = "Bad Gateway"
                flow.error = str(e)
                flow.duration_ms = int((time.time() - t0) * 1000)
                flow.resp_body_raw = f"代理请求目标服务器失败 ({host}:{port}):\n{e}".encode("utf-8")
                self.flow_queue.put(flow)
                return False
            finally:
                if upstream:
                    try:
                        upstream.close()
                    except Exception:
                        pass

        # 解析初始响应码与原因
        s_parts = status_line.split(None, 2)
        if len(s_parts) >= 2:
            try:
                flow.status_code = int(s_parts[1])
            except ValueError:
                flow.status_code = 200
        if len(s_parts) >= 3:
            flow.reason = s_parts[2]
        else:
            flow.reason = _HTTP_REASON_MAP.get(flow.status_code, "OK")

        flow.resp_headers = dict(resp_headers)
        flow.resp_body_raw = resp_body

        # -------- 阶段 3：响应返回给手机前（固定状态码 + 自动修改响应体 + 响应断点） --------
        if rule:
            if rule.fixed_status_enabled:
                flow.status_code = rule.fixed_status_code
                flow.reason = _HTTP_REASON_MAP.get(flow.status_code, "Modified Status")
                status_line = f"HTTP/1.1 {flow.status_code} {flow.reason}"
                if f"⚡Mock({flow.status_code})" not in note_tags:
                    note_tags.append(f"⚡状态码={flow.status_code}")

            if rule.modify_resp_enabled:
                resp_body = rule.fixed_resp_body.encode("utf-8")
                flow.resp_body_raw = resp_body
                # 移除 gzip/deflate 头，因为修改后的响应体已是明文 UTF-8 字节流
                for hk in list(resp_headers.keys()):
                    if hk.lower() == "content-encoding":
                        resp_headers.pop(hk, None)
                flow.resp_headers = dict(resp_headers)
                note_tags.append("✏️改响应")

            if rule.breakpoint_resp:
                decoded_resp = flow.get_decoded_body(is_request=False)
                bp_resp = BreakpointSession(
                    stage="response",
                    scheme=scheme,
                    method=method,
                    host=host,
                    port=port,
                    path=path,
                    req_headers=req_headers,
                    req_body_text="",
                    status_code=flow.status_code,
                    resp_headers=resp_headers,
                    resp_body_text=decoded_resp,
                )
                self.flow_queue.put(("__BREAKPOINT__", bp_resp))
                bp_resp.event.wait(timeout=300)
                flow.status_code = int(bp_resp.status_code or flow.status_code)
                flow.reason = _HTTP_REASON_MAP.get(flow.status_code, "Breakpoint Modified")
                status_line = f"HTTP/1.1 {flow.status_code} {flow.reason}"
                resp_headers = dict(bp_resp.resp_headers)
                for hk in list(resp_headers.keys()):
                    if hk.lower() == "content-encoding":
                        resp_headers.pop(hk, None)
                resp_body = bp_resp.resp_body_text.encode("utf-8")
                flow.resp_headers = dict(resp_headers)
                flow.resp_body_raw = resp_body
                note_tags.append("🛑断响应")

        flow.notes = " ".join(note_tags)
        flow.size_bytes = len(resp_body)
        flow.duration_ms = int((time.time() - t0) * 1000)
        for k, v in resp_headers.items():
            if k.lower() == "content-type":
                flow.content_type = v
                break

        # 判断客户端是否希望保持 Keep-Alive 长连接（Chrome 刷新非常依赖连接复用）
        req_conn = ""
        for rk, rv in req_headers.items():
            if rk.lower() in ("connection", "proxy-connection"):
                req_conn = rv.lower().strip()
                break
        wants_keep_alive = (version == "HTTP/1.1" and req_conn != "close") or (req_conn == "keep-alive")

        # 将最终响应写回客户端
        try:
            resp_out = [f"{status_line}\r\n"]
            for k, v in resp_headers.items():
                kl = k.lower()
                if kl in ("transfer-encoding", "content-length", "connection", "proxy-connection"):
                    continue
                resp_out.append(f"{k}: {v}\r\n")
            resp_out.append(f"Content-Length: {len(resp_body)}\r\n")
            if wants_keep_alive:
                resp_out.append("Connection: keep-alive\r\n\r\n")
            else:
                resp_out.append("Connection: close\r\n\r\n")
            client_sock.sendall("".join(resp_out).encode("latin-1", errors="replace") + resp_body)
        except Exception:
            wants_keep_alive = False

        if should_record_flow:
            self.flow_queue.put(flow)
        return wants_keep_alive

    def _handle_connect_tunnel(
        self,
        client_sock: socket.socket,
        client_ip: str,
        host: str,
        port: int,
        connect_headers: dict,
        process_name: str = "",
        connect_ip: str = "",
        connect_port: int = 0,
    ):
        """纯 TCP 隧道透传模式（无需证书，不破坏 SSL Pinning，记录连接域名与流量）"""
        t0 = time.time()
        flow = HttpFlow(self.next_flow_id(), "tunnel", "CONNECT", host, port, "/", client_ip)
        flow.process_name = process_name
        flow.req_headers = dict(connect_headers)
        upstream = None
        total_bytes = 0
        real_host = connect_ip or host
        real_port = connect_port or port
        try:
            upstream = _create_outbound_socket(real_host, real_port, timeout=6)
            flow.server_ip = _peer_ip_of(upstream)
            flow.status_code = 200
            flow.reason = "Tunnel Established"
            flow.duration_ms = int((time.time() - t0) * 1000)
            flow.resp_body_raw = (
                f"🔒 HTTPS 隧道透传连接 ({host}:{port}) — 当前未对该域名启用抓包解密\n\n"
                "💡 如需查看此域名的 HTTPS 明文接口参数与返回 JSON：\n"
                "请在左侧『📂 域名结构』列表中对着该域名点击【鼠标右键】→ 选择『🎯 抓包此域名』！"
            ).encode("utf-8")
            self.flow_queue.put(flow)
            queued = True

            sockets = [client_sock, upstream]
            while self.running:
                if self.should_mitm_host(host, process_name):
                    # 用户刚刚右键开启了该域名的抓包解密，立即中断未解密旧隧道，让客户端下一秒自动重连进入 MITM 解密
                    break
                rlist, _, xlist = select.select(sockets, [], sockets, 2.0)
                if xlist:
                    break
                if not rlist:
                    continue
                eof = False
                for s in rlist:
                    data = s.recv(32768)
                    if not data:
                        eof = True
                        break
                    total_bytes += len(data)
                    other = upstream if s is client_sock else client_sock
                    other.sendall(data)
                if eof:
                    break
            flow.size_bytes = total_bytes
            flow.duration_ms = int((time.time() - t0) * 1000)
            flow.resp_body_raw = (
                f"🔒 HTTPS 隧道透传连接 ({host}:{port}) — 当前未对该域名启用抓包解密\n"
                f"双向累计传输字节: {total_bytes:,} Bytes\n"
                f"持续耗时: {flow.duration_ms} ms\n\n"
                "💡 如需查看此域名的 HTTPS 明文接口参数与返回 JSON：\n"
                "请在左侧『📂 域名结构』列表中对着该域名点击【鼠标右键】→ 选择『🎯 抓包此域名』！"
            ).encode("utf-8")
        except Exception as e:
            flow.status_code = 502
            flow.reason = "Tunnel Failed"
            flow.error = str(e)
            flow.duration_ms = int((time.time() - t0) * 1000)
            # 若该域名并非用户指定的抓包目标且电脑内网无法连通（如海外域名），自动通知手机直连放行
            if not self.is_target_captured(host):
                clean_h = host.split(":")[0].strip().lower()
                if clean_h and clean_h not in self.auto_direct_rules:
                    root_d = _extract_root_domain(clean_h)
                    self.auto_direct_rules.add(clean_h)
                    if root_d:
                        self.auto_direct_rules.add(root_d)
                        self.auto_direct_rules.add(f"*.{root_d}")
                    self.flow_queue.put(("__AUTO_DIRECT__", clean_h))
            if not locals().get("queued", False):
                self.flow_queue.put(flow)
        finally:
            if upstream:
                try:
                    upstream.close()
                except Exception:
                    pass


# ==================== 类 Charles 抓包可视化窗口 ====================

class CharlesCaptureWindow:
    """类 Charles HTTP/HTTPS 接口抓包分析界面（默认直接作为程序主界面，也可作为独立窗口）"""

    def __init__(self, app, is_main_window: bool = True):
        self.app = app
        self.is_main_window = is_main_window
        if is_main_window:
            self.win = app.root
            self.win.title("🌐 RMYYDS - HTTP/HTTPS 接口抓包 & 手机投屏 & Logcat 工具")
        else:
            self.win = tk.Toplevel(app.root)
            self.win.title("🌐 RMYYDS - HTTP/HTTPS 接口抓包器 (类 Charles)")
        self.win.geometry("1380x840")
        self.win.minsize(1020, 640)
        self.win.configure(bg="#1E1F22")
        self.app._apply_app_icon(self.win)

        self.flow_queue = queue.Queue()
        self.cert_mgr = CertManager()
        self.engine = CharlesProxyEngine(self.flow_queue, self.cert_mgr)

        self.all_flows: list[HttpFlow] = []
        self.filtered_flows: list[HttpFlow] = []
        self.flow_map: dict[int, HttpFlow] = {}
        self.host_counts: dict[str, int] = {}
        self.max_keep_flows: int = 5000  # 内存保护：最大保留5000条抓包记录，超出自动滚动淘汰最旧流
        self.selected_host = "__ALL__"
        self.selected_flow: HttpFlow | None = None
        self.mounted_proxy_serial = ""
        self._after_id = None
        self._is_closing = False

        # 控制变量
        self.port_var = tk.StringVar(value="8888")
        self.mitm_var = tk.BooleanVar(value=True)
        self.auto_adb_proxy_var = tk.BooleanVar(value=True)
        self.pc_proxy_var = tk.BooleanVar(value=True)
        self.filter_text_var = tk.StringVar()
        self.method_filter_var = tk.StringVar(value="全部")
        self.proc_filter_var = tk.StringVar(value="全部来源")
        self.known_processes: set[str] = set()
        self.only_captured_var = tk.BooleanVar(value=False)
        self.hide_static_var = tk.BooleanVar(value=True)
        self.hide_tunnel_var = tk.BooleanVar(value=False)
        self.auto_scroll_var = tk.BooleanVar(value=True)

        self.pc_ip = self._detect_best_pc_ip()
        register_local_pc_ip(self.pc_ip)

        self._setup_treeview_style()
        self._build_ui()

        # 启动防呆自检：如果上次异常强退残留系统代理，自动修复并提示
        fixed, msg = check_and_restore_residual_proxy(default_port=8888)
        if fixed and hasattr(self, "status_label"):
            self.status_label.config(text=f"🛡️ {msg}")
        self._refresh_rules_button_count()
        self.win.protocol("WM_DELETE_WINDOW", self._on_close)
        self._poll_flows()

    def sync_devices_combo(self, devices: list[str]):
        """同步主窗口上的 Android 设备下拉框列表"""
        if hasattr(self, "main_device_combo") and self.main_device_combo.winfo_exists():
            self.main_device_combo["values"] = devices

    def _detect_best_pc_ip(self) -> str:
        """自动探测电脑局域网 IP（优先匹配与当前手机同一网段的网卡 IP）"""
        candidates = []
        try:
            hostname = socket.gethostname()
            for info in socket.getaddrinfo(hostname, None, socket.AF_INET):
                ip = info[4][0]
                if not ip.startswith("127.") and not ip.startswith("169.254."):
                    candidates.append(ip)
        except Exception:
            pass

        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            primary_ip = s.getsockname()[0]
            s.close()
            if primary_ip and primary_ip not in candidates:
                candidates.insert(0, primary_ip)
        except Exception:
            pass

        serial = self.app._get_selected_serial()
        if serial and ":" in serial:
            phone_ip = serial.split(":")[0]
            prefix = ".".join(phone_ip.split(".")[:3]) + "."
            for ip in candidates:
                if ip.startswith(prefix):
                    return ip

        return candidates[0] if candidates else "127.0.0.1"

    def _setup_treeview_style(self):
        style = ttk.Style(self.win)
        style.configure(
            "Charles.Treeview",
            background="#1E1F22",
            foreground="#DFE1E5",
            fieldbackground="#1E1F22",
            rowheight=25,
            font=("Consolas", 9),
            borderwidth=0,
        )
        style.configure(
            "Charles.Treeview.Heading",
            background="#2B2D30",
            foreground="#A9B7C6",
            font=("Microsoft YaHei UI", 9, "bold"),
            relief="flat",
        )
        style.map(
            "Charles.Treeview",
            background=[("selected", "#2E436E")],
            foreground=[("selected", "#FFFFFF")],
        )
        style.configure(
            "TNotebook",
            background="#2B2D30",
            borderwidth=0,
            tabmargins=[2, 2, 2, 0],
        )
        style.configure(
            "TNotebook.Tab",
            background="#2B2D30",
            foreground="#A9B7C6",
            padding=(12, 5),
            font=("Microsoft YaHei UI", 9, "bold"),
            borderwidth=1,
        )
        style.map(
            "TNotebook.Tab",
            background=[("selected", "#3574F0"), ("active", "#393B40")],
            foreground=[("selected", "#FFFFFF"), ("active", "#FFFFFF")],
            expand=[("selected", [1, 1, 1, 0])],
        )

    def _build_ui(self):
        # 1. 顶部控制栏：启动/停止代理、端口、HTTPS 解密开关、ADB 挂载、证书安装、断点规则、以及手机投屏/Logcat入口
        top_bar = ttk.Frame(self.win, padding=(8, 7))
        top_bar.pack(side=tk.TOP, fill=tk.X, padx=6, pady=(6, 2))

        self.btn_toggle = ttk.Button(
            top_bar,
            text="▶ 启动代理抓包",
            style="Primary.TButton",
            command=self.toggle_proxy,
        )
        self.btn_toggle.pack(side=tk.LEFT, padx=(0, 5))

        ttk.Label(top_bar, text="端口:").pack(side=tk.LEFT, padx=(2, 2))
        self.port_entry = tk.Entry(
            top_bar,
            textvariable=self.port_var,
            width=5,
            bg="#1E1F22",
            fg="#DFE1E5",
            insertbackground="#FFFFFF",
            relief=tk.FLAT,
            font=("Consolas", 10),
            highlightthickness=1,
            highlightbackground="#393B40",
        )
        self.port_entry.pack(side=tk.LEFT, padx=(0, 6), ipady=2)

        ttk.Checkbutton(
            top_bar,
            text="🔓 解密HTTPS",
            variable=self.mitm_var,
            command=self._on_mitm_toggled,
        ).pack(side=tk.LEFT, padx=3)

        ttk.Checkbutton(
            top_bar,
            text="💻 抓电脑程序",
            variable=self.pc_proxy_var,
            command=self._on_pc_proxy_toggled,
        ).pack(side=tk.LEFT, padx=3)

        ttk.Checkbutton(
            top_bar,
            text="📱自动挂手机",
            variable=self.auto_adb_proxy_var,
        ).pack(side=tk.LEFT, padx=3)

        ttk.Separator(top_bar, orient=tk.VERTICAL).pack(side=tk.LEFT, fill=tk.Y, padx=6, pady=2)

        ttk.Button(
            top_bar, text="🔗 挂载代理", command=self.mount_adb_proxy
        ).pack(side=tk.LEFT, padx=2)
        ttk.Button(
            top_bar, text="🧹 清除代理", command=self.clear_adb_proxy
        ).pack(side=tk.LEFT, padx=2)
        ttk.Button(
            top_bar, text="📲 安装证书", command=self.open_cert_guide_dialog
        ).pack(side=tk.LEFT, padx=2)

        self.btn_rules = ttk.Button(
            top_bar,
            text="🛑 断点/篡改规则 (0)",
            command=self.open_intercept_manager_dialog,
        )
        self.btn_rules.pack(side=tk.LEFT, padx=2)

        ttk.Button(
            top_bar,
            text="🚀 接口调试",
            style="Primary.TButton",
            command=lambda: self.open_compose_dialog(self.selected_flow),
        ).pack(side=tk.LEFT, padx=2)

        ttk.Button(top_bar, text="🗑 清空", command=self.clear_flows).pack(side=tk.LEFT, padx=2)

        # 右侧：手机设备选择 + WiFi连接 + 手机投屏 + 打开 Logcat 日志窗口
        ttk.Button(
            top_bar,
            text="📜 Logcat日志",
            style="Primary.TButton",
            command=self.app.open_logcat_window,
        ).pack(side=tk.RIGHT, padx=(4, 0))
        ttk.Button(
            top_bar,
            text="📱 手机投屏",
            command=self.app.start_screen_mirror,
        ).pack(side=tk.RIGHT, padx=2)
        ttk.Button(
            top_bar,
            text="📶 WiFi连接",
            command=self.app.open_wifi_adb_dialog,
        ).pack(side=tk.RIGHT, padx=2)
        ttk.Button(
            top_bar,
            text="🔄 刷新设备",
            command=self.app.refresh_devices,
        ).pack(side=tk.RIGHT, padx=2)
        ttk.Button(
            top_bar,
            text="⚡ 重启ADB",
            command=self.app.restart_adb_server,
        ).pack(side=tk.RIGHT, padx=2)
        self.main_device_combo = ttk.Combobox(
            top_bar,
            textvariable=self.app.device_var,
            width=18,
            state="readonly",
        )
        self.main_device_combo.pack(side=tk.RIGHT, padx=2)
        ttk.Label(top_bar, text="设备:").pack(side=tk.RIGHT, padx=(4, 2))

        # 2. 第二栏：过滤栏 + 本机代理地址提示
        filter_bar = ttk.Frame(self.win, padding=(10, 5))
        filter_bar.pack(side=tk.TOP, fill=tk.X, padx=6, pady=2)

        ttk.Label(filter_bar, text="🔍 过滤:").pack(side=tk.LEFT, padx=(0, 4))
        self.filter_entry = tk.Entry(
            filter_bar,
            textvariable=self.filter_text_var,
            width=30,
            bg="#1E1F22",
            fg="#DFE1E5",
            insertbackground="#FFFFFF",
            relief=tk.FLAT,
            font=("Consolas", 10),
            highlightthickness=1,
            highlightbackground="#393B40",
        )
        self.filter_entry.pack(side=tk.LEFT, padx=(0, 8), ipady=2)
        self.filter_text_var.trace_add("write", lambda *_: self.refilter_flows())

        ttk.Label(filter_bar, text="Method:").pack(side=tk.LEFT, padx=(2, 4))
        method_cb = ttk.Combobox(
            filter_bar,
            textvariable=self.method_filter_var,
            values=["全部", "GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"],
            width=7,
            state="readonly",
        )
        method_cb.pack(side=tk.LEFT, padx=(0, 6))
        method_cb.bind("<<ComboboxSelected>>", lambda _e: self.refilter_flows())

        ttk.Label(filter_bar, text="来源/进程:").pack(side=tk.LEFT, padx=(2, 4))
        self.proc_cb = ttk.Combobox(
            filter_bar,
            textvariable=self.proc_filter_var,
            values=["全部来源", "💻 仅看电脑程序", "📱 仅看手机设备"],
            width=18,
            state="readonly",
        )
        self.proc_cb.pack(side=tk.LEFT, padx=(0, 6))
        self.proc_cb.bind("<<ComboboxSelected>>", lambda _e: self.refilter_flows())

        ttk.Checkbutton(
            filter_bar,
            text="🎯 仅看已选抓包域名",
            variable=self.only_captured_var,
            command=self.refilter_flows,
        ).pack(side=tk.LEFT, padx=4)

        ttk.Checkbutton(
            filter_bar,
            text="隐藏图片/静态资源",
            variable=self.hide_static_var,
            command=self.refilter_flows,
        ).pack(side=tk.LEFT, padx=4)

        ttk.Checkbutton(
            filter_bar,
            text="隐藏未解密CONNECT隧道",
            variable=self.hide_tunnel_var,
            command=self.refilter_flows,
        ).pack(side=tk.LEFT, padx=4)

        ttk.Checkbutton(
            filter_bar,
            text="自动滚底",
            variable=self.auto_scroll_var,
        ).pack(side=tk.LEFT, padx=4)

        self.proxy_addr_label = ttk.Label(
            filter_bar,
            text=f"📡 电脑代理地址: {self.pc_ip}:{self.port_var.get()}  |  手机浏览器证书安装地址: http://yyds.ca",
            foreground="#56A8F5",
        )
        self.proxy_addr_label.pack(side=tk.RIGHT, padx=4)

        # 3. 主体分栏：左侧域名树 (Structure) + 右侧上下分栏 (请求表 Sequence + 详情 Inspector)
        outer_paned = tk.PanedWindow(
            self.win, orient=tk.HORIZONTAL, bg="#393B40", sashwidth=4, bd=0
        )
        outer_paned.pack(side=tk.TOP, fill=tk.BOTH, expand=True, padx=6, pady=4)

        # 3.1 左侧域名导航树
        left_frame = ttk.Frame(outer_paned)
        outer_paned.add(left_frame, minsize=230, width=265)

        left_header = ttk.Frame(left_frame, padding=(6, 4))
        left_header.pack(side=tk.TOP, fill=tk.X)
        ttk.Label(
            left_header,
            text="📂 域名结构 (右键选抓包)",
            font=("Microsoft YaHei UI", 9, "bold"),
            foreground="#56A8F5",
        ).pack(side=tk.LEFT)

        left_footer = ttk.Frame(left_frame, padding=(4, 4))
        left_footer.pack(side=tk.BOTTOM, fill=tk.X)
        ttk.Button(
            left_footer,
            text="🎯 抓包/取消选中",
            command=self.toggle_selected_host_capture,
        ).pack(side=tk.LEFT, padx=2, expand=True, fill=tk.X)
        ttk.Button(
            left_footer,
            text="⚙ 抓包目标",
            command=self.open_capture_targets_dialog,
        ).pack(side=tk.LEFT, padx=2)

        host_list_frame = tk.Frame(left_frame, bg="#1E1F22")
        host_list_frame.pack(side=tk.TOP, fill=tk.BOTH, expand=True)

        host_scroll = ttk.Scrollbar(host_list_frame, orient=tk.VERTICAL)
        self.host_listbox = tk.Listbox(
            host_list_frame,
            bg="#1E1F22",
            fg="#DFE1E5",
            selectbackground="#2E436E",
            selectforeground="#FFFFFF",
            font=("Consolas", 9),
            bd=0,
            highlightthickness=0,
            activestyle="none",
            yscrollcommand=host_scroll.set,
        )
        host_scroll.config(command=self.host_listbox.yview)
        host_scroll.pack(side=tk.RIGHT, fill=tk.Y)
        self.host_listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=4, pady=4)
        self.host_listbox.insert(tk.END, "🌐 全部域名 (0)")
        self.host_listbox.selection_set(0)
        self.host_listbox.bind("<<ListboxSelect>>", self._on_host_selected)
        self.host_listbox.bind("<Button-3>", self._on_host_right_click)

        # 3.2 右侧上下分栏
        right_paned = tk.PanedWindow(
            outer_paned, orient=tk.VERTICAL, bg="#393B40", sashwidth=5, bd=0
        )
        outer_paned.add(right_paned, minsize=680)

        # 右上：请求序列 Treeview 表格
        table_frame = tk.Frame(right_paned, bg="#1E1F22")
        right_paned.add(table_frame, minsize=260, height=380)

        cols = ("id", "time", "source", "method", "status", "scheme", "host", "ip", "path", "type", "size", "duration")
        self.tree = ttk.Treeview(
            table_frame,
            columns=cols,
            show="headings",
            style="Charles.Treeview",
            selectmode="browse",
        )
        col_defs = [
            ("id", "#", 50, tk.CENTER),
            ("time", "时间", 88, tk.CENTER),
            ("source", "来源/进程", 130, tk.W),
            ("method", "Method", 64, tk.CENTER),
            ("status", "状态码", 60, tk.CENTER),
            ("scheme", "协议", 56, tk.CENTER),
            ("host", "Host (域名)", 180, tk.W),
            ("ip", "服务器 IP", 118, tk.W),
            ("path", "Path (接口路径与参数)", 320, tk.W),
            ("type", "类型", 64, tk.CENTER),
            ("size", "大小", 74, tk.E),
            ("duration", "耗时", 64, tk.E),
        ]
        for cid, title, width, anchor in col_defs:
            self.tree.heading(cid, text=title)
            self.tree.column(cid, width=width, anchor=anchor, stretch=(cid in ("path", "host")))

        # 状态码颜色标签
        self.tree.tag_configure("s_2xx", foreground="#A9B7C6")
        self.tree.tag_configure("s_2xx_json", foreground="#73C991")
        self.tree.tag_configure("s_3xx", foreground="#56A8F5")
        self.tree.tag_configure("s_4xx", foreground="#D6BF55")
        self.tree.tag_configure("s_5xx", foreground="#FF6B68")
        self.tree.tag_configure("s_tunnel", foreground="#6F737A")

        tree_yscroll = ttk.Scrollbar(table_frame, orient=tk.VERTICAL, command=self.tree.yview)
        tree_xscroll = ttk.Scrollbar(table_frame, orient=tk.HORIZONTAL, command=self.tree.xview)
        self.tree.configure(yscrollcommand=tree_yscroll.set, xscrollcommand=tree_xscroll.set)

        tree_yscroll.pack(side=tk.RIGHT, fill=tk.Y)
        tree_xscroll.pack(side=tk.BOTTOM, fill=tk.X)
        self.tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        self.tree.bind("<<TreeviewSelect>>", self._on_flow_selected)
        self.tree.bind("<Button-3>", self._on_tree_right_click)

        # 右下：详情 Inspector 标签页
        inspector_frame = ttk.Frame(right_paned)
        right_paned.add(inspector_frame, minsize=220)

        insp_bar = ttk.Frame(inspector_frame, padding=(8, 4))
        insp_bar.pack(side=tk.TOP, fill=tk.X)

        # 先 pack 右侧功能按钮，确保无论左侧 URL 多长，右侧按钮永远固定可见不被挤出屏幕
        ttk.Button(insp_bar, text="📋 复制 cURL", command=self.copy_curl).pack(side=tk.RIGHT, padx=2)
        ttk.Button(insp_bar, text="📋 复制响应体", command=self.copy_response_body).pack(
            side=tk.RIGHT, padx=2
        )
        ttk.Button(insp_bar, text="📋 复制完整 URL", command=self.copy_url).pack(
            side=tk.RIGHT, padx=2
        )
        ttk.Button(
            insp_bar,
            text="🔒 加密选中内容",
            command=self.encrypt_selected_text,
        ).pack(side=tk.RIGHT, padx=2)
        ttk.Button(
            insp_bar,
            text="🔓 解密选中内容",
            style="Primary.TButton",
            command=self.decrypt_selected_text,
        ).pack(side=tk.RIGHT, padx=(2, 4))
        ttk.Button(
            insp_bar,
            text="🔍 搜索内容 (Ctrl+F)",
            command=self.open_active_inspector_search,
        ).pack(side=tk.RIGHT, padx=2)

        self.insp_title_label = ttk.Label(
            insp_bar,
            text="📋 点击上方任意一条接口请求查看 Request / Response 详情 (按 Ctrl+F 可在入参/返回内容中搜索)",
            foreground="#56A8F5",
            font=("Microsoft YaHei UI", 9, "bold"),
        )
        self.insp_title_label.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 8))

        self.notebook = ttk.Notebook(inspector_frame)
        self.notebook.pack(side=tk.TOP, fill=tk.BOTH, expand=True, padx=4, pady=2)

        self.txt_resp_body = self._create_inspector_tab("📥 Response Body (响应 JSON/内容)")
        self.txt_req_body = self._create_inspector_tab("📤 Request Params & Body (请求参数)")
        self.txt_headers = self._create_inspector_tab("📋 Headers & 概览 (请求头/响应头)")
        self.txt_curl = self._create_inspector_tab("💻 cURL 命令")

        # 主窗口全局绑定 Ctrl+F，方便随时呼出当前激活详情页的内容搜索框
        self.win.bind("<Control-f>", self._on_main_ctrl_f)
        self.win.bind("<Control-F>", self._on_main_ctrl_f)

        # 4. 底部状态栏
        status_bar = ttk.Frame(self.win, padding=(10, 4))
        status_bar.pack(side=tk.BOTTOM, fill=tk.X)
        self.status_label = ttk.Label(
            status_bar,
            text="💡 就绪：点击左上角「▶ 启动代理抓包」即可开始抓取手机 HTTP/HTTPS 请求（或点击「🚀 接口调试」发送请求）",
            foreground="#8C9099",
        )
        self.status_label.pack(side=tk.LEFT)
        self.count_label = ttk.Label(status_bar, text="总请求: 0 | 当前显示: 0", foreground="#8C9099")
        self.count_label.pack(side=tk.RIGHT)

    def _create_inspector_tab(self, title: str) -> tk.Text:
        frame = tk.Frame(self.notebook, bg="#1E1F22")
        self.notebook.add(frame, text=f"  {title}  ")
        yscroll = ttk.Scrollbar(frame, orient=tk.VERTICAL)
        txt = tk.Text(
            frame,
            bg="#1E1F22",
            fg="#DFE1E5",
            insertbackground="#FFFFFF",
            selectbackground="#2E436E",
            font=("Consolas", 10),
            wrap=tk.WORD,
            bd=0,
            padx=10,
            pady=8,
            yscrollcommand=yscroll.set,
        )
        yscroll.config(command=txt.yview)
        yscroll.pack(side=tk.RIGHT, fill=tk.Y)
        txt.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        self._attach_text_search(txt)
        return txt

    def _attach_text_search(self, txt: tk.Text):
        """为任意 tk.Text 控件挂载 Ctrl+F 浮动内容搜索条（支持高亮全部匹配、上/下一个跳转、区分大小写、Esc 关闭）"""
        parent = txt.master
        txt.tag_configure("find_match", background="#5C4813", foreground="#FFE082")
        txt.tag_configure("find_current", background="#FF9800", foreground="#000000")

        search_bar = tk.Frame(
            parent,
            bg="#2B2D30",
            highlightthickness=1,
            highlightbackground="#3574F0",
            padx=6,
            pady=3,
        )
        search_bar._is_open = False
        matches: list[tuple[str, str]] = []
        cur_idx = -1

        tk.Label(
            search_bar,
            text="🔍",
            bg="#2B2D30",
            fg="#56A8F5",
            font=("Microsoft YaHei UI", 9),
        ).pack(side=tk.LEFT, padx=(0, 3))

        search_var = tk.StringVar()
        ent = tk.Entry(
            search_bar,
            textvariable=search_var,
            width=22,
            bg="#1E1F22",
            fg="#DFE1E5",
            insertbackground="#FFFFFF",
            relief=tk.FLAT,
            font=("Consolas", 9),
            highlightthickness=1,
            highlightbackground="#393B40",
        )
        ent.pack(side=tk.LEFT, padx=2, ipady=2)

        cnt_lbl = tk.Label(
            search_bar,
            text="0/0",
            width=7,
            bg="#2B2D30",
            fg="#8C9099",
            font=("Consolas", 8),
        )
        cnt_lbl.pack(side=tk.LEFT, padx=3)

        case_var = tk.BooleanVar(value=False)

        def _highlight_current():
            txt.tag_remove("find_current", "1.0", tk.END)
            if not matches or cur_idx < 0 or cur_idx >= len(matches):
                return
            s_pos, e_pos = matches[cur_idx]
            txt.tag_add("find_current", s_pos, e_pos)
            txt.tag_raise("find_match")
            txt.tag_raise("find_current")
            txt.see(s_pos)
            cnt_lbl.config(text=f"{cur_idx + 1}/{len(matches)}", fg="#73C991")

        def _do_search(reset_index: bool = True):
            nonlocal matches, cur_idx
            txt.tag_remove("find_match", "1.0", tk.END)
            txt.tag_remove("find_current", "1.0", tk.END)
            matches = []
            kw = search_var.get()
            if not kw:
                cur_idx = -1
                cnt_lbl.config(text="0/0", fg="#8C9099")
                return

            pos = "1.0"
            nocase = 0 if case_var.get() else 1
            count_var = tk.IntVar()
            while True:
                idx = txt.search(kw, pos, stopindex=tk.END, nocase=nocase, count=count_var)
                if not idx:
                    break
                match_len = count_var.get() or len(kw)
                end_idx = f"{idx}+{match_len}c"
                matches.append((idx, end_idx))
                txt.tag_add("find_match", idx, end_idx)
                pos = end_idx
                if len(matches) >= 5000:
                    break

            if not matches:
                cur_idx = -1
                cnt_lbl.config(text="无匹配", fg="#FF6B68")
                return

            if reset_index or cur_idx < 0 or cur_idx >= len(matches):
                cur_idx = 0
            _highlight_current()

        def _next_match(_event=None):
            nonlocal cur_idx
            if not matches:
                _do_search(reset_index=True)
                return "break"
            cur_idx = (cur_idx + 1) % len(matches)
            _highlight_current()
            return "break"

        def _prev_match(_event=None):
            nonlocal cur_idx
            if not matches:
                _do_search(reset_index=True)
                return "break"
            cur_idx = (cur_idx - 1) % len(matches)
            _highlight_current()
            return "break"

        def _close_search(_event=None):
            search_bar._is_open = False
            search_bar.place_forget()
            txt.tag_remove("find_match", "1.0", tk.END)
            txt.tag_remove("find_current", "1.0", tk.END)
            txt.focus_set()
            return "break"

        def _open_search(_event=None):
            search_bar._is_open = True
            search_bar.place(relx=1.0, x=-22, y=6, anchor="ne")
            search_bar.lift()
            try:
                sel = txt.get(tk.SEL_FIRST, tk.SEL_LAST).strip()
                if sel and len(sel) <= 80 and "\n" not in sel:
                    search_var.set(sel)
            except tk.TclError:
                pass
            ent.focus_set()
            ent.selection_range(0, tk.END)
            _do_search(reset_index=True)
            return "break"

        tk.Button(
            search_bar,
            text="▲",
            width=2,
            bg="#393B40",
            fg="#DFE1E5",
            activebackground="#4E5254",
            activeforeground="#FFFFFF",
            relief=tk.FLAT,
            bd=0,
            command=_prev_match,
        ).pack(side=tk.LEFT, padx=1)

        tk.Button(
            search_bar,
            text="▼",
            width=2,
            bg="#393B40",
            fg="#DFE1E5",
            activebackground="#4E5254",
            activeforeground="#FFFFFF",
            relief=tk.FLAT,
            bd=0,
            command=_next_match,
        ).pack(side=tk.LEFT, padx=1)

        tk.Checkbutton(
            search_bar,
            text="Aa",
            variable=case_var,
            bg="#2B2D30",
            fg="#A9B7C6",
            selectcolor="#1E1F22",
            activebackground="#2B2D30",
            activeforeground="#FFFFFF",
            font=("Consolas", 8, "bold"),
            bd=0,
            command=lambda: _do_search(reset_index=True),
        ).pack(side=tk.LEFT, padx=2)

        tk.Button(
            search_bar,
            text="✕",
            width=2,
            bg="#2B2D30",
            fg="#8C9099",
            activebackground="#C75450",
            activeforeground="#FFFFFF",
            relief=tk.FLAT,
            bd=0,
            command=_close_search,
        ).pack(side=tk.LEFT, padx=(2, 0))

        search_var.trace_add("write", lambda *_: _do_search(reset_index=True))
        ent.bind("<Return>", _next_match)
        ent.bind("<Shift-Return>", _prev_match)
        ent.bind("<F3>", _next_match)
        ent.bind("<Shift-F3>", _prev_match)
        ent.bind("<Escape>", _close_search)
        ent.bind("<Control-f>", _open_search)
        ent.bind("<Control-F>", _open_search)

        txt.bind("<Control-f>", _open_search)
        txt.bind("<Control-F>", _open_search)
        txt.bind("<Escape>", lambda e: _close_search(e) if search_bar._is_open else None)
        txt._open_search_bar = _open_search
        txt._refresh_search_bar = lambda: _do_search(reset_index=True) if search_bar._is_open else None

    def open_active_inspector_search(self):
        txt = self._get_active_inspector_text_widget()
        if txt and hasattr(txt, "_open_search_bar"):
            txt._open_search_bar()

    def _on_main_ctrl_f(self, event=None):
        focused = self.win.focus_get()
        if isinstance(focused, tk.Text) and hasattr(focused, "_open_search_bar"):
            return focused._open_search_bar()
        self.open_active_inspector_search()
        return "break"

    # -------------------- 代理启停与 ADB 自动挂载 --------------------

    def toggle_proxy(self):
        if self.engine.running:
            self.stop_proxy()
        else:
            self.start_proxy()

    def start_proxy(self):
        try:
            port = int(self.port_var.get().strip())
            if not (1 <= port <= 65535):
                raise ValueError
        except ValueError:
            messagebox.showwarning("端口无效", "请输入 1 ~ 65535 之间的有效端口号（推荐 8888）", parent=self.win)
            return

        self.pc_ip = self._detect_best_pc_ip()
        register_local_pc_ip(self.pc_ip)
        ok, msg = self.engine.start(port=port, mitm_enabled=self.mitm_var.get())
        if not ok:
            # 若首选端口（如 8888）被企业微信等本机程序临时占用，自动顺延寻找可用端口
            for alt_port in (8899, 8898, 9888, 18888, 8880, 8889):
                if alt_port == port:
                    continue
                ok_alt, msg_alt = self.engine.start(port=alt_port, mitm_enabled=self.mitm_var.get())
                if ok_alt:
                    port = alt_port
                    self.port_var.set(str(alt_port))
                    ok, msg = True, msg_alt
                    break
        if not ok:
            messagebox.showerror(
                "启动代理失败",
                f"无法监听端口 {port}：\n{msg}\n\n请检查该端口是否被其他程序占用，或换个端口（如 9888）。",
                parent=self.win,
            )
            return

        self.btn_toggle.config(text="⏹ 停止代理抓包", style="Danger.TButton")
        self.proxy_addr_label.config(
            text=f"🟢 正在监听: {self.pc_ip}:{port}  |  手机浏览器访问 http://yyds.ca 可下载证书"
        )
        if self.pc_proxy_var.get():
            self.engine.pc_auto_mitm = True
            self._ensure_pc_cert_installed_silently()
            _, info_msg = _set_windows_system_proxy(True, port)
            self.status_label.config(
                text=f"🟢 代理已启动 ({self.pc_ip}:{port}) | 💻 已启用电脑程序透明强抓模式 ({info_msg}) — 支持雷神客户端/微信小程序！"
            )
        else:
            self.engine.pc_auto_mitm = False
            self.status_label.config(text=f"🟢 代理服务已启动 ({self.pc_ip}:{port})，等待手机或电脑请求...")

        if self.auto_adb_proxy_var.get():
            self.mount_adb_proxy(silent_if_no_device=True)

    def stop_proxy(self):
        self.engine.pc_auto_mitm = False
        self.engine.stop()
        if self.pc_proxy_var.get() or _WIN_PROXY_ACTIVE or _GLOBAL_DIVERT.running:
            _set_windows_system_proxy(False)
            self.pc_proxy_var.set(False)
        self.btn_toggle.config(text="▶ 启动代理抓包", style="Primary.TButton")
        self.proxy_addr_label.config(
            text=f"⏹ 代理已停止 ({self.pc_ip}:{self.port_var.get()})"
        )
        if self.mounted_proxy_serial or self.auto_adb_proxy_var.get():
            self.clear_adb_proxy(silent=True)
        self.status_label.config(text="⏹ 已停止代理抓包，并已自动还原电脑与手机网络设置")

    def _on_pc_proxy_toggled(self):
        """切换『💻 抓电脑程序』开关：一键启动 WinDivert 驱动透明劫持 + Windows 系统代理"""
        if self.pc_proxy_var.get():
            self.engine.pc_auto_mitm = True
            self._ensure_pc_cert_installed_silently()
            if not self.engine.running:
                self.start_proxy()
                if not self.engine.running:
                    self.pc_proxy_var.set(False)
                    self.engine.pc_auto_mitm = False
                    return
            else:
                ok, info_msg = _set_windows_system_proxy(True, self.engine.port)
                if not ok:
                    self.pc_proxy_var.set(False)
                    self.engine.pc_auto_mitm = False
                    messagebox.showwarning("开启失败", f"无法开启电脑抓包模式：\n{info_msg}", parent=self.win)
                    return
                self.status_label.config(
                    text=f"💻 已开启『抓电脑程序』强抓模式 ({info_msg})！雷神客户端、微信小程序等直连请求均将自动透明解密并识别 .exe 进程名"
                )
        else:
            self.engine.pc_auto_mitm = False
            _set_windows_system_proxy(False)
            self.status_label.config(text="🧹 已关闭『抓电脑程序』模式，驱动重定向与系统代理已全部还原")

    def _on_mitm_toggled(self):
        self.engine.mitm_enabled = self.mitm_var.get()
        mode_str = "🔓 HTTPS MITM 解密模式" if self.engine.mitm_enabled else "🔒 纯 CONNECT 隧道透传模式"
        self.status_label.config(text=f"已切换为：{mode_str}")

    def _build_adb_exclusion_string(self) -> str:
        items = []
        for r in sorted(self.engine.auto_direct_rules):
            # 若用户明确指定要抓包该域名，则不放入手机直连排除列表
            check_host = r[2:] if r.startswith("*.") else r
            if self.engine.is_target_captured(check_host):
                continue
            if r.startswith("*."):
                base = r[2:]
                if base and base not in items:
                    items.append(base)
                if r not in items:
                    items.append(r)
            else:
                if r not in items:
                    items.append(r)
        return ",".join(items)

    def _sync_adb_exclusion_list(self, serial: str = ""):
        target_serial = serial or self.mounted_proxy_serial or self.app._get_selected_serial()
        if not target_serial:
            return
        excl_str = self._build_adb_exclusion_string()

        def _worker():
            if excl_str:
                self.app._run_adb_cmd(
                    [
                        "-s",
                        target_serial,
                        "shell",
                        "settings",
                        "put",
                        "global",
                        "global_http_proxy_exclusion_list",
                        excl_str,
                    ],
                    timeout=5,
                )
            else:
                self.app._run_adb_cmd(
                    ["-s", target_serial, "shell", "settings", "delete", "global", "global_http_proxy_exclusion_list"],
                    timeout=5,
                )

        threading.Thread(target=_worker, daemon=True).start()

    def mount_adb_proxy(self, silent_if_no_device: bool = False):
        serial = self.app._get_selected_serial()
        if not serial:
            if not silent_if_no_device:
                messagebox.showinfo("提示", "请先在主窗口选择一台已连接的 Android 设备", parent=self.win)
            return

        self.pc_ip = self._detect_best_pc_ip()
        port = self.port_var.get().strip() or "8888"
        proxy_str = f"{self.pc_ip}:{port}"
        excl_str = self._build_adb_exclusion_string()

        def _worker():
            ok, out = self.app._run_adb_cmd(
                ["-s", serial, "shell", "settings", "put", "global", "http_proxy", proxy_str],
                timeout=5,
            )
            if excl_str:
                self.app._run_adb_cmd(
                    [
                        "-s",
                        serial,
                        "shell",
                        "settings",
                        "put",
                        "global",
                        "global_http_proxy_exclusion_list",
                        excl_str,
                    ],
                    timeout=5,
                )
            else:
                self.app._run_adb_cmd(
                    ["-s", serial, "shell", "settings", "delete", "global", "global_http_proxy_exclusion_list"],
                    timeout=5,
                )
            if ok:
                self.mounted_proxy_serial = serial
                c_cnt = len(self.engine.capture_rules)
                c_tip = f"（当前已选 {c_cnt} 个抓包目标域名，在左侧右键域名即可开启抓包解密）"
                self._post_status(
                    f"✅ 已通过 ADB 将手机 [{serial}] 代理指向电脑 {proxy_str} {c_tip}"
                )
            else:
                self._post_status(f"⚠ 自动设置手机代理失败: {out}")

        threading.Thread(target=_worker, daemon=True).start()

    def clear_adb_proxy(self, silent: bool = False):
        # 同时恢复电脑 Windows 系统代理为直连模式
        force_reset_system_proxy()
        serial = self.mounted_proxy_serial or self.app._get_selected_serial()
        if not serial:
            if not silent:
                self._post_status("🧹 已将电脑系统代理重置为直连模式（当前未连接手机）")
            return

        def _worker():
            for cmd in [
                ["-s", serial, "shell", "settings", "put", "global", "http_proxy", ":0"],
                ["-s", serial, "shell", "settings", "delete", "global", "http_proxy"],
                ["-s", serial, "shell", "settings", "delete", "global", "global_http_proxy_host"],
                ["-s", serial, "shell", "settings", "delete", "global", "global_http_proxy_port"],
                ["-s", serial, "shell", "settings", "delete", "global", "global_http_proxy_exclusion_list"],
            ]:
                self.app._run_adb_cmd(cmd, timeout=4)
            self.mounted_proxy_serial = ""
            if not silent:
                self._post_status(f"🧹 已清除手机 [{serial}] 的全局代理设置，手机已恢复直接联网")

        threading.Thread(target=_worker, daemon=True).start()

    def _post_status(self, text: str):
        self.flow_queue.put(("__STATUS__", text))

    # -------------------- 证书推送与安装向导 --------------------

    def open_cert_guide_dialog(self):
        dlg = tk.Toplevel(self.win)
        dlg.title("📲 HTTPS 抓包根证书安装向导 (支持电脑端一键信任 & 手机端推送)")
        dlg.geometry("620x490")
        auto_fit_dialog(dlg)
        dlg.configure(bg="#2B2D30")
        dlg.transient(self.win)
        self.app._apply_app_icon(dlg)

        info = (
            "为什么需要安装证书？\n"
            "• HTTP 明文接口：无需证书，直接抓包即可看到完整参数与返回 JSON。\n"
            "• HTTPS 加密接口：需要在抓包设备上安装一次「RM YYDS Root CA」根证书。\n\n"
            "💻 抓电脑程序 (PC 客户端 / 浏览器 HTTPS 抓包)：\n"
            "  • 直接点击下方「💻 一键安装证书到本机电脑 (自动加入受信任根证书库)」即可完成信任！\n\n"
            "📱 抓手机 App — 方式一：ADB 一键推送证书到手机 Download 目录（推荐）\n"
            "  1. 点击下方「📲 一键推送证书到手机并打开安全设置」按钮\n"
            "  2. 在手机上依次进入：设置 → 安全/更多安全设置 → 加密与凭据 → 从存储设备安装 → CA 证书\n"
            "  3. 在 Download（下载）目录中选择 liuzu_yyds_ca.crt 完成安装\n\n"
            "📱 抓手机 App — 方式二：手机浏览器在线下载安装\n"
            f"  1. 先启动代理抓包并挂载手机代理 ({self.pc_ip}:{self.port_var.get()})\n"
            "  2. 打开手机自带浏览器访问：http://yyds.ca  或  http://chls.pro/ssl 点击下载安装"
        )
        tk.Label(
            dlg,
            text=info,
            bg="#1E1F22",
            fg="#DFE1E5",
            font=("Microsoft YaHei UI", 9),
            justify=tk.LEFT,
            padx=14,
            pady=12,
        ).pack(fill=tk.X, padx=14, pady=(12, 8))

        pc_row = ttk.Frame(dlg)
        pc_row.pack(fill=tk.X, padx=14, pady=(2, 6))
        ttk.Button(
            pc_row,
            text="💻 一键安装证书到本机电脑 (抓电脑程序 HTTPS 必点，自动信任)",
            style="Primary.TButton",
            command=lambda: self._install_cert_on_pc(dlg),
        ).pack(side=tk.LEFT, padx=4, expand=True, fill=tk.X)

        btn_row = ttk.Frame(dlg)
        btn_row.pack(fill=tk.X, padx=14, pady=4)

        ttk.Button(
            btn_row,
            text="📲 一键推送证书到手机并打开手机安全设置",
            command=lambda: self._push_cert_to_phone(dlg),
        ).pack(side=tk.LEFT, padx=4, expand=True, fill=tk.X)

        ttk.Button(
            btn_row,
            text="💾 导出证书到电脑桌面/文件夹",
            command=self._export_cert_to_pc,
        ).pack(side=tk.LEFT, padx=4)

        tk.Label(
            dlg,
            text=f"本机证书路径: {self.cert_mgr.ca_cert_path}",
            bg="#2B2D30",
            fg="#8C9099",
            font=("Consolas", 8),
        ).pack(side=tk.BOTTOM, pady=8)

    def _ensure_pc_cert_installed_silently(self):
        """静默确保本机 Windows 的系统级 (LocalMachine) 与当前用户级 (CurrentUser) 均已信任抓包根证书"""
        if getattr(self, "_pc_cert_ensured", False):
            return
        if not os.path.exists(self.cert_mgr.ca_cert_path):
            return
        self._pc_cert_ensured = True

        def _bg():
            try:
                cflags = 0x08000000 if os.name == "nt" else 0
                subprocess.run(
                    ["certutil", "-user", "-addstore", "Root", self.cert_mgr.ca_cert_path],
                    capture_output=True,
                    timeout=10,
                    creationflags=cflags,
                )
                subprocess.run(
                    ["certutil", "-addstore", "Root", self.cert_mgr.ca_cert_path],
                    capture_output=True,
                    timeout=10,
                    creationflags=cflags,
                )
            except Exception:
                pass

        threading.Thread(target=_bg, daemon=True).start()

    def _install_cert_on_pc(self, parent_win):
        """一键将 CA 根证书导入本机 Windows 系统级与用户级受信任根证书颁发机构"""
        if not os.path.exists(self.cert_mgr.ca_cert_path):
            messagebox.showerror("错误", f"未找到证书文件: {self.cert_mgr.ca_cert_path}", parent=parent_win)
            return

        def _worker():
            try:
                cflags = 0x08000000 if os.name == "nt" else 0
                proc1 = subprocess.run(
                    ["certutil", "-user", "-addstore", "Root", self.cert_mgr.ca_cert_path],
                    capture_output=True,
                    text=True,
                    timeout=15,
                    creationflags=cflags,
                )
                proc2 = subprocess.run(
                    ["certutil", "-addstore", "Root", self.cert_mgr.ca_cert_path],
                    capture_output=True,
                    text=True,
                    timeout=15,
                    creationflags=cflags,
                )
                if proc1.returncode == 0 or proc2.returncode == 0:
                    self._pc_cert_ensured = True
                    self._post_status("✅ 已成功将『RM YYDS Root CA』安装到本机 Windows 系统级与用户级受信任根证书库！")
                    self.win.after(
                        0,
                        lambda: messagebox.showinfo(
                            "电脑证书安装成功",
                            "✅ 已成功将抓包根证书导入本机 Windows「受信任的根证书颁发机构」（系统级 + 用户级）！\n\n"
                            "现在只需勾选主界面顶部的「💻 抓电脑程序」，即可直接抓包解密雷神客户端、微信小程序及任意电脑软件的 HTTPS 接口！",
                            parent=parent_win,
                        ),
                    )
                else:
                    err_msg = (proc1.stdout or "") + "\n" + (proc1.stderr or "")
                    self._post_status(f"⚠ 安装本机证书返回非0状态: {err_msg.strip()}")
            except Exception as e:
                self._post_status(f"❌ 安装本机证书失败: {e}")

        threading.Thread(target=_worker, daemon=True).start()

    def _push_cert_to_phone(self, parent_win):
        serial = self.app._get_selected_serial()
        if not serial:
            messagebox.showinfo("提示", "请先连接一台 Android 手机", parent=parent_win)
            return

        if not os.path.exists(self.cert_mgr.ca_cert_path):
            messagebox.showerror("错误", f"未找到证书文件: {self.cert_mgr.ca_cert_path}", parent=parent_win)
            return

        def _worker():
            remote_path = "/sdcard/Download/liuzu_yyds_ca.crt"
            ok, out = self.app._run_adb_cmd(
                ["-s", serial, "push", self.cert_mgr.ca_cert_path, remote_path],
                timeout=8,
            )
            # 尝试在手机上直接拉起证书安装或安全设置界面
            self.app._run_adb_cmd(
                ["-s", serial, "shell", "am", "start", "-a", "android.settings.SECURITY_SETTINGS"],
                timeout=4,
            )
            if ok:
                self._post_status(f"✅ 已推送证书至手机 {remote_path}，请在手机安全设置中从 Download 目录选择安装")
            else:
                self._post_status(f"❌ 推送证书失败: {out}")

        threading.Thread(target=_worker, daemon=True).start()
        messagebox.showinfo(
            "证书已推送",
            "已将抓包根证书推送到手机：\n"
            "/sdcard/Download/liuzu_yyds_ca.crt\n\n"
            "并已在手机上为您打开「安全设置」，请在手机上点击：\n"
            "「更多安全设置 / 加密与凭据 → 安装证书 → CA 证书」\n"
            "选中 Download 目录下的 liuzu_yyds_ca.crt 即可！",
            parent=parent_win,
        )

    def _export_cert_to_pc(self):
        save_path = filedialog.asksaveasfilename(
            parent=self.win,
            title="导出刘组YYDS Root CA 证书",
            initialfile="liuzu_yyds_ca.crt",
            defaultextension=".crt",
            filetypes=[("CA 证书文件", "*.crt *.cer *.pem")],
        )
        if save_path:
            with open(save_path, "wb") as f:
                f.write(self.cert_mgr.get_ca_pem_bytes())
            self.status_label.config(text=f"💾 已导出根证书至: {save_path}")

    # -------------------- 队列轮询、过滤与视图更新 --------------------

    def _poll_flows(self):
        if self._is_closing or not self.win.winfo_exists():
            return
        try:
            new_flows = []
            while True:
                try:
                    item = self.flow_queue.get_nowait()
                except queue.Empty:
                    break
                if isinstance(item, tuple) and len(item) == 2 and item[0] == "__STATUS__":
                    self.status_label.config(text=item[1])
                elif isinstance(item, tuple) and len(item) == 2 and item[0] == "__AUTO_DIRECT__":
                    self._sync_adb_exclusion_list()
                elif isinstance(item, tuple) and len(item) == 2 and item[0] == "__BREAKPOINT__":
                    self._open_live_breakpoint_dialog(item[1])
                elif isinstance(item, HttpFlow):
                    new_flows.append(item)

            if new_flows:
                host_changed = False
                proc_changed = False
                for flow in new_flows:
                    self.all_flows.append(flow)
                    self.flow_map[flow.flow_id] = flow
                    prev_cnt = self.host_counts.get(flow.host, 0)
                    self.host_counts[flow.host] = prev_cnt + 1
                    host_changed = True
                    if flow.process_name and flow.process_name.startswith("💻 ") and flow.process_name not in self.known_processes:
                        self.known_processes.add(flow.process_name)
                        proc_changed = True
                    if self._matches_flow_filter(flow):
                        self.filtered_flows.append(flow)
                        self._insert_flow_row(flow)

                # 内存保护机制：超出最大保留条数时，滚动淘汰最旧记录，防止长期运行内存无限暴涨
                if len(self.all_flows) > self.max_keep_flows:
                    overflow = len(self.all_flows) - self.max_keep_flows
                    evicted = self.all_flows[:overflow]
                    del self.all_flows[:overflow]
                    for ef in evicted:
                        self.flow_map.pop(ef.flow_id, None)
                        if ef.host in self.host_counts:
                            self.host_counts[ef.host] -= 1
                            if self.host_counts[ef.host] <= 0:
                                self.host_counts.pop(ef.host, None)
                        iid = str(ef.flow_id)
                        if self.tree.exists(iid):
                            self.tree.delete(iid)
                    evicted_ids = {ef.flow_id for ef in evicted}
                    self.filtered_flows = [f for f in self.filtered_flows if f.flow_id not in evicted_ids]
                    host_changed = True

                if proc_changed and hasattr(self, "proc_cb") and self.proc_cb.winfo_exists():
                    self.proc_cb["values"] = [
                        "全部来源",
                        "💻 仅看电脑程序",
                        "📱 仅看手机设备",
                    ] + sorted(self.known_processes)
                if host_changed:
                    self._refresh_host_listbox()
                self._update_counts()
                if self.auto_scroll_var.get() and self.tree.get_children():
                    self.tree.see(self.tree.get_children()[-1])
        except Exception:
            pass
        finally:
            if not self._is_closing and self.win.winfo_exists():
                self._after_id = self.win.after(60, self._poll_flows)

    def _refresh_host_listbox(self):
        cur_sel = self.selected_host
        self.host_listbox.delete(0, tk.END)
        self.host_listbox.insert(tk.END, f"🌐 全部域名 ({len(self.all_flows)})")
        sel_idx = 0

        # 合并已抓取的域名与抓包目标列表中的精确域名，确保已选抓包域名始终在左侧列表置顶可见
        merged_counts = dict(self.host_counts)
        for r in self.engine.capture_rules:
            if r != "*" and not r.startswith("*.") and r not in merged_counts:
                merged_counts[r] = 0

        sorted_hosts = sorted(
            merged_counts.items(),
            key=lambda kv: (0 if self.engine.is_target_captured(kv[0]) else 1, -kv[1], kv[0]),
        )
        for idx, (host, cnt) in enumerate(sorted_hosts, start=1):
            is_cap = self.engine.is_target_captured(host)
            prefix = "🎯" if is_cap else "⚪"
            suffix = " [抓包中]" if is_cap else ""
            self.host_listbox.insert(tk.END, f"{prefix} {host} ({cnt}){suffix}")
            if host == cur_sel:
                sel_idx = idx
        self.host_listbox.selection_set(sel_idx)

    def _extract_host_from_listbox_item(self, text: str) -> str:
        m = re.match(r"^(?:🎯|⚪|🔹|🛡️)\s+(.+?)\s+\(\d+\)(?:\s+\[.*?\])?$", text.strip())
        return m.group(1) if m else ""

    def _on_host_selected(self, _event=None):
        sel = self.host_listbox.curselection()
        if not sel:
            return
        idx = sel[0]
        if idx == 0:
            self.selected_host = "__ALL__"
        else:
            text = self.host_listbox.get(idx)
            host = self._extract_host_from_listbox_item(text)
            self.selected_host = host if host else "__ALL__"
        self.refilter_flows()

    # -------------------- 左侧域名右键选择抓包目标与管理 --------------------

    def add_capture_rule_and_sync(self, rule: str):
        self.engine.add_capture_rule(rule)
        self._refresh_host_listbox()
        self.refilter_flows()
        self._sync_adb_exclusion_list()
        self.status_label.config(text=f"🎯 已加入抓包目标: {rule}（后续该域名的 HTTPS 请求将自动解密展示详情）")

    def remove_capture_rule_and_sync(self, host_or_rule: str):
        self.engine.remove_capture_rule(host_or_rule)
        self._refresh_host_listbox()
        self.refilter_flows()
        self._sync_adb_exclusion_list()
        self.status_label.config(text=f"⏹ 已取消抓包: {host_or_rule}（该域名已恢复直通透传，不拦截 HTTPS 证书）")

    def toggle_selected_host_capture(self):
        if not self.selected_host or self.selected_host == "__ALL__":
            messagebox.showinfo(
                "提示",
                "请先在左侧「📂 域名结构」列表中点击选择一个具体域名（或者直接在域名上点击鼠标右键选择抓包）！",
                parent=self.win,
            )
            return
        host = self.selected_host
        if self.engine.is_target_captured(host):
            self.remove_capture_rule_and_sync(host)
        else:
            self.add_capture_rule_and_sync(host)

    def _on_host_right_click(self, event):
        idx = self.host_listbox.nearest(event.y)
        if idx < 0:
            return
        self.host_listbox.selection_clear(0, tk.END)
        self.host_listbox.selection_set(idx)
        self._on_host_selected()
        if idx == 0:
            menu = tk.Menu(self.win, tearoff=0, bg="#2B2D30", fg="#DFE1E5", activebackground="#2E436E", activeforeground="#FFFFFF")
            menu.add_command(label="⚙ 打开抓包目标域名管理...", command=self.open_capture_targets_dialog)
            menu.tk_popup(event.x_root, event.y_root)
            return
        text = self.host_listbox.get(idx)
        host = self._extract_host_from_listbox_item(text)
        if host:
            self._popup_domain_menu(event, host)

    def _on_tree_right_click(self, event):
        row_id = self.tree.identify_row(event.y)
        if not row_id:
            return
        self.tree.selection_set(row_id)
        self._on_flow_selected()
        flow = self.flow_map.get(int(row_id))
        if flow and flow.host:
            self._popup_flow_menu(event, flow)

    def _popup_flow_menu(self, event, flow: HttpFlow):
        """右侧请求列表右键菜单：支持接口断点、修改请求参数、修改响应体、固定响应码(如500)及域名抓包设置"""
        menu = tk.Menu(
            self.win,
            tearoff=0,
            bg="#2B2D30",
            fg="#DFE1E5",
            activebackground="#2E436E",
            activeforeground="#FFFFFF",
        )
        host = flow.host
        api_path = _clean_api_path(flow.path)
        existing_rule = self.engine.intercept_rules.get(f"{host.lower()}{api_path}")
        has_bp = bool(existing_rule and (existing_rule.breakpoint_req or existing_rule.breakpoint_resp))

        if flow.method != "CONNECT":
            if has_bp:
                menu.add_command(
                    label=f"⏹ 取消此接口断点: {api_path}",
                    command=lambda: self._quick_toggle_breakpoint(flow, enable=False),
                )
            else:
                menu.add_command(
                    label=f"🛑 断点此接口 (拦截请求+响应): {api_path}",
                    command=lambda: self._quick_toggle_breakpoint(flow, enable=True),
                )

            menu.add_command(
                label=f"✏️ 修改请求参数 / 响应体参数 / 断点设置 ({api_path})...",
                command=lambda: self.open_flow_rule_dialog(flow),
            )
            menu.add_command(
                label=f"⚡ 固定此接口返回响应码 -> 500 (Internal Server Error)",
                command=lambda: self._quick_set_fixed_status(flow, 500),
            )
            menu.add_command(
                label=f"⚡ 固定此接口返回响应码 -> 自定义 (401/404/502...)...",
                command=lambda: self.open_flow_rule_dialog(flow, focus_status=True),
            )
            if existing_rule:
                menu.add_command(
                    label=f"🧹 清除此接口的所有断点/篡改规则",
                    command=lambda: self._clear_single_flow_rule(flow),
                )
            menu.add_separator()
            menu.add_command(
                label="🚀 接口调试 (编辑请求并发送)...",
                command=lambda: self.open_compose_dialog(flow),
            )
            menu.add_separator()

        # 域名级抓包开关
        root_dom = _extract_root_domain(host)
        is_cap = self.engine.is_target_captured(host)
        if is_cap:
            menu.add_command(
                label=f"⏹ 取消抓包该域名: {host} (恢复直通不解密)",
                command=lambda: self.remove_capture_rule_and_sync(host),
            )
        else:
            menu.add_command(
                label=f"🎯 抓包此域名 (解密 HTTPS): {host}",
                command=lambda: self.add_capture_rule_and_sync(host),
            )
            if root_dom and root_dom != host:
                menu.add_command(
                    label=f"🎯 抓包整个根域名 (解密 HTTPS): *.{root_dom}",
                    command=lambda: self.add_capture_rule_and_sync(f"*.{root_dom}"),
                )

        menu.add_separator()
        if flow.process_name:
            menu.add_command(
                label=f"💻 仅看此来源/进程: {flow.process_name}",
                command=lambda p=flow.process_name: (self.proc_filter_var.set(p), self.refilter_flows()),
            )
            if self.proc_filter_var.get() != "全部来源":
                menu.add_command(
                    label="🌐 恢复显示全部来源/进程",
                    command=lambda: (self.proc_filter_var.set("全部来源"), self.refilter_flows()),
                )
            menu.add_separator()
        menu.add_command(label="📋 复制完整 URL", command=self.copy_url)
        menu.add_command(
            label="📋 复制域名",
            command=lambda: (self.win.clipboard_clear(), self.win.clipboard_append(host)),
        )
        if flow.server_ip:
            menu.add_command(
                label=f"📋 复制服务器 IP: {flow.server_ip}",
                command=lambda ip=flow.server_ip: (self.win.clipboard_clear(), self.win.clipboard_append(ip)),
            )
        menu.add_command(label="🛑 打开断点/篡改规则管理器...", command=self.open_intercept_manager_dialog)
        menu.tk_popup(event.x_root, event.y_root)

    def _popup_domain_menu(self, event, host: str):
        menu = tk.Menu(
            self.win,
            tearoff=0,
            bg="#2B2D30",
            fg="#DFE1E5",
            activebackground="#2E436E",
            activeforeground="#FFFFFF",
        )
        root_dom = _extract_root_domain(host)
        is_cap = self.engine.is_target_captured(host)

        if is_cap:
            menu.add_command(
                label=f"⏹ 取消抓包该域名: {host} (恢复直通不解密)",
                command=lambda: self.remove_capture_rule_and_sync(host),
            )
        else:
            menu.add_command(
                label=f"🎯 抓包此域名 (解密 HTTPS): {host}",
                command=lambda: self.add_capture_rule_and_sync(host),
            )
            if root_dom and root_dom != host:
                menu.add_command(
                    label=f"🎯 抓包整个根域名 (解密 HTTPS): *.{root_dom}",
                    command=lambda: self.add_capture_rule_and_sync(f"*.{root_dom}"),
                )

        menu.add_separator()
        menu.add_command(
            label="📋 复制域名",
            command=lambda: (self.win.clipboard_clear(), self.win.clipboard_append(host)),
        )
        menu.add_command(label="⚙ 打开抓包目标域名管理...", command=self.open_capture_targets_dialog)
        menu.tk_popup(event.x_root, event.y_root)

    def open_capture_targets_dialog(self):
        dlg = tk.Toplevel(self.win)
        dlg.title("🎯 抓包目标域名管理 (类似 Charles SSL Proxying Include)")
        dlg.geometry("520x430")
        auto_fit_dialog(dlg)
        dlg.configure(bg="#2B2D30")
        dlg.transient(self.win)
        self.app._apply_app_icon(dlg)

        tk.Label(
            dlg,
            text="说明：只有在此列表中的域名才会进行 HTTPS 证书解密抓包；\n未选中的其他域名（如谷歌商店、第三方应用）默认直接透传，互不干扰！\n支持填写具体域名（如 api.example.com）、通配根域名（如 *.example.com）或 *（抓全部）。",
            bg="#2B2D30",
            fg="#A9B7C6",
            font=("Microsoft YaHei UI", 8),
            justify=tk.LEFT,
        ).pack(fill=tk.X, padx=14, pady=(10, 6))

        add_row = ttk.Frame(dlg)
        add_row.pack(fill=tk.X, padx=14, pady=4)
        new_rule_var = tk.StringVar()
        ent = tk.Entry(
            add_row,
            textvariable=new_rule_var,
            bg="#1E1F22",
            fg="#DFE1E5",
            insertbackground="#FFFFFF",
            relief=tk.FLAT,
            font=("Consolas", 10),
            highlightthickness=1,
            highlightbackground="#393B40",
        )
        ent.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 6), ipady=3)

        lb_frame = tk.Frame(dlg, bg="#1E1F22")
        lb_frame.pack(fill=tk.BOTH, expand=True, padx=14, pady=6)
        lb_scroll = ttk.Scrollbar(lb_frame, orient=tk.VERTICAL)
        lb = tk.Listbox(
            lb_frame,
            bg="#1E1F22",
            fg="#DFE1E5",
            selectbackground="#2E436E",
            font=("Consolas", 10),
            bd=0,
            highlightthickness=0,
            yscrollcommand=lb_scroll.set,
        )
        lb_scroll.config(command=lb.yview)
        lb_scroll.pack(side=tk.RIGHT, fill=tk.Y)
        lb.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=6, pady=6)

        def _reload_lb():
            lb.delete(0, tk.END)
            for r in sorted(self.engine.capture_rules):
                lb.insert(tk.END, r)

        def _add_custom():
            val = new_rule_var.get().strip().lower()
            if not val:
                return
            self.add_capture_rule_and_sync(val)
            new_rule_var.set("")
            _reload_lb()

        def _remove_selected():
            sel = lb.curselection()
            if not sel:
                return
            rule = lb.get(sel[0])
            self.engine.remove_capture_rule(rule)
            self._refresh_host_listbox()
            self.refilter_flows()
            self._sync_adb_exclusion_list()
            _reload_lb()
            self.status_label.config(text=f"⏹ 已从抓包白名单移除: {rule}（恢复直通不解密，随时可在左侧右键重新开启）")

        def _clear_all():
            self.engine.capture_rules.clear()
            self.engine.save_capture_rules()
            self._refresh_host_listbox()
            self.refilter_flows()
            self._sync_adb_exclusion_list()
            _reload_lb()
            self.status_label.config(text="🧹 已清空所有抓包目标域名（当前所有 HTTPS 请求均直通不解密）")

        ttk.Button(add_row, text="➕ 添加抓包域名", style="Primary.TButton", command=_add_custom).pack(side=tk.LEFT)
        ent.bind("<Return>", lambda _e: _add_custom())

        btm_row = ttk.Frame(dlg)
        btm_row.pack(fill=tk.X, padx=14, pady=(2, 12))
        ttk.Button(btm_row, text="🗑 移除选中", command=_remove_selected).pack(side=tk.LEFT, padx=2)
        ttk.Button(btm_row, text="🧹 清空全部", command=_clear_all).pack(side=tk.LEFT, padx=2)

        _reload_lb()

    def _matches_flow_filter(self, flow: HttpFlow) -> bool:
        if self.selected_host != "__ALL__" and flow.host != self.selected_host:
            return False

        if self.only_captured_var.get() and not self.engine.is_target_captured(flow.host):
            return False

        m_filter = self.method_filter_var.get()
        if m_filter != "全部" and flow.method != m_filter:
            return False

        p_filter = self.proc_filter_var.get()
        if p_filter == "💻 仅看电脑程序":
            if not (flow.process_name and flow.process_name.startswith("💻")):
                return False
        elif p_filter == "📱 仅看手机设备":
            if not (flow.process_name and flow.process_name.startswith("📱")):
                return False
        elif p_filter and p_filter != "全部来源":
            if flow.process_name != p_filter:
                return False

        if self.hide_tunnel_var.get() and flow.method == "CONNECT":
            return False

        if self.hide_static_var.get():
            lower_path = flow.path.split("?", 1)[0].lower()
            if lower_path.endswith(
                (".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico", ".svg", ".woff", ".woff2", ".ttf", ".css")
            ):
                return False
            if flow.short_type in ("PNG", "JPEG", "GIF", "WEBP", "CSS", "ICO"):
                return False

        q = self.filter_text_var.get().strip().lower()
        if q:
            haystack = f"{flow.full_url} {flow.method} {flow.status_code} {flow.short_type} {flow.server_ip}".lower()
            if q not in haystack:
                # 也支持搜索请求/响应内容中的关键词
                req_preview = flow.req_body_raw[:4096].decode("utf-8", errors="ignore").lower()
                resp_preview = flow.resp_body_raw[:4096].decode("utf-8", errors="ignore").lower()
                if q not in req_preview and q not in resp_preview:
                    return False
        return True

    def refilter_flows(self):
        self.tree.delete(*self.tree.get_children())
        self.filtered_flows = [f for f in self.all_flows if self._matches_flow_filter(f)]
        for flow in self.filtered_flows:
            self._insert_flow_row(flow)
        self._update_counts()

    def _insert_flow_row(self, flow: HttpFlow):
        if flow.method == "CONNECT":
            tag = "s_tunnel" if flow.status_code == 200 else "s_4xx"
        elif 200 <= flow.status_code < 300:
            tag = "s_2xx_json" if flow.short_type == "JSON" else "s_2xx"
        elif 300 <= flow.status_code < 400:
            tag = "s_3xx"
        elif 400 <= flow.status_code < 500:
            tag = "s_4xx"
        else:
            tag = "s_5xx"

        status_disp = str(flow.status_code) if flow.status_code else "-"
        scheme_disp = "HTTPS" if flow.scheme == "https" else ("TUNNEL" if flow.scheme == "tunnel" else "HTTP")
        path_disp = f"[{flow.notes}] {flow.path}" if flow.notes else flow.path
        src_disp = flow.process_name or "-"

        self.tree.insert(
            "",
            tk.END,
            iid=str(flow.flow_id),
            values=(
                flow.flow_id,
                flow.timestamp,
                src_disp,
                flow.method,
                status_disp,
                scheme_disp,
                flow.host,
                flow.server_ip or "-",
                path_disp,
                flow.short_type,
                flow.format_size(),
                f"{flow.duration_ms} ms",
            ),
            tags=(tag,),
        )

    def _update_counts(self):
        self.count_label.config(
            text=f"总请求: {len(self.all_flows):,} 条 | 当前显示: {len(self.filtered_flows):,} 条"
        )

    def _on_flow_selected(self, _event=None):
        sel = self.tree.selection()
        if not sel:
            return
        fid = int(sel[0])
        flow = self.flow_map.get(fid)
        if not flow:
            return
        self.selected_flow = flow
        self._render_flow_detail(flow)

    def _render_flow_detail(self, flow: HttpFlow):
        short_url = flow.full_url if len(flow.full_url) <= 68 else (flow.full_url[:65] + "...")
        self.insp_title_label.config(
            text=f"🔍 [{flow.method}] {short_url}  |  状态: {flow.status_code}  |  {flow.duration_ms} ms  |  {flow.format_size()}"
        )

        # 1. Response Body
        self.txt_resp_body.delete("1.0", tk.END)
        resp_text = flow.get_decoded_body(is_request=False)
        self.txt_resp_body.insert("1.0", resp_text if resp_text else "[响应无 Body 内容]")

        # 2. Request Params & Body
        self.txt_req_body.delete("1.0", tk.END)
        req_parts = []
        parsed = urllib.parse.urlsplit(flow.full_url)
        if parsed.query:
            q_items = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
            q_dict = {k: v for k, v in q_items}
            req_parts.append("🔹 [URL Query 参数]:\n" + json.dumps(q_dict, indent=2, ensure_ascii=False))

        req_body_str = flow.get_decoded_body(is_request=True)
        if req_body_str:
            req_parts.append("🔹 [Request Body 请求体]:\n" + req_body_str)

        self.txt_req_body.insert("1.0", "\n\n".join(req_parts) if req_parts else "[该请求无 Query 参数或 Body 内容]")

        # 3. Headers & 概览
        self.txt_headers.delete("1.0", tk.END)
        h_lines = [
            f"URL:          {flow.full_url}",
            f"Method:       {flow.method}",
            f"Status:       {flow.status_code} {flow.reason}",
            f"Source/Proc:  {flow.process_name or '-'}",
            f"Server IP:    {flow.server_ip or '-'}",
            f"Client Addr:  {flow.client_addr}",
            f"Duration:     {flow.duration_ms} ms",
            f"Response Size:{flow.format_size()}",
        ]
        if flow.error:
            h_lines.append(f"Error:        {flow.error}")
        h_lines.append("\n" + "=" * 32 + " Request Headers " + "=" * 32)
        for k, v in flow.req_headers.items():
            h_lines.append(f"{k}: {v}")
        h_lines.append("\n" + "=" * 32 + " Response Headers " + "=" * 31)
        for k, v in flow.resp_headers.items():
            h_lines.append(f"{k}: {v}")
        self.txt_headers.insert("1.0", "\n".join(h_lines))

        # 4. cURL 命令
        self.txt_curl.delete("1.0", tk.END)
        self.txt_curl.insert("1.0", self._build_curl(flow))

        # 若搜索框正处于打开状态，切换接口后自动刷新高亮匹配
        for t_w in (self.txt_resp_body, self.txt_req_body, self.txt_headers, self.txt_curl):
            if hasattr(t_w, "_refresh_search_bar"):
                t_w._refresh_search_bar()

    def _build_curl(self, flow: HttpFlow) -> str:
        if flow.method == "CONNECT":
            return f"# CONNECT 隧道请求\ncurl -v https://{flow.host}:{flow.port}/"
        parts = [f'curl -X {flow.method} "{flow.full_url}"']
        for k, v in flow.req_headers.items():
            if k.lower() in ("content-length", "host", "connection", "accept-encoding"):
                continue
            safe_v = v.replace('"', '\\"')
            parts.append(f'  -H "{k}: {safe_v}"')
        req_body = flow.get_decoded_body(is_request=True)
        if req_body and not req_body.startswith("[二进制"):
            compact = req_body.replace('"', '\\"').replace("\n", " ")
            parts.append(f'  -d "{compact}"')
        return " \\\n".join(parts)

    # -------------------- 模拟数据、复制与清理 --------------------

    def generate_simulated_flows(self):
        """生成一组贴近真实业务测试场景的 HTTP/HTTPS 接口请求，方便直接体验筛选、树形结构和 JSON 解析"""
        samples = [
            (
                "https",
                "POST",
                "api.liuzu-yyds.com",
                443,
                "/v1/auth/login",
                200,
                "OK",
                "application/json; charset=utf-8",
                {"Content-Type": "application/json", "User-Agent": "okhttp/4.12.0", "X-App-Version": "3.8.2"},
                json.dumps({"phone": "13800138000", "loginType": "sms_code", "code": "8866", "deviceModel": "Xiaomi 15"}, ensure_ascii=False).encode("utf-8"),
                {"Content-Type": "application/json; charset=utf-8", "Server": "nginx/1.24.0"},
                json.dumps({"code": 0, "message": "登录成功", "data": {"uid": 9527, "nickname": "刘组YYDS", "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...", "vipLevel": 9}}, ensure_ascii=False).encode("utf-8"),
                86,
            ),
            (
                "https",
                "GET",
                "api.liuzu-yyds.com",
                443,
                "/v2/home/feed?page=1&pageSize=20&channel=recommend",
                200,
                "OK",
                "application/json; charset=utf-8",
                {"Authorization": "Bearer eyJhbGciOi...", "User-Agent": "okhttp/4.12.0"},
                b"",
                {"Content-Type": "application/json; charset=utf-8"},
                json.dumps({"code": 0, "data": {"hasMore": True, "items": [{"id": 101, "title": "Android 抓包与投屏一体化神器", "likes": 9999}, {"id": 102, "title": "支持 JSON 自动美化与 cURL 一键复制", "likes": 8888}]}}, ensure_ascii=False).encode("utf-8"),
                142,
            ),
            (
                "https",
                "POST",
                "pay.liuzu-yyds.com",
                443,
                "/v1/order/submit",
                500,
                "Internal Server Error",
                "application/json; charset=utf-8",
                {"Content-Type": "application/json", "User-Agent": "okhttp/4.12.0"},
                json.dumps({"skuId": "VIP-YEAR-2026", "couponId": "CPN-99", "payChannel": "wechat"}, ensure_ascii=False).encode("utf-8"),
                {"Content-Type": "application/json; charset=utf-8"},
                json.dumps({"code": 50012, "message": "库存扣减超时：优惠券 CPN-99 已过期", "traceId": "tr-20261031-ab91ef"}, ensure_ascii=False).encode("utf-8"),
                523,
            ),
            (
                "http",
                "GET",
                "cfg.liuzu-yyds.com",
                80,
                "/app/abtest/config?platform=android&env=staging",
                200,
                "OK",
                "application/json",
                {"User-Agent": "Dalvik/2.1.0 (Linux; U; Android 15)"},
                b"",
                {"Content-Type": "application/json"},
                json.dumps({"code": 0, "abFlags": {"new_checkout_ui": True, "max_retry": 3}}, ensure_ascii=False).encode("utf-8"),
                38,
            ),
            (
                "https",
                "POST",
                "api.liuzu-yyds.com",
                443,
                "/v1/sdk/lines_encrypted",
                200,
                "OK",
                "text/plain; charset=utf-8",
                {"Content-Type": "application/json", "User-Agent": "okhttp/4.12.0"},
                b'{"app_area_id":2}',
                {"Content-Type": "text/plain; charset=utf-8"},
                b"tQEEvROwPjM8Z5CAGkv1OF5zvkWrWmUIbtudda9xz14JKuVZKF34s2PLLJR7RmjQx9pbweVXM+V0iPzRzKuslrBkkk9R13rhGK8OITsAP4dQ/97ewjYkAhIirkX0QQhCZ+9L1nNOfNe1kBPmXD6TUgjBIqCgKKyr73FKccusAURwXI49SAGBiBsPBxBQKgXXRd/KSqZNvB0CFMQOnibU3xAxTAWFUK+kMvdgqyc2+XsBs/oKImP1TwnNNfyfBJKjrhFT0j14J6fQi1rxazNfozOK6NX9LsNsjQ6BJ9ooYR2ONKRjeS9NvhGZoWigBPUJHGGj5byW/JdaqXVL30a6ER/F3+gvrWssQma8xJq5jybE0A8qINXx0IWzIJ8yV68kfEIGSTL48+bpYys96wBQzmoduUc1/EqztfeFlSznZe2Pjx1FEuopM4vZz3tKBYnZuUOEUgKsQN/tqAGbO+yNVd3SP0Df3JLbbMAJLxDnJ/NoTxHvA+P5PaNsVaZlJRjwGyFSBUCt8eTetC2wO8OQH20QjUrruFUw9PYMxCkumdCvt77BscBfwR6T3MlQpFQMjAQ4UbePGQpC1HBoiRbf/uHGBmgczJN0EgNA",
                64,
            ),
        ]

        self.engine.add_capture_rule("*.liuzu-yyds.com")
        sample_procs = [
            ("💻 leigod.exe", "127.0.0.1:54321"),
            ("📱 手机 (10.1.111.206)", "10.1.111.206:54322"),
            ("💻 leigod.exe", "127.0.0.1:54323"),
            ("📱 手机 (10.1.111.206)", "10.1.111.206:54324"),
            ("💻 leigod.exe", "127.0.0.1:54325"),
        ]
        for idx, (scheme, method, host, port, path, status, reason, ct, req_h, req_b, resp_h, resp_b, dur) in enumerate(samples):
            proc_label, c_addr = sample_procs[idx % len(sample_procs)]
            f = HttpFlow(self.engine.next_flow_id(), scheme, method, host, port, path, c_addr)
            f.process_name = proc_label
            f.req_headers = req_h
            f.req_body_raw = req_b
            f.status_code = status
            f.reason = reason
            f.resp_headers = resp_h
            f.resp_body_raw = resp_b
            f.content_type = ct
            f.size_bytes = len(resp_b)
            f.duration_ms = dur
            self.flow_queue.put(f)

        self.status_label.config(text="🧪 已生成 5 条模拟接口数据（第 5 条含加密 Payload，选中密文后点击『🔓 解密选中内容』即可直接解密）")

    # -------------------- 内置选中密文一键解密 / 加密 --------------------

    def _get_active_inspector_text_widget(self) -> tk.Text:
        try:
            idx = self.notebook.index(self.notebook.select())
            return [self.txt_resp_body, self.txt_req_body, self.txt_headers, self.txt_curl][idx]
        except Exception:
            return self.txt_resp_body

    def _decrypt_in_text_widget(self, target_txt: tk.Text = None, parent_win=None):
        """将指定 Text 控件中鼠标选中的密文直接解密并替换（若未选中则自动尝试解密全文）"""
        win_ref = parent_win or self.win
        # 1. 优先检查焦点所在的 Text 控件是否有选中内容
        txt = target_txt
        if txt is None:
            focused = self.win.focus_get()
            if isinstance(focused, tk.Text):
                txt = focused
            else:
                txt = self._get_active_inspector_text_widget()

        sel_text = ""
        has_sel = False
        for candidate in ([txt] if target_txt else [txt, self.txt_resp_body, self.txt_req_body, self.txt_headers]):
            try:
                sel_text = candidate.get(tk.SEL_FIRST, tk.SEL_LAST)
                if sel_text and sel_text.strip():
                    txt = candidate
                    has_sel = True
                    break
            except tk.TclError:
                continue

        if not has_sel:
            # 若用户没有用鼠标框选，则自动读取当前文本框内容尝试解密
            full_content = txt.get("1.0", tk.END).strip()
            if not full_content or full_content.startswith("["):
                messagebox.showinfo(
                    "提示",
                    "请先在下方文本框中用鼠标选中要解密的 Base64 密文字符串，再点击「🔓 解密选中内容」！",
                    parent=win_ref,
                )
                return
            sel_text = full_content

        try:
            decrypted = decrypt_leigod_payload(sel_text, pretty_json=True)
        except Exception as e:
            # 如果用户选中的是完整 JSON 对象（如 {"code":0,"data":"tQEE..."}），尝试自动寻找里面的密文字段解密
            replaced_any = False
            try:
                obj = json.loads(sel_text)
                if isinstance(obj, dict):
                    for k, v in list(obj.items()):
                        if isinstance(v, str) and len(v) > 16:
                            try:
                                dec_sub = decrypt_leigod_payload(v, pretty_json=False)
                                try:
                                    obj[k] = json.loads(dec_sub)
                                except Exception:
                                    obj[k] = dec_sub
                                replaced_any = True
                            except Exception:
                                pass
                if replaced_any:
                    decrypted = json.dumps(obj, ensure_ascii=False, indent=2)
                else:
                    raise e
            except Exception:
                messagebox.showwarning(
                    "解密失败",
                    f"未能解密所选内容：\n{e}\n\n💡 提示：请用鼠标精确选中加密的 Base64 字符串（如 tQEE...）后再点击解密。",
                    parent=win_ref,
                )
                return

        if has_sel:
            txt.delete(tk.SEL_FIRST, tk.SEL_LAST)
            txt.insert(tk.INSERT, decrypted)
        else:
            txt.delete("1.0", tk.END)
            txt.insert("1.0", decrypted)

        self.win.clipboard_clear()
        self.win.clipboard_append(decrypted)
        self.status_label.config(text="🔓 已成功解密选中内容为明文 JSON！（已原地替换显示并自动复制到剪贴板）")

    def _encrypt_in_text_widget(self, target_txt: tk.Text = None, parent_win=None):
        """将指定 Text 控件中选中的明文 JSON/文本加密为 Base64(RC4+zlib) 密文"""
        win_ref = parent_win or self.win
        txt = target_txt
        if txt is None:
            focused = self.win.focus_get()
            if isinstance(focused, tk.Text):
                txt = focused
            else:
                txt = self._get_active_inspector_text_widget()

        sel_text = ""
        has_sel = False
        for candidate in ([txt] if target_txt else [txt, self.txt_resp_body, self.txt_req_body]):
            try:
                sel_text = candidate.get(tk.SEL_FIRST, tk.SEL_LAST)
                if sel_text and sel_text.strip():
                    txt = candidate
                    has_sel = True
                    break
            except tk.TclError:
                continue

        if not has_sel:
            sel_text = txt.get("1.0", tk.END).strip()
            if not sel_text or sel_text.startswith("["):
                messagebox.showinfo(
                    "提示",
                    "请先在文本框中选中要加密的明文 JSON/内容，再点击「🔒 加密选中内容」！",
                    parent=win_ref,
                )
                return

        try:
            encrypted = encrypt_leigod_payload(sel_text)
        except Exception as e:
            messagebox.showwarning("加密失败", f"加密出错：\n{e}", parent=win_ref)
            return

        if has_sel:
            txt.delete(tk.SEL_FIRST, tk.SEL_LAST)
            txt.insert(tk.INSERT, encrypted)
        else:
            txt.delete("1.0", tk.END)
            txt.insert("1.0", encrypted)

        self.win.clipboard_clear()
        self.win.clipboard_append(encrypted)
        self.status_label.config(text="🔒 已将选中内容加密为 Base64 密文！（已原地替换并复制到剪贴板）")

    def decrypt_selected_text(self):
        self._decrypt_in_text_widget()

    def encrypt_selected_text(self):
        self._encrypt_in_text_widget()

    # -------------------- 断点、修改请求参数、修改响应体、固定响应码 (eg: 500) --------------------

    def _refresh_rules_button_count(self):
        if hasattr(self, "btn_rules") and self.btn_rules.winfo_exists():
            cnt = sum(1 for r in self.engine.intercept_rules.values() if r.enabled)
            self.btn_rules.config(text=f"🛑 断点/篡改规则 ({cnt})")

    def _quick_toggle_breakpoint(self, flow: HttpFlow, enable: bool):
        api_path = _clean_api_path(flow.path)
        key = f"{flow.host.lower()}{api_path}"
        rule = self.engine.intercept_rules.get(key) or InterceptRule(host=flow.host, path=api_path)
        rule.enabled = True
        rule.breakpoint_req = enable
        rule.breakpoint_resp = enable
        self.engine.set_intercept_rule(rule)
        self._refresh_host_listbox()
        self._refresh_rules_button_count()
        if enable:
            self.status_label.config(
                text=f"🛑 已对接口 [{flow.host}{api_path}] 开启实时断点！客户端 (电脑/手机) 下次触发该接口时将自动暂停并弹出修改窗口"
            )
        else:
            self.status_label.config(text=f"⏹ 已取消接口 [{flow.host}{api_path}] 的实时断点")

    def _quick_set_fixed_status(self, flow: HttpFlow, code: int = 500):
        api_path = _clean_api_path(flow.path)
        key = f"{flow.host.lower()}{api_path}"
        rule = self.engine.intercept_rules.get(key) or InterceptRule(host=flow.host, path=api_path)
        rule.enabled = True
        rule.fixed_status_enabled = True
        rule.fixed_status_code = code
        self.engine.set_intercept_rule(rule)
        self._refresh_host_listbox()
        self._refresh_rules_button_count()
        self.status_label.config(
            text=f"⚡ 已固定接口 [{flow.host}{api_path}] 返回状态码为 {code}！后续该接口将始终返回 HTTP {code}"
        )

    def _clear_single_flow_rule(self, flow: HttpFlow):
        api_path = _clean_api_path(flow.path)
        key = f"{flow.host.lower()}{api_path}"
        self.engine.remove_intercept_rule(key)
        self._refresh_rules_button_count()
        self.status_label.config(text=f"🧹 已清除接口 [{flow.host}{api_path}] 的所有断点与篡改规则")

    def open_flow_rule_dialog(self, flow: HttpFlow, focus_status: bool = False):
        """打开针对某条接口的可视化配置窗口：支持断点开关、固定返回响应码(如500)、修改请求参数、修改响应体参数"""
        api_path = _clean_api_path(flow.path)
        key = f"{flow.host.lower()}{api_path}"
        existing = self.engine.intercept_rules.get(key)

        parsed_u = urllib.parse.urlsplit(flow.full_url)
        orig_query = parsed_u.query
        orig_req_body = flow.get_decoded_body(is_request=True)
        orig_resp_body = flow.get_decoded_body(is_request=False)

        dlg = tk.Toplevel(self.win)
        dlg.title(f"🛠️ 接口断点与参数篡改配置 — {flow.host}{api_path}")
        dlg.geometry("780x680")
        auto_fit_dialog(dlg)
        dlg.configure(bg="#2B2D30")
        dlg.transient(self.win)
        self.app._apply_app_icon(dlg)

        # 顶部接口路径提示
        hdr = tk.Frame(dlg, bg="#1E1F22", padx=12, pady=8)
        hdr.pack(fill=tk.X, padx=12, pady=(10, 6))
        tk.Label(
            hdr,
            text=f"🎯 目标接口: [{flow.method}] {flow.scheme}://{flow.host}{api_path}",
            bg="#1E1F22",
            fg="#56A8F5",
            font=("Consolas", 10, "bold"),
            anchor="w",
        ).pack(fill=tk.X)

        # 1. 断点设置与固定状态码区
        sec_top = tk.LabelFrame(
            dlg,
            text=" 🛑 1. 实时断点拦截 & ⚡ 固定返回响应状态码 (eg: 500) ",
            bg="#2B2D30",
            fg="#73C991",
            font=("Microsoft YaHei UI", 9, "bold"),
            padx=10,
            pady=8,
        )
        sec_top.pack(fill=tk.X, padx=12, pady=4)

        bp_req_var = tk.BooleanVar(value=existing.breakpoint_req if existing else False)
        bp_resp_var = tk.BooleanVar(value=existing.breakpoint_resp if existing else False)
        fix_status_var = tk.BooleanVar(value=existing.fixed_status_enabled if existing else focus_status)
        status_code_var = tk.StringVar(value=str(existing.fixed_status_code if existing else 500))
        mock_direct_var = tk.BooleanVar(value=existing.mock_direct if existing else False)

        r_bp = ttk.Frame(sec_top)
        r_bp.pack(fill=tk.X, pady=(0, 6))
        ttk.Checkbutton(
            r_bp,
            text="🛑 断点拦截请求 (发出前暂停弹窗改请求参数)",
            variable=bp_req_var,
        ).pack(side=tk.LEFT, padx=(0, 16))
        ttk.Checkbutton(
            r_bp,
            text="🛑 断点拦截响应 (返回前暂停弹窗改状态码/响应体)",
            variable=bp_resp_var,
        ).pack(side=tk.LEFT)

        r_st = ttk.Frame(sec_top)
        r_st.pack(fill=tk.X)
        ttk.Checkbutton(
            r_st,
            text="⚡ 固定接口返回响应码:",
            variable=fix_status_var,
        ).pack(side=tk.LEFT, padx=(0, 6))
        st_cb = ttk.Combobox(
            r_st,
            textvariable=status_code_var,
            values=["500", "502", "503", "504", "400", "401", "403", "404", "429", "200"],
            width=7,
        )
        st_cb.pack(side=tk.LEFT, padx=(0, 8))
        for quick_code in (500, 404, 401, 200):
            ttk.Button(
                r_st,
                text=f"设 {quick_code}",
                command=lambda c=quick_code: (fix_status_var.set(True), status_code_var.set(str(c))),
            ).pack(side=tk.LEFT, padx=2)
        ttk.Checkbutton(
            r_st,
            text="直接本地 Mock 返回(不请求真实后端)",
            variable=mock_direct_var,
        ).pack(side=tk.RIGHT, padx=4)

        # 2. 修改请求参数区 (Query & Body)
        sec_req = tk.LabelFrame(
            dlg,
            text=" 📤 2. 固定修改请求参数 (Request Query & Body) ",
            bg="#2B2D30",
            fg="#D6BF55",
            font=("Microsoft YaHei UI", 9, "bold"),
            padx=10,
            pady=6,
        )
        sec_req.pack(fill=tk.BOTH, expand=True, padx=12, pady=4)

        mod_req_var = tk.BooleanVar(value=existing.modify_req_enabled if existing else False)
        req_top = ttk.Frame(sec_req)
        req_top.pack(fill=tk.X, pady=(0, 4))
        ttk.Checkbutton(
            req_top,
            text="启用固定替换请求参数 (自动用下方填写的参数覆盖电脑/手机发出的请求)",
            variable=mod_req_var,
        ).pack(side=tk.LEFT)
        ttk.Button(
            req_top,
            text="🔒 加密选中",
            command=lambda: self._encrypt_in_text_widget(txt_req_edit, dlg),
        ).pack(side=tk.RIGHT, padx=2)
        ttk.Button(
            req_top,
            text="🔓 解密选中",
            command=lambda: self._decrypt_in_text_widget(txt_req_edit, dlg),
        ).pack(side=tk.RIGHT, padx=2)

        q_row = ttk.Frame(sec_req)
        q_row.pack(fill=tk.X, pady=2)
        ttk.Label(q_row, text="URL Query 参数:").pack(side=tk.LEFT, padx=(0, 6))
        query_var = tk.StringVar(value=existing.fixed_query if (existing and existing.fixed_query) else orig_query)
        tk.Entry(
            q_row,
            textvariable=query_var,
            bg="#1E1F22",
            fg="#DFE1E5",
            insertbackground="#FFFFFF",
            relief=tk.FLAT,
            font=("Consolas", 9),
        ).pack(side=tk.LEFT, fill=tk.X, expand=True, ipady=2)

        txt_req_edit = tk.Text(
            sec_req,
            height=5,
            bg="#1E1F22",
            fg="#DFE1E5",
            insertbackground="#FFFFFF",
            selectbackground="#2E436E",
            font=("Consolas", 9),
            bd=0,
            padx=8,
            pady=6,
        )
        txt_req_edit.pack(fill=tk.BOTH, expand=True, pady=(4, 2))
        txt_req_edit.insert(
            "1.0",
            existing.fixed_req_body if (existing and existing.fixed_req_body) else orig_req_body,
        )
        self._attach_text_search(txt_req_edit)

        # 3. 修改响应体参数区 (Response Body)
        sec_resp = tk.LabelFrame(
            dlg,
            text=" 📥 3. 固定修改响应体参数 (Response Body JSON / 密文) ",
            bg="#2B2D30",
            fg="#56A8F5",
            font=("Microsoft YaHei UI", 9, "bold"),
            padx=10,
            pady=6,
        )
        sec_resp.pack(fill=tk.BOTH, expand=True, padx=12, pady=4)

        mod_resp_var = tk.BooleanVar(value=existing.modify_resp_enabled if existing else False)
        resp_top = ttk.Frame(sec_resp)
        resp_top.pack(fill=tk.X, pady=(0, 4))
        ttk.Checkbutton(
            resp_top,
            text="启用固定替换响应体 (自动将下方内容返回给电脑程序/手机 App)",
            variable=mod_resp_var,
        ).pack(side=tk.LEFT)
        ttk.Button(
            resp_top,
            text="🔒 加密回密文",
            command=lambda: self._encrypt_in_text_widget(txt_resp_edit, dlg),
        ).pack(side=tk.RIGHT, padx=2)
        ttk.Button(
            resp_top,
            text="🔓 解密选中/全文",
            style="Primary.TButton",
            command=lambda: self._decrypt_in_text_widget(txt_resp_edit, dlg),
        ).pack(side=tk.RIGHT, padx=2)

        txt_resp_edit = tk.Text(
            sec_resp,
            height=8,
            bg="#1E1F22",
            fg="#DFE1E5",
            insertbackground="#FFFFFF",
            selectbackground="#2E436E",
            font=("Consolas", 9),
            bd=0,
            padx=8,
            pady=6,
        )
        txt_resp_edit.pack(fill=tk.BOTH, expand=True, pady=(2, 2))
        txt_resp_edit.insert(
            "1.0",
            existing.fixed_resp_body if (existing and existing.fixed_resp_body) else orig_resp_body,
        )
        self._attach_text_search(txt_resp_edit)

        # 底部保存/取消按钮
        btm = ttk.Frame(dlg)
        btm.pack(fill=tk.X, padx=12, pady=(6, 12))

        def _save_rule():
            try:
                s_code = int(status_code_var.get().strip() or "500")
            except ValueError:
                s_code = 500
            new_rule = InterceptRule(
                host=flow.host,
                path=api_path,
                enabled=True,
                breakpoint_req=bp_req_var.get(),
                breakpoint_resp=bp_resp_var.get(),
                modify_req_enabled=mod_req_var.get(),
                fixed_query=query_var.get().strip(),
                fixed_req_body=txt_req_edit.get("1.0", tk.END).strip(),
                fixed_status_enabled=fix_status_var.get(),
                fixed_status_code=s_code,
                modify_resp_enabled=mod_resp_var.get(),
                fixed_resp_body=txt_resp_edit.get("1.0", tk.END).strip(),
                mock_direct=mock_direct_var.get(),
            )
            self.engine.set_intercept_rule(new_rule)
            self._refresh_host_listbox()
            self._refresh_rules_button_count()
            self.status_label.config(
                text=f"✅ 已保存接口规则 [{new_rule.key}]：{new_rule.summary_tags()}"
            )
            dlg.destroy()

        ttk.Button(
            btm,
            text="💾 保存并立即生效",
            style="Primary.TButton",
            command=_save_rule,
        ).pack(side=tk.RIGHT, padx=4)
        ttk.Button(btm, text="取消", command=dlg.destroy).pack(side=tk.RIGHT, padx=4)

    def _open_live_breakpoint_dialog(self, bp: BreakpointSession):
        """当命中接口实时断点时自动弹出的拦截修改器窗口"""
        dlg = tk.Toplevel(self.win)
        stage_cn = "📤 请求阶段 (发往后端前)" if bp.stage == "request" else "📥 响应阶段 (发回客户端前)"
        dlg.title(f"🛑 断点实时拦截中 — {stage_cn} — {bp.host}{bp.path}")
        dlg.geometry("760x580")
        auto_fit_dialog(dlg)
        dlg.configure(bg="#2B2D30")
        dlg.transient(self.win)
        self.app._apply_app_icon(dlg)
        dlg.lift()
        dlg.focus_force()

        banner = tk.Frame(dlg, bg="#7A1C1C", padx=12, pady=8)
        banner.pack(fill=tk.X, padx=12, pady=(10, 6))
        tk.Label(
            banner,
            text=f"🛑 接口已挂起等待您修改：{bp.method} {bp.scheme}://{bp.host}{bp.path}",
            bg="#7A1C1C",
            fg="#FFFFFF",
            font=("Microsoft YaHei UI", 10, "bold"),
            anchor="w",
        ).pack(fill=tk.X)

        if bp.stage == "request":
            row1 = ttk.Frame(dlg)
            row1.pack(fill=tk.X, padx=12, pady=4)
            ttk.Label(row1, text="Method:").pack(side=tk.LEFT, padx=(0, 4))
            m_var = tk.StringVar(value=bp.method)
            ttk.Combobox(
                row1,
                textvariable=m_var,
                values=["GET", "POST", "PUT", "DELETE", "PATCH"],
                width=8,
            ).pack(side=tk.LEFT, padx=(0, 10))

            ttk.Label(row1, text="Path & Query 参数:").pack(side=tk.LEFT, padx=(0, 4))
            p_var = tk.StringVar(value=bp.path)
            tk.Entry(
                row1,
                textvariable=p_var,
                bg="#1E1F22",
                fg="#DFE1E5",
                insertbackground="#FFFFFF",
                relief=tk.FLAT,
                font=("Consolas", 10),
            ).pack(side=tk.LEFT, fill=tk.X, expand=True, ipady=3)

            bar_edit = ttk.Frame(dlg)
            bar_edit.pack(fill=tk.X, padx=12, pady=(6, 2))
            ttk.Label(
                bar_edit,
                text="✏️ 修改 Request Body (请求参数 JSON / 表单):",
                foreground="#D6BF55",
                font=("Microsoft YaHei UI", 9, "bold"),
            ).pack(side=tk.LEFT)
            ttk.Button(
                bar_edit,
                text="🔒 加密回密文",
                command=lambda: self._encrypt_in_text_widget(txt_body, dlg),
            ).pack(side=tk.RIGHT, padx=2)
            ttk.Button(
                bar_edit,
                text="🔓 解密选中/全文",
                style="Primary.TButton",
                command=lambda: self._decrypt_in_text_widget(txt_body, dlg),
            ).pack(side=tk.RIGHT, padx=2)

            txt_body = tk.Text(
                dlg,
                bg="#1E1F22",
                fg="#DFE1E5",
                insertbackground="#FFFFFF",
                selectbackground="#2E436E",
                font=("Consolas", 10),
                bd=0,
                padx=10,
                pady=8,
            )
            txt_body.pack(fill=tk.BOTH, expand=True, padx=12, pady=4)
            txt_body.insert("1.0", bp.req_body_text)

            btm = ttk.Frame(dlg)
            btm.pack(fill=tk.X, padx=12, pady=(6, 12))

            def _resume_req(abort_500: bool = False):
                bp.method = m_var.get().strip().upper() or bp.method
                bp.path = p_var.get().strip() or bp.path
                bp.req_body_text = txt_body.get("1.0", tk.END).strip()
                bp.abort_with_500 = abort_500
                bp.event.set()
                dlg.destroy()

            ttk.Button(
                btm,
                text="▶ 继续发送修改后的请求 (Execute)",
                style="Primary.TButton",
                command=lambda: _resume_req(False),
            ).pack(side=tk.RIGHT, padx=4)
            ttk.Button(
                btm,
                text="⚡ 不发后端，直接给客户端返回 500 错误",
                style="Danger.TButton",
                command=lambda: _resume_req(True),
            ).pack(side=tk.RIGHT, padx=4)
            dlg.protocol("WM_DELETE_WINDOW", lambda: _resume_req(False))

        else:
            # 响应阶段断点
            row_st = ttk.Frame(dlg)
            row_st.pack(fill=tk.X, padx=12, pady=6)
            ttk.Label(
                row_st,
                text="⚡ 返回响应状态码 (Status Code):",
                font=("Microsoft YaHei UI", 9, "bold"),
            ).pack(side=tk.LEFT, padx=(0, 6))
            st_var = tk.StringVar(value=str(bp.status_code))
            tk.Entry(
                row_st,
                textvariable=st_var,
                width=8,
                bg="#1E1F22",
                fg="#73C991",
                insertbackground="#FFFFFF",
                relief=tk.FLAT,
                font=("Consolas", 11, "bold"),
            ).pack(side=tk.LEFT, padx=(0, 8), ipady=2)

            for c_val in (500, 502, 404, 401, 403, 200):
                ttk.Button(
                    row_st,
                    text=f"设为 {c_val}",
                    command=lambda c=c_val: st_var.set(str(c)),
                ).pack(side=tk.LEFT, padx=2)

            bar_edit = ttk.Frame(dlg)
            bar_edit.pack(fill=tk.X, padx=12, pady=(6, 2))
            ttk.Label(
                bar_edit,
                text="✏️ 修改 Response Body (若为加密串可先点『🔓 解密』→ 改 JSON → 再点『🔒 加密回密文』):",
                foreground="#56A8F5",
                font=("Microsoft YaHei UI", 9, "bold"),
            ).pack(side=tk.LEFT)
            ttk.Button(
                bar_edit,
                text="🔒 加密回密文",
                command=lambda: self._encrypt_in_text_widget(txt_body, dlg),
            ).pack(side=tk.RIGHT, padx=2)
            ttk.Button(
                bar_edit,
                text="🔓 解密选中/全文",
                style="Primary.TButton",
                command=lambda: self._decrypt_in_text_widget(txt_body, dlg),
            ).pack(side=tk.RIGHT, padx=2)

            txt_body = tk.Text(
                dlg,
                bg="#1E1F22",
                fg="#DFE1E5",
                insertbackground="#FFFFFF",
                selectbackground="#2E436E",
                font=("Consolas", 10),
                bd=0,
                padx=10,
                pady=8,
            )
            txt_body.pack(fill=tk.BOTH, expand=True, padx=12, pady=4)
            txt_body.insert("1.0", bp.resp_body_text)

            btm = ttk.Frame(dlg)
            btm.pack(fill=tk.X, padx=12, pady=(6, 12))

            def _resume_resp():
                try:
                    bp.status_code = int(st_var.get().strip() or "200")
                except ValueError:
                    pass
                bp.resp_body_text = txt_body.get("1.0", tk.END).strip()
                bp.event.set()
                dlg.destroy()

            ttk.Button(
                btm,
                text="▶ 放行返回给客户端 (Execute)",
                style="Primary.TButton",
                command=_resume_resp,
            ).pack(side=tk.RIGHT, padx=4)
            dlg.protocol("WM_DELETE_WINDOW", _resume_resp)

    def open_intercept_manager_dialog(self):
        """管理所有已配置的接口断点、固定响应码与参数篡改规则"""
        dlg = tk.Toplevel(self.win)
        dlg.title("🛑 接口断点 & 参数篡改 & 固定状态码规则管理器")
        dlg.geometry("680x440")
        auto_fit_dialog(dlg)
        dlg.configure(bg="#2B2D30")
        dlg.transient(self.win)
        self.app._apply_app_icon(dlg)

        tk.Label(
            dlg,
            text="💡 提示：在主界面右侧请求列表任意一行点击【鼠标右键】，即可对该接口打断点、修改请求/响应参数或固定返回 500 状态码。",
            bg="#2B2D30",
            fg="#A9B7C6",
            font=("Microsoft YaHei UI", 9),
            anchor="w",
        ).pack(fill=tk.X, padx=14, pady=(10, 6))

        lb_frame = tk.Frame(dlg, bg="#1E1F22")
        lb_frame.pack(fill=tk.BOTH, expand=True, padx=14, pady=6)
        lb_scroll = ttk.Scrollbar(lb_frame, orient=tk.VERTICAL)
        lb = tk.Listbox(
            lb_frame,
            bg="#1E1F22",
            fg="#DFE1E5",
            selectbackground="#2E436E",
            font=("Consolas", 10),
            bd=0,
            highlightthickness=0,
            yscrollcommand=lb_scroll.set,
        )
        lb_scroll.config(command=lb.yview)
        lb_scroll.pack(side=tk.RIGHT, fill=tk.Y)
        lb.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=6, pady=6)

        rule_keys = []

        def _reload():
            nonlocal rule_keys
            lb.delete(0, tk.END)
            rule_keys = sorted(self.engine.intercept_rules.keys())
            for k in rule_keys:
                r = self.engine.intercept_rules[k]
                state = "🟢启用" if r.enabled else "⚪禁用"
                lb.insert(tk.END, f"[{state}] {r.key}   -->   {r.summary_tags()}")
            self._refresh_rules_button_count()

        def _toggle_sel():
            sel = lb.curselection()
            if not sel:
                return
            k = rule_keys[sel[0]]
            r = self.engine.intercept_rules.get(k)
            if r:
                r.enabled = not r.enabled
                self.engine.save_intercept_rules()
                _reload()

        def _delete_sel():
            sel = lb.curselection()
            if not sel:
                return
            k = rule_keys[sel[0]]
            self.engine.remove_intercept_rule(k)
            _reload()

        def _clear_all():
            self.engine.intercept_rules.clear()
            self.engine.save_intercept_rules()
            _reload()
            self.status_label.config(text="🧹 已清空所有接口断点与参数篡改规则")

        btm = ttk.Frame(dlg)
        btm.pack(fill=tk.X, padx=14, pady=(4, 12))
        ttk.Button(btm, text="🔄 启用/禁用选中", command=_toggle_sel).pack(side=tk.LEFT, padx=2)
        ttk.Button(btm, text="🗑 删除选中规则", command=_delete_sel).pack(side=tk.LEFT, padx=2)
        ttk.Button(btm, text="🧹 清空全部规则", command=_clear_all).pack(side=tk.LEFT, padx=2)
        ttk.Button(btm, text="关闭", command=dlg.destroy).pack(side=tk.RIGHT, padx=2)

        _reload()

    def open_compose_dialog(self, flow: HttpFlow | None = None):
        """接口调试窗口：支持自定义构造 HTTP/HTTPS 请求、从当前抓包载入、从 cURL 导入、编辑 Headers/Params/Body、Ctrl+F 搜索及缩小/全屏切换"""
        init_flow = flow if (flow and flow.method != "CONNECT") else None
        if init_flow is None and self.selected_flow and self.selected_flow.method != "CONNECT":
            init_flow = self.selected_flow

        dlg = tk.Toplevel(self.win)
        title_suffix = f" — [{init_flow.method}] {init_flow.host}{_clean_api_path(init_flow.path)}" if init_flow else ""
        dlg.title(f"🚀 接口调试 (HTTP/HTTPS 请求发送与调试器){title_suffix}")
        dlg.geometry("940x740")
        dlg.minsize(720, 500)
        dlg.resizable(True, True)
        # 注意：不设置 dlg.transient(self.win)，以保留 Windows 标题栏右上角原生的「最小化(缩小)」和「最大化(全屏)」按钮
        auto_fit_dialog(dlg)
        dlg.configure(bg="#2B2D30")
        self.app._apply_app_icon(dlg)

        # 1. 顶部地址栏：Method + URL + 发送按钮 + 缩小/全屏按钮
        top_r = ttk.Frame(dlg, padding=(12, 10, 12, 4))
        top_r.pack(fill=tk.X)

        m_var = tk.StringVar(value=init_flow.method if init_flow else "GET")
        method_cb = ttk.Combobox(
            top_r,
            textvariable=m_var,
            values=["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"],
            width=9,
            state="readonly",
            font=("Consolas", 10, "bold"),
        )
        method_cb.pack(side=tk.LEFT, padx=(0, 6))

        default_url = init_flow.full_url if init_flow else "https://"
        url_var = tk.StringVar(value=default_url)
        url_entry = tk.Entry(
            top_r,
            textvariable=url_var,
            bg="#1E1F22",
            fg="#DFE1E5",
            insertbackground="#FFFFFF",
            relief=tk.FLAT,
            font=("Consolas", 10),
            highlightthickness=1,
            highlightbackground="#393B40",
        )
        url_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 8), ipady=4)

        # 窗口全屏/还原 & 缩小按钮
        def _toggle_fullscreen(_event=None):
            try:
                if dlg.state() == "zoomed":
                    dlg.state("normal")
                    btn_full.config(text="🗖 全屏")
                else:
                    dlg.state("zoomed")
                    btn_full.config(text="🗗 还原")
            except Exception:
                pass

        def _shrink_or_minimize():
            try:
                if dlg.state() == "zoomed":
                    dlg.state("normal")
                    btn_full.config(text="🗖 全屏")
                else:
                    dlg.iconify()
            except Exception:
                pass

        btn_full = ttk.Button(
            top_r,
            text="🗖 全屏",
            command=_toggle_fullscreen,
        )
        btn_full.pack(side=tk.RIGHT, padx=(2, 0))

        btn_shrink = ttk.Button(
            top_r,
            text="🗕 缩小",
            command=_shrink_or_minimize,
        )
        btn_shrink.pack(side=tk.RIGHT, padx=2)

        btn_send = ttk.Button(
            top_r,
            text="🚀 发送请求 (Ctrl+Enter)",
            style="Primary.TButton",
        )
        btn_send.pack(side=tk.RIGHT, padx=(0, 4))

        # 2. 快捷工具栏：载入选中抓包、粘贴导入 cURL、复制为 cURL、清空重置、同步到抓包列表开关
        tool_r = ttk.Frame(dlg, padding=(12, 2, 12, 6))
        tool_r.pack(fill=tk.X)

        record_to_list_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(
            tool_r,
            text="📌 同步记录到主抓包列表",
            variable=record_to_list_var,
        ).pack(side=tk.RIGHT, padx=(6, 0))

        # 3. 上下分栏 PanedWindow（上半部分：请求参数配置；下半部分：实时响应结果）
        paned = tk.PanedWindow(dlg, orient=tk.VERTICAL, bg="#393B40", sashwidth=5, bd=0)
        paned.pack(fill=tk.BOTH, expand=True, padx=12, pady=4)

        # -------------------- 3.1 上半区：请求构造器 (Body / Headers / Query) --------------------
        req_frame = ttk.Frame(paned)
        paned.add(req_frame, minsize=200, height=300)

        req_nb = ttk.Notebook(req_frame)
        req_nb.pack(fill=tk.BOTH, expand=True)

        # Tab 1: Request Body
        tab_body = tk.Frame(req_nb, bg="#2B2D30")
        req_nb.add(tab_body, text="  📤 Body (请求体)  ")

        body_bar = ttk.Frame(tab_body, padding=(6, 4))
        body_bar.pack(fill=tk.X)
        ttk.Label(body_bar, text="快捷类型:").pack(side=tk.LEFT, padx=(0, 4))

        def _set_content_type(ct_val: str):
            raw_h = txt_req_headers.get("1.0", tk.END).splitlines()
            new_lines = []
            found = False
            for line in raw_h:
                if line.strip().lower().startswith("content-type:"):
                    new_lines.append(f"Content-Type: {ct_val}")
                    found = True
                else:
                    new_lines.append(line)
            if not found:
                new_lines.append(f"Content-Type: {ct_val}")
            txt_req_headers.delete("1.0", tk.END)
            txt_req_headers.insert("1.0", "\n".join(new_lines).strip())
            if m_var.get() == "GET":
                m_var.set("POST")

        ttk.Button(
            body_bar,
            text="JSON",
            command=lambda: _set_content_type("application/json; charset=utf-8"),
        ).pack(side=tk.LEFT, padx=2)
        ttk.Button(
            body_bar,
            text="Form表单",
            command=lambda: _set_content_type("application/x-www-form-urlencoded; charset=utf-8"),
        ).pack(side=tk.LEFT, padx=2)
        ttk.Button(
            body_bar,
            text="Text",
            command=lambda: _set_content_type("text/plain; charset=utf-8"),
        ).pack(side=tk.LEFT, padx=2)

        def _format_req_json():
            raw = txt_req_body.get("1.0", tk.END).strip()
            if not raw:
                return
            try:
                obj = json.loads(raw)
                txt_req_body.delete("1.0", tk.END)
                txt_req_body.insert("1.0", json.dumps(obj, ensure_ascii=False, indent=2))
            except Exception as e:
                messagebox.showwarning("JSON 格式有误", f"无法格式化为 JSON：\n{e}", parent=dlg)

        def _minify_req_json():
            raw = txt_req_body.get("1.0", tk.END).strip()
            if not raw:
                return
            try:
                obj = json.loads(raw)
                txt_req_body.delete("1.0", tk.END)
                txt_req_body.insert("1.0", json.dumps(obj, ensure_ascii=False, separators=(",", ":")))
            except Exception as e:
                messagebox.showwarning("JSON 格式有误", f"无法压缩 JSON：\n{e}", parent=dlg)

        ttk.Button(
            body_bar,
            text="🔒 加密选中",
            command=lambda: self._encrypt_in_text_widget(txt_req_body, dlg),
        ).pack(side=tk.RIGHT, padx=2)
        ttk.Button(
            body_bar,
            text="🔓 解密选中",
            command=lambda: self._decrypt_in_text_widget(txt_req_body, dlg),
        ).pack(side=tk.RIGHT, padx=2)
        ttk.Button(body_bar, text="🗜 压缩一行", command=_minify_req_json).pack(side=tk.RIGHT, padx=2)
        ttk.Button(body_bar, text="✨ 格式化 JSON", command=_format_req_json).pack(side=tk.RIGHT, padx=2)
        ttk.Button(
            body_bar,
            text="🔍 搜索 (Ctrl+F)",
            command=lambda: txt_req_body._open_search_bar() if hasattr(txt_req_body, "_open_search_bar") else None,
        ).pack(side=tk.RIGHT, padx=2)

        body_edit_frame = tk.Frame(tab_body, bg="#1E1F22")
        body_edit_frame.pack(fill=tk.BOTH, expand=True, padx=4, pady=(0, 4))
        b_scroll = ttk.Scrollbar(body_edit_frame, orient=tk.VERTICAL)
        txt_req_body = tk.Text(
            body_edit_frame,
            bg="#1E1F22",
            fg="#DFE1E5",
            insertbackground="#FFFFFF",
            selectbackground="#2E436E",
            font=("Consolas", 10),
            bd=0,
            padx=10,
            pady=8,
            yscrollcommand=b_scroll.set,
        )
        b_scroll.config(command=txt_req_body.yview)
        b_scroll.pack(side=tk.RIGHT, fill=tk.Y)
        txt_req_body.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        self._attach_text_search(txt_req_body)

        # Tab 2: Request Headers
        tab_headers = tk.Frame(req_nb, bg="#2B2D30")
        req_nb.add(tab_headers, text="  📋 Headers (请求头)  ")

        hdr_bar = ttk.Frame(tab_headers, padding=(6, 4))
        hdr_bar.pack(fill=tk.X)
        ttk.Label(
            hdr_bar,
            text="💡 每行一条 Header，格式为 Key: Value（如 Authorization: Bearer xxx，按 Ctrl+F 可搜索）",
            foreground="#8C9099",
        ).pack(side=tk.LEFT)

        hdr_edit_frame = tk.Frame(tab_headers, bg="#1E1F22")
        hdr_edit_frame.pack(fill=tk.BOTH, expand=True, padx=4, pady=(0, 4))
        h_scroll = ttk.Scrollbar(hdr_edit_frame, orient=tk.VERTICAL)
        txt_req_headers = tk.Text(
            hdr_edit_frame,
            bg="#1E1F22",
            fg="#DFE1E5",
            insertbackground="#FFFFFF",
            selectbackground="#2E436E",
            font=("Consolas", 10),
            bd=0,
            padx=10,
            pady=8,
            yscrollcommand=h_scroll.set,
        )
        h_scroll.config(command=txt_req_headers.yview)
        h_scroll.pack(side=tk.RIGHT, fill=tk.Y)
        txt_req_headers.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        self._attach_text_search(txt_req_headers)

        # Tab 3: URL Query 参数
        tab_query = tk.Frame(req_nb, bg="#2B2D30")
        req_nb.add(tab_query, text="  🔗 Query 参数 (URL参数)  ")

        q_bar = ttk.Frame(tab_query, padding=(6, 4))
        q_bar.pack(fill=tk.X)
        ttk.Label(
            q_bar,
            text="💡 每行一个参数 key=value，修改后可一键同步到上方 URL 地址栏",
            foreground="#8C9099",
        ).pack(side=tk.LEFT)

        def _extract_query_from_url():
            u = url_var.get().strip()
            parsed = urllib.parse.urlsplit(u)
            items = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
            txt_req_query.delete("1.0", tk.END)
            if items:
                txt_req_query.insert("1.0", "\n".join(f"{k}={v}" for k, v in items))

        def _apply_query_to_url():
            u = url_var.get().strip()
            if not u:
                return
            parsed = urllib.parse.urlsplit(u)
            pairs = []
            for line in txt_req_query.get("1.0", tk.END).splitlines():
                s = line.strip()
                if not s or s.startswith("#"):
                    continue
                if "=" in s:
                    k, v = s.split("=", 1)
                    pairs.append((k.strip(), v.strip()))
                else:
                    pairs.append((s, ""))
            new_query = urllib.parse.urlencode(pairs, doseq=True)
            new_url = urllib.parse.urlunsplit(
                (parsed.scheme or "https", parsed.netloc, parsed.path, new_query, parsed.fragment)
            )
            url_var.set(new_url)

        ttk.Button(q_bar, text="⬆ 同步参数到 URL", style="Primary.TButton", command=_apply_query_to_url).pack(
            side=tk.RIGHT, padx=2
        )
        ttk.Button(q_bar, text="⬇ 从 URL 提取参数", command=_extract_query_from_url).pack(side=tk.RIGHT, padx=2)

        q_edit_frame = tk.Frame(tab_query, bg="#1E1F22")
        q_edit_frame.pack(fill=tk.BOTH, expand=True, padx=4, pady=(0, 4))
        q_scroll = ttk.Scrollbar(q_edit_frame, orient=tk.VERTICAL)
        txt_req_query = tk.Text(
            q_edit_frame,
            bg="#1E1F22",
            fg="#DFE1E5",
            insertbackground="#FFFFFF",
            selectbackground="#2E436E",
            font=("Consolas", 10),
            bd=0,
            padx=10,
            pady=8,
            yscrollcommand=q_scroll.set,
        )
        q_scroll.config(command=txt_req_query.yview)
        q_scroll.pack(side=tk.RIGHT, fill=tk.Y)
        txt_req_query.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        self._attach_text_search(txt_req_query)

        # -------------------- 3.2 下半区：实时响应结果查看器 --------------------
        resp_frame = ttk.Frame(paned)
        paned.add(resp_frame, minsize=220, height=340)

        resp_bar = ttk.Frame(resp_frame, padding=(6, 4))
        resp_bar.pack(fill=tk.X)

        lbl_resp_status = tk.Label(
            resp_bar,
            text="💡 响应结果区：点击上方「🚀 发送请求」后将在此实时显示状态码、耗时与返回数据",
            bg="#2B2D30",
            fg="#56A8F5",
            font=("Microsoft YaHei UI", 9, "bold"),
            anchor="w",
        )
        lbl_resp_status.pack(side=tk.LEFT, fill=tk.X, expand=True)

        def _copy_debug_resp():
            content = txt_resp_body.get("1.0", tk.END).strip()
            if not content:
                return
            dlg.clipboard_clear()
            dlg.clipboard_append(content)
            lbl_resp_status.config(text="📋 已复制响应内容到剪贴板", fg="#73C991")

        ttk.Button(
            resp_bar,
            text="🔒 加密选中",
            command=lambda: self._encrypt_in_text_widget(txt_resp_body, dlg),
        ).pack(side=tk.RIGHT, padx=2)
        ttk.Button(
            resp_bar,
            text="🔓 解密选中/全文",
            style="Primary.TButton",
            command=lambda: self._decrypt_in_text_widget(txt_resp_body, dlg),
        ).pack(side=tk.RIGHT, padx=2)
        ttk.Button(resp_bar, text="📋 复制响应体", command=_copy_debug_resp).pack(side=tk.RIGHT, padx=2)
        ttk.Button(
            resp_bar,
            text="🔍 搜索响应 (Ctrl+F)",
            command=lambda: txt_resp_body._open_search_bar() if hasattr(txt_resp_body, "_open_search_bar") else None,
        ).pack(side=tk.RIGHT, padx=2)

        resp_nb = ttk.Notebook(resp_frame)
        resp_nb.pack(fill=tk.BOTH, expand=True)

        # Resp Tab 1: Response Body
        tab_resp_body = tk.Frame(resp_nb, bg="#1E1F22")
        resp_nb.add(tab_resp_body, text="  📥 Response Body (响应内容)  ")
        rb_scroll = ttk.Scrollbar(tab_resp_body, orient=tk.VERTICAL)
        txt_resp_body = tk.Text(
            tab_resp_body,
            bg="#1E1F22",
            fg="#DFE1E5",
            insertbackground="#FFFFFF",
            selectbackground="#2E436E",
            font=("Consolas", 10),
            bd=0,
            padx=10,
            pady=8,
            yscrollcommand=rb_scroll.set,
        )
        rb_scroll.config(command=txt_resp_body.yview)
        rb_scroll.pack(side=tk.RIGHT, fill=tk.Y)
        txt_resp_body.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        self._attach_text_search(txt_resp_body)

        # Resp Tab 2: Response Headers
        tab_resp_hdr = tk.Frame(resp_nb, bg="#1E1F22")
        resp_nb.add(tab_resp_hdr, text="  📋 Response Headers (响应头与详情)  ")
        rh_scroll = ttk.Scrollbar(tab_resp_hdr, orient=tk.VERTICAL)
        txt_resp_hdr = tk.Text(
            tab_resp_hdr,
            bg="#1E1F22",
            fg="#DFE1E5",
            insertbackground="#FFFFFF",
            selectbackground="#2E436E",
            font=("Consolas", 10),
            bd=0,
            padx=10,
            pady=8,
            yscrollcommand=rh_scroll.set,
        )
        rh_scroll.config(command=txt_resp_hdr.yview)
        rh_scroll.pack(side=tk.RIGHT, fill=tk.Y)
        txt_resp_hdr.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        self._attach_text_search(txt_resp_hdr)

        # -------------------- 辅助函数：填充 Flow / 导入导出 cURL --------------------

        def _parse_headers_text() -> dict[str, str]:
            hdrs: dict[str, str] = {}
            for line in txt_req_headers.get("1.0", tk.END).splitlines():
                s = line.strip()
                if not s or s.startswith("#"):
                    continue
                if ":" in s:
                    k, v = s.split(":", 1)
                    k = k.strip()
                    v = v.strip()
                    if k.lower() not in ("content-length", "host", "connection"):
                        hdrs[k] = v
            return hdrs

        def _load_from_flow(target_flow: HttpFlow | None):
            if not target_flow or target_flow.method == "CONNECT":
                messagebox.showinfo(
                    "提示",
                    "请先在主界面抓包列表中选中一条有效的 HTTP/HTTPS 接口请求！",
                    parent=dlg,
                )
                return
            m_var.set(target_flow.method or "GET")
            url_var.set(target_flow.full_url)
            h_lines = []
            for k, v in target_flow.req_headers.items():
                if k.lower() in ("content-length", "host", "connection", "accept-encoding"):
                    continue
                h_lines.append(f"{k}: {v}")
            txt_req_headers.delete("1.0", tk.END)
            txt_req_headers.insert("1.0", "\n".join(h_lines))

            txt_req_body.delete("1.0", tk.END)
            body_decoded = target_flow.get_decoded_body(is_request=True)
            if body_decoded and not body_decoded.startswith("[二进制"):
                txt_req_body.insert("1.0", body_decoded)

            _extract_query_from_url()

            if target_flow.status_code:
                txt_resp_body.delete("1.0", tk.END)
                txt_resp_body.insert("1.0", target_flow.get_decoded_body(is_request=False))
                rh_lines = [
                    f"Request URL:   {target_flow.full_url}",
                    f"Request Method:{target_flow.method}",
                    f"Status Code:   {target_flow.status_code} {target_flow.reason}",
                    f"Server IP:     {target_flow.server_ip or '-'}",
                    f"Duration:      {target_flow.duration_ms} ms",
                    "\n" + "=" * 28 + " Response Headers " + "=" * 28,
                ]
                for k, v in target_flow.resp_headers.items():
                    rh_lines.append(f"{k}: {v}")
                txt_resp_hdr.delete("1.0", tk.END)
                txt_resp_hdr.insert("1.0", "\n".join(rh_lines))
                lbl_resp_status.config(
                    text=f"📌 已载入抓包记录 #{target_flow.flow_id}（原状态: {target_flow.status_code} | {target_flow.duration_ms} ms），可修改参数后点击「🚀 发送请求」",
                    fg="#56A8F5",
                )

        def _import_from_curl():
            import shlex
            try:
                clip = dlg.clipboard_get().strip()
            except Exception:
                clip = ""
            if not clip or not clip.lower().lstrip().startswith("curl"):
                messagebox.showinfo(
                    "导入 cURL",
                    "请先复制一条以 curl 开头的命令到剪贴板，再点击「📋 粘贴导入 cURL」！",
                    parent=dlg,
                )
                return
            try:
                cleaned = re.sub(r"\\\r?\n", " ", clip)
                cleaned = re.sub(r"\^\r?\n", " ", cleaned)
                tokens = shlex.split(cleaned, posix=True)
                parsed_method = ""
                parsed_url = ""
                parsed_headers = []
                parsed_data = []
                i = 1
                while i < len(tokens):
                    tk_item = tokens[i]
                    if tk_item in ("-X", "--request") and i + 1 < len(tokens):
                        parsed_method = tokens[i + 1].upper()
                        i += 2
                    elif tk_item in ("-H", "--header") and i + 1 < len(tokens):
                        parsed_headers.append(tokens[i + 1])
                        i += 2
                    elif tk_item in ("-d", "--data", "--data-raw", "--data-binary", "--data-urlencode") and i + 1 < len(tokens):
                        parsed_data.append(tokens[i + 1])
                        i += 2
                    elif tk_item in ("-u", "--user", "-A", "--user-agent", "-e", "--referer", "-b", "--cookie") and i + 1 < len(tokens):
                        if tk_item in ("-A", "--user-agent"):
                            parsed_headers.append(f"User-Agent: {tokens[i + 1]}")
                        elif tk_item in ("-e", "--referer"):
                            parsed_headers.append(f"Referer: {tokens[i + 1]}")
                        elif tk_item in ("-b", "--cookie"):
                            parsed_headers.append(f"Cookie: {tokens[i + 1]}")
                        i += 2
                    elif tk_item.startswith("http://") or tk_item.startswith("https://"):
                        parsed_url = tk_item
                        i += 1
                    elif not tk_item.startswith("-") and not parsed_url and "." in tk_item:
                        parsed_url = "https://" + tk_item
                        i += 1
                    else:
                        i += 1

                if not parsed_method:
                    parsed_method = "POST" if parsed_data else "GET"
                m_var.set(parsed_method)
                if parsed_url:
                    url_var.set(parsed_url)
                txt_req_headers.delete("1.0", tk.END)
                txt_req_headers.insert("1.0", "\n".join(parsed_headers))
                txt_req_body.delete("1.0", tk.END)
                if parsed_data:
                    joined_body = "&".join(parsed_data) if len(parsed_data) > 1 else parsed_data[0]
                    try:
                        joined_body = json.dumps(json.loads(joined_body), ensure_ascii=False, indent=2)
                    except Exception:
                        pass
                    txt_req_body.insert("1.0", joined_body)
                _extract_query_from_url()
                lbl_resp_status.config(text=f"✅ 已从剪贴板成功导入 cURL 命令: [{parsed_method}] {parsed_url}", fg="#73C991")
            except Exception as e:
                messagebox.showwarning("解析 cURL 失败", f"未能解析剪贴板中的 cURL 命令：\n{e}", parent=dlg)

        def _copy_as_curl():
            target_url = url_var.get().strip()
            method = m_var.get().strip().upper() or "GET"
            hdrs = _parse_headers_text()
            body_str = txt_req_body.get("1.0", tk.END).strip()
            parts = [f'curl -X {method} "{target_url}"']
            for k, v in hdrs.items():
                safe_v = v.replace('"', '\\"')
                parts.append(f'  -H "{k}: {safe_v}"')
            if body_str and method not in ("GET", "HEAD"):
                compact = body_str.replace('"', '\\"').replace("\n", " ")
                parts.append(f'  -d "{compact}"')
            curl_str = " \\\n".join(parts)
            dlg.clipboard_clear()
            dlg.clipboard_append(curl_str)
            lbl_resp_status.config(text="📋 已将当前接口配置复制为 cURL 命令", fg="#73C991")

        def _reset_fields():
            m_var.set("GET")
            url_var.set("https://")
            txt_req_headers.delete("1.0", tk.END)
            txt_req_headers.insert(
                "1.0",
                "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) RMYYDS-Client/1.0\n"
                "Accept: application/json, text/plain, */*\n"
                "Content-Type: application/json; charset=utf-8",
            )
            txt_req_body.delete("1.0", tk.END)
            txt_req_query.delete("1.0", tk.END)
            txt_resp_body.delete("1.0", tk.END)
            txt_resp_hdr.delete("1.0", tk.END)
            lbl_resp_status.config(text="🧹 已重置为空白请求模板", fg="#8C9099")
            url_entry.focus_set()

        ttk.Button(
            tool_r,
            text="📥 载入选中抓包",
            command=lambda: _load_from_flow(self.selected_flow),
        ).pack(side=tk.LEFT, padx=(0, 4))
        ttk.Button(
            tool_r,
            text="📋 粘贴导入 cURL",
            command=_import_from_curl,
        ).pack(side=tk.LEFT, padx=4)
        ttk.Button(
            tool_r,
            text="📋 复制为 cURL",
            command=_copy_as_curl,
        ).pack(side=tk.LEFT, padx=4)
        ttk.Button(
            tool_r,
            text="🧹 清空重置",
            command=_reset_fields,
        ).pack(side=tk.LEFT, padx=4)

        if init_flow:
            _load_from_flow(init_flow)
        else:
            _reset_fields()

        # -------------------- 发送请求核心逻辑 --------------------
        def _do_send(_event=None):
            import urllib.request
            target_url = url_var.get().strip()
            if not target_url or target_url in ("http://", "https://"):
                messagebox.showwarning("提示", "请输入完整的接口请求 URL 地址！", parent=dlg)
                url_entry.focus_set()
                return
            if not target_url.startswith(("http://", "https://")):
                target_url = "https://" + target_url
                url_var.set(target_url)

            method = m_var.get().strip().upper() or "GET"
            headers = _parse_headers_text()
            if not any(k.lower() == "user-agent" for k in headers):
                headers["User-Agent"] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) RMYYDS-Client/1.0"

            body_str = txt_req_body.get("1.0", tk.END).strip()
            body_bytes = body_str.encode("utf-8") if (body_str and method not in ("GET", "HEAD")) else None
            if body_bytes and not any(k.lower() == "content-type" for k in headers):
                if body_str.startswith(("{", "[")):
                    headers["Content-Type"] = "application/json; charset=utf-8"
                else:
                    headers["Content-Type"] = "application/x-www-form-urlencoded; charset=utf-8"

            btn_send.config(state=tk.DISABLED, text="⏳ 发送中...")
            lbl_resp_status.config(text=f"⏳ 正在请求 [{method}] {target_url} ...", fg="#D6BF55")

            def _bg():
                t0 = time.time()
                parsed = urllib.parse.urlsplit(target_url)
                scheme = parsed.scheme or "https"
                host = parsed.hostname or ""
                port = parsed.port or (443 if scheme == "https" else 80)
                path = (parsed.path or "/") + (("?" + parsed.query) if parsed.query else "")

                new_f = HttpFlow(
                    self.engine.next_flow_id(),
                    scheme,
                    method,
                    host,
                    port,
                    path,
                    "接口调试",
                )
                new_f.process_name = "💻 接口调试"
                new_f.req_headers = dict(headers)
                new_f.req_body_raw = body_bytes or b""
                new_f.notes = "🚀调试"
                try:
                    new_f.server_ip = socket.gethostbyname(host) if host else ""
                except Exception:
                    pass

                try:
                    req = urllib.request.Request(target_url, data=body_bytes, headers=headers, method=method)
                    handlers = [urllib.request.ProxyHandler({})]
                    if scheme == "https":
                        handlers.append(urllib.request.HTTPSHandler(context=ssl._create_unverified_context()))
                    opener = urllib.request.build_opener(*handlers)
                    with opener.open(req, timeout=20) as resp:
                        resp_data = resp.read()
                        new_f.status_code = resp.status
                        new_f.reason = resp.reason
                        new_f.resp_headers = dict(resp.headers.items())
                        new_f.resp_body_raw = resp_data
                        new_f.content_type = resp.headers.get("Content-Type", "")
                        new_f.size_bytes = len(resp_data)
                except urllib.error.HTTPError as he:
                    err_data = he.read() if he.fp else b""
                    new_f.status_code = he.code
                    new_f.reason = str(he.reason)
                    new_f.resp_headers = dict(he.headers.items()) if he.headers else {}
                    new_f.resp_body_raw = err_data
                    new_f.content_type = he.headers.get("Content-Type", "") if he.headers else ""
                    new_f.size_bytes = len(err_data)
                except Exception as ex:
                    new_f.status_code = 502
                    new_f.reason = "Request Failed"
                    new_f.error = str(ex)
                    new_f.resp_body_raw = f"请求发送失败: {ex}".encode("utf-8")
                    new_f.size_bytes = len(new_f.resp_body_raw)

                new_f.duration_ms = int((time.time() - t0) * 1000)

                if record_to_list_var.get():
                    self.flow_queue.put(new_f)
                self._post_status(
                    f"🚀 接口调试完成: [{method}] {target_url} -> HTTP {new_f.status_code} ({new_f.duration_ms} ms)"
                )

                def _update_ui():
                    if not dlg.winfo_exists():
                        return
                    btn_send.config(state=tk.NORMAL, text="🚀 发送请求 (Ctrl+Enter)")
                    if 200 <= new_f.status_code < 300:
                        st_color = "#73C991"
                        st_icon = "🟢"
                    elif 300 <= new_f.status_code < 400:
                        st_color = "#56A8F5"
                        st_icon = "🔵"
                    elif 400 <= new_f.status_code < 500:
                        st_color = "#D6BF55"
                        st_icon = "🟡"
                    else:
                        st_color = "#FF6B68"
                        st_icon = "🔴"

                    lbl_resp_status.config(
                        text=(
                            f"{st_icon} 状态: {new_f.status_code} {new_f.reason}   |   "
                            f"耗时: {new_f.duration_ms} ms   |   "
                            f"大小: {new_f.format_size()}   |   "
                            f"IP: {new_f.server_ip or '-'}"
                        ),
                        fg=st_color,
                    )
                    decoded_resp = new_f.get_decoded_body(is_request=False)
                    txt_resp_body.delete("1.0", tk.END)
                    txt_resp_body.insert("1.0", decoded_resp if decoded_resp else "[响应无 Body 内容]")
                    if hasattr(txt_resp_body, "_refresh_search_bar"):
                        txt_resp_body._refresh_search_bar()

                    rh_lines = [
                        f"URL:           {new_f.full_url}",
                        f"Method:        {new_f.method}",
                        f"Status:        {new_f.status_code} {new_f.reason}",
                        f"Server IP:     {new_f.server_ip or '-'}",
                        f"Duration:      {new_f.duration_ms} ms",
                        f"Response Size: {new_f.format_size()}",
                    ]
                    if new_f.error:
                        rh_lines.append(f"Error:         {new_f.error}")
                    rh_lines.append("\n" + "=" * 28 + " Response Headers " + "=" * 28)
                    for k, v in new_f.resp_headers.items():
                        rh_lines.append(f"{k}: {v}")
                    rh_lines.append("\n" + "=" * 28 + " Request Headers " + "=" * 29)
                    for k, v in new_f.req_headers.items():
                        rh_lines.append(f"{k}: {v}")
                    txt_resp_hdr.delete("1.0", tk.END)
                    txt_resp_hdr.insert("1.0", "\n".join(rh_lines))
                    if hasattr(txt_resp_hdr, "_refresh_search_bar"):
                        txt_resp_hdr._refresh_search_bar()

                self.win.after(0, _update_ui)

            threading.Thread(target=_bg, daemon=True).start()

        def _on_dlg_ctrl_f(_event=None):
            focused = dlg.focus_get()
            if isinstance(focused, tk.Text) and hasattr(focused, "_open_search_bar"):
                return focused._open_search_bar()
            # 默认优先搜索下方响应内容（若响应为空则搜索请求体）
            if txt_resp_body.get("1.0", tk.END).strip() and hasattr(txt_resp_body, "_open_search_bar"):
                return txt_resp_body._open_search_bar()
            if hasattr(txt_req_body, "_open_search_bar"):
                return txt_req_body._open_search_bar()
            return "break"

        btn_send.config(command=_do_send)
        url_entry.bind("<Return>", _do_send)
        dlg.bind("<Control-Return>", _do_send)
        dlg.bind("<F11>", _toggle_fullscreen)
        dlg.bind("<Control-f>", _on_dlg_ctrl_f)
        dlg.bind("<Control-F>", _on_dlg_ctrl_f)

    def clear_flows(self):
        self.all_flows.clear()
        self.filtered_flows.clear()
        self.flow_map.clear()
        self.host_counts.clear()
        self.selected_flow = None
        self.selected_host = "__ALL__"
        self.tree.delete(*self.tree.get_children())
        self._refresh_host_listbox()
        for txt in (self.txt_resp_body, self.txt_req_body, self.txt_headers, self.txt_curl):
            txt.delete("1.0", tk.END)
        import gc
        gc.collect()
        self._update_counts()
        self.status_label.config(text="🗑 已清空所有抓包记录，内存已安全释放")

    def copy_url(self):
        if not self.selected_flow:
            return
        self.win.clipboard_clear()
        self.win.clipboard_append(self.selected_flow.full_url)
        self.status_label.config(text="📋 已复制完整 URL 到剪贴板")

    def copy_response_body(self):
        if not self.selected_flow:
            return
        text = self.selected_flow.get_decoded_body(is_request=False)
        self.win.clipboard_clear()
        self.win.clipboard_append(text)
        self.status_label.config(text="📋 已复制格式化后的 Response 内容到剪贴板")

    def copy_curl(self):
        if not self.selected_flow:
            return
        self.win.clipboard_clear()
        self.win.clipboard_append(self._build_curl(self.selected_flow))
        self.status_label.config(text="📋 已复制 cURL 命令到剪贴板")

    def shutdown_cleanly(self):
        """供主程序关闭或抓包窗口关闭时调用，确保停止代理并还原电脑与手机网络设置"""
        self._is_closing = True
        if self._after_id:
            try:
                self.win.after_cancel(self._after_id)
            except Exception:
                pass
            self._after_id = None
        if self.pc_proxy_var.get() or _WIN_PROXY_ACTIVE:
            try:
                _set_windows_system_proxy(False)
            except Exception:
                pass
        if self.engine.running:
            self.engine.stop()
        if self.mounted_proxy_serial:
            serial = self.mounted_proxy_serial
            self.mounted_proxy_serial = ""
            try:
                self.app._run_adb_cmd(
                    ["-s", serial, "shell", "settings", "put", "global", "http_proxy", ":0"],
                    timeout=2,
                )
                self.app._run_adb_cmd(
                    ["-s", serial, "shell", "settings", "delete", "global", "http_proxy"],
                    timeout=2,
                )
            except Exception:
                pass

    def _on_close(self):
        self.shutdown_cleanly()
        if getattr(self, "is_main_window", False):
            self.app._on_close()
        else:
            try:
                self.win.destroy()
            except Exception:
                pass
