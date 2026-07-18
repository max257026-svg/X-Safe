"""
X-Safe — 核心扫描引擎
Core Antivirus Engine: Signature-based + Heuristic + Entropy Analysis
"""

import hashlib
import os
import re
import json
import math
import struct
import datetime
import threading
import queue
from pathlib import Path
from collections import Counter
from dataclasses import dataclass, field, asdict
from typing import Optional, Callable
from enum import Enum


# ============================================================
# 威胁等级
# ============================================================
class ThreatLevel(Enum):
    SAFE = "safe"
    SUSPICIOUS = "suspicious"
    HIGH_RISK = "high_risk"
    MALICIOUS = "malicious"


class ScanCancelled(Exception):
    """扫描被用户取消 — 由 cancel_scan() 触发，用于中断正在进行的单文件扫描"""
    pass


# ============================================================
# 扫描结果
# ============================================================
@dataclass
class ScanResult:
    file_path: str
    file_name: str
    file_size: int
    threat_level: ThreatLevel = ThreatLevel.SAFE
    threat_name: str = ""
    detection_method: str = ""
    hash_md5: str = ""
    hash_sha256: str = ""
    entropy: float = 0.0
    details: str = ""
    timestamp: str = ""

    def to_dict(self) -> dict:
        d = asdict(self)
        d["threat_level"] = self.threat_level.value
        return d

    @property
    def is_threat(self) -> bool:
        return self.threat_level in (ThreatLevel.SUSPICIOUS,
                                     ThreatLevel.HIGH_RISK,
                                     ThreatLevel.MALICIOUS)


# ============================================================
# 扫描统计
# ============================================================
@dataclass
class ScanStats:
    total_files: int = 0
    scanned_files: int = 0
    threats_found: int = 0
    suspicious_found: int = 0
    quarantined: int = 0
    errors: int = 0
    start_time: float = 0.0
    end_time: float = 0.0
    current_file: str = ""  # 正在扫描的文件路径（ESET 风格：进度条显示当前文件）

    @property
    def elapsed_seconds(self) -> float:
        """实时耗时 — 扫描中用当前时间，扫描完用 end_time"""
        if self.start_time <= 0:
            return 0.0
        if self.end_time and self.end_time > 0:
            return self.end_time - self.start_time
        # 扫描进行中 — 实时计时
        import time
        return time.time() - self.start_time

    @property
    def scan_speed(self) -> float:
        if self.elapsed_seconds > 0:
            return self.scanned_files / self.elapsed_seconds
        return 0.0


# ============================================================
# 签名数据库
# ============================================================
class SignatureDB:
    """病毒签名数据库 — 支持哈希和模式匹配"""

    def __init__(self, sig_file: str = ""):
        self._hash_sigs: dict[str, dict] = {}  # md5 -> {name, severity, ...}
        self._sha256_sigs: dict[str, dict] = {}
        self._pattern_sigs: list[dict] = []  # [{pattern, name, severity, ...}]
        self._string_sigs: list[dict] = []  # [{strings: [...], name, ...}]
        self._yara_rules: list[dict] = []  # simple yara-like rules
        self._ext_blacklist: set[str] = set()
        self._heuristic_rules: list[dict] = []

        if sig_file:
            self.load(sig_file)

    def load(self, filepath: str):
        """从 JSON 文件加载签名数据库"""
        try:
            with open(filepath, "r", encoding="utf-8") as f:
                data = json.load(f)

            # 加载哈希签名
            for entry in data.get("hash_signatures", []):
                md5 = entry.get("md5", "").lower()
                sha256 = entry.get("sha256", "").lower()
                info = {
                    "name": entry.get("name", "Unknown"),
                    "severity": entry.get("severity", "high"),
                    "type": entry.get("type", "unknown"),
                    "description": entry.get("description", ""),
                }
                if md5:
                    self._hash_sigs[md5] = info
                if sha256:
                    self._sha256_sigs[sha256] = info

            # 加载模式签名 (正则)
            for entry in data.get("pattern_signatures", []):
                self._pattern_sigs.append(entry)

            # 加载字符串签名
            for entry in data.get("string_signatures", []):
                self._string_sigs.append(entry)

            # 加载 YARA 风格规则
            for entry in data.get("yara_rules", []):
                self._yara_rules.append(entry)

            # 危险扩展名黑名单
            self._ext_blacklist = set(
                ext.lower() for ext in data.get("dangerous_extensions", [])
            )

            # 启发式规则
            self._heuristic_rules = data.get("heuristic_rules", [])

            return True
        except Exception as e:
            print(f"[!] 签名库加载失败: {e}")
            return False

    def match_hash(self, md5: str = "", sha256: str = "") -> Optional[dict]:
        """哈希匹配"""
        md5 = md5.lower()
        sha256 = sha256.lower()
        if md5 and md5 in self._hash_sigs:
            return self._hash_sigs[md5]
        if sha256 and sha256 in self._sha256_sigs:
            return self._sha256_sigs[sha256]
        return None

    def match_patterns(self, content: str, file_ext: str = "") -> list[dict]:
        """模式匹配 — 返回匹配到的规则列表"""
        matches = []
        for rule in self._pattern_sigs:
            # 检查文件类型限制
            allowed_exts = rule.get("file_types", [])
            if allowed_exts and file_ext.lower() not in allowed_exts:
                continue

            pattern = rule.get("pattern", "")
            try:
                if re.search(pattern, content, re.IGNORECASE | re.DOTALL):
                    matches.append(rule)
            except re.error:
                pass
        return matches

    def match_strings(self, content: str) -> list[dict]:
        """字符串匹配"""
        matches = []
        for rule in self._string_sigs:
            strings = rule.get("strings", [])
            min_matches = rule.get("min_matches", 1)
            count = sum(1 for s in strings if s.lower() in content.lower())
            if count >= min_matches:
                matches.append(rule)
        return matches

    def match_yara(self, content: str, file_ext: str = "") -> list[dict]:
        """简易 YARA 规则匹配"""
        matches = []
        for rule in self._yara_rules:
            # 文件类型过滤
            allowed_exts = rule.get("file_types", [])
            if allowed_exts and file_ext.lower() not in allowed_exts:
                continue

            condition = rule.get("condition", "")
            strings = rule.get("strings", {})
            # 替换 $str_name 为实际字符串
            eval_cond = condition
            for name, value in strings.items():
                found = value.lower() in content.lower()
                eval_cond = eval_cond.replace(name, str(found))
            try:
                if eval(eval_cond):
                    matches.append(rule)
            except Exception:
                pass
        return matches

    @property
    def hash_count(self) -> int:
        return len(self._hash_sigs) + len(self._sha256_sigs)

    @property
    def pattern_count(self) -> int:
        return len(self._pattern_sigs) + len(self._string_sigs)

    @property
    def ext_blacklist(self) -> set[str]:
        return self._ext_blacklist

    @property
    def heuristic_rules(self) -> list[dict]:
        return self._heuristic_rules


# ============================================================
# 启发式分析器
# ============================================================
class HeuristicAnalyzer:
    """启发式检测：熵值分析、PE结构分析、可疑模式检测"""

    # 这些 API 名称在安全工具代码中也可能出现，因此在 Python 文件中需要更高阈值
    SECURITY_API_STRINGS = {
        "VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread",
        "NtCreateThreadEx", "QueueUserAPC", "SetWindowsHookEx",
        "IsDebuggerPresent", "CheckRemoteDebuggerPresent",
        "NtQueryInformationProcess",
    }

    # 高置信度恶意特征 — 单独命中即可判定可疑
    HIGH_CONFIDENCE_INDICATORS = [
        # 混淆执行
        "eval(base64_decode", "eval(gzinflate", "eval(stripslashes",
        "eval(gzuncompress", "eval(str_rot13", "eval(chr(",
        "FromBase64String", "Invoke-Expression",
        # 隐藏执行
        "Start-Process -WindowStyle Hidden",
        "IEX (New-Object Net.WebClient)",
        "CreateObject(\"WScript.Shell\")",
        "regsvr32 /s /u /i:",
        "rundll32.exe javascript:",
        # 勒索软件
        "decrypt_files", "encrypt_all_files", "bitcoin_address",
        # 远控
        "reverse_shell", "bind_shell", "keylogger",
        "credential_dump", "mimikatz", "sekurlsa::",
    ]

    # 中等置信度特征 — 需要组合命中 (≥2个) 才判定
    MEDIUM_CONFIDENCE_INDICATORS = [
        # 下载执行 (需组合)
        "DownloadString", "DownloadFile", "DownloadData",
        "Net.WebClient", "Invoke-WebRequest",
        # 注册表持久化
        "CurrentVersion\\Run",
        "CurrentVersion\\\\Run",
        # 进程注入 API
        "VirtualAllocEx", "WriteProcessMemory",
        "CreateRemoteThread", "NtCreateThreadEx",
        # 文件系统操作
        "CreateObject(\"Scripting.FileSystemObject\")",
    ]

    # 低置信度特征 — 仅作为辅助参考，不单独触发告警
    # exec/system/popen 等标准函数不在此列表，避免误报

    # 可疑字符串（脚本类恶意软件常见）— 保留用于兼容，实际检测使用上面分级
    SUSPICIOUS_STRINGS = HIGH_CONFIDENCE_INDICATORS + MEDIUM_CONFIDENCE_INDICATORS

    # 高危扩展名
    DANGEROUS_EXTENSIONS = {
        ".exe", ".dll", ".sys", ".bat", ".cmd", ".ps1", ".vbs",
        ".vbe", ".js", ".jse", ".wsf", ".wsh", ".hta", ".scr",
        ".pif", ".cpl", ".msi", ".msp", ".com", ".pif", ".gadget",
    }

    # 脚本扩展名
    SCRIPT_EXTENSIONS = {
        ".py", ".js", ".vbs", ".ps1", ".bat", ".cmd", ".sh",
        ".php", ".pl", ".rb", ".lua", ".wsf", ".wsh",
    }

    DOUBLE_EXT_PATTERN = re.compile(
        r'\.(doc|docx|xls|xlsx|pdf|txt|jpg|jpeg|png|gif|mp3|mp4|avi|zip|rar)'
        r'\.(exe|scr|bat|cmd|vbs|ps1|js|vbe|com|pif)$',
        re.IGNORECASE,
    )

    @staticmethod
    def calculate_entropy(data: bytes) -> float:
        """计算香农熵 — 高熵值可能表示加密/压缩/混淆"""
        if not data:
            return 0.0
        entropy = 0.0
        length = len(data)
        counter = Counter(data)
        for count in counter.values():
            p = count / length
            entropy -= p * math.log2(p)
        return entropy

    @classmethod
    def analyze_file(cls, filepath: str) -> list[tuple[str, str, ThreatLevel]]:
        """综合启发式分析 — 返回 [(原因, 详情, 威胁等级), ...]"""
        findings = []
        path = Path(filepath)
        name = path.name.lower()
        ext = path.suffix.lower()

        # 1. 双扩展名检测 (如 .pdf.exe)
        if cls.DOUBLE_EXT_PATTERN.search(name):
            findings.append((
                "双扩展名伪装",
                f"文件名 {path.name} 使用双扩展名伪装文件类型",
                ThreatLevel.HIGH_RISK,
            ))

        # 2. 高危扩展名 + 可疑目录
        if ext in cls.DANGEROUS_EXTENSIONS:
            temp_dirs = {"temp", "tmp", "downloads", "appdata\\local\\temp"}
            parent_lower = str(path.parent).lower()
            if any(td in parent_lower for td in temp_dirs):
                findings.append((
                    "高危文件位于临时目录",
                    f"可执行文件 {path.name} 位于临时目录，可能是恶意软件投放",
                    ThreatLevel.HIGH_RISK,
                ))

        # 3. 内容分析 (仅对文本/脚本类文件)
        if ext in cls.SCRIPT_EXTENSIONS or ext == "":
            try:
                # 只读前 64KB 用于分析
                with open(filepath, "rb") as f:
                    sample = f.read(65536)

                # 尝试解码为文本
                text_content = ""
                for encoding in ["utf-8", "latin-1", "gbk"]:
                    try:
                        text_content = sample.decode(encoding, errors="replace")
                        break
                    except Exception:
                        pass

                # 分级检测可疑特征
                text_lower = text_content.lower()

                # 高置信度 — 单独命中即可
                high_hits = [
                    s for s in cls.HIGH_CONFIDENCE_INDICATORS
                    if s.lower() in text_lower
                ]
                # .py 文件过滤安全工具 API 引用
                if ext == ".py":
                    high_hits = [
                        s for s in high_hits
                        if s not in cls.SECURITY_API_STRINGS
                    ]

                # 中等置信度 — 需组合
                medium_hits = [
                    s for s in cls.MEDIUM_CONFIDENCE_INDICATORS
                    if s.lower() in text_lower
                ]
                if ext == ".py":
                    medium_hits = [
                        s for s in medium_hits
                        if s not in cls.SECURITY_API_STRINGS
                    ]

                # 判定逻辑
                if len(high_hits) >= 1:
                    findings.append((
                        "高危代码特征",
                        f"检测到高危特征: {', '.join(high_hits[:5])}",
                        ThreatLevel.MALICIOUS,
                    ))
                elif len(medium_hits) >= 2:
                    findings.append((
                        "多个可疑代码特征",
                        f"检测到 {len(medium_hits)} 个可疑特征: {', '.join(medium_hits[:5])}",
                        ThreatLevel.HIGH_RISK,
                    ))
                elif len(medium_hits) >= 1:
                    findings.append((
                        "可疑代码特征",
                        f"检测到: {medium_hits[0]}",
                        ThreatLevel.SUSPICIOUS,
                    ))

                # 熵值分析 (仅对脚本文件有意义，压缩/加密文件本身高熵是正常的)
                entropy = cls.calculate_entropy(sample)
                if entropy > 7.8:
                    findings.append((
                        "极高熵值",
                        f"文件熵值 {entropy:.2f}，高度疑似加密/混淆/打包",
                        ThreatLevel.SUSPICIOUS,
                    ))

            except (PermissionError, OSError):
                pass

        # 4. PE 文件分析 (Windows 可执行文件)
        if ext in {".exe", ".dll", ".sys", ".scr", ".com"}:
            try:
                with open(filepath, "rb") as f:
                    header = f.read(2)
                if header == b"MZ":
                    # PE 文件基础检查
                    try:
                        with open(filepath, "rb") as f:
                            f.seek(0x3C)
                            pe_offset_data = f.read(4)
                            pe_offset = struct.unpack("<I", pe_offset_data)[0]
                            f.seek(pe_offset)
                            pe_sig = f.read(4)
                            if pe_sig == b"PE\x00\x00":
                                findings.append((
                                    "PE 可执行文件",
                                    "检测到标准 Windows PE 可执行文件结构",
                                    ThreatLevel.SAFE,  # 仅标识，不报警
                                ))
                    except Exception:
                        pass
            except (PermissionError, OSError):
                pass

        return findings


# ============================================================
# 文件哈希器
# ============================================================
class FileHasher:
    """高性能流式文件哈希计算"""

    CHUNK_SIZE = 8192

    @classmethod
    def compute_hashes(
        cls,
        filepath: str,
        should_cancel: Optional[Callable[[], bool]] = None,
    ) -> tuple[str, str]:
        """返回 (md5, sha256)。若 should_cancel() 返回 True，立即中断并返回 "CANCELLED"。

        说明: 大文件哈希可能耗时数秒，必须在读取循环中持续检查取消标志，
        否则用户点击「停止」后要等到整个文件读完才能生效，造成明显卡顿。
        """
        md5_hash = hashlib.md5()
        sha256_hash = hashlib.sha256()
        try:
            with open(filepath, "rb") as f:
                while chunk := f.read(cls.CHUNK_SIZE):
                    md5_hash.update(chunk)
                    sha256_hash.update(chunk)
                    if should_cancel is not None and should_cancel():
                        return "CANCELLED", "CANCELLED"
            return md5_hash.hexdigest(), sha256_hash.hexdigest()
        except (PermissionError, OSError):
            return "ACCESS_DENIED", "ACCESS_DENIED"


# ============================================================
# 核心扫描器
# ============================================================
class AntivirusScanner:
    """病毒扫描器 — 协调所有检测模块"""

    # 跳过扫描的目录
    SKIP_DIRS = {
        # Linux
        "/proc", "/sys", "/dev", "/run", "/snap", "/boot", "/lib/modules",
        # Windows 系统
        "C:\\Windows\\System32\\config",
        "C:\\Windows\\System32\\drivers",
        "C:\\Windows\\WinSxS",
        "C:\\Windows\\Assembly",
        "C:\\Windows\\Installer",
        "C:\\Windows\\CSC",
        "C:\\Windows\\Temp",
        "C:\\Windows\\SoftwareDistribution",
        "C:\\Windows\\Prefetch",
        "C:\\Windows\\Logs",
        # Windows 用户缓存
        "AppData\\Local\\Temp",
        "AppData\\Local\\Microsoft\\Windows\\INetCache",
        "AppData\\Local\\Google\\Chrome\\User Data",
        "AppData\\Local\\Mozilla\\Firefox",
        "AppData\\Local\\Packages",
        "AppData\\Local\\CrashDumps",
        # 回收站 / 系统卷信息
        "$RECYCLE.BIN", "System Volume Information", "$WinREAgent",
        # node_modules / .git 等开发目录
        "node_modules", ".git", "__pycache__", ".venv", "venv",
    }

    # 跳过扫描的文件大小上限 (默认 500MB)
    MAX_FILE_SIZE = 500 * 1024 * 1024

    # 可信路径 — 这些目录中的文件降低告警等级 (仅启发式检测时)
    TRUSTED_PATHS = [
        "c:\\program files", "c:\\program files (x86)",
        "c:\\windows", "c:\\programdata",
        "/usr/bin", "/usr/lib", "/usr/share",
        "/system", "/system32",
    ]

    def __init__(self, signature_db: SignatureDB, whitelist=None):
        self.sig_db = signature_db
        self.whitelist = whitelist  # WhitelistEngine 实例 (可为 None)
        self.stats = ScanStats()
        self._results: list[ScanResult] = []
        self._cancel_flag = threading.Event()
        self._callback: Optional[Callable] = None
        self._lock = threading.Lock()

    def set_progress_callback(self, callback: Callable[[ScanResult], None]):
        self._callback = callback

    def cancel_scan(self):
        self._cancel_flag.set()

    def is_cancelled(self) -> bool:
        """是否已请求取消扫描 — 供 UI/回调实时判断是否继续重活"""
        return self._cancel_flag.is_set()

    def reset(self):
        self._cancel_flag.clear()
        self.stats = ScanStats()
        self._results.clear()

    # ----------------------------------------------------------
    # 单文件扫描
    # ----------------------------------------------------------
    def scan_file(
        self,
        filepath: str,
        should_cancel: Optional[Callable[[], bool]] = None,
    ) -> ScanResult:
        """扫描单个文件 — 综合所有检测方法

        Args:
            should_cancel: 取消检查回调。若返回 True，立即抛出 ScanCancelled
                           中断当前文件扫描（不产出结果），让「停止」即时生效。
        """
        if should_cancel is None:
            should_cancel = self._cancel_flag.is_set
        if should_cancel():
            raise ScanCancelled(filepath)

        path = Path(filepath)
        result = ScanResult(
            file_path=str(path.absolute()),
            file_name=path.name,
            file_size=0,
            timestamp=datetime.datetime.now().isoformat(),
        )

        # 检查文件是否存在
        if not path.exists():
            result.threat_level = ThreatLevel.SAFE
            result.details = "文件不存在"
            return result

        # 获取文件大小
        try:
            result.file_size = path.stat().st_size
        except OSError:
            result.details = "无法访问文件"
            return result

        # ---- 白名单 / 信任区检查 (路径) ----
        # 受信任文件直接判定安全，跳过后续所有检测，避免误报
        if self.whitelist is not None and self.whitelist.is_trusted(str(path.absolute())):
            result.threat_level = ThreatLevel.SAFE
            result.detection_method = "白名单信任"
            result.details = "该文件/路径已在信任区中，已跳过检测"
            return result

        # ---- 自保护：XSafe 自身 exe / _internal 运行时目录（防止自己杀自己） ----
        if self.whitelist is not None and self.whitelist.is_self_protected(str(path.absolute())):
            result.threat_level = ThreatLevel.SAFE
            result.detection_method = "自保护"
            result.details = "XSafe 自身组件，已自动加入白名单"
            return result

        # 跳过超大文件
        if result.file_size > self.MAX_FILE_SIZE:
            result.threat_level = ThreatLevel.SAFE
            result.details = f"文件过大 ({result.file_size} bytes)，跳过扫描"
            return result

        detected = False

        # ---- 第1层：哈希签名检测 ----
        try:
            md5, sha256 = FileHasher.compute_hashes(filepath, should_cancel)
            if md5 == "CANCELLED":
                raise ScanCancelled(filepath)
            result.hash_md5 = md5
            result.hash_sha256 = sha256

            # ---- 白名单 / 信任区检查 (哈希) ----
            if self.whitelist is not None and self.whitelist.is_trusted(None, sha256=sha256):
                result.threat_level = ThreatLevel.SAFE
                result.detection_method = "白名单信任"
                result.details = "该文件哈希已在信任区中，已跳过检测"
                return result

            sig_match = self.sig_db.match_hash(md5=md5, sha256=sha256)
            if sig_match:
                sev = sig_match.get("severity", "high")
                if sev == "critical":
                    result.threat_level = ThreatLevel.MALICIOUS
                elif sev in ("high",):
                    result.threat_level = ThreatLevel.HIGH_RISK
                else:
                    result.threat_level = ThreatLevel.SUSPICIOUS

                result.threat_name = sig_match.get("name", "Unknown Threat")
                result.detection_method = f"哈希签名匹配 (MD5/SHA256)"
                result.details = sig_match.get("description", "")
                detected = True
        except Exception:
            pass

        # ---- 第2层：模式/规则检测 ----
        if not detected:
            try:
                # 对文本/脚本文件读取内容
                ext = path.suffix.lower()
                if ext in HeuristicAnalyzer.SCRIPT_EXTENSIONS or ext == "":
                    with open(filepath, "rb") as f:
                        sample = f.read(65536)
                    text = ""
                    for enc in ["utf-8", "latin-1", "gbk"]:
                        try:
                            text = sample.decode(enc, errors="replace")
                            break
                        except Exception:
                            pass

                    if text:
                        # 模式匹配
                        pattern_matches = self.sig_db.match_patterns(text, ext)
                        # 字符串匹配
                        string_matches = self.sig_db.match_strings(text)
                        # YARA 规则
                        yara_matches = self.sig_db.match_yara(text, ext)

                        all_rule_matches = pattern_matches + string_matches + yara_matches
                        if all_rule_matches:
                            worst = "low"
                            names = []
                            for m in all_rule_matches:
                                names.append(m.get("name", "Unknown"))
                                sev = m.get("severity", "low")
                                if sev == "critical":
                                    worst = "critical"
                                elif sev == "high" and worst != "critical":
                                    worst = "high"
                                elif sev == "medium" and worst not in ("critical", "high"):
                                    worst = "medium"

                            if worst == "critical":
                                result.threat_level = ThreatLevel.MALICIOUS
                            elif worst == "high":
                                result.threat_level = ThreatLevel.HIGH_RISK
                            else:
                                result.threat_level = ThreatLevel.SUSPICIOUS

                            result.threat_name = names[0]
                            result.detection_method = f"规则匹配 ({len(all_rule_matches)} 条规则命中)"
                            result.details = f"命中规则: {', '.join(names)}"
                            detected = True
            except (PermissionError, OSError, UnicodeDecodeError):
                pass

        # ---- 第3层：启发式分析 ----
        if not detected:
            heuristic_findings = HeuristicAnalyzer.analyze_file(filepath)
            if heuristic_findings:
                # 取最高威胁等级
                worst_level = ThreatLevel.SAFE
                details_parts = []
                for reason, detail, level in heuristic_findings:
                    details_parts.append(f"[{reason}] {detail}")
                    if level.value > worst_level.value:
                        worst_level = level

                if worst_level != ThreatLevel.SAFE:
                    # 可信路径降级 — 系统目录/Program Files 仅启发式命中时降一级
                    abs_path = str(path.absolute()).lower()
                    is_trusted = any(tp in abs_path for tp in self.TRUSTED_PATHS)
                    if is_trusted:
                        if worst_level == ThreatLevel.MALICIOUS:
                            worst_level = ThreatLevel.HIGH_RISK
                        elif worst_level == ThreatLevel.HIGH_RISK:
                            worst_level = ThreatLevel.SUSPICIOUS
                        elif worst_level == ThreatLevel.SUSPICIOUS:
                            worst_level = ThreatLevel.SAFE
                        details_parts.append("[可信路径] 位于系统目录，已降级处理")

                    if worst_level != ThreatLevel.SAFE:
                        result.threat_level = worst_level
                        result.threat_name = "启发式检测"
                        result.detection_method = "启发式行为分析"
                        result.details = "; ".join(details_parts)
                        detected = worst_level != ThreatLevel.SAFE

        # ---- 第4层：扩展名黑名单快速检查 (仅临时/下载目录) ----
        if not detected:
            ext = path.suffix.lower()
            if ext in self.sig_db.ext_blacklist:
                parent_lower = str(path.parent).lower()
                risky_dirs = ("temp", "tmp", "downloads", "desktop", "appdata\\local\\temp")
                abs_path = str(path.absolute()).lower()
                is_trusted = any(tp in abs_path for tp in self.TRUSTED_PATHS)
                if any(rd in parent_lower for rd in risky_dirs) and not is_trusted:
                    result.threat_level = ThreatLevel.SUSPICIOUS
                    result.threat_name = "可疑文件类型"
                    result.detection_method = "扩展名黑名单"
                    result.details = f"高危扩展名 {ext} 位于下载/临时目录"
                    detected = True

        # ---- 计算熵值（附加信息） ----
        try:
            with open(filepath, "rb") as f:
                sample = f.read(65536)
            result.entropy = HeuristicAnalyzer.calculate_entropy(sample)
        except Exception:
            pass

        return result

    # ----------------------------------------------------------
    # 目录递归扫描
    # ----------------------------------------------------------
    def _count_target_files(
        self,
        target_dir: str,
        recursive: bool = True,
        extensions: Optional[list[str]] = None,
    ) -> int:
        """预统计目标目录下待扫描文件总数（仅枚举目录结构，不读取文件内容）"""
        count = 0
        target_path = Path(target_dir)
        if not target_path.exists():
            return 0
        try:
            if recursive:
                for root, dirs, filenames in os.walk(target_path):
                    if self._cancel_flag.is_set():
                        return count
                    # 跳过系统目录
                    dirs[:] = [d for d in dirs if not self._should_skip_dir(
                        os.path.join(root, d))]
                    for fname in filenames:
                        if extensions:
                            ext = Path(fname).suffix.lower()
                            if ext not in extensions:
                                continue
                        count += 1
            else:
                for entry in target_path.iterdir():
                    if entry.is_file():
                        if extensions:
                            if entry.suffix.lower() not in extensions:
                                continue
                        count += 1
        except (PermissionError, OSError):
            pass
        return count

    def scan_directory(
        self,
        target_dir: str,
        recursive: bool = True,
        extensions: Optional[list[str]] = None,
        _is_sub_scan: bool = False,
        _streaming: bool = False,
    ) -> list[ScanResult]:
        """扫描目录

        Args:
            _is_sub_scan: 内部参数，True 时不 reset（用于 full_scan 多盘符累积）
            _streaming:  流式模式 — 跳过预统计，单次遍历边走边扫边更新 total_files。
                           全盘扫描必须启用，否则预计数耗时数分钟期间 UI 永远显示 0。
        """
        if not _is_sub_scan:
            self.reset()
        self.stats.start_time = datetime.datetime.now().timestamp()

        target_path = Path(target_dir)
        if not target_path.exists():
            return self._results

        if _streaming:
            # ── 流式模式：单次遍历，发现文件即计入总数、立即扫描 ──
            # 全盘扫描时避免"先花几分钟数文件再开始扫"导致 UI 长期显示 0
            return self._streaming_scan(target_dir, recursive, extensions)

        # 预统计文件总数 → 让进度条能从 0 连贯走到 100（小目录够快）
        count = self._count_target_files(target_dir, recursive, extensions)
        if _is_sub_scan:
            self.stats.total_files += count
        else:
            self.stats.total_files = count

        # 边遍历边扫描 — 不再先收集全部文件
        try:
            if recursive:
                for root, dirs, filenames in os.walk(target_path):
                    if self._cancel_flag.is_set():
                        break
                    # 跳过系统目录
                    dirs[:] = [d for d in dirs if not self._should_skip_dir(
                        os.path.join(root, d))]
                    for fname in filenames:
                        if self._cancel_flag.is_set():
                            break
                        fpath = os.path.join(root, fname)
                        if extensions:
                            ext = Path(fname).suffix.lower()
                            if ext not in extensions:
                                continue
                        try:
                            self._scan_one_file(fpath)
                        except ScanCancelled:
                            break
                    if self._cancel_flag.is_set():
                        break
            else:
                for entry in target_path.iterdir():
                    if self._cancel_flag.is_set():
                        break
                    if entry.is_file():
                        if extensions:
                            if entry.suffix.lower() not in extensions:
                                continue
                        try:
                            self._scan_one_file(str(entry))
                        except ScanCancelled:
                            break
        except (PermissionError, OSError):
            pass

        self.stats.end_time = datetime.datetime.now().timestamp()
        return self._results

    # ----------------------------------------------------------
    # 流式扫描 — 单次遍历 + 即时进度（全盘扫描专用）
    # ----------------------------------------------------------
    def _streaming_scan(
        self,
        target_dir: str,
        recursive: bool = True,
        extensions: Optional[list[str]] = None,
    ) -> list[ScanResult]:
        """流式扫描：os.walk 单次遍历，每发现一个文件 → total_files++ → 立即扫描。
        保证第一个文件就能在 UI 上看到进度跳动，不会出现"已扫描: 0"的假死现象。"""
        try:
            if recursive:
                for root, dirs, filenames in os.walk(target_dir):
                    if self._cancel_flag.is_set():
                        break
                    # 跳过系统目录 / 隐藏目录
                    dirs[:] = [
                        d for d in dirs
                        if not self._should_skip_dir(os.path.join(root, d))
                    ]
                    for fname in filenames:
                        if self._cancel_flag.is_set():
                            break
                        fpath = os.path.join(root, fname)
                        if extensions:
                            ext = Path(fname).suffix.lower()
                            if ext not in extensions:
                                continue
                        # 先把文件计入总数（进度条分子/分母同时增长）
                        self.stats.total_files += 1
                        try:
                            self._scan_one_file(fpath)
                        except ScanCancelled:
                            break
                    if self._cancel_flag.is_set():
                        break
            else:
                for entry in Path(target_dir).iterdir():
                    if self._cancel_flag.is_set():
                        break
                    if entry.is_file():
                        if extensions:
                            if entry.suffix.lower() not in extensions:
                                continue
                        self.stats.total_files += 1
                        try:
                            self._scan_one_file(str(entry))
                        except ScanCancelled:
                            break
        except (PermissionError, OSError):
            pass

        self.stats.end_time = datetime.datetime.now().timestamp()
        return self._results

    def _scan_one_file(self, fpath: str):
        """扫描单个文件并更新统计/回调"""
        self.stats.current_file = fpath  # ESET 风格：记录当前扫描文件
        result = self.scan_file(fpath, should_cancel=self._cancel_flag.is_set)
        self.stats.scanned_files += 1

        if result.is_threat:
            self.stats.threats_found += 1
            if result.threat_level == ThreatLevel.SUSPICIOUS:
                self.stats.suspicious_found += 1
            with self._lock:
                self._results.append(result)

        if self._callback:
            self._callback(result)

    # ----------------------------------------------------------
    # 快速扫描 (常见感染位置)
    # ----------------------------------------------------------
    def quick_scan(self) -> list[ScanResult]:
        """快速扫描 — 仅扫描关键目录（累积统计 + 真实进度）"""
        import tempfile

        critical_paths = [
            str(Path.home() / "Downloads"),
            str(Path.home() / "Desktop"),
            str(Path.home() / "Documents"),
            tempfile.gettempdir(),
            str(Path.home() / "AppData" / "Local" / "Temp"),
        ]

        existing = [p for p in critical_paths if os.path.exists(p)]
        self.reset()
        self.stats.start_time = datetime.datetime.now().timestamp()

        for i, p in enumerate(existing):
            if self._cancel_flag.is_set():
                break
            # i=0 正常扫描(含 reset + 计数)，后续作为子扫描累积到同一统计
            self.scan_directory(p, recursive=True, _is_sub_scan=(i > 0))

        self.stats.end_time = datetime.datetime.now().timestamp()
        return self._results

    # ----------------------------------------------------------
    # 全盘扫描
    # ----------------------------------------------------------
    def full_scan(self) -> list[ScanResult]:
        """全盘扫描 — 流式模式，单次遍历边走边扫，第一个文件即有进度反馈"""
        self.reset()
        self.stats.start_time = datetime.datetime.now().timestamp()

        if os.name == "nt":
            # Windows: 扫描所有可用磁盘（全部流式模式）
            import string
            drives = []
            for letter in string.ascii_uppercase:
                drive = f"{letter}:\\"
                if os.path.exists(drive):
                    drives.append(drive)
            # 第一个盘符正常扫描（已 reset），后续标记为子扫描
            for i, drive in enumerate(drives):
                if self._cancel_flag.is_set():
                    break
                self.scan_directory(
                    drive, recursive=True,
                    _is_sub_scan=(i > 0), _streaming=True,
                )
        else:
            # Linux/macOS: 从根目录扫描
            self.scan_directory("/", recursive=True, _is_sub_scan=True, _streaming=True)

        self.stats.end_time = datetime.datetime.now().timestamp()
        return self._results

    @property
    def results(self) -> list[ScanResult]:
        return self._results

    @staticmethod
    def _should_skip_dir(dirpath: str) -> bool:
        """判断是否跳过该目录"""
        dir_lower = dirpath.lower()
        for skip in AntivirusScanner.SKIP_DIRS:
            if skip.lower() in dir_lower:
                return True
        # 跳过隐藏目录
        if os.path.basename(dirpath).startswith("."):
            return True
        return False


# ============================================================
# 隔离区管理
# ============================================================
class QuarantineManager:
    """隔离区 — 安全存储可疑文件"""

    def __init__(self, quarantine_dir: str):
        self.quarantine_dir = Path(quarantine_dir)
        self.quarantine_dir.mkdir(parents=True, exist_ok=True)
        self._index_file = self.quarantine_dir / "index.json"
        self._load_index()

    def _load_index(self):
        self._index: dict[str, dict] = {}
        if self._index_file.exists():
            try:
                with open(self._index_file, "r", encoding="utf-8") as f:
                    self._index = json.load(f)
            except Exception:
                self._index = {}

    def _save_index(self):
        with open(self._index_file, "w", encoding="utf-8") as f:
            json.dump(self._index, f, ensure_ascii=False, indent=2)

    def quarantine_file(self, scan_result: ScanResult) -> bool:
        """将文件移入隔离区 — 分块流式加解密 (大文件也不卡死/不爆内存)"""
        src = Path(scan_result.file_path)
        if not src.exists():
            return False

        # 生成隔离文件名
        import uuid
        q_name = f"{uuid.uuid4().hex}_{src.name}"
        dst = self.quarantine_dir / q_name

        key = hashlib.md5(src.name.encode()).digest()
        try:
            # 分块读取 → 大整数块异或加密(底层 C 实现, 极快) → 立即写入
            # 避免一次性 read() 整个文件导致内存暴涨 / 主线程长时间无响应
            CHUNK = 1 << 16  # 64KB (16 字节密钥的整数倍, 可直接大整数异或)
            key_block = key * (CHUNK // len(key))
            kint = int.from_bytes(key_block, "big")
            with open(src, "rb") as f_in, open(dst, "wb") as f_out:
                while True:
                    chunk = f_in.read(CHUNK)
                    if not chunk:
                        break
                    # 补齐最后一块 (长度不足 CHUNK 时按实际长度重复密钥)
                    if len(chunk) < CHUNK:
                        kb = key * ((len(chunk) // len(key)) + 1)
                        kint = int.from_bytes(kb[:len(chunk)], "big")
                    cint = int.from_bytes(chunk, "big")
                    f_out.write((cint ^ kint).to_bytes(len(chunk), "big"))

            # 删除原文件
            src.unlink()

            # 记录索引
            self._index[q_name] = {
                "original_path": str(src.absolute()),
                "original_name": src.name,
                "file_size": scan_result.file_size,
                "threat_name": scan_result.threat_name,
                "hash_md5": scan_result.hash_md5,
                "hash_sha256": scan_result.hash_sha256,
                "quarantined_at": datetime.datetime.now().isoformat(),
            }
            self._save_index()
            return q_name

        except Exception as e:
            print(f"[!] 隔离失败: {e}")
            # 清理半成品，避免隔离区残留损坏文件
            try:
                if dst.exists():
                    dst.unlink()
            except Exception:
                pass
            return False

    def restore_file(self, quarantine_name: str) -> bool:
        """从隔离区恢复文件"""
        if quarantine_name not in self._index:
            return False

        info = self._index[quarantine_name]
        src = self.quarantine_dir / quarantine_name
        dst = Path(info["original_path"])

        try:
            # 解密
            with open(src, "rb") as f:
                encrypted = f.read()
            key = hashlib.md5(info["original_name"].encode()).digest()
            decrypted = bytes(b ^ key[i % len(key)] for i, b in enumerate(encrypted))

            # 确保目录存在
            dst.parent.mkdir(parents=True, exist_ok=True)

            # 写入原位置
            with open(dst, "wb") as f:
                f.write(decrypted)

            # 删除隔离文件
            src.unlink()
            del self._index[quarantine_name]
            self._save_index()
            return True

        except Exception as e:
            print(f"[!] 恢复失败: {e}")
            return False

    def delete_quarantined(self, quarantine_name: str) -> bool:
        """永久删除隔离文件"""
        if quarantine_name not in self._index:
            return False
        try:
            (self.quarantine_dir / quarantine_name).unlink(missing_ok=True)
            del self._index[quarantine_name]
            self._save_index()
            return True
        except Exception:
            return False

    def list_quarantined(self) -> list[dict]:
        """列出所有隔离文件"""
        result = []
        for qname, info in self._index.items():
            result.append({
                "quarantine_name": qname,
                **info,
            })
        return result

    @property
    def count(self) -> int:
        return len(self._index)
