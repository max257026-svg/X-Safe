"""
X-Safe — 白名单 / 信任区引擎 (Whitelist Engine)
Whitelist / Trusted-Zone engine: 受信任的文件 (路径或哈希) 在扫描时直接判定安全，
不会被实时防护、手动扫描或系统敏感文件防护误报。

【自保护机制】XSafe 自身可执行文件 + PyInstaller _internal 运行时目录
会被自动加入白名单，扫描时绝不会被误报。避免出现"自己杀自己"。
"""

import os
import sys
import time
import uuid
import threading
import hashlib
from pathlib import Path
from typing import Optional, List


def _normalize_path(path: str) -> str:
    """规范化路径用于精确匹配 (大小写/分隔符归一)"""
    try:
        return os.path.normcase(os.path.abspath(path))
    except Exception:
        return str(path).strip().lower()


def _sha256_of_file(filepath: str) -> Optional[str]:
    """计算文件 SHA-256 (失败返回 None)"""
    try:
        h = hashlib.sha256()
        with open(filepath, "rb") as f:
            for chunk in iter(lambda: f.read(1 << 16), b""):
                h.update(chunk)
        return h.hexdigest()
    except Exception:
        return None


def _detect_self_protection_paths() -> List[str]:
    """检测 XSafe 自身的可执行文件路径与 _internal 运行时目录。
    返回所有需要默认信任的绝对路径列表。
    兼容源码运行 / PyInstaller frozen / onedir 打包三种模式。
    """
    paths: list[str] = []
    try:
        # PyInstaller 冻结后，sys.executable 即 XSafe.exe
        exe = os.path.abspath(sys.executable)
        if exe and os.path.isfile(exe):
            paths.append(exe)
            # onedir 模式：同目录下的 _internal/
            internal_dir = os.path.join(os.path.dirname(exe), "_internal")
            if os.path.isdir(internal_dir):
                paths.append(internal_dir)
        # 源码运行：sys.argv[0] 即 main.py
        argv0 = os.path.abspath(sys.argv[0]) if sys.argv else ""
        if argv0 and os.path.isfile(argv0):
            paths.append(argv0)
    except Exception:
        pass
    # 去重 + 过滤不存在的
    out: list[str] = []
    seen = set()
    for p in paths:
        try:
            if os.path.exists(p):
                n = _normalize_path(p)
                if n not in seen:
                    seen.add(n)
                    out.append(p)
        except Exception:
            continue
    return out


class WhitelistEngine:
    """信任区引擎 — 管理受信任文件清单 (持久化到 trusted.json)"""

    def __init__(self, store_path: str = "trusted.json"):
        self._store = Path(store_path)
        self._entries: list[dict] = []   # [{id, name, path, sha256, added_at, note}]
        self._lock = threading.Lock()
        # 自保护路径（不写入 trusted.json，避免污染用户信任区列表）
        self._self_protected: list[str] = []
        self._load()
        # 启动时自动识别 XSafe 自身路径并加入自保护
        try:
            self.add_self_protection()
        except Exception:
            pass

    # ----------------------------------------------------------
    # 自保护：避免自己杀自己
    # ----------------------------------------------------------
    def add_self_protection(self) -> List[str]:
        """检测并加入 XSafe 自身可执行文件 / _internal 目录到自保护列表。
        返回新加入的路径列表。多次调用幂等。"""
        added: list[str] = []
        for p in _detect_self_protection_paths():
            np = _normalize_path(p)
            if np not in [os.path.normcase(x) for x in self._self_protected]:
                self._self_protected.append(p)
                added.append(p)
        return added

    @property
    def self_protected_paths(self) -> List[str]:
        """返回当前自保护路径列表的副本"""
        with self._lock:
            return list(self._self_protected)

    def is_self_protected(self, file_path: Optional[str]) -> bool:
        """判断路径是否落在 XSafe 自保护范围内（自身 exe / _internal 目录）
        命中规则：路径等于自保护路径，或其父目录链路上有自保护目录。
        """
        if not file_path:
            return False
        try:
            target = _normalize_path(file_path)
            with self._lock:
                prot_set = [os.path.normcase(x) for x in self._self_protected]
            for p in prot_set:
                if target == p:
                    return True
                # 目录保护：target 以 p + os.sep 开头
                if target.startswith(p + os.sep):
                    return True
                # 反向：target 是 p 的父级（不可能，但兼容）
            # 兜底：直接看绝对路径是否在 _internal 目录下
            try:
                ap = os.path.abspath(file_path).lower()
                if "\\_internal\\" in ap or "/_internal/" in ap:
                    return True
            except Exception:
                pass
        except Exception:
            return False
        return False

    # ----------------------------------------------------------
    # 持久化
    # ----------------------------------------------------------
    def _load(self):
        try:
            if self._store.exists():
                import json
                with open(self._store, "r", encoding="utf-8") as f:
                    data = json.load(f)
                if isinstance(data, list):
                    self._entries = data
        except Exception:
            self._entries = []

    def _save(self):
        try:
            import json
            with open(self._store, "w", encoding="utf-8") as f:
                json.dump(self._entries, f, ensure_ascii=False, indent=2)
        except Exception:
            pass

    # ----------------------------------------------------------
    # 增删查
    # ----------------------------------------------------------
    def add(self, file_path: str, sha256: Optional[str] = None,
            note: str = "") -> dict:
        """添加受信任文件。返回新增/已存在的条目。"""
        norm = _normalize_path(file_path)
        with self._lock:
            # 去重：同一路径不重复添加
            for e in self._entries:
                if e.get("path_norm") == norm:
                    e["note"] = note or e.get("note", "")
                    self._save()
                    return e
            sha = sha256 or _sha256_of_file(file_path)
            entry = {
                "id": uuid.uuid4().hex,
                "name": os.path.basename(file_path),
                "path": file_path,
                "path_norm": norm,
                "sha256": sha,
                "added_at": time.strftime("%Y-%m-%d %H:%M:%S"),
                "note": note,
            }
            self._entries.append(entry)
            self._save()
            return entry

    def remove(self, entry_id: str) -> bool:
        """按条目 ID 移除"""
        with self._lock:
            before = len(self._entries)
            self._entries = [e for e in self._entries if e.get("id") != entry_id]
            changed = len(self._entries) != before
            if changed:
                self._save()
            return changed

    def remove_by_path(self, file_path: str) -> bool:
        """按路径移除"""
        norm = _normalize_path(file_path)
        with self._lock:
            before = len(self._entries)
            self._entries = [e for e in self._entries if e.get("path_norm") != norm]
            changed = len(self._entries) != before
            if changed:
                self._save()
            return changed

    def is_trusted(self, file_path: Optional[str] = None,
                   sha256: Optional[str] = None) -> bool:
        """判断文件是否受信任 (路径精确匹配 或 哈希匹配)"""
        with self._lock:
            if file_path:
                norm = _normalize_path(file_path)
                for e in self._entries:
                    if e.get("path_norm") == norm:
                        return True
            if sha256:
                s = sha256.lower()
                for e in self._entries:
                    if e.get("sha256") and e["sha256"].lower() == s:
                        return True
        return False

    def list_entries(self) -> list[dict]:
        """返回全部受信任条目副本"""
        with self._lock:
            return [dict(e) for e in self._entries]

    @property
    def count(self) -> int:
        with self._lock:
            return len(self._entries)
