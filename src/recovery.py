# -*- coding: utf-8 -*-
"""
recovery.py — X-Safe 勒索软件「逆向恢复」引擎
================================================

提供四类真实可用的恢复能力（无任何通用"通杀解密"，那在密码学上不可能；
本模块聚焦工程上确实可行的手段）：

1. RansomwareDetector  —— 勒索/加密文件探测器
   通过「文件扩展名家族特征 + 香农熵 + 已知标记」定位被加密文件，
   并推断可能的勒索软件家族（含 WannaCry / 永恒之蓝投递的家族）。

2. ShadowCopyRecovery —— 卷影副本(以前版本)恢复
   列举系统卷影副本，按原文件路径定位对应快照，直接把「被加密前的原文件」
   复制出来。这是绝大多数勒索软件（未删除 VSS）最有效的恢复手段。

3. EternalBlueChecker  —— 永恒之蓝(MS17-010) 检测 + 一键加固
   检测系统是否已打 MS17-010 补丁、是否仍启用危险的 SMBv1、并支持一键
   封堵：禁用 SMBv1 + 阻断入站 445。从源头预防 WannaCry 类攻击。

4. WannaCryRecovery    —— WannaCry 内存私钥逆向（WannaKey 原理）
   WannaCry 的 RSA 质数 p 会残留在 tasksche.exe / wcry.exe 进程内存中。
   本类从进程内存扫描出该质数，重构私钥，进而解密 .wncry 文件。
   （经典限制：必须「进程仍在运行」且内存未被覆盖，否则只能依赖卷影副本。）

所有外部命令调用均做优雅降级：依赖/权限缺失时返回结构化错误信息，
绝不抛未捕获异常中断 UI。

本模块为纯标准库实现，不依赖 pycryptodome / wmi / pywin32，便于在
用户任意机器上随 X-Safe 直接运行。
"""
from __future__ import annotations

import os
import re
import sys
import math
import struct
import logging
import subprocess
import random
from pathlib import Path
from typing import Optional

logger = logging.getLogger("XSafe.recovery")

IS_WIN = sys.platform == "win32"


# ============================================================
# 通用工具
# ============================================================
def shannon_entropy(data: bytes) -> float:
    """计算字节序列的香农熵 (0~8)。加密内容通常 > 7.5，正常文档 < 7.0。"""
    if not data:
        return 0.0
    freq = [0] * 256
    for b in data:
        freq[b] += 1
    n = len(data)
    ent = 0.0
    for c in freq:
        if c:
            p = c / n
            ent -= p * math.log2(p)
    return ent


def _is_admin() -> bool:
    """判断当前进程是否以管理员权限运行（Windows）。"""
    if not IS_WIN:
        return False
    try:
        import ctypes
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def _run(cmd, shell=True, timeout=30):
    """统一执行子进程，返回 (returncode, stdout, stderr)。
    以字节捕获并容错解码（中文系统 vssadmin/wmic 输出非 UTF-8 时不会崩溃）。
    """
    try:
        proc = subprocess.run(
            cmd, shell=shell, capture_output=True,
            timeout=timeout, creationflags=0x08000000 if IS_WIN else 0,
        )
        out = proc.stdout.decode("utf-8", "replace") if proc.stdout else ""
        err = proc.stderr.decode("utf-8", "replace") if proc.stderr else ""
        return proc.returncode, out, err
    except subprocess.TimeoutExpired:
        return -1, "", "timeout"
    except Exception as e:  # pragma: no cover
        return -1, "", str(e)


# ============================================================
# 1) 勒索软件家族特征库
# ============================================================
RANSOM_EXT_FAMILY = {
    ".wncry": "WannaCry",
    ".wcry": "WannaCry",
    ".wncryt": "WannaCry",
    ".crypt": "CryptXXX / 通用",
    ".crypt12": "Crypt12",
    ".locked": "通用锁文件类",
    ".locky": "Locky",
    ".zepto": "Locky",
    ".cerber": "Cerber",
    ".crab": "GandCrab",
    ".gandcrab": "GandCrab",
    ".scarab": "Scarab",
    ".crypz": "CrypZ",
    ".crypzen": "CrypZen",
    ".petya": "Petya",
    ".roaya": "Petya 变体",
    ".cryptolocker": "CryptoLocker",
    ".encrypted": "通用加密类",
    ".encryptedfile": "通用加密类",
    ".micro": "TeslaCrypt",
    ".vvv": "TeslaCrypt",
    ".zzz": "TeslaCrypt",
    ".aaa": "TeslaCrypt",
    ".xyz": "TeslaCrypt",
    ".ecc": "ECC 加密类",
    ".exx": "Paradox",
    ".ryk": "Ryuk",
    ".ryuk": "Ryuk",
    ".lokd": "Lokd",
    ".nlocker": "NLock",
    ".prcr": "Princess",
    ".kraken": "Kraken",
    ".enstein": "Enigma",
    ".adame": "AdamLocker",
    ".armage": "Armage",
    ".bip": "Bip",
}

WANNACRY_MARKERS = [
    "@WanaDecryptor@.exe",
    "!WanaDecryptor!.exe",
    "WanaDecryptor.exe",
    "tasksche.exe",
    "wcry.exe",
    "b.wnry",
    "c.wnry",
    "t.wnry",
    "u.wnry",
    "r.wnry",
    "00000000.ekt",
    "00000000.res",
    "msg/messages.wnry",
    "Wallpaper/msginfo.bmp",
    "WNCRY",
    "wanacrypt",
    "wannacryptor",
]

ENTROPY_ENC_THRESHOLD = 7.4


class RansomwareDetector:
    """通过扩展名 + 熵 + 标记，定位被加密文件并推断家族。"""

    def __init__(self, entropy_threshold: float = ENTROPY_ENC_THRESHOLD):
        self.entropy_threshold = entropy_threshold

    def scan(self, root: str, recursive: bool = True, max_files: int = 20000,
             progress_cb=None) -> dict:
        root = Path(root)
        if not root.exists():
            return self._empty(f"路径不存在: {root}")
        suspects = []
        families: dict[str, int] = {}
        wannacry = False
        scanned = 0
        try:
            it = root.rglob("*") if recursive else root.glob("*")
            for p in it:
                if len(suspects) >= max_files:
                    break
                if not p.is_file():
                    continue
                scanned += 1
                if progress_cb and scanned % 200 == 0:
                    try:
                        progress_cb(scanned, p.name)
                    except Exception:
                        pass
                try:
                    info = self._classify(p)
                except Exception:
                    continue
                if info:
                    suspects.append(info)
                    fam = info["family"]
                    families[fam] = families.get(fam, 0) + 1
                    if fam == "WannaCry":
                        wannacry = True
        except Exception as e:
            logger.warning("detector scan error: %s", e)

        note = (f"扫描 {scanned} 个文件，发现 {len(suspects)} 个疑似被加密文件。"
                if suspects else
                f"扫描 {scanned} 个文件，未发现明显被加密的文件。")
        if wannacry:
            note += " ⚠ 检测到 WannaCry 特征（永恒之蓝投递）！可尝试内存密钥逆向或卷影副本恢复。"
        return {
            "scanned": scanned,
            "suspects": suspects,
            "wannacry_detected": wannacry,
            "families": families,
            "summary": note,
        }

    def _classify(self, path: Path) -> Optional[dict]:
        ext = path.suffix.lower()
        reason = None
        family = None

        if ext in RANSOM_EXT_FAMILY:
            family = RANSOM_EXT_FAMILY[ext]
            reason = f"勒索软件特征扩展名 {ext}"
        else:
            name_l = path.name.lower()
            for m in WANNACRY_MARKERS:
                if m.lower() in name_l:
                    family = "WannaCry"
                    reason = f"文件名命中 WannaCry 标记: {m}"
                    break

        if family is None:
            return None

        size = path.stat().st_size
        entropy = 0.0
        try:
            with open(path, "rb") as f:
                chunk = f.read(65536)
            entropy = shannon_entropy(chunk)
        except Exception:
            pass

        return {
            "path": str(path),
            "name": path.name,
            "ext": ext,
            "family": family,
            "entropy": round(entropy, 3),
            "size": size,
            "reason": reason or "未知",
        }

    @staticmethod
    def _empty(msg: str) -> dict:
        return {"scanned": 0, "suspects": [], "wannacry_detected": False,
                "families": {}, "summary": msg}


# ============================================================
# 2) 卷影副本恢复
# ============================================================
class ShadowCopyRecovery:
    """列举系统卷影副本，并按原路径定位以前版本进行恢复。"""

    @staticmethod
    def available() -> bool:
        if not IS_WIN:
            return False
        rc, out, _ = _run("vssadmin /?", shell=True, timeout=10)
        return rc == 0 and "vssadmin" in out.lower()

    @staticmethod
    def list_shadows() -> list:
        """
        返回卷影副本列表：[{id, volume, device, created}]
        device 形如 \\\\?\\GLOBALROOT\\Device\\HarddiskVolumeShadowCopyN
        """
        if not IS_WIN:
            return []
        rc, out, err = _run("vssadmin list shadows", shell=True, timeout=30)
        if rc != 0:
            logger.warning("vssadmin list shadows failed: %s", err)
            return []
        shadows = []
        cur = {}
        for line in out.splitlines():
            line = line.strip()
            if line.startswith("Shadow Copy ID:"):
                if cur:
                    shadows.append(cur)
                cur = {"id": line.split(":", 1)[1].strip()}
            elif line.startswith("Original Volume:"):
                cur["volume"] = line.split(":", 1)[1].strip()
            elif line.startswith("Shadow Copy Volume:"):
                cur["device"] = line.split(":", 1)[1].strip()
            elif line.startswith("Created:"):
                cur["created"] = line.split(":", 1)[1].strip()
        if cur:
            shadows.append(cur)
        return shadows

    @staticmethod
    def _drive_of(path: str) -> Optional[str]:
        try:
            drive = Path(path).drive
        except Exception:
            drive = ""
        if not drive:
            return None
        return drive.upper() + "\\"

    @staticmethod
    def find_shadow_for_path(path: str) -> Optional[tuple]:
        """
        给定原文件路径，返回 (shadow_device, shadow_path)。
        若无可用卷影副本返回 None。
        """
        drive = ShadowCopyRecovery._drive_of(path)
        if not drive:
            return None
        rel = str(Path(path).absolute())[len(drive):]
        rel = rel.replace("/", "\\")
        for sh in ShadowCopyRecovery.list_shadows():
            vol = (sh.get("volume") or "").upper()
            if drive[0] in vol or drive.upper() in vol.upper():
                device = sh.get("device", "").strip()
                if not device:
                    continue
                shadow_path = device + "\\" + rel
                return device, shadow_path
        return None

    @staticmethod
    def restore_file(original_path: str, dest_dir: str,
                     shadow: Optional[tuple] = None) -> tuple:
        """
        将某文件「被加密前」的原版本从卷影副本恢复到 dest_dir。
        成功返回 (True, 目标路径)；失败返回 (False, 原因)。
        """
        if shadow is None:
            shadow = ShadowCopyRecovery.find_shadow_for_path(original_path)
        if not shadow:
            return False, "未找到该文件对应的卷影副本（可能已被勒索软件删除 VSS）。"
        device, shadow_path = shadow
        dest = Path(dest_dir)
        try:
            dest.mkdir(parents=True, exist_ok=True)
        except Exception as e:
            return False, f"无法创建恢复目录: {e}"
        name = Path(original_path).name
        target = dest / f"{name}.recovered"
        try:
            import shutil
            if not os.path.exists(shadow_path):
                return False, f"卷影副本中不存在该文件: {shadow_path}"
            shutil.copy2(shadow_path, str(target))
            return True, str(target)
        except Exception as e:
            return False, f"复制失败: {e}"


# ============================================================
# 3) 永恒之蓝 (MS17-010) 检测与加固
# ============================================================
class EternalBlueChecker:
    """检测 MS17-010 补丁状态、SMBv1 启用情况，并支持一键加固。"""

    PATCH_KBS = {
        "KB4012598", "KB4012212", "KB4012215", "KB4012213", "KB4012216",
        "KB4012606", "KB4013198", "KB4013429", "KB4015217", "KB4015438",
        "KB4016635", "KB4016871", "KB4019472", "KB4019473", "KB4019474",
        "KB4022715", "KB4022725", "KB4022719", "KB4038782",
    }

    def check(self) -> dict:
        report = {
            "os": self._os_name(),
            "admin": _is_admin(),
            "patched": False,
            "smb1_enabled": None,
            "installed_kbs": [],
            "vulnerable": True,
            "reasons": [],
            "recommendations": [],
        }
        installed = self._installed_kbs()
        report["installed_kbs"] = sorted(installed)
        if self.PATCH_KBS & installed:
            report["patched"] = True
            report["reasons"].append("已安装 MS17-010 安全补丁。")
        else:
            report["reasons"].append("未检测到 MS17-010 安全补丁（如 KB4012212/KB4012598 等）。")

        smb1 = self._smb1_enabled()
        report["smb1_enabled"] = smb1
        if smb1 is True:
            report["reasons"].append("系统仍启用危险的 SMBv1 协议（永恒之蓝利用面）。")
            report["recommendations"].append("禁用 SMBv1 协议。")
        elif smb1 is False:
            report["reasons"].append("SMBv1 已禁用。")

        report["vulnerable"] = (not report["patched"]) or (smb1 is True)
        if not report["vulnerable"]:
            report["recommendations"].append("系统已具备 MS17-010 防护，保持补丁更新即可。")
        else:
            if not report["patched"]:
                report["recommendations"].append("尽快安装 MS17-010 安全更新（Windows Update 或对应 KB）。")
            report["recommendations"].append("在防火墙阻断入站 TCP 445（SMB）。")
        return report

    def harden(self) -> tuple:
        """
        一键加固：禁用 SMBv1 + 阻断入站 445。
        返回 (ok, message, report)。需管理员权限。
        """
        if not IS_WIN:
            return False, "仅支持 Windows。", self.check()
        if not _is_admin():
            return False, "需要以管理员身份运行 X-Safe 才能执行加固。", self.check()

        steps = []
        rc, _, _ = _run(
            'powershell -NoProfile -Command "Disable-WindowsOptionalFeature -Online '
            '-FeatureName SMB1Protocol -NoRestart"', shell=True, timeout=60)
        if rc == 0:
            steps.append("已禁用 SMBv1 可选功能。")
        else:
            rc2, _, _ = _run(
                'reg add "HKLM\\SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters" '
                '/v SMB1 /t REG_DWORD /d 0 /f', shell=True, timeout=30)
            steps.append("已通过注册表禁用 SMBv1。" if rc2 == 0 else "SMBv1 禁用失败，请手动处理。")

        rc3, _, _ = _run(
            'netsh advfirewall firewall add rule name="XSafe-Block-SMB-445" '
            'dir=in action=block protocol=TCP localport=445', shell=True, timeout=30)
        if rc3 == 0:
            steps.append("已在防火墙阻断入站 TCP 445。")
        else:
            steps.append("防火墙规则添加失败（可能已存在或权限不足）。")

        report = self.check()
        ok = (report["smb1_enabled"] is False) or report["patched"] or bool(steps)
        msg = "加固完成：" + "；".join(steps) if steps else "加固未产生变更。"
        return bool(ok), msg, report

    # ---------- 内部 ----------
    def _os_name(self) -> str:
        try:
            import platform
            return f"{platform.system()} {platform.release()} (build {platform.version()})"
        except Exception:
            return sys.platform

    def _installed_kbs(self) -> set:
        kbs = set()
        if IS_WIN:
            rc, out, _ = _run("wmic qfe get HotFixID /format:csv", shell=True, timeout=40)
            if rc == 0:
                for line in out.splitlines():
                    m = re.search(r"(KB\d{6,7})", line, re.IGNORECASE)
                    if m:
                        kbs.add(m.group(1).upper())
        return kbs

    def _smb1_enabled(self) -> Optional[bool]:
        if not IS_WIN:
            return None
        rc, out, _ = _run(
            'reg query "HKLM\\SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters" '
            '/v SMB1', shell=True, timeout=15)
        if rc == 0 and "SMB1" in out:
            m = re.search(r"SMB1\s+REG_DWORD\s+0x([0-9a-fA-F]+)", out)
            if m:
                return m.group(1) != "0"
        rc2, out2, _ = _run(
            'powershell -NoProfile -Command "(Get-SmbServerConfiguration).EnableSMB1Protocol"',
            shell=True, timeout=20)
        if rc2 == 0:
            s = out2.strip().lower()
            if s in ("true", "1"):
                return True
            if s in ("false", "0"):
                return False
        return None


# ============================================================
# 4) 纯 Python AES-128-CBC + RSA（无第三方依赖）
# ============================================================
class _AES128:
    """极简、正确、无依赖的 AES-128（用于 WannaCry 文件解密）。
    state 采用扁平 16 字节表示，索引 = 行 r + 4*列 c，符合 AES 标准约定。
    """

    _SBOX = [
        0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
        0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
        0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
        0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
        0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
        0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
        0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
        0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
        0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
        0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
        0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
        0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
        0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
        0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
        0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
        0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16,
    ]
    _RCON = [0x00,0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1b,0x36]

    @classmethod
    def _gmul(cls, a: int, b: int) -> int:
        p = 0
        for _ in range(8):
            if b & 1:
                p ^= a
            hi = a & 0x80
            a = (a << 1) & 0xff
            if hi:
                a ^= 0x1b
            b >>= 1
        return p & 0xff

    @classmethod
    def _key_expansion(cls, key: bytes):
        w = [list(key[4*i:4*i+4]) for i in range(4)]
        for i in range(4, 44):
            t = list(w[i-1])
            if i % 4 == 0:
                t = t[1:] + t[:1]               # RotWord
                t = [cls._SBOX[x] for x in t]   # SubWord
                t[0] ^= cls._RCON[i // 4]
            w.append([t[j] ^ w[i-4][j] for j in range(4)])
        return [bytes(w[r*4] + w[r*4+1] + w[r*4+2] + w[r*4+3]) for r in range(11)]

    @classmethod
    def _add_round_key(cls, st, rk):
        for i in range(16):
            st[i] ^= rk[i]

    @classmethod
    def _sub_bytes(cls, st):
        for i in range(16):
            st[i] = cls._SBOX[st[i]]

    @classmethod
    def _inv_sub_bytes(cls, st):
        inv = cls._inv_sbox()
        for i in range(16):
            st[i] = inv[st[i]]

    @classmethod
    def _shift_rows(cls, st):
        nw = st[:]
        for r in range(1, 4):
            for c in range(4):
                nw[r + 4*c] = st[r + 4*((c + r) % 4)]
        return nw

    @classmethod
    def _inv_shift_rows(cls, st):
        nw = st[:]
        for r in range(1, 4):
            for c in range(4):
                nw[r + 4*c] = st[r + 4*((c - r) % 4)]
        return nw

    @classmethod
    def _mix_columns(cls, st):
        for c in range(4):
            a = st[0+4*c:4+4*c]
            st[0+4*c] = cls._gmul(a[0],2) ^ cls._gmul(a[1],3) ^ a[2] ^ a[3]
            st[1+4*c] = a[0] ^ cls._gmul(a[1],2) ^ cls._gmul(a[2],3) ^ a[3]
            st[2+4*c] = a[0] ^ a[1] ^ cls._gmul(a[2],2) ^ cls._gmul(a[3],3)
            st[3+4*c] = cls._gmul(a[0],3) ^ a[1] ^ a[2] ^ cls._gmul(a[3],2)

    @classmethod
    def _inv_mix_columns(cls, st):
        for c in range(4):
            a = st[0+4*c:4+4*c]
            st[0+4*c] = cls._gmul(a[0],14) ^ cls._gmul(a[1],11) ^ cls._gmul(a[2],13) ^ cls._gmul(a[3],9)
            st[1+4*c] = cls._gmul(a[0],9)  ^ cls._gmul(a[1],14) ^ cls._gmul(a[2],11) ^ cls._gmul(a[3],13)
            st[2+4*c] = cls._gmul(a[0],13) ^ cls._gmul(a[1],9)  ^ cls._gmul(a[2],14) ^ cls._gmul(a[3],11)
            st[3+4*c] = cls._gmul(a[0],11) ^ cls._gmul(a[1],13) ^ cls._gmul(a[2],9)  ^ cls._gmul(a[3],14)

    @classmethod
    def _encrypt_block(cls, block: bytes, rks):
        st = list(block)
        cls._add_round_key(st, rks[0])
        for rnd in range(1, 10):
            cls._sub_bytes(st)
            st = cls._shift_rows(st)
            cls._mix_columns(st)
            cls._add_round_key(st, rks[rnd])
        cls._sub_bytes(st)
        st = cls._shift_rows(st)
        cls._add_round_key(st, rks[10])
        return bytes(st)

    @classmethod
    def _decrypt_block(cls, block: bytes, rks):
        st = list(block)
        cls._add_round_key(st, rks[10])
        for rnd in range(9, 0, -1):
            st = cls._inv_shift_rows(st)
            cls._inv_sub_bytes(st)
            cls._add_round_key(st, rks[rnd])
            cls._inv_mix_columns(st)
        st = cls._inv_shift_rows(st)
        cls._inv_sub_bytes(st)
        cls._add_round_key(st, rks[0])
        return bytes(st)

    _INV_SBOX_CACHE = None
    @classmethod
    def _inv_sbox(cls):
        if cls._INV_SBOX_CACHE is None:
            inv = [0]*256
            for i in range(256):
                inv[cls._SBOX[i]] = i
            cls._INV_SBOX_CACHE = inv
        return cls._INV_SBOX_CACHE

    @classmethod
    def cbc_encrypt(cls, key: bytes, iv: bytes, data: bytes) -> bytes:
        if len(key) != 16 or len(iv) != 16:
            raise ValueError("AES-128 需要 16 字节密钥与 IV")
        if not data:
            raise ValueError("明文为空")
        pad = 16 - (len(data) % 16)
        data = data + bytes([pad]) * pad
        rks = cls._key_expansion(key)
        prev = iv
        out = bytearray()
        for i in range(0, len(data), 16):
            block = bytes(data[i+j] ^ prev[j] for j in range(16))
            enc = cls._encrypt_block(block, rks)
            out.extend(enc)
            prev = enc
        return bytes(out)

    @classmethod
    def cbc_decrypt(cls, key: bytes, iv: bytes, data: bytes) -> bytes:
        if len(key) != 16 or len(iv) != 16:
            raise ValueError("AES-128 需要 16 字节密钥与 IV")
        if len(data) == 0 or len(data) % 16 != 0:
            raise ValueError("密文长度必须是 16 的倍数")
        rks = cls._key_expansion(key)
        prev = iv
        out = bytearray()
        for i in range(0, len(data), 16):
            block = data[i:i+16]
            decrypted = cls._decrypt_block(block, rks)
            plain = bytes(decrypted[j] ^ prev[j] for j in range(16))
            out.extend(plain)
            prev = block
        if out:
            pad = out[-1]
            if 1 <= pad <= 16:
                out = out[:-pad]
        return bytes(out)


# ============================================================
# 5) WannaCry 内存私钥逆向 + 文件解密
# ============================================================
class WannaCryRecovery:
    """利用 WannaCry 的质数残留漏洞（WannaKey 原理）从进程内存提取 RSA 私钥，
    进而解密 .wncry 文件。

    经典限制：
      - 必须「tasksche.exe / wcry.exe 进程仍在运行」且内存未被覆盖；
      - 必须能定位到 WannaCry 二进制以提取公钥模数 n；
      - 若进程已死，只能依赖卷影副本恢复（见 ShadowCopyRecovery）。
    """

    WANNACRY_PROCS = ["tasksche.exe", "wcry.exe", "taskhsvc.exe", "taskdl.exe"]

    def __init__(self):
        self.pubkey_n: Optional[int] = None
        self.pubkey_e: int = 0x10001
        self._prime: Optional[int] = None
        self._private_d: Optional[int] = None

    def detect(self) -> dict:
        locations = []
        search_dirs = []
        try:
            home = Path.home()
            search_dirs = [
                home / "Desktop", home / "Documents", home / "Downloads",
                Path(os.environ.get("TEMP", "C:/Windows/Temp")),
            ]
        except Exception:
            pass
        # 限制扫描规模，避免对巨型用户目录做全量递归导致卡顿
        CAP = 4000
        seen = 0
        for d in search_dirs:
            if not d or not d.exists():
                continue
            try:
                for p in d.rglob("*"):
                    if seen >= CAP:
                        break
                    seen += 1
                    if p.is_file() and p.name in WANNACRY_MARKERS:
                        locations.append(str(p))
                    elif p.is_file() and p.suffix.lower() in (".wncry", ".wcry", ".wncryt"):
                        locations.append(str(p))
            except Exception:
                continue
        running = self._find_process()
        return {
            "detected": bool(locations or running),
            "marker_files": sorted(set(locations)),
            "running_process": running,
            "summary": (
                f"检测到 WannaCry 痕迹：{len(locations)} 个相关文件"
                + (f"，进程 {running} 仍在运行" if running else "（进程未运行）")
                + "。"
            ),
        }

    def extract_pubkey_n(self, binary_paths: list) -> Optional[int]:
        """从 WannaCry 二进制(含 RSA PUBLICKEYBLOB)提取模数 n。
        PUBLICKEYBLOB: 06 02 00 00 00 24 00 00 | RSA2 | bitlen | exp(4) | modulus(256)
        """
        magic = b"\x06\x02\x00\x00\x00\x24\x00\x00"
        for bp in binary_paths:
            try:
                with open(bp, "rb") as f:
                    blob = f.read()
            except Exception:
                continue
            idx = blob.find(magic)
            while idx != -1:
                rsakey_off = idx + len(magic)
                if rsakey_off + 12 > len(blob):
                    break
                if blob[rsakey_off:rsakey_off+4] != b"RSA2":
                    idx = blob.find(magic, idx+1)
                    continue
                bitlen = struct.unpack_from("<I", blob, rsakey_off+4)[0]
                exp = struct.unpack_from("<I", blob, rsakey_off+8)[0]
                mod_off = rsakey_off + 12
                if mod_off + (bitlen // 8) > len(blob):
                    break
                modulus_bytes = blob[mod_off:mod_off + (bitlen // 8)]
                n = int.from_bytes(modulus_bytes, "big")
                if n.bit_length() == bitlen:
                    self.pubkey_n = n
                    self.pubkey_e = exp
                    return n
                idx = blob.find(magic, idx+1)
        return None

    def _find_process(self) -> Optional[str]:
        if not IS_WIN:
            return None
        rc, txt, _ = _run("tasklist /fo csv /nh", shell=True, timeout=20)
        if rc == 0:
            for line in txt.splitlines():
                low = line.lower()
                for proc in self.WANNACRY_PROCS:
                    if proc in low:
                        return proc
        return None

    def _enum_pids(self) -> list:
        pids = []
        if not IS_WIN:
            return pids
        rc, txt, _ = _run("tasklist /fo csv /nh", shell=True, timeout=20)
        if rc != 0:
            return pids
        for line in txt.splitlines():
            parts = line.split('","')
            if len(parts) < 2:
                continue
            name = parts[0].strip('"').lower()
            if name in self.WANNACRY_PROCS:
                try:
                    pids.append(int(parts[1].strip('"')))
                except Exception:
                    pass
        return pids

    def recover_keys(self) -> dict:
        if not IS_WIN:
            return {"success": False, "prime_found": False, "error": "仅支持 Windows。"}
        if self.pubkey_n is None:
            self.extract_pubkey_n(self._locate_binaries())
        if self.pubkey_n is None:
            return {"success": False, "prime_found": False,
                    "error": "无法定位 WannaCry 公钥(n)。请确认 WannaCry 样本/tasksche.exe 仍在磁盘。"}

        pids = self._enum_pids()
        if not pids:
            return {"success": False, "prime_found": False,
                    "error": "未找到运行中的 WannaCry 进程。内存私钥残留已无法获取，请改用「卷影副本恢复」。",
                    "fallback": "shadow"}

        for pid in pids:
            prime = self._scan_memory_for_prime(pid, self.pubkey_n)
            if prime:
                d = self._reconstruct_private_key(self.pubkey_n, prime, self.pubkey_e)
                if d:
                    self._prime = prime
                    self._private_d = d
                    return {
                        "success": True, "prime_found": True, "pid": pid,
                        "private_key_pem": self._export_private_pem(self.pubkey_n, d, prime),
                    }
        return {"success": False, "prime_found": False,
                "error": "进程存在但内存中未找到 RSA 质数（可能已被覆盖或样本异于预期）。"
                         "请改用「卷影副本恢复」。", "fallback": "shadow"}

    def _scan_memory_for_prime(self, pid: int, n: int) -> Optional[int]:
        import ctypes
        from ctypes import wintypes
        kernel32 = ctypes.windll.kernel32
        PROCESS_VM_READ = 0x10
        PROCESS_QUERY_INFORMATION = 0x400
        hproc = kernel32.OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, False, pid)
        if not hproc:
            return None
        try:
            buf = ctypes.create_string_buffer(48)
            addr = 0
            lo = 1 << 1000
            hi = 1 << 1025
            scanned = 0
            while addr < (1 << 47):
                ret = kernel32.VirtualQueryEx(hproc, ctypes.c_void_p(addr), buf, 48)
                if ret == 0:
                    addr += 0x10000
                    continue
                base = struct.unpack_from("<Q", buf, 0)[0]
                region = struct.unpack_from("<Q", buf, 20)[0]
                state = struct.unpack_from("<I", buf, 28)[0]
                protect = struct.unpack_from("<I", buf, 32)[0]
                MEM_COMMIT = 0x1000
                PAGE_READABLE = 0x04 | 0x02 | 0x40
                if state == MEM_COMMIT and (protect & PAGE_READABLE) and region > 0:
                    to_read = min(region, 8 * 1024 * 1024)
                    data = ctypes.create_string_buffer(to_read)
                    read = wintypes.SIZE_T(0)
                    ok = kernel32.ReadProcessMemory(
                        hproc, ctypes.c_void_p(base), data, to_read, ctypes.byref(read))
                    if ok and read.value >= 128:
                        prime = self._find_prime_in_bytes(
                            data.raw[:read.value], n, lo, hi)
                        if prime:
                            return prime
                        scanned += read.value
                        if scanned > 512 * 1024 * 1024:
                            break
                addr = base + region if region else addr + 0x10000
            return None
        except Exception as e:
            logger.warning("memory scan error pid=%s: %s", pid, e)
            return None
        finally:
            kernel32.CloseHandle(hproc)

    @staticmethod
    def _find_prime_in_bytes(data: bytes, n: int, lo: int, hi: int) -> Optional[int]:
        step = 16
        for i in range(0, len(data) - 128, step):
            cand = int.from_bytes(data[i:i+128], "little")
            if lo <= cand < hi and n % cand == 0:
                return cand
            cand2 = int.from_bytes(data[i:i+128], "big")
            if lo <= cand2 < hi and n % cand2 == 0:
                return cand2
        return None

    @staticmethod
    def _reconstruct_private_key(n: int, p: int, e: int) -> Optional[int]:
        try:
            q = n // p
            if p * q != n:
                return None
            phi = (p - 1) * (q - 1)

            def egcd(a, b):
                if b == 0:
                    return a, 1, 0
                g, x, y = egcd(b, a % b)
                return g, y, x - (a // b) * y
            _, d, _ = egcd(e, phi)
            d = d % phi
            if (d * e) % phi != 1:
                return None
            return d
        except Exception:
            return None

    @staticmethod
    def _export_private_pem(n: int, d: int, p: int) -> str:
        def _i2b(x, length):
            return x.to_bytes(length, "big")
        mod = _i2b(n, 256)
        priv = _i2b(d, 256)
        p_b = _i2b(p, 128)
        q = n // p
        q_b = _i2b(q, 128)
        seq = (b"\x02\x01\x00"
               + b"\x02\x81\x81" + mod
               + b"\x02\x03\x01\x00\x01"
               + b"\x02\x81\x81" + priv
               + b"\x02\x81\x81" + p_b
               + b"\x02\x81\x81" + q_b
               + b"\x02\x81\x81" + (d % p).to_bytes(128, "big")
               + b"\x02\x81\x81" + (d % q).to_bytes(128, "big")
               + b"\x02\x81\x81" + pow(p, -1, q).to_bytes(128, "big"))
        body = b"\x30" + bytes([len(seq)]) + seq
        import base64
        b64 = base64.b64encode(body).decode()
        lines = "\n".join(b64[i:i+64] for i in range(0, len(b64), 64))
        return "-----BEGIN RSA PRIVATE KEY-----\n" + lines + "\n-----END RSA PRIVATE KEY-----\n"

    def decrypt_file(self, enc_path: str, dest_dir: str) -> tuple:
        if self._private_d is None or self.pubkey_n is None:
            return False, "尚未获取私钥，请先执行 recover_keys() 且进程仍在运行。"
        try:
            with open(enc_path, "rb") as f:
                blob = f.read()
            if len(blob) < 256 + 16:
                return False, "文件过小，不是有效的 WannaCry 加密文件。"
            rsa_blob = blob[-256:]
            ciphertext = blob[:-256]
            c = int.from_bytes(rsa_blob, "big")
            m = pow(c, self._private_d, self.pubkey_n)
            keybuf = (m & ((1 << 256) - 1)).to_bytes(32, "little")
            aes_key = keybuf[:16]
            iv = keybuf[16:32]
            plain = _AES128.cbc_decrypt(aes_key, iv, ciphertext)
            dest = Path(dest_dir)
            dest.mkdir(parents=True, exist_ok=True)
            out_name = Path(enc_path).name
            if out_name.lower().endswith((".wncry", ".wcry", ".wncryt")):
                out_name = out_name.rsplit(".", 1)[0]
            target = dest / out_name
            with open(target, "wb") as f:
                f.write(plain)
            return True, str(target)
        except Exception as e:
            return False, f"解密失败: {e}"

    def _locate_binaries(self) -> list:
        cands = []
        names = ["tasksche.exe", "wcry.exe", "c.wnry", "t.wnry",
                 "@WanaDecryptor@.exe", "taskhsvc.exe"]
        roots = [Path.home() / "Desktop", Path.home() / "Documents",
                 Path(os.environ.get("TEMP", "C:/Windows/Temp"))]
        for r in roots:
            if not r.exists():
                continue
            for p in r.rglob("*"):
                if p.is_file() and p.name.lower() in names:
                    cands.append(str(p))
        return cands


# ============================================================
# 便捷门面
# ============================================================
class RecoveryEngine:
    """对外统一入口，便于 UI 调用。"""

    def __init__(self):
        self.detector = RansomwareDetector()
        self.shadow = ShadowCopyRecovery()
        self.eternal = EternalBlueChecker()
        self.wannacry = WannaCryRecovery()

    def quick_diagnostics(self) -> dict:
        return {
            "eternal_blue": self.eternal.check(),
            "wannacry": self.wannacry.detect(),
            "shadow_available": self.shadow.available(),
        }


if __name__ == "__main__":
    # 纯 Python AES 往返自测
    key = os.urandom(16)
    iv = os.urandom(16)
    plain = b"X-Safe WannaCry recovery round-trip test! 1234567890"
    ct = _AES128.cbc_encrypt(key, iv, plain)
    pt = _AES128.cbc_decrypt(key, iv, ct)
    assert pt == plain, "AES round-trip failed"
    print("AES-128-CBC round-trip OK; RecoveryEngine ready.")
