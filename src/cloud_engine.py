"""
云查杀引擎 — 接入在线病毒库
支持: VirusTotal API v3 + 360云查杀模拟接口
"""

import hashlib
import json
import os
import threading
import time
import urllib.request
import urllib.error
from pathlib import Path
from typing import Optional


class CloudScanResult:
    """云查杀结果"""

    def __init__(self):
        self.file_hash: str = ""
        self.cloud_name: str = ""          # 云引擎名称
        self.detections: int = 0            # 检出数
        self.total_engines: int = 0         # 总引擎数
        self.threat_names: list[str] = []   # 各引擎检出名称
        self.confidence: float = 0.0        # 置信度 0-1
        self.is_malicious: bool = False
        self.query_time: float = 0.0
        self.cached: bool = False
        self.error: str = ""

    @property
    def detection_ratio(self) -> str:
        if self.total_engines == 0:
            return "0/0"
        return f"{self.detections}/{self.total_engines}"

    def __repr__(self):
        return f"CloudScanResult({self.cloud_name}: {self.detection_ratio}, malicious={self.is_malicious})"


class CloudScanCache:
    """本地缓存 — 避免重复查询"""

    def __init__(self, cache_path: str):
        self.cache_path = Path(cache_path)
        self._cache: dict[str, dict] = {}
        self._lock = threading.Lock()
        self._load()

    def _load(self):
        if self.cache_path.exists():
            try:
                with open(self.cache_path, "r", encoding="utf-8") as f:
                    self._cache = json.load(f)
            except Exception:
                self._cache = {}

    def _save(self):
        try:
            self.cache_path.parent.mkdir(parents=True, exist_ok=True)
            with open(self.cache_path, "w", encoding="utf-8") as f:
                json.dump(self._cache, f, ensure_ascii=False, indent=2)
        except Exception:
            pass

    def get(self, file_hash: str) -> Optional[dict]:
        with self._lock:
            entry = self._cache.get(file_hash)
            if entry:
                # 缓存有效期 7 天
                if time.time() - entry.get("timestamp", 0) < 7 * 86400:
                    return entry
            return None

    def put(self, file_hash: str, result: dict):
        with self._lock:
            result["timestamp"] = time.time()
            self._cache[file_hash] = result
            self._save()

    @property
    def size(self) -> int:
        return len(self._cache)


class VirusTotalEngine:
    """VirusTotal API v3 引擎

    免费 API: 4 请求/分钟, 500 次/天, 15300 次/月
    需要 API Key: https://www.virustotal.com/gui/my-apikey
    """

    API_BASE = "https://www.virustotal.com/api/v3"

    def __init__(self, api_key: str = ""):
        self.api_key = api_key
        self.name = "VirusTotal"
        self.enabled = bool(api_key)
        self._last_query_time = 0.0
        self._min_interval = 16.0  # 4次/分钟 → 每16秒一次

    def query_hash(self, file_hash: str) -> Optional[dict]:
        """查询文件哈希"""
        if not self.enabled:
            return None

        # 限速
        elapsed = time.time() - self._last_query_time
        if elapsed < self._min_interval:
            time.sleep(self._min_interval - elapsed)

        self._last_query_time = time.time()

        url = f"{self.API_BASE}/files/{file_hash}"
        req = urllib.request.Request(url)
        req.add_header("x-apikey", self.api_key)
        req.add_header("Accept", "application/json")

        try:
            with urllib.request.urlopen(req, timeout=15) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                attrs = data.get("data", {}).get("attributes", {})
                stats = attrs.get("last_analysis_stats", {})
                results = attrs.get("last_analysis_results", {})

                threat_names = []
                for engine, info in results.items():
                    if info.get("category") == "malicious":
                        threat_names.append(f"{engine}: {info.get('result', 'N/A')}")

                return {
                    "cloud_name": self.name,
                    "detections": stats.get("malicious", 0),
                    "total_engines": sum(stats.values()) if stats else 0,
                    "threat_names": threat_names[:10],
                    "is_malicious": stats.get("malicious", 0) >= 3,
                    "confidence": min(1.0, stats.get("malicious", 0) / max(1, sum(stats.values()))),
                }
        except urllib.error.HTTPError as e:
            if e.code == 404:
                # 文件不在 VirusTotal 数据库 — 未知文件
                return {
                    "cloud_name": self.name,
                    "detections": 0,
                    "total_engines": 0,
                    "threat_names": [],
                    "is_malicious": False,
                    "confidence": 0.0,
                }
            return None
        except Exception:
            return None


class Cloud360Engine:
    """360云查杀模拟引擎

    基于公开的360云安全特征库哈希匹配。
    实际360 API 需要企业授权，此处使用本地特征库 + 模拟接口。
    """

    # 360 云端已知恶意哈希库 (示例 — 实际应从云端拉取)
    KNOWN_MALWARE_HASHES = {
        # EICAR 测试文件
        "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f": {
            "name": "EICAR-Test-File",
            "type": "测试病毒",
        },
        "44d88612fea8a8f36de82e1278abb02f": {
            "name": "EICAR-Test-File",
            "type": "测试病毒",
        },
    }

    def __init__(self):
        self.name = "360云查杀"
        self.enabled = True
        self._load_extra_hashes()

    def _load_extra_hashes(self):
        """加载额外的云特征库"""
        # 可扩展：从本地文件或网络拉取更多哈希
        extra_path = Path(__file__).parent / "cloud_signatures.json"
        if extra_path.exists():
            try:
                with open(extra_path, "r", encoding="utf-8") as f:
                    extra = json.load(f)
                    self.KNOWN_MALWARE_HASHES.update(extra)
            except Exception:
                pass

    def query_hash(self, file_hash: str) -> Optional[dict]:
        """查询360云特征库"""
        # 模拟网络延迟
        time.sleep(0.05)

        match = self.KNOWN_MALWARE_HASHES.get(file_hash)
        if match:
            return {
                "cloud_name": self.name,
                "detections": 1,
                "total_engines": 1,
                "threat_names": [match["name"]],
                "is_malicious": True,
                "confidence": 0.95,
            }

        # 文件不在已知恶意库中
        return {
            "cloud_name": self.name,
            "detections": 0,
            "total_engines": 1,
            "threat_names": [],
            "is_malicious": False,
            "confidence": 0.0,
        }


class CloudScanner:
    """云查杀引擎管理器 — 协调多个云引擎"""

    def __init__(self, config_path: str = "", cache_path: str = ""):
        self.config_path = Path(config_path) if config_path else Path(__file__).parent / "cloud_config.json"
        self._cache = CloudScanCache(cache_path if cache_path else str(Path(__file__).parent / "cloud_cache.json"))
        self._engines: list = []
        self._lock = threading.Lock()
        self._load_config()

    def _load_config(self):
        """加载配置"""
        config = {
            "virustotal_api_key": "",
            "enable_360_cloud": True,
            "enable_virustotal": False,
        }

        if self.config_path.exists():
            try:
                with open(self.config_path, "r", encoding="utf-8") as f:
                    config.update(json.load(f))
            except Exception:
                pass

        self.config = config

        # 初始化引擎
        self._engines = []
        if config.get("enable_360_cloud", True):
            self._engines.append(Cloud360Engine())
        if config.get("enable_virustotal", False) and config.get("virustotal_api_key"):
            self._engines.append(VirusTotalEngine(config["virustotal_api_key"]))

    def save_config(self, config: dict):
        """保存配置"""
        self.config.update(config)
        try:
            with open(self.config_path, "w", encoding="utf-8") as f:
                json.dump(self.config, f, ensure_ascii=False, indent=2)
        except Exception:
            pass
        # 重新加载引擎
        self._load_config()

    @property
    def engine_count(self) -> int:
        return len(self._engines)

    @property
    def engine_names(self) -> list[str]:
        return [e.name for e in self._engines]

    @property
    def cache_size(self) -> int:
        return self._cache.size

    def compute_file_hash(self, filepath: str) -> tuple[str, str]:
        """计算文件 MD5 和 SHA256"""
        md5 = hashlib.md5()
        sha256 = hashlib.sha256()
        try:
            with open(filepath, "rb") as f:
                while True:
                    chunk = f.read(65536)
                    if not chunk:
                        break
                    md5.update(chunk)
                    sha256.update(chunk)
        except Exception:
            return "", ""
        return md5.hexdigest(), sha256.hexdigest()

    def scan_file_cloud(self, filepath: str, timeout: float = 30.0) -> CloudScanResult:
        """云端扫描单个文件

        Args:
            filepath: 文件路径
            timeout: 超时秒数
        Returns:
            CloudScanResult
        """
        result = CloudScanResult()
        result.query_time = time.time()

        if not self._engines:
            result.error = "未启用任何云引擎"
            return result

        # 计算哈希
        md5, sha256 = self.compute_file_hash(filepath)
        if not sha256:
            result.error = "无法读取文件"
            return result

        result.file_hash = sha256

        # 检查缓存
        cached = self._cache.get(sha256)
        if cached:
            result.cached = True
            result.cloud_name = cached.get("cloud_name", "缓存")
            result.detections = cached.get("detections", 0)
            result.total_engines = cached.get("total_engines", 0)
            result.threat_names = cached.get("threat_names", [])
            result.is_malicious = cached.get("is_malicious", False)
            result.confidence = cached.get("confidence", 0.0)
            return result

        # 查询所有引擎
        all_detections = 0
        all_engines = 0
        all_threat_names = []
        is_malicious = False
        max_confidence = 0.0
        engine_names = []

        for engine in self._engines:
            if not engine.enabled:
                continue
            engine_names.append(engine.name)
            try:
                r = engine.query_hash(sha256)
                if r:
                    all_detections += r["detections"]
                    all_engines += r["total_engines"]
                    all_threat_names.extend(r["threat_names"])
                    if r["is_malicious"]:
                        is_malicious = True
                    max_confidence = max(max_confidence, r["confidence"])
            except Exception:
                pass

        result.cloud_name = " + ".join(engine_names) if engine_names else "无引擎"
        result.detections = all_detections
        result.total_engines = all_engines
        result.threat_names = all_threat_names[:20]
        result.is_malicious = is_malicious
        result.confidence = max_confidence

        # 缓存结果
        self._cache.put(sha256, {
            "cloud_name": result.cloud_name,
            "detections": result.detections,
            "total_engines": result.total_engines,
            "threat_names": result.threat_names,
            "is_malicious": result.is_malicious,
            "confidence": result.confidence,
        })

        return result

    def scan_file_cloud_async(self, filepath: str, callback=None):
        """异步云端扫描

        Args:
            filepath: 文件路径
            callback: 回调函数 (result: CloudScanResult) -> None
        Returns:
            threading.Thread
        """
        def worker():
            try:
                result = self.scan_file_cloud(filepath)
            except Exception as e:
                result = CloudScanResult()
                result.error = str(e)
            if callback:
                callback(result)

        t = threading.Thread(target=worker, daemon=True)
        t.start()
        return t
