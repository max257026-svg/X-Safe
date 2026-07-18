"""
X-Safe — AI 自学习引擎
Adaptive Learning Engine: 贝叶斯置信度评分 + 用户反馈学习 + 自适应阈值

核心理念:
  - 每次用户确认/误报反馈都会训练本地模型
  - 检测特征权重动态调整，误报率持续下降
  - 使用频率分析自动识别良性模式
  - 上下文感知: 文件位置、来源影响判断
"""

import json
import hashlib
import math
import os
import re
import sqlite3
import time
from pathlib import Path
from collections import defaultdict, Counter
from dataclasses import dataclass, field
from typing import Optional
from enum import Enum


# ============================================================
# 学习事件类型
# ============================================================
class FeedbackType(Enum):
    CONFIRM_THREAT = "confirm_threat"   # 用户确认是威胁 → 特征加权
    FALSE_POSITIVE = "false_positive"    # 用户标记误报 → 特征降权
    MARK_SAFE = "mark_safe"              # 用户标记安全 → 加入白名单
    AUTO_LEARN = "auto_learn"            # 系统自动学习


# ============================================================
# 置信度评分结果
# ============================================================
@dataclass
class ConfidenceScore:
    raw_score: float = 0.0          # 原始检测分数 (0-1)
    adjusted_score: float = 0.0     # AI 调整后分数 (0-1)
    confidence: float = 0.5          # 模型置信度 (模型对自身判断的确信程度)
    feature_scores: dict = field(default_factory=dict)
    is_known_safe: bool = False     # 是否已知安全文件
    similar_to_fp: bool = False     # 是否与历史误报相似
    learning_note: str = ""         # AI 学习备注

    @property
    def is_threat(self) -> bool:
        """基于自适应阈值判断"""
        threshold = max(0.35, 0.7 - self.confidence * 0.3)
        return self.adjusted_score >= threshold and not self.is_known_safe

    @property
    def risk_level(self) -> str:
        if self.is_known_safe:
            return "safe"
        s = self.adjusted_score
        if s >= 0.85:
            return "malicious"
        elif s >= 0.65:
            return "high_risk"
        elif s >= 0.40:
            return "suspicious"
        elif s >= 0.20:
            return "low_risk"
        return "safe"


# ============================================================
# AI 学习数据库
# ============================================================
class LearningDatabase:
    """SQLite 持久化学习数据 — 免安装，零依赖"""

    SCHEMA = """
    CREATE TABLE IF NOT EXISTS feedback (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        file_hash TEXT NOT NULL,
        file_path TEXT,
        file_name TEXT,
        file_ext TEXT,
        file_size INTEGER,
        detection_features TEXT,
        feedback_type TEXT NOT NULL,
        timestamp REAL NOT NULL,
        notes TEXT
    );

    CREATE TABLE IF NOT EXISTS feature_weights (
        feature_name TEXT PRIMARY KEY,
        base_weight REAL NOT NULL DEFAULT 0.5,
        current_weight REAL NOT NULL DEFAULT 0.5,
        false_positive_count INTEGER DEFAULT 0,
        true_positive_count INTEGER DEFAULT 0,
        total_detections INTEGER DEFAULT 0,
        last_updated REAL NOT NULL,
        confidence REAL NOT NULL DEFAULT 0.5
    );

    CREATE TABLE IF NOT EXISTS whitelist (
        file_hash TEXT PRIMARY KEY,
        file_path TEXT,
        file_name TEXT,
        reason TEXT,
        added_at REAL NOT NULL
    );

    CREATE TABLE IF NOT EXISTS benign_patterns (
        pattern_hash TEXT PRIMARY KEY,
        pattern_type TEXT NOT NULL,
        pattern_content TEXT NOT NULL,
        occurrences_safe INTEGER DEFAULT 0,
        occurrences_threat INTEGER DEFAULT 0,
        benign_ratio REAL DEFAULT 1.0,
        last_seen REAL NOT NULL
    );

    CREATE TABLE IF NOT EXISTS learning_stats (
        key TEXT PRIMARY KEY,
        value TEXT NOT NULL
    );

    CREATE INDEX IF NOT EXISTS idx_feedback_hash ON feedback(file_hash);
    CREATE INDEX IF NOT EXISTS idx_feedback_type ON feedback(feedback_type);
    CREATE INDEX IF NOT EXISTS idx_whitelist_hash ON whitelist(file_hash);
    """

    def __init__(self, db_path: str = ""):
        if not db_path:
            db_path = str(Path(__file__).parent / "ai_learning.db")
        self.db_path = db_path
        self._conn: Optional[sqlite3.Connection] = None
        self._init_db()

    def _init_db(self):
        # timeout + busy handler：对「database is locked」（如沙箱文件系统/双开实例）更宽容
        self._conn = sqlite3.connect(
            self.db_path, check_same_thread=False, timeout=30,
        )
        self._conn.execute("PRAGMA busy_timeout=30000")
        for _ in range(5):
            try:
                self._conn.executescript(self.SCHEMA)
                self._conn.commit()
                break
            except sqlite3.OperationalError as e:
                if "locked" in str(e).lower():
                    time.sleep(0.3)
                    continue
                raise

        # 初始化特征权重 (不同特征有不同的基础权重)
        features_config = [
            ("hash_signature", 0.85),        # 哈希签名 — 最高可信度
            ("pattern_regex", 0.65),         # 正则匹配 — 较高可信度
            ("pattern_string", 0.55),        # 字符串匹配 — 中高可信度
            ("yara_rule", 0.60),             # YARA规则 — 较高可信度
            ("heuristic_entropy", 0.35),     # 熵值 — 低可信度 (易误报)
            ("heuristic_double_ext", 0.55),  # 双扩展名 — 中高可信度
            ("heuristic_suspicious_strings", 0.40),  # 可疑字符串 — 中低可信度
            ("heuristic_temp_dir", 0.45),    # 临时目录 — 中低可信度
            ("heuristic_pe_analysis", 0.30), # PE分析 — 低可信度 (仅标记)
            ("ext_blacklist", 0.25),         # 扩展名 — 低可信度
        ]
        now = time.time()
        for f, base_w in features_config:
            self._conn.execute(
                "INSERT OR IGNORE INTO feature_weights "
                "(feature_name, base_weight, current_weight, last_updated) "
                "VALUES (?, ?, ?, ?)",
                (f, base_w, base_w, now),
            )

    # ----- 白名单 -----
    def is_whitelisted(self, file_hash: str) -> bool:
        row = self._conn.execute(
            "SELECT 1 FROM whitelist WHERE file_hash = ?", (file_hash,)
        ).fetchone()
        return row is not None

    def add_to_whitelist(self, file_hash: str, file_path: str,
                         file_name: str, reason: str = "user_marked_safe"):
        self._conn.execute(
            "INSERT OR REPLACE INTO whitelist VALUES (?, ?, ?, ?, ?)",
            (file_hash, file_path, file_name, reason, time.time()),
        )
        self._conn.commit()

    def remove_from_whitelist(self, file_hash: str):
        self._conn.execute("DELETE FROM whitelist WHERE file_hash = ?", (file_hash,))
        self._conn.commit()

    def get_whitelist_count(self) -> int:
        return self._conn.execute("SELECT COUNT(*) FROM whitelist").fetchone()[0]

    # ----- 反馈记录 -----
    def record_feedback(self, file_hash: str, file_path: str, file_name: str,
                        file_ext: str, file_size: int, detection_features: dict,
                        feedback_type: FeedbackType, notes: str = ""):
        self._conn.execute(
            """INSERT INTO feedback
               (file_hash, file_path, file_name, file_ext, file_size,
                detection_features, feedback_type, timestamp, notes)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (file_hash, file_path, file_name, file_ext, file_size,
             json.dumps(detection_features, ensure_ascii=False),
             feedback_type.value, time.time(), notes),
        )
        self._conn.commit()

    def get_feedback_count(self, feedback_type: Optional[FeedbackType] = None) -> int:
        if feedback_type:
            return self._conn.execute(
                "SELECT COUNT(*) FROM feedback WHERE feedback_type = ?",
                (feedback_type.value,),
            ).fetchone()[0]
        return self._conn.execute("SELECT COUNT(*) FROM feedback").fetchone()[0]

    def get_recent_false_positives(self, limit: int = 50) -> list[dict]:
        """获取最近的误报，用于相似性分析"""
        rows = self._conn.execute(
            "SELECT file_hash, file_path, file_name, file_ext, detection_features, notes "
            "FROM feedback WHERE feedback_type = ? "
            "ORDER BY timestamp DESC LIMIT ?",
            (FeedbackType.FALSE_POSITIVE.value, limit),
        ).fetchall()

        results = []
        for row in rows:
            try:
                features = json.loads(row[4])
            except (json.JSONDecodeError, TypeError):
                features = {}
            results.append({
                "file_hash": row[0],
                "file_path": row[1],
                "file_name": row[2],
                "file_ext": row[3],
                "features": features,
                "notes": row[5],
            })
        return results

    # ----- 特征权重 -----
    def get_feature_weights(self) -> dict:
        rows = self._conn.execute(
            "SELECT feature_name, base_weight, current_weight, "
            "false_positive_count, true_positive_count, total_detections, confidence "
            "FROM feature_weights"
        ).fetchall()

        weights = {}
        for row in rows:
            weights[row[0]] = {
                "base_weight": row[1],
                "current_weight": row[2],
                "fp_count": row[3],
                "tp_count": row[4],
                "total": row[5],
                "confidence": row[6],
            }
        return weights

    def update_feature_weight(self, feature_name: str, is_false_positive: bool):
        """根据反馈更新特征权重"""
        self._conn.execute(
            "UPDATE feature_weights SET "
            "total_detections = total_detections + 1, "
            + ("false_positive_count = false_positive_count + 1, "
               if is_false_positive else
               "true_positive_count = true_positive_count + 1, ") +
            "last_updated = ? "
            "WHERE feature_name = ?",
            (time.time(), feature_name),
        )

        # 重新计算权重
        row = self._conn.execute(
            "SELECT false_positive_count, true_positive_count, total_detections "
            "FROM feature_weights WHERE feature_name = ?",
            (feature_name,),
        ).fetchone()

        if row:
            fp, tp, total = row
            if total > 0:
                # 精确率 = TP / (TP + FP)，作为调整后的权重
                precision = tp / max(total, 1)
                # 平滑: 少量样本时不过度调整
                alpha = min(1.0, total / 10.0)
                base = self._conn.execute(
                    "SELECT base_weight FROM feature_weights WHERE feature_name = ?",
                    (feature_name,),
                ).fetchone()[0]
                new_weight = base * (1 - alpha) + precision * alpha

                # 置信度 = min(1.0, total / 20) — 样本越多越自信
                confidence = min(1.0, total / 20.0)

                self._conn.execute(
                    "UPDATE feature_weights SET current_weight = ?, confidence = ? "
                    "WHERE feature_name = ?",
                    (new_weight, confidence, feature_name),
                )

        self._conn.commit()

    # ----- 良性模式 -----
    def learn_benign_pattern(self, pattern_content: str, pattern_type: str,
                             is_threat: bool):
        """学习模式：记录在安全/恶意文件中出现的频率"""
        pattern_hash = hashlib.md5(
            f"{pattern_type}:{pattern_content}".encode()
        ).hexdigest()

        self._conn.execute(
            "INSERT INTO benign_patterns (pattern_hash, pattern_type, "
            "pattern_content, occurrences_safe, occurrences_threat, last_seen) "
            "VALUES (?, ?, ?, ?, ?, ?) "
            "ON CONFLICT(pattern_hash) DO UPDATE SET "
            + ("occurrences_safe = occurrences_safe + 1, " if not is_threat else
               "occurrences_threat = occurrences_threat + 1, ") +
            "last_seen = ?",
            (pattern_hash, pattern_type, pattern_content,
             1 if not is_threat else 0,
             1 if is_threat else 0,
             time.time()),
        )

        # 更新良性比率
        row = self._conn.execute(
            "SELECT occurrences_safe, occurrences_threat FROM benign_patterns "
            "WHERE pattern_hash = ?",
            (pattern_hash,),
        ).fetchone()

        if row and (row[0] + row[1]) > 0:
            ratio = row[0] / (row[0] + row[1])
            self._conn.execute(
                "UPDATE benign_patterns SET benign_ratio = ? WHERE pattern_hash = ?",
                (ratio, pattern_hash),
            )

        self._conn.commit()

    def get_pattern_benign_ratio(self, pattern_content: str,
                                  pattern_type: str) -> float:
        """获取模式的良性比率 (越高越安全)"""
        pattern_hash = hashlib.md5(
            f"{pattern_type}:{pattern_content}".encode()
        ).hexdigest()

        row = self._conn.execute(
            "SELECT benign_ratio FROM benign_patterns WHERE pattern_hash = ?",
            (pattern_hash,),
        ).fetchone()

        return row[0] if row else 1.0  # 未知模式默认认为可能良性

    # ----- 统计 -----
    def get_stats(self) -> dict:
        """获取学习统计"""
        return {
            "total_feedback": self.get_feedback_count(),
            "false_positives": self.get_feedback_count(FeedbackType.FALSE_POSITIVE),
            "confirmed_threats": self.get_feedback_count(FeedbackType.CONFIRM_THREAT),
            "whitelist_count": self.get_whitelist_count(),
            "benign_patterns": self._conn.execute(
                "SELECT COUNT(*) FROM benign_patterns"
            ).fetchone()[0],
            "feature_weights": self.get_feature_weights(),
        }

    def close(self):
        if self._conn:
            self._conn.close()


# ============================================================
# AI 置信度评分器
# ============================================================
class AIScorer:
    """智能评分器 — 综合多维度特征计算置信度"""

    def __init__(self, db: LearningDatabase):
        self.db = db
        self._feature_weights_cache = {}
        self._cache_time = 0
        self._cache_ttl = 30  # 30秒缓存

    def _get_weights(self) -> dict:
        """获取特征权重 (带缓存)"""
        now = time.time()
        if now - self._cache_time > self._cache_ttl:
            self._feature_weights_cache = self.db.get_feature_weights()
            self._cache_time = now
        return self._feature_weights_cache

    def score_detection(self, detection_features: dict,
                        file_path: str = "", file_ext: str = "",
                        file_hash: str = "") -> ConfidenceScore:
        """
        综合评分 — 核心 AI 推理入口

        Args:
            detection_features: 各检测模块的发现
                {
                    "hash_match": Optional[dict],
                    "pattern_matches": list[dict],
                    "yara_matches": list[dict],
                    "heuristic_findings": list[tuple],
                    "ext_blacklist_hit": bool,
                    "entropy": float,
                }

        Returns:
            ConfidenceScore with adjusted_score
        """

        score = ConfidenceScore()
        weights = self._get_weights()

        # ---- 1. 检查白名单 ----
        if file_hash and self.db.is_whitelisted(file_hash):
            score.is_known_safe = True
            score.adjusted_score = 0.0
            score.learning_note = "文件在白名单中 — AI 已学习为安全"
            return score

        # ---- 2. 逐特征评分 ----
        raw = 0.0
        total_weight = 0.0
        feature_scores = {}

        # 哈希签名 — 高权重
        if detection_features.get("hash_match"):
            w = weights.get("hash_signature", {}).get("current_weight", 0.7)
            raw += w * 0.9
            total_weight += w
            feature_scores["hash_signature"] = 0.9

        # 模式匹配
        pattern_matches = detection_features.get("pattern_matches", [])
        if pattern_matches:
            w = weights.get("pattern_regex", {}).get("current_weight", 0.5)
            # 检查每个匹配模式的良性比率
            total_pattern_score = 0.0
            for pm in pattern_matches:
                pattern_str = pm.get("pattern", pm.get("name", ""))
                benign_ratio = self.db.get_pattern_benign_ratio(pattern_str, "regex")
                # 高良性比率的模式贡献更低的威胁分
                pattern_score = max(0.2, 1.0 - benign_ratio)
                total_pattern_score += pattern_score

            avg_pattern = min(1.0, total_pattern_score / len(pattern_matches))
            # 多模式匹配更可信，单模式也有足够权重
            pattern_count_factor = min(1.0, len(pattern_matches) / 1.5)
            raw += w * avg_pattern * pattern_count_factor
            total_weight += w * pattern_count_factor
            feature_scores["pattern_regex"] = avg_pattern

        # YARA 规则
        yara_matches = detection_features.get("yara_matches", [])
        if yara_matches:
            w = weights.get("yara_rule", {}).get("current_weight", 0.55)
            raw += w * 0.8
            total_weight += w
            feature_scores["yara_rule"] = 0.8

        # 启发式分析
        heuristic = detection_features.get("heuristic_findings", [])
        if heuristic:
            for reason, detail, level in heuristic:
                if "熵值" in reason:
                    w = weights.get("heuristic_entropy", {}).get("current_weight", 0.3)
                    entropy_val = detection_features.get("entropy", 5.0)
                    h_score = min(1.0, (entropy_val - 6.0) / 2.0)
                    raw += w * max(0, h_score)
                    total_weight += w
                    feature_scores["heuristic_entropy"] = h_score

                elif "双扩展名" in reason:
                    w = weights.get("heuristic_double_ext", {}).get("current_weight", 0.6)
                    raw += w * 0.7
                    total_weight += w
                    feature_scores["heuristic_double_ext"] = 0.7

                elif "可疑代码" in reason or "可疑字符串" in reason:
                    w = weights.get("heuristic_suspicious_strings",
                                    {}).get("current_weight", 0.4)
                    raw += w * 0.5
                    total_weight += w
                    feature_scores["heuristic_suspicious_strings"] = 0.5

                elif "临时目录" in reason:
                    w = weights.get("heuristic_temp_dir", {}).get("current_weight", 0.45)
                    raw += w * 0.6
                    total_weight += w
                    feature_scores["heuristic_temp_dir"] = 0.6

        # 扩展名黑名单
        if detection_features.get("ext_blacklist_hit"):
            w = weights.get("ext_blacklist", {}).get("current_weight", 0.2)
            raw += w * 0.3
            total_weight += w
            feature_scores["ext_blacklist"] = 0.3

        # ---- 3. 计算最终分数 ----
        if total_weight > 0:
            score.raw_score = raw / total_weight
        else:
            score.raw_score = 0.0

        # ---- 4. 检查与历史误报的相似性 ----
        if score.raw_score > 0.2:
            similarity = self._check_fp_similarity(
                detection_features, file_path, file_ext
            )
            if similarity > 0.6:
                score.similar_to_fp = True
                # 相似性越高，降权越强
                score.raw_score *= (1.0 - similarity * 0.5)

        # ---- 5. 上下文调整 ----
        context_modifier = self._context_modifier(file_path, file_ext)
        score.adjusted_score = min(1.0, score.raw_score * context_modifier)

        # ---- 6. 模型置信度 ----
        # 基于特征权重的平均置信度
        confidences = [w.get("confidence", 0.5) for w in weights.values()]
        score.confidence = sum(confidences) / max(1, len(confidences))
        score.feature_scores = feature_scores

        # ---- 7. 学习备注 ----
        if score.similar_to_fp:
            score.learning_note = "⚠️ 与历史误报相似 — 已自动降权"
        if score.confidence < 0.3:
            score.learning_note += " | 📊 模型置信度低，需要更多训练数据"

        return score

    def _check_fp_similarity(self, features: dict, file_path: str,
                              file_ext: str) -> float:
        """检查当前检测与历史误报的相似度"""
        recent_fps = self.db.get_recent_false_positives(limit=30)
        if not recent_fps:
            return 0.0

        similarity_scores = []

        for fp in recent_fps:
            sim = 0.0
            count = 0

            # 扩展名相同 +0.3
            if fp.get("file_ext") == file_ext:
                sim += 0.3
                count += 1

            # 路径相似 (同一目录)
            fp_path = fp.get("file_path", "")
            if fp_path and file_path:
                fp_dir = os.path.dirname(fp_path)
                file_dir = os.path.dirname(file_path)
                if fp_dir == file_dir:
                    sim += 0.4
                    count += 1

            # 检测特征相似
            fp_features = fp.get("features", {})
            current_patterns = set()
            for pm in features.get("pattern_matches", []):
                current_patterns.add(pm.get("name", ""))

            fp_patterns = set()
            for pm in fp_features.get("pattern_matches", []):
                if isinstance(pm, dict):
                    fp_patterns.add(pm.get("name", ""))
                elif isinstance(pm, str):
                    fp_patterns.add(pm)

            if current_patterns and fp_patterns:
                overlap = len(current_patterns & fp_patterns)
                union = len(current_patterns | fp_patterns)
                if union > 0:
                    sim += 0.5 * (overlap / union)
                    count += 1

            if count > 0:
                similarity_scores.append(sim / count)

        return max(similarity_scores) if similarity_scores else 0.0

    def _context_modifier(self, file_path: str, file_ext: str) -> float:
        """上下文感知调整因子"""
        modifier = 1.0

        if file_path:
            path_lower = file_path.lower()

            # 系统目录中的文件 — 通常更可信 (除非有强证据)
            system_dirs = [
                "windows\\system32", "windows\\syswow64",
                "program files", "program files (x86)",
            ]
            if any(sd in path_lower for sd in system_dirs):
                modifier *= 0.85  # 略微降低威胁评分

            # 临时目录中的可执行文件 — 更可疑
            temp_dirs = ["\\temp", "\\tmp", "appdata\\local\\temp"]
            if file_ext in {".exe", ".dll", ".bat", ".ps1", ".vbs"}:
                if any(td in path_lower for td in temp_dirs):
                    modifier *= 1.25  # 提升威胁评分

            # 下载目录 — 中等可疑
            if "downloads" in path_lower:
                modifier *= 1.1

        return modifier

    def learn_from_feedback(self, detection_features: dict, file_hash: str,
                            file_path: str, file_name: str, file_ext: str,
                            file_size: int, feedback: FeedbackType,
                            entropy: float = 0.0):
        """从用户反馈中学习 — 更新所有权重和模式"""

        # 1. 记录反馈
        self.db.record_feedback(
            file_hash, file_path, file_name, file_ext, file_size,
            detection_features, feedback,
            notes=f"entropy={entropy:.2f}",
        )

        is_fp = (feedback == FeedbackType.FALSE_POSITIVE or
                 feedback == FeedbackType.MARK_SAFE)

        # 2. 更新特征权重
        affected_features = set()

        if detection_features.get("hash_match"):
            self.db.update_feature_weight("hash_signature", is_fp)
            affected_features.add("hash_signature")

        if detection_features.get("pattern_matches"):
            self.db.update_feature_weight("pattern_regex", is_fp)
            affected_features.add("pattern_regex")
            # 学习具体模式
            for pm in detection_features["pattern_matches"]:
                pattern_str = pm.get("pattern", pm.get("name", ""))
                self.db.learn_benign_pattern(pattern_str, "regex", not is_fp)

        if detection_features.get("yara_matches"):
            self.db.update_feature_weight("yara_rule", is_fp)
            affected_features.add("yara_rule")

        heuristic = detection_features.get("heuristic_findings", [])
        for reason, _, _ in heuristic:
            if "熵值" in reason:
                self.db.update_feature_weight("heuristic_entropy", is_fp)
            elif "双扩展名" in reason:
                self.db.update_feature_weight("heuristic_double_ext", is_fp)
            elif "可疑" in reason:
                self.db.update_feature_weight("heuristic_suspicious_strings", is_fp)
            elif "临时目录" in reason:
                self.db.update_feature_weight("heuristic_temp_dir", is_fp)

        # 3. 处理白名单
        if feedback == FeedbackType.MARK_SAFE:
            self.db.add_to_whitelist(file_hash, file_path, file_name,
                                      reason="user_marked_safe")
        elif feedback == FeedbackType.CONFIRM_THREAT:
            # 从白名单移除 (如果错误地加入了)
            self.db.remove_from_whitelist(file_hash)

        # 4. 清除权重缓存
        self._cache_time = 0

        return len(affected_features)


# ============================================================
# AI 增强扫描器 — 包装原始扫描器
# ============================================================
class AIScanner:
    """
    AI 增强扫描器 — 在原始扫描引擎上叠加 AI 推理层

    工作流程:
      1. 原始引擎扫描 → 获得 detection_features
      2. AI 评分器评估 → 获得 ConfidenceScore
      3. 根据自适应阈值决定是否报警
      4. 用户反馈 → 持续学习
    """

    def __init__(self, original_scanner, db_path: str = ""):
        self.scanner = original_scanner
        self.db = LearningDatabase(db_path)
        self.scorer = AIScorer(self.db)
        self._scan_count = 0
        self._false_positive_rate = 0.0

    def scan_file(self, filepath: str, should_cancel=None) -> tuple:
        """
        AI 增强扫描
        Returns: (original_result, ai_score, detection_features)
        """
        # 1. 原始扫描
        result = self.scanner.scan_file(filepath, should_cancel)

        # 2. 提取检测特征
        features = self._extract_features(result, filepath)

        # 3. AI 评分
        path_obj = Path(filepath)
        ai_score = self.scorer.score_detection(
            detection_features=features,
            file_path=str(path_obj.absolute()),
            file_ext=path_obj.suffix.lower(),
            file_hash=result.hash_md5 or result.hash_sha256,
        )

        # 4. 根据 AI 判断调整结果
        if ai_score.is_known_safe:
            from engine import ThreatLevel
            result.threat_level = ThreatLevel.SAFE
            result.threat_name = ""
            result.detection_method = "AI 识别为安全文件 (白名单)"
            result.details = ai_score.learning_note
            # 增加熵值信息
            if not hasattr(result, 'ai_score'):
                setattr(result, 'ai_score', ai_score)
        elif ai_score.similar_to_fp and ai_score.adjusted_score < 0.5:
            from engine import ThreatLevel
            if result.threat_level.value == "malicious":
                result.threat_level = ThreatLevel.SUSPICIOUS
            result.details = (result.details or "") + f" | {ai_score.learning_note}"
            if not hasattr(result, 'ai_score'):
                setattr(result, 'ai_score', ai_score)
        else:
            if not hasattr(result, 'ai_score'):
                setattr(result, 'ai_score', ai_score)

        # 5. 自动学习 (无监督)
        self._auto_learn(result, features, filepath)

        self._scan_count += 1
        return result, ai_score, features

    def _extract_features(self, result, filepath: str) -> dict:
        """从扫描结果提取结构化特征"""
        path = Path(filepath)
        features = {
            "hash_match": None,
            "pattern_matches": [],
            "yara_matches": [],
            "heuristic_findings": [],
            "ext_blacklist_hit": False,
            "entropy": result.entropy if hasattr(result, 'entropy') else 0.0,
        }

        # 从 detection_method 和 details 反向提取
        method = result.detection_method or ""
        details = result.details or ""

        if "哈希签名" in method:
            features["hash_match"] = {
                "name": result.threat_name,
                "severity": result.threat_level.value,
            }

        if "规则匹配" in method:
            if "命中规则" in details:
                # 解析规则名
                rule_names = details.replace("命中规则: ", "").split(", ")
                features["pattern_matches"] = [
                    {"name": rn.strip()} for rn in rule_names
                ]

        if "启发式" in method:
            findings = []
            for line in details.split(";"):
                line = line.strip()
                if not line:
                    continue
                # 解析: [原因] 详情
                match = re.match(r'\[(.+?)\]\s*(.+)', line)
                if match:
                    findings.append((match.group(1), match.group(2), result.threat_level.value))
            features["heuristic_findings"] = findings

        if "扩展名黑名单" in method:
            features["ext_blacklist_hit"] = True

        return features

    def _auto_learn(self, result, features: dict, filepath: str):
        """无监督自动学习 — 识别高度确定的模式"""
        path = Path(filepath)
        ext = path.suffix.lower()

        # 自动学习: 系统目录中的已签名文件 → 低威胁
        path_lower = str(path.absolute()).lower()
        system_paths = ["windows\\system32", "windows\\syswow64"]
        if any(sp in path_lower for sp in system_paths):
            if ext in {".exe", ".dll", ".sys"}:
                hash_val = result.hash_md5 or result.hash_sha256
                if hash_val and hash_val != "ACCESS_DENIED":
                    # 自动白名单系统文件
                    if not self.db.is_whitelisted(hash_val):
                        self.db.add_to_whitelist(
                            hash_val, str(path.absolute()), path.name,
                            reason="auto_system_file",
                        )

        # 自动学习: 低熵值 + 无危险特征的脚本文件 → 标记模式为良性
        if result.entropy and result.entropy < 5.0 and not result.is_threat:
            for pm in features.get("pattern_matches", []):
                self.db.learn_benign_pattern(
                    pm.get("name", ""), "regex", is_threat=False,
                )

    def provide_feedback(self, result, filepath: str, features: dict,
                         feedback: FeedbackType):
        """用户提供反馈 → AI 学习"""
        path = Path(filepath)
        hash_val = result.hash_md5 or result.hash_sha256 or ""
        entropy_val = result.entropy if hasattr(result, 'entropy') else 0.0

        count = self.scorer.learn_from_feedback(
            detection_features=features,
            file_hash=hash_val,
            file_path=str(path.absolute()),
            file_name=path.name,
            file_ext=path.suffix.lower(),
            file_size=result.file_size if hasattr(result, 'file_size') else 0,
            feedback=feedback,
            entropy=entropy_val,
        )

        # 重新计算误报率
        total = self.db.get_feedback_count()
        fp_count = self.db.get_feedback_count(FeedbackType.FALSE_POSITIVE)
        if total > 0:
            self._false_positive_rate = fp_count / total

        return count

    def scan_directory(self, *args, **kwargs):
        """目录扫描 — 通过 AI 增强"""
        # TODO: 集成 AI 评分到批量扫描
        return self.scanner.scan_directory(*args, **kwargs)

    def quick_scan(self):
        return self.scanner.quick_scan()

    def full_scan(self):
        return self.scanner.full_scan()

    @property
    def stats(self):
        return self.scanner.stats

    @property
    def false_positive_rate(self) -> float:
        return self._false_positive_rate

    @property
    def learning_stats(self) -> dict:
        return self.db.get_stats()

    def set_progress_callback(self, callback):
        self.scanner.set_progress_callback(callback)

    def cancel_scan(self):
        self.scanner.cancel_scan()

    def is_cancelled(self) -> bool:
        return self.scanner.is_cancelled()

    def reset(self):
        self.scanner.reset()
