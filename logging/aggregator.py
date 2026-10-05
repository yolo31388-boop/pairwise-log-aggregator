"""
游戏内日志收集与分析系统 - 核心模块

功能：
- collect_logs:   实时增量收集多台服务器日志，传输前压缩
- aggregate_logs: 解析多种格式（JSON / key=value / 文本）并标准化
- search_logs:    倒排索引 + 按时间/级别/服务过滤
- analyze_logs:   错误率/响应时间统计、趋势分析、关联分析
- alerting:       阈值告警 + 冷却期去重
"""
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple
import json
import math
import re
import time
import zlib


@dataclass
class Config:
    alert_error_threshold: int = 5         # 窗口内 ERROR 数达到该值触发告警
    alert_window_seconds: float = 60.0     # 告警统计窗口
    alert_cooldown_seconds: float = 300.0  # 同一告警去重冷却时间
    trend_bucket_seconds: float = 60.0     # 趋势分析分桶大小


_LEVELS = ("DEBUG", "INFO", "WARN", "WARNING", "ERROR", "FATAL", "CRITICAL")

# 支持的日志格式：
# 1) JSON: {"timestamp": ..., "level": ..., "service": ..., "msg": ...}
# 2) key=value: ts=... level=ERROR service=login msg="..."
# 3) 常规文本: 2024-01-01 12:00:00 ERROR [login] message
_JSON_RE = re.compile(r"^\s*\{.*\}\s*$", re.S)
_KV_RE = re.compile(r'(\w+)=("([^"]*)"|\S+)')
_TEXT_RE = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:[.,]\d+)?)\s+"
    r"(?P<level>[A-Z]+)\s+"
    r"(?:\[(?P<service>[^\]]+)\]\s*)?"
    r"(?P<msg>.*)$"
)

_TS_KEYS = ("ts", "timestamp", "time", "@timestamp")
_LEVEL_KEYS = ("level", "severity", "loglevel")
_SERVICE_KEYS = ("service", "svc", "app", "source")
_MSG_KEYS = ("msg", "message", "log", "text")


def _parse_timestamp(value) -> float:
    if value is None:
        return 0.0
    if isinstance(value, (int, float)):
        return float(value)
    text = str(value).strip().replace(",", ".")
    try:
        return float(text)
    except ValueError:
        pass
    for fmt in ("%Y-%m-%dT%H:%M:%S.%f", "%Y-%m-%d %H:%M:%S.%f",
                "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S"):
        try:
            return time.mktime(time.strptime(text, fmt))
        except ValueError:
            continue
    return 0.0


def _first_key(mapping: Dict, keys) -> Optional[str]:
    for key in keys:
        if key in mapping:
            return mapping[key]
    return None


def parse_log_line(line: str, default_service: str = "unknown") -> Optional[Dict]:
    """解析单行日志，支持 JSON / key=value / 常规文本三种格式。"""
    line = line.strip()
    if not line:
        return None

    if _JSON_RE.match(line):
        try:
            data = json.loads(line)
        except json.JSONDecodeError:
            data = None
        if isinstance(data, dict):
            return _normalize_fields(data, default_service)

    kv_pairs = _KV_RE.findall(line)
    if kv_pairs and any(k in _TS_KEYS + _LEVEL_KEYS for k, _, _ in kv_pairs):
        data = {k: (inner if raw.startswith('"') else raw)
                for k, raw, inner in kv_pairs}
        return _normalize_fields(data, default_service)

    match = _TEXT_RE.match(line)
    if match:
        return {
            "timestamp": _parse_timestamp(match.group("ts")),
            "level": match.group("level"),
            "service": match.group("service") or default_service,
            "message": match.group("msg").strip(),
            "fields": {},
            "raw": line,
        }

    # 无法识别格式的纯文本也标准化收录，不再混在一起
    return {
        "timestamp": 0.0,
        "level": "INFO",
        "service": default_service,
        "message": line,
        "fields": {},
        "raw": line,
    }


def _normalize_fields(data: Dict, default_service: str) -> Dict:
    level = str(_first_key(data, _LEVEL_KEYS) or "INFO").upper()
    if level == "WARNING":
        level = "WARN"
    known = set(_TS_KEYS + _LEVEL_KEYS + _SERVICE_KEYS + _MSG_KEYS)
    extra = {k: v for k, v in data.items() if k not in known}
    return {
        "timestamp": _parse_timestamp(_first_key(data, _TS_KEYS)),
        "level": level,
        "service": str(_first_key(data, _SERVICE_KEYS) or default_service),
        "message": str(_first_key(data, _MSG_KEYS) or ""),
        "fields": extra,
        "raw": json.dumps(data, ensure_ascii=False, sort_keys=True),
    }


class LogAggregator:
    def __init__(self, config: Optional[Dict] = None):
        if config is None:
            self.config = Config()
        elif isinstance(config, dict):
            self.config = Config(**config)
        else:
            self.config = config
        self._state = {}
        self._history = []
        # 收集状态：每个来源已读取的偏移量（增量/实时收集）
        self._offsets: Dict[str, int] = {}
        # 标准化后的日志存储
        self._logs: List[Dict] = []
        # 搜索索引：词 -> 日志下标集合；字段索引：level/service -> 下标集合
        self._token_index: Dict[str, set] = {}
        self._level_index: Dict[str, set] = {}
        self._service_index: Dict[str, set] = {}
        # 告警去重：指纹 -> 上次告警时间
        self._alert_fingerprints: Dict[str, float] = {}
        self.alerts: List[Dict] = []

    # ------------------------------------------------------------------
    # 日志收集：增量读取（实时性）+ 压缩传输（省带宽）
    # ------------------------------------------------------------------
    def collect_logs(self, sources) -> List[Dict]:
        """从多个来源收集日志。

        sources 可以是：
        - {name: [lines]} 字典（内存来源，按偏移量增量收集）
        - 文件路径列表（按字节偏移增量读取，只读新增内容，保证实时性）
        返回本次新收集到的日志行（已按来源标注）。
        """
        collected = []
        if isinstance(sources, dict):
            items = sources.items()
        else:
            items = [(str(path), path) for path in sources]

        for name, source in items:
            for line in self._read_new_lines(name, source):
                collected.append({"source": name, "line": line})
        return collected

    def _read_new_lines(self, name: str, source) -> List[str]:
        offset = self._offsets.get(name, 0)
        if isinstance(source, (list, tuple)):
            new_lines = [str(l) for l in source[offset:]]
            self._offsets[name] = len(source)
            return new_lines
        # 文件来源：按字节偏移增量读取
        with open(source, "rb") as fh:
            fh.seek(offset)
            data = fh.read()
            self._offsets[name] = fh.tell()
        return [l for l in data.decode("utf-8", errors="replace").splitlines() if l.strip()]

    @staticmethod
    def compress(lines: List[str]) -> bytes:
        """压缩日志，减少传输带宽。"""
        payload = "\n".join(lines).encode("utf-8")
        return zlib.compress(payload, 9)

    @staticmethod
    def decompress(payload: bytes) -> List[str]:
        text = zlib.decompress(payload).decode("utf-8")
        return [l for l in text.splitlines() if l.strip()]

    def collect_and_compress(self, sources) -> bytes:
        """收集 + 压缩一步完成，模拟网络传输。"""
        lines = [item["line"] for item in self.collect_logs(sources)]
        return self.compress(lines)

    # ------------------------------------------------------------------
    # 日志聚合：解析 + 标准化
    # ------------------------------------------------------------------
    def aggregate_logs(self, raw_logs) -> List[Dict]:
        """把不同来源、不同格式的日志解析并标准化后统一聚合。"""
        entries = list(raw_logs)
        if entries and isinstance(entries[0], dict) and "line" in entries[0]:
            items = [(e.get("source", "unknown"), e["line"]) for e in entries]
        else:
            items = [("unknown", str(e)) for e in entries]

        for source, line in items:
            record = parse_log_line(line, default_service=source)
            if record is None:
                continue
            record["source"] = source
            self._index_record(record)
            self._logs.append(record)
        return self._logs

    def _index_record(self, record: Dict):
        idx = len(self._logs)
        self._level_index.setdefault(record["level"], set()).add(idx)
        self._service_index.setdefault(record["service"], set()).add(idx)
        for token in self._tokenize(record["message"]):
            self._token_index.setdefault(token, set()).add(idx)

    @staticmethod
    def _tokenize(text: str) -> List[str]:
        return re.findall(r"[A-Za-z0-9_]+", text.lower())

    # ------------------------------------------------------------------
    # 日志搜索：索引 + 过滤
    # ------------------------------------------------------------------
    def search_logs(self, query: Optional[str] = None,
                    level: Optional[str] = None,
                    service: Optional[str] = None,
                    start_time: Optional[float] = None,
                    end_time: Optional[float] = None) -> List[Dict]:
        """基于索引的搜索，支持关键词 + 时间/级别/服务过滤。"""
        if query:
            candidate_sets = [self._token_index.get(token, set())
                              for token in self._tokenize(query)]
            candidates = set.intersection(*candidate_sets) if candidate_sets else set()
        else:
            candidates = set(range(len(self._logs)))

        if level:
            candidates &= self._level_index.get(level.upper(), set())
        if service:
            candidates &= self._service_index.get(service, set())

        results = []
        for idx in sorted(candidates):
            record = self._logs[idx]
            ts = record["timestamp"]
            if start_time is not None and ts < start_time:
                continue
            if end_time is not None and ts > end_time:
                continue
            if query and query.lower() not in record["message"].lower() \
                    and not set(self._tokenize(query)) <= set(self._tokenize(record["message"])):
                continue
            results.append(record)
        return results

    # ------------------------------------------------------------------
    # 日志分析：统计 + 趋势 + 关联
    # ------------------------------------------------------------------
    def analyze_logs(self, logs: Optional[List[Dict]] = None) -> Dict:
        logs = self._logs if logs is None else logs
        total = len(logs)
        errors = [l for l in logs if l["level"] in ("ERROR", "FATAL", "CRITICAL")]
        response_times = [float(l["fields"].get("response_time"))
                          for l in logs
                          if isinstance(l.get("fields"), dict)
                          and str(l["fields"].get("response_time", "")).replace(".", "", 1).isdigit()]

        return {
            "total": total,
            "error_count": len(errors),
            "error_rate": (len(errors) / total) if total else 0.0,
            "avg_response_time": (sum(response_times) / len(response_times)) if response_times else 0.0,
            "max_response_time": max(response_times) if response_times else 0.0,
            "by_level": self._count_by(logs, "level"),
            "by_service": self._count_by(logs, "service"),
            "trend": self._trend(logs),
            "correlations": self._correlate(logs),
        }

    @staticmethod
    def _count_by(logs, key):
        counts: Dict[str, int] = {}
        for record in logs:
            counts[record[key]] = counts.get(record[key], 0) + 1
        return counts

    def _trend(self, logs) -> Dict:
        """按时间分桶统计错误数，判断错误是增加还是减少。"""
        bucket = self.config.trend_bucket_seconds
        error_logs = [l for l in logs
                      if l["level"] in ("ERROR", "FATAL", "CRITICAL") and l["timestamp"] > 0]
        if not error_logs:
            return {"buckets": {}, "direction": "flat"}
        buckets: Dict[int, int] = {}
        for record in error_logs:
            key = int(record["timestamp"] // bucket)
            buckets[key] = buckets.get(key, 0) + 1
        keys = sorted(buckets)
        if len(keys) < 2:
            direction = "flat"
        else:
            mid = len(keys) // 2
            first_half = sum(buckets[k] for k in keys[:mid]) / max(mid, 1)
            second_half = sum(buckets[k] for k in keys[mid:]) / max(len(keys) - mid, 1)
            if second_half > first_half * 1.1:
                direction = "increasing"
            elif second_half < first_half * 0.9:
                direction = "decreasing"
            else:
                direction = "flat"
        return {"buckets": {k * bucket: v for k, v in sorted(buckets.items())},
                "direction": direction}

    @staticmethod
    def _correlate(logs) -> Dict[str, List[Dict]]:
        """按 request_id / trace_id 把相关日志关联起来。"""
        groups: Dict[str, List[Dict]] = {}
        for record in logs:
            fields = record.get("fields") or {}
            corr_id = fields.get("request_id") or fields.get("trace_id")
            if corr_id:
                groups.setdefault(str(corr_id), []).append(record)
        for group in groups.values():
            group.sort(key=lambda r: r["timestamp"])
        return groups

    # ------------------------------------------------------------------
    # 告警：阈值 + 去重
    # ------------------------------------------------------------------
    def alerting(self, logs: Optional[List[Dict]] = None,
                 now: Optional[float] = None) -> List[Dict]:
        """窗口内 ERROR 数超过阈值则告警；同一指纹在冷却期内去重。"""
        logs = self._logs if logs is None else logs
        now = now if now is not None else time.time()
        cfg = self.config

        window_start = now - cfg.alert_window_seconds
        errors = [l for l in logs
                  if l["level"] in ("ERROR", "FATAL", "CRITICAL")
                  and (l["timestamp"] == 0.0 or l["timestamp"] >= window_start)]

        new_alerts = []
        if len(errors) >= cfg.alert_error_threshold:
            # 按 (service, message) 生成指纹做去重
            groups: Dict[Tuple[str, str], List[Dict]] = {}
            for record in errors:
                key = (record["service"], record["message"])
                groups.setdefault(key, []).append(record)
            for (service, message), group in groups.items():
                fingerprint = f"{service}:{message}"
                last = self._alert_fingerprints.get(fingerprint)
                if last is not None and now - last < cfg.alert_cooldown_seconds:
                    continue  # 冷却期内，去重不再重复告警
                self._alert_fingerprints[fingerprint] = now
                alert = {
                    "fingerprint": fingerprint,
                    "service": service,
                    "message": message,
                    "count": len(group),
                    "threshold": cfg.alert_error_threshold,
                    "window_seconds": cfg.alert_window_seconds,
                    "timestamp": now,
                }
                self.alerts.append(alert)
                new_alerts.append(alert)
        return new_alerts

    # ------------------------------------------------------------------
    def update(self, dt: float):
        pass

    def reset(self):
        self._state = {}
        self._history = []
        self._offsets = {}
        self._logs = []
        self._token_index = {}
        self._level_index = {}
        self._service_index = {}
        self._alert_fingerprints = {}
        self.alerts = []
