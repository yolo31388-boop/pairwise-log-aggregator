"""
游戏内日志收集与分析系统 - 验收测试
运行方式：python -m pytest tests/test_log_aggregator.py -q
共 15 个测试用例（同时兼容 python -m unittest 运行）
"""
import json
import os
import sys
import tempfile
import time
import unittest
import zlib

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from logging.aggregator import LogAggregator, parse_log_line

BASE_TS = 1_700_000_000.0


def json_line(level="INFO", service="login", msg="ok", ts=BASE_TS, **extra):
    data = {"timestamp": ts, "level": level, "service": service, "msg": msg}
    data.update(extra)
    return json.dumps(data)


class TestLogAggregator(unittest.TestCase):
    def setUp(self):
        self.system = LogAggregator({"alert_error_threshold": 3,
                                     "alert_window_seconds": 60.0,
                                     "alert_cooldown_seconds": 100.0})
        self._source_seq = 0

    def _ingest(self, raw):
        self._source_seq += 1
        collected = self.system.collect_logs({"server-%d" % self._source_seq: raw})
        return self.system.aggregate_logs(collected)

    # ---- 1-3: 日志收集（实时增量 + 压缩） ----
    def test_case_01(self):
        """日志收集：能从多台服务器收集日志，而不是只留在本机"""
        logs = self.system.collect_logs({
            "server-a": ["2023-11-14 22:13:20 INFO [login] hi"],
            "server-b": ["2023-11-14 22:13:21 ERROR [battle] boom"],
        })
        self.assertEqual(len(logs), 2)
        sources = {item["source"] for item in logs}
        self.assertEqual(sources, {"server-a", "server-b"})

    def test_case_02(self):
        """日志收集：增量读取，第二次只收集新日志，保证实时性"""
        stream = ["2023-11-14 22:13:20 INFO [login] a"]
        first = self.system.collect_logs({"s1": stream})
        self.assertEqual(len(first), 1)
        second = self.system.collect_logs({"s1": stream})
        self.assertEqual(second, [])
        stream.append("2023-11-14 22:13:21 INFO [login] b")
        third = self.system.collect_logs({"s1": stream})
        self.assertEqual(len(third), 1)
        self.assertIn("b", third[0]["line"])

    def test_case_03(self):
        """日志收集：传输前压缩，体积明显减小且可还原"""
        raw = [json_line(msg="player moved to new position " * 5) for _ in range(50)]
        payload = self.system.compress(raw)
        self.assertLess(len(payload), len("\n".join(raw).encode("utf-8")))
        restored = self.system.decompress(payload)
        self.assertEqual(restored, raw)

    # ---- 4-6: 日志聚合（解析 + 标准化） ----
    def test_case_04(self):
        """日志聚合：JSON / key=value / 纯文本三种格式都能解析出字段"""
        json_rec = parse_log_line(json_line(level="ERROR", service="login",
                                            msg="db down", ts=BASE_TS))
        kv_rec = parse_log_line(
            "ts=%d level=WARN service=battle msg=%s" % (BASE_TS, '"hp low"'))
        text_rec = parse_log_line("2023-11-14 22:13:20 INFO [chat] hello")
        for rec in (json_rec, kv_rec, text_rec):
            self.assertTrue(rec["timestamp"] > 0)
            self.assertIn(rec["level"], ("ERROR", "WARN", "INFO"))
            self.assertTrue(rec["service"])
            self.assertTrue(rec["message"])

    def test_case_05(self):
        """日志聚合：不同服务不同格式的日志标准化为统一结构"""
        raw = [
            json_line(level="ERROR", service="login", msg="fail"),
            "ts=%d level=info service=battle msg=%s" % (BASE_TS, '"hit"'),
            "2023-11-14 22:13:20 WARN [chat] lag",
        ]
        logs = self._ingest(raw)
        self.assertEqual(len(logs), 3)
        keys = {"timestamp", "level", "service", "message", "fields"}
        for record in logs:
            self.assertTrue(keys <= set(record.keys()))
        self.assertEqual(logs[1]["level"], "INFO")
        self.assertEqual(logs[2]["service"], "chat")

    def test_case_06(self):
        """日志聚合：额外字段（如 request_id、response_time）被提取保留"""
        rec = parse_log_line(json_line(level="INFO", service="api", msg="req",
                                       request_id="abc", response_time=42))
        self.assertEqual(rec["fields"]["request_id"], "abc")
        self.assertEqual(rec["fields"]["response_time"], 42)

    # ---- 7-9: 日志搜索（索引 + 过滤） ----
    def test_case_07(self):
        """日志搜索：关键词搜索走索引，能命中结果"""
        raw = [
            json_line(level="INFO", service="login", msg="user login success"),
            json_line(level="INFO", service="login", msg="player moved"),
        ]
        self._ingest(raw)
        hits = self.system.search_logs(query="login")
        self.assertEqual(len(hits), 1)
        self.assertIn("login success", hits[0]["message"])

    def test_case_08(self):
        """日志搜索：支持按级别和服务过滤"""
        raw = [
            json_line(level="INFO", service="login", msg="x"),
            json_line(level="ERROR", service="login", msg="y"),
            json_line(level="ERROR", service="battle", msg="z"),
        ]
        self._ingest(raw)
        self.assertEqual(len(self.system.search_logs(level="ERROR")), 2)
        result = self.system.search_logs(level="ERROR", service="battle")
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["service"], "battle")

    def test_case_09(self):
        """日志搜索：支持按时间范围过滤"""
        raw = [
            json_line(level="ERROR", msg="early", ts=BASE_TS),
            json_line(level="ERROR", msg="late", ts=BASE_TS + 1000),
        ]
        self._ingest(raw)
        hits = self.system.search_logs(start_time=BASE_TS + 500)
        self.assertEqual(len(hits), 1)
        self.assertIn("late", hits[0]["message"])

    # ---- 10-12: 日志分析（统计 + 趋势 + 关联） ----
    def test_case_10(self):
        """日志分析：统计错误率和响应时间"""
        raw = [
            json_line(level="INFO", msg="a", response_time=100),
            json_line(level="INFO", msg="b", response_time=200),
            json_line(level="ERROR", msg="c"),
            json_line(level="ERROR", msg="d"),
        ]
        self._ingest(raw)
        stats = self.system.analyze_logs()
        self.assertEqual(stats["total"], 4)
        self.assertEqual(stats["error_count"], 2)
        self.assertEqual(stats["error_rate"], 0.5)
        self.assertEqual(stats["avg_response_time"], 150)
        self.assertEqual(stats["max_response_time"], 200)

    def test_case_11(self):
        """日志分析：按时间桶给出错误趋势（增加/减少）"""
        raw = []
        for i in range(2):
            raw.append(json_line(level="ERROR", msg="old", ts=BASE_TS + i * 10))
        for i in range(8):
            raw.append(json_line(level="ERROR", msg="new",
                                 ts=BASE_TS + 300 + i * 10))
        self.system.config.trend_bucket_seconds = 60
        self._ingest(raw)
        trend = self.system.analyze_logs()["trend"]
        self.assertEqual(trend["direction"], "increasing")
        self.assertGreaterEqual(len(trend["buckets"]), 2)

    def test_case_12(self):
        """日志分析：通过 request_id 关联同一次请求的多条日志"""
        raw = [
            json_line(level="INFO", service="login", msg="start", request_id="r1",
                      ts=BASE_TS),
            json_line(level="INFO", service="db", msg="query", request_id="r1",
                      ts=BASE_TS + 1),
            json_line(level="ERROR", service="login", msg="fail", request_id="r1",
                      ts=BASE_TS + 2),
            json_line(level="INFO", service="login", msg="other", request_id="r2",
                      ts=BASE_TS + 3),
        ]
        self._ingest(raw)
        groups = self.system.analyze_logs()["correlations"]
        self.assertEqual(len(groups["r1"]), 3)
        self.assertEqual([r["message"] for r in groups["r1"]],
                         ["start", "query", "fail"])

    # ---- 13-15: 告警（阈值 + 去重） ----
    def test_case_13(self):
        """告警：窗口内 ERROR 数达到阈值才通知，INFO 不应触发"""
        raw = [json_line(level="INFO", msg="noise", ts=BASE_TS) for _ in range(5)]
        raw += [json_line(level="ERROR", service="login", msg="boom",
                          ts=BASE_TS) for _ in range(3)]
        self._ingest(raw)
        alerts = self.system.alerting(now=BASE_TS + 10)
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["service"], "login")
        self.assertGreaterEqual(alerts[0]["count"], 3)

    def test_case_14(self):
        """告警：同一错误在冷却期内不重复告警（去重）"""
        raw = [json_line(level="ERROR", service="login", msg="boom",
                         ts=BASE_TS) for _ in range(3)]
        self._ingest(raw)
        first = self.system.alerting(now=BASE_TS + 10)
        second = self.system.alerting(now=BASE_TS + 20)
        self.assertEqual(len(first), 1)
        self.assertEqual(second, [])
        self.assertEqual(len(self.system.alerts), 1)

    def test_case_15(self):
        """告警：冷却期过后同一错误可再次告警，但冷却期内不同错误仍可各自告警"""
        raw = [json_line(level="ERROR", service="login", msg="boom",
                         ts=BASE_TS) for _ in range(3)]
        self._ingest(raw)
        self.system.alerting(now=BASE_TS + 10)
        fresh = [json_line(level="ERROR", service="login", msg="boom",
                           ts=BASE_TS + 195) for _ in range(3)]
        self._ingest(fresh)
        again = self.system.alerting(now=BASE_TS + 200)
        self.assertEqual(len(again), 1)
        raw2 = [json_line(level="ERROR", service="battle", msg="crash",
                          ts=BASE_TS + 50) for _ in range(3)]
        self._ingest(raw2)
        mixed = self.system.alerting(now=BASE_TS + 60)
        self.assertEqual({a["fingerprint"] for a in mixed},
                         {"battle:crash"})


if __name__ == "__main__":
    try:
        import pytest
        pytest.main([__file__, "-v"])
    except ImportError:
        unittest.main(verbosity=2)
