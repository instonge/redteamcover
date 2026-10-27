"""redteamcover —— 自检测试。

检查红队用例覆盖了哪些攻击面

覆盖：正常路径、边界输入、防呆红线、幂等性。
"""
from __future__ import annotations

import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import redteamcover  # noqa: E402

SAMPLE_TEXT = '第一条要求说明系统行为\n第二条要求说明系统行为\n第三条完全不同的话'


class TestRedteamcover(unittest.TestCase):
    """红队用例覆盖"""

    def test_cli_help_exits_zero(self):
        """--help 必须能正常退出。"""
        import subprocess
        proc = subprocess.run(
            [sys.executable, os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                         "redteamcover.py"), "--help"],
            capture_output=True, text=True, encoding="utf-8")
        self.assertEqual(proc.returncode, 0)

    def test_cli_rejects_empty_input(self):
        """空输入必须明确报错，不能静默成功。"""
        import subprocess
        proc = subprocess.run(
            [sys.executable, os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                         "redteamcover.py"), "--text", "   "],
            capture_output=True, text=True, encoding="utf-8")
        self.assertNotEqual(proc.returncode, 0)

    def test_cli_json_output_parses(self):
        """--json 输出必须是合法 JSON。"""
        import subprocess
        proc = subprocess.run(
            [sys.executable, os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                         "redteamcover.py"), "--text", SAMPLE_TEXT,
             "--json"],
            capture_output=True, text=True, encoding="utf-8")
        if proc.returncode not in (0, 1):
            self.fail(f"退出码异常：{proc.returncode} {proc.stderr[:300]}")
        data = json.loads(proc.stdout)
        self.assertIsInstance(data, dict)

    def test_does_not_mutate_input(self):
        """防呆：分析过程不得改动调用方传入的对象。"""
        payload = SAMPLE_TEXT
        before = payload
        redteamcover.redteamcover_analyze(payload)
        self.assertEqual(before, payload)

    def test_is_idempotent(self):
        """同一输入跑两次结果必须一致。"""
        a = redteamcover.redteamcover_analyze(SAMPLE_TEXT)
        b = redteamcover.redteamcover_analyze(SAMPLE_TEXT)
        self.assertEqual(json.dumps(a, ensure_ascii=False, sort_keys=True),
                         json.dumps(b, ensure_ascii=False, sort_keys=True))

    def test_reports_coverage(self):
        r = redteamcover.redteamcover_analyze(SAMPLE_TEXT)
        self.assertTrue(r["ok"])
        self.assertGreater(r["coverage"], 0)

    def test_lists_missing_items(self):
        r = redteamcover.redteamcover_analyze(SAMPLE_TEXT)
        self.assertIn("missing_items", r)
        self.assertEqual(len(r["missing_items"]), len(r["missing_texts"]))
