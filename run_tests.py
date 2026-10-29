#!/usr/bin/env python3
"""运行 offline_qualification_v1 的测试套件。

为什么需要这个入口：
    tests/test_records.py 有意不提供环境变量或产品默认的临时目录，
    TEST_ROOT 必须由调用方显式注入一个已批准的根（见该文件
    EXPLICIT_APPROVED_TEST_ROOT_REQUIRED）。这是设计选择，不是遗漏。
    因此直接 `python -m unittest discover` 会以 RuntimeError 失败，
    必须经由本入口或等价的显式注入。

用法：
    python run_tests.py              # 全部测试
    python run_tests.py -v           # 详细输出
    python run_tests.py test_records # 只跑某个文件

退出码：0 = 全部通过，1 = 有失败/错误。
"""
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).absolute().parent
sys.path.insert(0, str(ROOT))

from offline_qualification_v1.tests import test_records  # noqa: E402

verbosity = 2 if "-v" in sys.argv else 1
patterns = [a for a in sys.argv[1:] if not a.startswith("-")] or ["test_*.py"]

# 显式注入一个一次性临时根；测试产生的记录按设计写在产品根之外。
test_records.TEST_ROOT = tempfile.mkdtemp(prefix="h56-tests-")

loader = unittest.TestLoader()
suite = unittest.TestSuite()
tests_dir = ROOT / "offline_qualification_v1" / "tests"
for pattern in patterns:
    if not pattern.endswith(".py"):
        pattern += ".py"
    for path in sorted(tests_dir.glob(pattern)):
        suite.addTests(loader.loadTestsFromName(f"offline_qualification_v1.tests.{path.stem}"))

print(f"h56 测试套件 ｜ 产品根 {ROOT}")
print(f"Python {sys.version.split()[0]} ｜ 测试根 {test_records.TEST_ROOT}")
print(f"用例 {suite.countTestCases()} 项")
print("-" * 60)

result = unittest.TextTestRunner(verbosity=verbosity).run(suite)
raise SystemExit(0 if result.wasSuccessful() else 1)
