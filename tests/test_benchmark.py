"""Detection-efficacy regression gate.

Runs the labeled benchmark corpus and fails if precision/recall drop below the
bar or any false positive appears on the safe look-alikes. This makes detection
quality a tracked, non-regressable property — a detector change that starts
over-firing (or stops catching a vuln) breaks the build.
"""
import importlib.util
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
_spec = importlib.util.spec_from_file_location("orthosec_bench_run", ROOT / "benchmark" / "run.py")
bench = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(bench)


class TestBenchmark(unittest.TestCase):
    def setUp(self):
        self.res = bench.run_benchmark(ROOT / "benchmark")

    def test_no_false_positives_on_safe_lookalikes(self):
        self.assertEqual(self.res["overall"]["fp"], 0,
                         msg=f"false positives: {[c for c in self.res['cases'] if c['fired'] and not c['expect']]}")

    def test_precision_recall_above_bar(self):
        o = self.res["overall"]
        self.assertGreaterEqual(o["precision"], 0.95)
        self.assertGreaterEqual(o["recall"], 0.95)

    def test_every_positive_case_detected(self):
        o = self.res["overall"]
        self.assertEqual(o["fn"], 0, msg="a vulnerable case went undetected")

    def test_no_adversarial_regression(self):
        adv = bench.run_adversarial(ROOT / "benchmark")
        regressions = [c for c in adv if c["status"] == "REGRESSION"]
        self.assertEqual(regressions, [], msg=f"adversarial regression: {regressions}")

    def test_split_secret_evasion_caught(self):
        # The concatenated-credential evasion must stay caught (ORTHO-SECRET-002).
        from orthosec.core.scanner import Scanner
        fired = {f.owasp_llm for f in
                 Scanner().scan(ROOT / "benchmark/adversarial/adv_secret_concat.py").findings}
        self.assertIn("LLM02", fired)


if __name__ == "__main__":
    unittest.main()
