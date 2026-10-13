import tempfile
import unittest
from pathlib import Path
from veilcheck import scan

class VeilCheckTests(unittest.TestCase):
    def test_detects_tls_and_redacts_secret(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "app.py").write_text(
                'requests.get(url, verify=False)\nAPI_KEY = "super-secret-value-123"\n',
                encoding="utf-8",
            )
            report = scan(root)
            rules = {f["rule"] for f in report["findings"]}
            self.assertIn("TLS_VERIFY_DISABLED", rules)
            self.assertIn("HARDCODED_SECRET_LIKE", rules)
            secret_findings = [f for f in report["findings"] if f["rule"] == "HARDCODED_SECRET_LIKE"]
            self.assertNotIn("super-secret-value-123", secret_findings[0]["excerpt"])
            self.assertIn("[REDACTED]", secret_findings[0]["excerpt"])

    def test_skips_git_directory(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / ".git").mkdir()
            (root / ".git" / "config.py").write_text("debug=True", encoding="utf-8")
            report = scan(root)
            self.assertEqual(report["files_scanned"], 0)

    def test_requires_directory(self):
        with tempfile.TemporaryDirectory() as tmp:
            file_path = Path(tmp) / "not_dir.txt"
            file_path.write_text("x", encoding="utf-8")
            with self.assertRaises(ValueError):
                scan(file_path)

if __name__ == "__main__":
    unittest.main()
