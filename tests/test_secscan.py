import unittest
from secscan.auditor import calculate_grade, evaluate_headers, compute_audit_summary

class TestSecScanAuditor(unittest.TestCase):
    def test_grade_calculation(self):
        self.assertEqual(calculate_grade(95), "A+")
        self.assertEqual(calculate_grade(85), "A")
        self.assertEqual(calculate_grade(75), "B")
        self.assertEqual(calculate_grade(65), "C")
        self.assertEqual(calculate_grade(55), "D")
        self.assertEqual(calculate_grade(30), "F")

    def test_header_evaluation(self):
        headers = {
            "Strict-Transport-Security": "max-age=31536000",
            "Content-Security-Policy": "default-src 'self'",
            "X-Frame-Options": "DENY"
        }
        results = evaluate_headers(headers)
        pass_items = [r for r in results if r["status"] == "PASS"]
        fail_items = [r for r in results if r["status"] == "FAIL"]
        
        self.assertEqual(len(pass_items), 3)
        self.assertEqual(len(fail_items), 3)

    def test_summary_computation(self):
        headers = {"Strict-Transport-Security": "max-age=31536000"}
        header_results = evaluate_headers(headers)
        ssl_info = {"status": "PASS", "valid": True, "issuer": "Let's Encrypt"}
        summary = compute_audit_summary("https://example.com", header_results, ssl_info)

        self.assertIn("score", summary)
        self.assertIn("grade", summary)
        self.assertTrue(0 <= summary["score"] <= 100)

if __name__ == "__main__":
    unittest.main()
