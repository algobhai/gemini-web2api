import json
import unittest
import urllib.parse

from hardened_transport import _category_from_form
from hardening import (
    MODEL_ID_FLASH,
    MODEL_ID_FLASH_LITE,
    MODEL_ID_PRO,
    REJECTED_MODEL_ID,
    build_model_header,
    constant_time_key_match,
    extract_route_metadata,
    is_loopback_host,
    redact_log_line,
    route_diagnostic,
)


class HardeningTests(unittest.TestCase):
    def test_model_header_contract_for_pro(self):
        raw = build_model_header(3)
        self.assertIsNotNone(raw)
        payload = json.loads(raw)
        self.assertEqual(payload[0], 1)
        self.assertEqual(payload[4], MODEL_ID_PRO)
        self.assertEqual(payload[8], [4, 5, 6, 8, 4, 5, 6, 8])
        self.assertEqual(payload[11], 2)
        self.assertEqual(payload[14], 3)
        self.assertEqual(payload[15], 0)
        self.assertIsInstance(payload[16], str)
        self.assertTrue(payload[16])

    def test_auto_has_no_header(self):
        self.assertIsNone(build_model_header(4))

    def test_category_ids(self):
        self.assertEqual(json.loads(build_model_header(1))[4], MODEL_ID_FLASH)
        self.assertEqual(json.loads(build_model_header(6))[4], MODEL_ID_FLASH_LITE)

    def test_category_parser_matches_upstream_form(self):
        inner = [None] * 80
        inner[79] = 3
        outer = [None, json.dumps(inner)]
        body = urllib.parse.urlencode({"f.req": json.dumps(outer)})
        self.assertEqual(_category_from_form(body), 3)

    def test_extract_route_metadata(self):
        inner = [None] * 43
        inner[39] = MODEL_ID_PRO
        inner[42] = "3.1 Pro"
        line = json.dumps([["wrb.fr", None, json.dumps(inner)]])
        served_id, label = extract_route_metadata(line)
        self.assertEqual(served_id, MODEL_ID_PRO)
        self.assertEqual(label, "3.1 Pro")

    def test_pro_mismatch_is_detected(self):
        diag = route_diagnostic(3, REJECTED_MODEL_ID, "3.5 Flash-Lite")
        self.assertEqual(diag.status, "mismatch")

    def test_pro_ok(self):
        diag = route_diagnostic(3, MODEL_ID_PRO, "3.1 Pro")
        self.assertEqual(diag.status, "ok")

    def test_loopback_detection(self):
        self.assertTrue(is_loopback_host("127.0.0.1"))
        self.assertTrue(is_loopback_host("::1"))
        self.assertTrue(is_loopback_host("localhost"))
        self.assertFalse(is_loopback_host("0.0.0.0"))
        self.assertFalse(is_loopback_host("192.168.1.10"))

    def test_constant_time_match_semantics(self):
        self.assertTrue(constant_time_key_match("abc", ["def", "abc"]))
        self.assertFalse(constant_time_key_match("zzz", ["def", "abc"]))

    def test_log_redaction(self):
        line = 'POST /v1/models?key=secret123&x=1 Authorization: Bearer topsecret'
        redacted = redact_log_line(line)
        self.assertNotIn("secret123", redacted)
        self.assertNotIn("topsecret", redacted)
        self.assertIn("<redacted>", redacted)


if __name__ == "__main__":
    unittest.main()
