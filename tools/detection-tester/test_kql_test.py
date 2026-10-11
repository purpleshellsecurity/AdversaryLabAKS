"""Focused regression tests for the Kusto HTTP client."""

import importlib.util
import unittest
from pathlib import Path


MODULE_PATH = Path(__file__).with_name("kql_test.py")
SPEC = importlib.util.spec_from_file_location("kql_test", MODULE_PATH)
kql_test = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(kql_test)


class FakeResponse:
    status_code = 200
    text = ""

    @staticmethod
    def json():
        return {"Tables": [{"Rows": [[1]]}]}


class FakeRequests:
    call = None

    @classmethod
    def post(cls, *args, **kwargs):
        cls.call = (args, kwargs)
        return FakeResponse()


class RunCountTests(unittest.TestCase):
    def setUp(self):
        self.original_requests = kql_test.requests
        kql_test.requests = FakeRequests
        FakeRequests.call = None

    def tearDown(self):
        kql_test.requests = self.original_requests

    def test_uses_supplied_token_as_bearer_authentication(self):
        self.assertEqual(
            kql_test.run_count("https://example.test", "db", "print n=1 | count", "token-value"),
            1,
        )

        _, kwargs = FakeRequests.call
        self.assertEqual(kwargs["headers"]["Authorization"], "Bearer token-value")

    def test_omits_authentication_when_no_token_is_supplied(self):
        kql_test.run_count("https://example.test", "db", "print n=1 | count", "")

        _, kwargs = FakeRequests.call
        self.assertNotIn("Authorization", kwargs["headers"])


if __name__ == "__main__":
    unittest.main()
