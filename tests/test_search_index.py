import os
import sys
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from src.core.vault import SearchIndex


class TestSearchIndex(unittest.TestCase):
    def test_index_searches_entries_by_field_tokens(self):
        index = SearchIndex()
        index.replace_scope(
            "entries",
            [
                (1, {"title": "GitHub", "tags": "dev code", "notes": "repository hosting"}),
                (2, {"title": "Router", "tags": "infra local", "notes": "home network"}),
            ],
        )

        self.assertEqual(index.search("github", fields=["title"], scope="entries"), {1})
        self.assertEqual(index.search("infra", fields=["tags"], scope="entries"), {2})

    def test_index_keeps_scopes_isolated_for_future_audit_integration(self):
        index = SearchIndex()
        index.index_document(1, {"title": "Primary Mail", "notes": "entry payload"}, scope="entries")
        index.index_document(101, {"action": "entry_added", "details": "mail account created"}, scope="audit")

        self.assertEqual(index.search("mail", scope="entries"), {1})
        self.assertEqual(index.search("created", scope="audit"), {101})
        self.assertEqual(index.search("created", scope="entries"), set())


if __name__ == "__main__":
    unittest.main()