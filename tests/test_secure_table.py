import os
import sys
import time
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from src.gui.widgets.secure_table import SecureTable


class FakeTree:
    def __init__(self):
        self.displaycolumns = None
        self.rows = {}

    def configure(self, **kwargs):
        if "displaycolumns" in kwargs:
            self.displaycolumns = list(kwargs["displaycolumns"])

    def get_children(self):
        return list(self.rows)

    def delete(self, item_id):
        self.rows.pop(item_id, None)

    def insert(self, _parent, _index, iid=None, values=None):
        self.rows[str(iid)] = values


class TestSecureTable(unittest.TestCase):
    def test_reorder_display_columns_updates_visible_order(self):
        table = SecureTable.__new__(SecureTable)
        table._column_order = ["title", "username", "url"]
        table.tree = FakeTree()

        table._reorder_display_columns("url", "username")

        self.assertEqual(table._column_order, ["title", "url", "username"])
        self.assertEqual(table.tree.displaycolumns, ["title", "url", "username"])

    def test_reorder_display_columns_ignores_unknown_columns(self):
        table = SecureTable.__new__(SecureTable)
        table._column_order = ["title", "username", "url"]
        table.tree = FakeTree()

        table._reorder_display_columns("missing", "username")

        self.assertEqual(table._column_order, ["title", "username", "url"])
        self.assertIsNone(table.tree.displaycolumns)

    def test_set_data_handles_1000_rows_without_noticeable_slowdown(self):
        table = SecureTable.__new__(SecureTable)
        table.columns = [
            {"id": "title", "label": "Title"},
            {"id": "username", "label": "Username"},
            {"id": "url", "label": "URL"},
            {"id": "updated_at", "label": "Updated"},
        ]
        table.tree = FakeTree()
        table.data = []

        rows = [
            {
                "title": f"Entry {index}",
                "username": f"user{index}",
                "url": f"https://example{index}.com",
                "updated_at": f"2026-04-02T12:{index % 60:02d}:00",
            }
            for index in range(1000)
        ]

        started_at = time.perf_counter()
        table.set_data(rows)
        elapsed = time.perf_counter() - started_at

        self.assertEqual(len(table.data), 1000)
        self.assertEqual(len(table.tree.rows), 1000)
        self.assertLess(elapsed, 1.0)


if __name__ == "__main__":
    unittest.main()