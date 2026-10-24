import unittest

import store


class StoreTest(unittest.TestCase):
    def setUp(self):
        self.conn = store.connect()
        store.add_user(self.conn, "alice", "pw1")
        store.add_user(self.conn, "bob", "pw2")

    def test_find_existing_user(self):
        self.assertEqual([(1, "alice")], store.find_user(self.conn, "alice"))

    def test_find_missing_user(self):
        self.assertEqual([], store.find_user(self.conn, "carol"))


if __name__ == "__main__":
    unittest.main()
