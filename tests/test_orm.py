import unittest

import orm

class ConnectTestCase(unittest.TestCase):
    # pylint: disable=no-self-use
    def test_invalid_connection_string_raises(self):
        with self.assertRaises(Exception):
            orm.connect('')

    # pylint: disable=no-self-use
    def test_valid_connection_doesnt_raise(self):
        # note creates in-memory DB
        orm.connect('sqlite://')
