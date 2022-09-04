# -*- coding: utf-8 -*-

import unittest

from cryptoparser.common.utils import bytes_to_hex_string


class TestBytesToHexString(unittest.TestCase):
    def test_separator(self):
        self.assertEqual(bytes_to_hex_string(b''), '')
        self.assertEqual(bytes_to_hex_string(b'\xde\xad\xbe\xef'), 'DEADBEEF')
        self.assertEqual(bytes_to_hex_string(b'\xde\xad\xbe\xef', separator=':'), 'DE:AD:BE:EF')

    def test_lowercase(self):
        self.assertEqual(bytes_to_hex_string(b''), '')
        self.assertEqual(bytes_to_hex_string(b'\xde\xad\xbe\xef'), 'DEADBEEF')
        self.assertEqual(bytes_to_hex_string(b'\xde\xad\xbe\xef', lowercase=True), 'deadbeef')
