# -*- coding: utf-8 -*-

import unittest

from cryptoparser.tls.grease import TlsInvalidType, TlsInvalidTypeParams, TlsInvalidTypeOneByte, TlsInvalidTypeTwoByte


class TestGrease(unittest.TestCase):
    def test_parse(self):
        self.assertEqual(
            TlsInvalidTypeOneByte.parse_exact_size(b'\x2a').value,
            TlsInvalidTypeParams(0x2a, TlsInvalidType.GREASE)
        )
        self.assertEqual(
            TlsInvalidTypeOneByte.parse_exact_size(b'\x2b').value,
            TlsInvalidTypeParams(0x2b, TlsInvalidType.UNKNOWN)
        )

        self.assertEqual(
            TlsInvalidTypeTwoByte.parse_exact_size(b'\x2a\x2a').value,
            TlsInvalidTypeParams(0x2a2a, TlsInvalidType.GREASE)
        )
        self.assertEqual(
            TlsInvalidTypeTwoByte.parse_exact_size(b'\x2b\x2b').value,
            TlsInvalidTypeParams(0x2b2b, TlsInvalidType.UNKNOWN)
        )

    def test_compose(self):
        self.assertEqual(
            b'\x2a',
            TlsInvalidTypeOneByte(0x2a).compose()
        )
        self.assertEqual(
            b'\x2b',
            TlsInvalidTypeOneByte(0x2b).compose()
        )

        self.assertEqual(
            b'\x2a\x2a',
            TlsInvalidTypeTwoByte(0x2a2a).compose()
        )
        self.assertEqual(
            b'\x2b\x2b',
            TlsInvalidTypeTwoByte(0x2b2b).compose()
        )
