# -*- coding: utf-8 -*-

import unittest

from cryptodatahub.common.exception import InvalidValue

from cryptoparser.common.exception import NotEnoughData
from cryptoparser.tls.postgresql import SslRequest, Sync


class TestSslRequest(unittest.TestCase):
    def setUp(self):
        self.ssl_request = SslRequest()
        self.ssl_request_bytes = b'\x00\x00\x00\x08\x04\xd2\x16\x2f'

    def test_error(self):
        with self.assertRaises(NotEnoughData) as context_manager:
            SslRequest.parse_exact_size(b'')
        self.assertEqual(context_manager.exception.bytes_needed, SslRequest.MESSAGE_SIZE)

        with self.assertRaises(InvalidValue) as context_manager:
            SslRequest.parse_exact_size(b'\x00\x00\x00\x04\x01\x02\x03\x04')
        self.assertEqual(context_manager.exception.value, 4)

        with self.assertRaises(InvalidValue) as context_manager:
            SslRequest.parse_exact_size(b'\x00\x00\x00\x08\x01\x02\x03\x04')
        self.assertEqual(context_manager.exception.value, 0x01020304)

    def test_parse(self):
        SslRequest.parse_exact_size(self.ssl_request_bytes)

    def test_compose(self):
        self.assertEqual(self.ssl_request.compose(), self.ssl_request_bytes)


class TestSync(unittest.TestCase):
    def setUp(self):
        self.ssl_request = Sync()
        self.ssl_request_bytes = b'S'

    def test_error(self):
        with self.assertRaises(InvalidValue) as context_manager:
            Sync.parse_exact_size(b'X')
        self.assertEqual(context_manager.exception.value, b'X')

    def test_parse(self):
        Sync.parse_exact_size(self.ssl_request_bytes)

    def test_compose(self):
        self.assertEqual(self.ssl_request.compose(), self.ssl_request_bytes)
