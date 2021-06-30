# -*- coding: utf-8 -*-

import unittest

from cryptoparser.tls.subprotocol import TlsApplicationDataMessage


class TestRecord(unittest.TestCase):
    _APPLICATION_DATA_MESSAGE_BYTES = b'\x01\x02\x03\x04'

    def test_error(self):
        pass

    def test_parse(self):
        self.assertEqual(
            TlsApplicationDataMessage.parse_exact_size(self._APPLICATION_DATA_MESSAGE_BYTES),
            TlsApplicationDataMessage(data=self._APPLICATION_DATA_MESSAGE_BYTES)
        )

    def test_compose(self):
        self.assertEqual(
            self._APPLICATION_DATA_MESSAGE_BYTES,
            TlsApplicationDataMessage(data=self._APPLICATION_DATA_MESSAGE_BYTES).compose()
        )
