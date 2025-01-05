# -*- coding: utf-8 -*-

import unittest


from cryptodatahub.common.exception import InvalidValue

from cryptoparser.common.exception import NotEnoughData

from cryptoparser.tls.record import TlsRecord
from cryptoparser.tls.subprotocol import TlsChangeCipherSpecMessage, TlsChangeCipherSpecType, TlsContentType
from cryptoparser.tls.version import TlsProtocolVersion, TlsVersion


class TestRecord(unittest.TestCase):
    def test_error(self):
        with self.assertRaisesRegex(InvalidValue, '0xff is not a valid TlsChangeCipherSpecType'):
            # pylint: disable=expression-not-assigned
            TlsChangeCipherSpecMessage.parse_exact_size(b'\xff')

        with self.assertRaises(NotEnoughData) as context_manager:
            # pylint: disable=expression-not-assigned
            TlsChangeCipherSpecMessage.parse_exact_size(b'')
        self.assertEqual(context_manager.exception.bytes_needed, 1)

    def test_parse(self):
        self.assertEqual(
            TlsChangeCipherSpecMessage.parse_exact_size(b'\x01'),
            TlsChangeCipherSpecMessage(TlsChangeCipherSpecType.CHANGE_CIPHER_SPEC)
        )

    def test_compose(self):
        self.assertEqual(
            b'\x01',
            TlsChangeCipherSpecMessage(TlsChangeCipherSpecType.CHANGE_CIPHER_SPEC).compose()
        )

    def test_record(self):
        self.assertEqual(
            b'\x14\x03\x03\x00\x01\x01',
            TlsRecord(
                TlsChangeCipherSpecMessage().compose(),
                TlsProtocolVersion(TlsVersion.TLS1_2),
                TlsContentType.CHANGE_CIPHER_SPEC,
            ).compose()
        )
