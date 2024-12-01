# -*- coding: utf-8 -*-

import unittest


from cryptodatahub.common.exception import InvalidValue

from cryptoparser.common.exception import NotEnoughData

from cryptoparser.tls.subprotocol import TlsAlertMessage, TlsAlertLevel, TlsAlertDescription


class TestAlert(unittest.TestCase):
    def test_error(self):
        with self.assertRaisesRegex(InvalidValue, '0xff is not a valid TlsAlertLevel'):
            # pylint: disable=expression-not-assigned
            TlsAlertMessage.parse_exact_size(b'\xff\x00')

        with self.assertRaisesRegex(InvalidValue, '0xff is not a valid TlsAlertDescription'):
            # pylint: disable=expression-not-assigned
            TlsAlertMessage.parse_exact_size(b'\x01\xff')

        with self.assertRaises(NotEnoughData) as context_manager:
            # pylint: disable=expression-not-assigned
            TlsAlertMessage.parse_exact_size(b'\xff')
        self.assertGreaterEqual(context_manager.exception.bytes_needed, 1)

    def test_parse(self):
        self.assertEqual(
            TlsAlertMessage.parse_exact_size(b'\x02\x28'),
            TlsAlertMessage(TlsAlertLevel.FATAL, TlsAlertDescription.HANDSHAKE_FAILURE)
        )

    def test_compose(self):
        self.assertEqual(
            b'\x02\x28',
            TlsAlertMessage(TlsAlertLevel.FATAL, TlsAlertDescription.HANDSHAKE_FAILURE).compose()
        )
