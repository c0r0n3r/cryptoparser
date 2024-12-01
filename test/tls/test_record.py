# -*- coding: utf-8 -*-

import unittest


from cryptodatahub.common.exception import InvalidValue
from cryptoparser.common.exception import NotEnoughData

from cryptoparser.tls.record import TlsRecord, SslRecord
from cryptoparser.tls.subprotocol import TlsContentType, TlsSubprotocolMessageBase
from cryptoparser.tls.version import TlsVersion, TlsProtocolVersion

from cryptoparser.tls.subprotocol import TlsAlertMessage, TlsAlertLevel, TlsAlertDescription
from cryptoparser.tls.subprotocol import SslErrorMessage, SslErrorType, SslMessageType


class TestTlsSubprotocolMessageBase(unittest.TestCase):
    def test_error(self):
        error_message = 'Can\'t instantiate abstract class TlsSubprotocolMessageBase'
        with self.assertRaisesRegex(BaseException, error_message) as context_manager:
            TlsSubprotocolMessageBase()  # pylint: disable=abstract-class-instantiated
        self.assertTrue(isinstance(context_manager.exception, (TypeError, AssertionError)))


class TestTlsRecord(unittest.TestCase):
    def setUp(self):
        self.test_message = TlsAlertMessage(
            level=TlsAlertLevel.FATAL,
            description=TlsAlertDescription.HANDSHAKE_FAILURE
        )
        self.test_record = TlsRecord(
            fragment=self.test_message.compose(),
            protocol_version=TlsProtocolVersion(TlsVersion.TLS1),
            content_type=TlsContentType.ALERT,
        )
        self.test_record_bytes = bytes(
            b'\x15' +      # type = ALERT
            b'\x03\x01' +  # version = TLS1
            b'\x00\x02' +  # length = 2
            b'\x02' +      # level = FATAL
            b'\x28' +      # description = HANDSHAKE_FAILURE
            b''
        )

    def test_error(self):
        with self.assertRaises(NotEnoughData) as context_manager:
            TlsRecord.parse_exact_size(b'')
        self.assertEqual(context_manager.exception.bytes_needed, TlsRecord.HEADER_SIZE)

        with self.assertRaisesRegex(InvalidValue, '0xff is not a valid TlsContentType'):
            TlsRecord.parse_exact_size(
                b'\xff' +      # type = INVALID
                b'\x03\x03' +  # version = TLS 1.2
                b'\x00\x00' +  # length = 0
                b''
            )

        with self.assertRaises(NotEnoughData) as context_manager:
            TlsRecord.parse_exact_size(
                b'\x15' +      # type = alert
                b'\x03\x03' +  # version = TLS 1.2
                b'\x00\x01' +  # length = 1 (alert message is 2 bytes!)
                b''
            )
        self.assertEqual(context_manager.exception.bytes_needed, 1)

        TlsRecord.parse_exact_size(
            b'\x15' +      # type = alert
            b'\x03\x03' +  # version = TLS 1.2
            b'\x00\x02' +  # length = 2
            b'\x02\x28'
        )

        with self.assertRaises(NotEnoughData) as context_manager:
            TlsRecord.parse_exact_size(
                b'\x16' +      # type = handshake
                b'\x03\x03' +  # version = TLS 1.2
                b'\x00\x02' +  # length = 2 (handshake message is at least 4 bytes!)
                b''
            )
        self.assertEqual(context_manager.exception.bytes_needed, 2)

    def test_parse(self):
        record = TlsRecord.parse_exact_size(self.test_record_bytes)

        self.assertEqual(record.fragment, self.test_message.compose())
        self.assertEqual(record.protocol_version, TlsProtocolVersion(TlsVersion.TLS1))
        self.assertEqual(record.content_type, TlsContentType.ALERT)

    def test_compose(self):
        self.assertEqual(
            self.test_record.compose(),
            self.test_record_bytes
        )


class TestSslRecord(unittest.TestCase):
    def setUp(self):
        self.test_message = SslErrorMessage(
            error_type=SslErrorType.NO_CIPHER_ERROR
        )
        self.test_record = SslRecord(
            message=self.test_message
        )
        self.test_record_bytes = bytes(
            b'\x80\x03' +  # length = 3
            b'\x00' +      # message_type = ERROR
            b'\x00\x01' +  # error_type = NO_CIPHER_ERROR
            b''
        )

    def test_error(self):
        with self.assertRaisesRegex(InvalidValue, '0xff is not a valid SslMessageType'):
            SslRecord.parse_exact_size(
                b'\x80\x00' +  # length = 0
                b'\xff' +      # type = INVALID
                b''
            )

        with self.assertRaises(NotEnoughData) as context_manager:
            SslRecord.parse_exact_size(
                b'\x80\x03' +  # length = 3 (with length bytes)
                b''
            )
        self.assertEqual(context_manager.exception.bytes_needed, 3)

        with self.assertRaises(InvalidValue) as context_manager:
            SslRecord.parse_exact_size(
                b'\x80\x03' +  # length = 3
                b'\x00' +      # message_type = ERROR
                b'\x00\xff' +  # error_type = INVALID
                b''
            )

        with self.assertRaises(NotEnoughData) as context_manager:
            SslRecord.parse_exact_size(
                b'\x80\x03' +  # length = 3
                b'\x00' +      # type = ERROR
                b''
            )
        self.assertEqual(context_manager.exception.bytes_needed, 2)

        with self.assertRaises(NotEnoughData) as context_manager:
            SslRecord.parse_exact_size(
                b'\x81\x03' +  # length = 256 + 3
                b''
            )
        self.assertEqual(context_manager.exception.bytes_needed, 256 + 3 - 0)

        with self.assertRaises(NotEnoughData) as context_manager:
            SslRecord.parse_exact_size(
                b'\x01\x03\x01' +  # length = 256 + 3
                b''
            )
        self.assertEqual(context_manager.exception.bytes_needed, 256 + 3 - 0)

    def test_setter(self):
        record = SslRecord(self.test_message)

        record.message = self.test_message
        record.protocol_version = TlsVersion.SSL2

    def test_parse(self):
        record = SslRecord.parse_exact_size(self.test_record_bytes)

        self.assertEqual(
            record.message,
            self.test_message
        )
        self.assertEqual(record.content_type, SslMessageType.ERROR)

    def test_compose(self):
        self.assertEqual(
            self.test_record.compose(),
            self.test_record_bytes
        )
