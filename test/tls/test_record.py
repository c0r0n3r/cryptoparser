#!/usr/bin/env python
# -*- coding: utf-8 -*-

import unittest

import six

from cryptoparser.common.exception import NotEnoughData, InvalidValue

from cryptoparser.tls.record import TlsRecord, SslRecord
from cryptoparser.tls.subprotocol import TlsSubprotocolMessageBase, TlsContentType
from cryptoparser.tls.version import TlsVersion, TlsProtocolVersionFinal

from cryptoparser.tls.subprotocol import TlsAlertMessage, TlsAlertLevel, TlsAlertDescription
from cryptoparser.tls.subprotocol import SslErrorMessage, SslErrorType, SslMessageType, SslVersion


class TestTlsSubprotocolMessageBase(unittest.TestCase):
    def test_error(self):
        error_message = 'Can\'t instantiate abstract class TlsSubprotocolMessageBase with abstract methods'
        with six.assertRaisesRegex(self, TypeError, error_message):
            TlsSubprotocolMessageBase()  # pylint: disable=abstract-class-instantiated


class TestTlsRecord(unittest.TestCase):
    def setUp(self):
        self.test_message = TlsAlertMessage(
            level=TlsAlertLevel.FATAL,
            description=TlsAlertDescription.HANDSHAKE_FAILURE
        )
        self.test_record = TlsRecord(
            messages=[self.test_message, ],
            protocol_version=TlsProtocolVersionFinal(TlsVersion.TLS1_0)
        )
        self.test_record_bytes = bytes(
            b'\x15' +      # type = ALERT
            b'\x03\x01' +  # version = TLS1_0
            b'\x00\x02' +  # length = 2
            b'\x02' +      # level = FATAL
            b'\x28' +      # description = HANDSHAKE_FAILURE
            b''
        )

    def test_error(self):
        with six.assertRaisesRegex(self, InvalidValue, '0xff is not a valid TlsContentType'):
            record = TlsRecord.parse_exact_size(
                b'\xff' +      # type = INVALID
                b'\x03\x03' +  # version = TLS 1.2
                b'\x00\x00' +  # length = 0
                b''
            )

        with self.assertRaises(NotEnoughData) as context_manager:
            record = TlsRecord.parse_exact_size(
                b'\x15' +      # type = alert
                b'\x03\x03' +  # version = TLS 1.2
                b'\x00\x01' +  # length = 1 (alert message is 2 bytes!)
                b''
            )
        self.assertEqual(context_manager.exception.bytes_needed, 1)

        record = TlsRecord.parse_exact_size(
            b'\x15' +      # type = alert
            b'\x03\x03' +  # version = TLS 1.2
            b'\x00\x02' +  # length = 2
            b'\x02\x28'
        )
        with self.assertRaises(InvalidValue):
            record.protocol_version = 'invalid version'
        with self.assertRaises(InvalidValue):
            record.messages = ['invalid message', ]

        with self.assertRaises(NotEnoughData) as context_manager:
            record = TlsRecord.parse_exact_size(
                b'\x16' +      # type = handshake
                b'\x03\x03' +  # version = TLS 1.2
                b'\x00\x02' +  # length = 2 (handshake message is at least 4 bytes!)
                b''
            )
        self.assertEqual(context_manager.exception.bytes_needed, 2)

        with self.assertRaises(NotEnoughData) as context_manager:
            record = TlsRecord.parse_exact_size(
                b'\x16' +          # type = handshake
                b'\x03\x01' +      # version = TLS 1.0
                b'\x00\x06' +      # length = 6
                b'\x01'            # handshake_type: CLIENT_HELLO
                b'\x00\x00\x03' +  # handshake_length = 3
                b'\x03\x03' +      # version = TLS 1.2
                b''
            )
        self.assertEqual(context_manager.exception.bytes_needed, 1)

        with self.assertRaises(InvalidValue) as context_manager:
            record = TlsRecord.parse_exact_size(
                b'\x16' +          # type = handshake
                b'\x03\x01' +      # version = TLS 1.0
                b'\x00\x06' +      # length = 10
                b'\xff'            # handshake_type: INVALID
                b'\x00\x00\x02' +  # handshake_length = 2
                b'\x03\x03' +      # version = TLS 1.2
                b''
            )

        with self.assertRaises(InvalidValue) as context_manager:
            record = TlsRecord.parse_exact_size(
                b'\x15' +          # type = alert
                b'\x03\x01' +      # version = TLS 1.0
                b'\x00\x02' +      # length = 6
                b'\x02'            # level: FATAL
                b'\xff'            # description: INVALID
                b''
            )

        with self.assertRaises(InvalidValue) as context_manager:
            record = TlsRecord.parse_exact_size(
                b'\x18' +      # type = heartbeat
                b'\x03\x03' +  # version = TLS 1.2
                b'\x00\x01' +  # length = 1
                b'\x00'
            )

    def test_setter(self):
        record = TlsRecord([self.test_message, ])
        self.assertEqual(len(record.messages), 1)

        record.messages = [self.test_message, self.test_message]
        self.assertEqual(len(record.messages), 2)

    def test_parse(self):
        record = TlsRecord.parse_exact_size(self.test_record_bytes)

        self.assertEqual(record.content_type, TlsContentType.ALERT)
        self.assertEqual(len(record.messages), 1)
        self.assertEqual(
            record.messages[0],
            self.test_message
        )

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
        with six.assertRaisesRegex(self, InvalidValue, '0xff is not a valid SslMessageType'):
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

        with self.assertRaises(InvalidValue):
            self.test_record.protocol_version = 'invalid version'
        with self.assertRaises(InvalidValue):
            self.test_record.message = 'invalid message'

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
        record.protocol_version = SslVersion.SSL2

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
