#!/usr/bin/env python
# -*- coding: utf-8 -*-

import unittest


from cryptoparser.common.exception import NotEnoughData

from cryptoparser.ssh.record import SshRecordInit, SshRecordKexDH, SshRecordKexDHGroup
from cryptoparser.ssh.subprotocol import SshDisconnectMessage, SshReasonCode


class TestRecord(unittest.TestCase):
    def setUp(self):
        self.test_packet = SshDisconnectMessage(
            SshReasonCode.PROTOCOL_ERROR,
            'αβγ',
            'en-US'
        )
        self.test_record = SshRecordInit(self.test_packet)
        self.test_record_bytes = bytes(
            b'\x00\x00\x00\x24' +                                 # length = 0x01020304
            b'\x0b' +                                             # padding length = 0x00
            b'\x01' +                                             # message code = DISCONNECT
            b'\x00\x00\x00\x02' +                                 # reason = PROTOCOL_ERROR
            b'\x00\x00\x00\x06' +                                 # description length = 6
            'αβγ'.encode('utf-8') +                               # description
            b'\x00\x00\x00\x05' +                                 # language length = 5
            b'en-US' +                                            # language
            b'\x00\x00\x00\x00\x00\x00\x00\x00' +                 # padding
            b'\x00\x00\x00' +                                     # padding
            b''
        )

    def test_error(self):
        with self.assertRaises(NotEnoughData) as context_manager:
            SshRecordInit.parse_exact_size(b'')
        self.assertEqual(context_manager.exception.bytes_needed, 4)

        with self.assertRaises(NotEnoughData) as context_manager:
            SshRecordInit.parse_exact_size(
                b'\x01\x02\x03\x04'  # length = 0x01020304
            )
        self.assertEqual(context_manager.exception.bytes_needed, 0x01020304)

    def test_parse(self):
        record = SshRecordInit.parse_exact_size(self.test_record_bytes)
        self.assertEqual(record.packet.reason, SshReasonCode.PROTOCOL_ERROR)
        self.assertEqual(record.packet.description, 'αβγ')
        self.assertEqual(record.packet.language, 'en-US')

        record = SshRecordKexDH.parse_exact_size(self.test_record_bytes)
        self.assertEqual(record.packet.reason, SshReasonCode.PROTOCOL_ERROR)
        self.assertEqual(record.packet.description, 'αβγ')
        self.assertEqual(record.packet.language, 'en-US')

        record = SshRecordKexDHGroup.parse_exact_size(self.test_record_bytes)
        self.assertEqual(record.packet.reason, SshReasonCode.PROTOCOL_ERROR)
        self.assertEqual(record.packet.description, 'αβγ')
        self.assertEqual(record.packet.language, 'en-US')

    def test_compose(self):
        self.assertEqual(
            self.test_record.compose(),
            self.test_record_bytes
        )
