# -*- coding: utf-8 -*-

import unittest

from cryptodatahub.common.exception import InvalidValue

from cryptoparser.common.exception import NotEnoughData

from cryptoparser.tls.mysql import (
    MySQLRecord,
    MySQLCapability,
    MySQLCharacterSet,
    MySQLStatusFlag,
    MySQLHandshakeSslRequest,
    MySQLHandshakeV10,
    MySQLVersion,
)


class TestMySQLRecord(unittest.TestCase):
    def setUp(self):
        self.test_record = MySQLRecord(
            packet_number=1,
            packet_bytes=b'\x01\x02\x03\x04'
        )
        self.test_record_bytes = bytes(
            b'\x04\x00\x00' +    # packet_length
            b'\x01' +            # packet_number
            b'\x01\x02\x03\x04'
        )

    def test_error(self):
        with self.assertRaises(NotEnoughData) as context_manager:
            MySQLRecord.parse_exact_size(b'\x00')
        self.assertEqual(context_manager.exception.bytes_needed, MySQLRecord.HEADER_SIZE - 1)

    def test_parse(self):
        MySQLRecord.parse_exact_size(self.test_record_bytes)

    def test_compose(self):
        self.assertEqual(self.test_record.compose(), self.test_record_bytes)


class TestMySQLHandshake10(unittest.TestCase):
    def setUp(self):
        self.handshake_minimal = MySQLHandshakeV10(
            protocol_version=MySQLVersion.MYSQL_9,
            server_version='1.2.3.4',
            connection_id=0x01020304,
            auth_plugin_data=b'\x01\x02\x03\x04\x05\x06\x07\x08',
            capabilities={
                MySQLCapability.CLIENT_SSL,
                MySQLCapability.CLIENT_MULTI_STATEMENTS,
            },
            character_set=MySQLCharacterSet.UTF8,
            states={MySQLStatusFlag.SERVER_STATUS_IN_TRANS, },
        )
        self.handshake_full = MySQLHandshakeV10(
            protocol_version=MySQLVersion.MYSQL_9,
            server_version='1.2.3.4',
            connection_id=0x01020304,
            auth_plugin_data=b'\x01\x02\x03\x04\x05\x06\x07\x08',
            capabilities={
                MySQLCapability.CLIENT_SSL,
                MySQLCapability.CLIENT_MULTI_STATEMENTS,
                MySQLCapability.CLIENT_PLUGIN_AUTH,
            },
            character_set=MySQLCharacterSet.UTF8,
            states={MySQLStatusFlag.SERVER_STATUS_IN_TRANS, },
            auth_plugin_name='auth_plugin_name',
            auth_plugin_data_2=b'\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d'
        )

        self.handshake_bytes_base = bytes(
            b'\x09' +                              # protocol_version
            b'1.2.3.4\x00' +                       # server_version
            b'\x04\x03\x02\x01' +                  # connection_id
            b'\x01\x02\x03\x04\x05\x06\x07\x08' +  # auth_plugin_data
            b'\x00' +                              # filler
            b'\x00\x08' +                          # capabilities
            b'\x21' +                              # character_set
            b'\x01\x00' +                          # states
            b''
        )
        self.handshake_bytes_minimal = self.handshake_bytes_base + bytes(
            b'\x01\x00' +                          # capabilities_2
            b'\x00' +                              # auth_plugin_data_len
            10 * b'\x00' +                         # reserved
            b''
        )
        self.handshake_bytes_full = self.handshake_bytes_base + bytes(
            b'\x09\x00' +                          # capabilities_2
            b'\x15' +                              # auth_plugin_data_len
            10 * b'\x00' +                         # reserved
            b'\x01\x02\x03\x04\x05\x06\x07\x08' +  # auth_plugin_data_2
            b'\x09\x0a\x0b\x0c\x0d' +
            b'auth_plugin_name\x00' +              # auth_plugin_name
            b''
        )

    def test_error_not_enough_data(self):
        with self.assertRaises(NotEnoughData) as context_manager:
            MySQLHandshakeV10.parse_exact_size(b'\x00')
        self.assertEqual(context_manager.exception.bytes_needed, MySQLHandshakeV10.MINIMUM_SIZE - 1)

    def test_error_no_auth_plugin_data(self):
        handshake_bytes_no_auth_plugin_data = self.handshake_bytes_base + bytes(
            b'\x09\x00' +                          # capabilities_2
            b'\x00' +                              # auth_plugin_data_len
            10 * b'\x00' +                         # reserved
            b''
        )
        with self.assertRaises(InvalidValue) as context_manager:
            MySQLHandshakeV10.parse_exact_size(handshake_bytes_no_auth_plugin_data)
        self.assertEqual(context_manager.exception.value, 0)

    def test_parse(self):
        handshake_minimal = MySQLHandshakeV10.parse_exact_size(self.handshake_bytes_minimal)
        self.assertEqual(handshake_minimal, self.handshake_minimal)

        handshake_full = MySQLHandshakeV10.parse_exact_size(self.handshake_bytes_full)
        self.assertEqual(handshake_full, self.handshake_full)

    def test_compose(self):
        self.assertEqual(self.handshake_minimal.compose(), self.handshake_bytes_minimal)
        self.assertEqual(self.handshake_full.compose(), self.handshake_bytes_full)


class TestMySQLHandshakeSslRequest(unittest.TestCase):
    def setUp(self):
        self.handshake_bytes_with_client_41_capability = bytes(
            b'\x00\x02\x00\x00' +                  # capabilities
            b'\x04\x03\x02\x01' +                  # max_packet_size
            b'\x21' +                              # character_set
            23 * b'\x00' +                         # filler
            b''
        )
        self.handshake_with_client_41_capability = MySQLHandshakeSslRequest(
            capabilities={MySQLCapability.CLIENT_PROTOCOL_41},
            max_packet_size=0x01020304,
            character_set=MySQLCharacterSet.UTF8
        )
        self.handshake_bytes_without_client_41_capability = bytes(
            b'\x00\x00' +                  # capabilities
            b'\x03\x02\x01' +              # max_packet_size
            b''
        )
        self.handshake_without_client_41_capability = MySQLHandshakeSslRequest(
            capabilities=set(),
            max_packet_size=0x010203,
        )

    def test_error_not_enough_data(self):
        with self.assertRaises(NotEnoughData) as context_manager:
            MySQLHandshakeSslRequest.parse_exact_size(b'\x00')
        self.assertEqual(context_manager.exception.bytes_needed, MySQLHandshakeSslRequest.MINIMUM_SIZE - 1)

    def test_with_client_41_character_set_is_none(self):
        ssl_request = MySQLHandshakeSslRequest(
            capabilities=set([MySQLCapability.CLIENT_PROTOCOL_41]), max_packet_size=1, character_set=None
        )
        self.assertEqual(ssl_request.character_set, MySQLCharacterSet.UTF8)

    def test_error_without_client_41_capability_too_large(self):
        with self.assertRaises(ValueError) as context_manager:
            MySQLHandshakeSslRequest(capabilities=set([MySQLCapability.CLIENT_MULTI_STATEMENTS]), max_packet_size=1)
        self.assertEqual(context_manager.exception.args[0], 1)

    def test_error_without_client_41_max_packet_size_too_large(self):  # pylint: disable=invalid-name
        with self.assertRaises(ValueError) as context_manager:
            MySQLHandshakeSslRequest(capabilities=set(), max_packet_size=2 ** 24)
        self.assertEqual(context_manager.exception.args[0], 2 ** 24)

    def test_with_client_41_capability(self):
        self.assertEqual(
            MySQLHandshakeSslRequest.parse_exact_size(self.handshake_bytes_with_client_41_capability),
            self.handshake_with_client_41_capability,
        )
        self.assertEqual(
            self.handshake_with_client_41_capability.compose(),
            self.handshake_bytes_with_client_41_capability,
        )

    def test_without_client_41_capability(self):
        self.assertEqual(
            MySQLHandshakeSslRequest.parse_exact_size(self.handshake_bytes_without_client_41_capability),
            self.handshake_without_client_41_capability,
        )
        self.assertEqual(
            self.handshake_without_client_41_capability.compose(),
            self.handshake_bytes_without_client_41_capability,
        )
