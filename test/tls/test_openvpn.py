# -*- coding: utf-8 -*-

import unittest
import collections

from cryptodatahub.common.exception import InvalidValue

from cryptoparser.common.exception import InvalidType, NotEnoughData
from cryptoparser.tls.openvpn import (
    OpenVpnPacketAckV1,
    OpenVpnPacketBase,
    OpenVpnPacketControlV1,
    OpenVpnPacketHardResetClientV2,
    OpenVpnPacketHardResetServerV2,
    OpenVpnPacketVariant,
    OpenVpnPacketWrapperTcp,
)


class TestOpenVpnPacketWrapperTcp(unittest.TestCase):
    def test_error_not_enough_data(self):
        with self.assertRaises(NotEnoughData) as context_manager:
            OpenVpnPacketWrapperTcp.parse_exact_size(b'\x00\x02\x00')

        self.assertEqual(context_manager.exception.bytes_needed, 1)

    def test_parse(self):
        packet = OpenVpnPacketWrapperTcp.parse_exact_size(b'\x00\x08\x00\x01\x02\x03\x04\x05\x06\x07')
        self.assertEqual(packet.payload, b'\x00\x01\x02\x03\x04\x05\x06\x07')

    def test_compose(self):
        packet = OpenVpnPacketWrapperTcp(b'\x00\x01\x02\x03\x04\x05\x06\x07')
        self.assertEqual(packet.compose(), b'\x00\x08\x00\x01\x02\x03\x04\x05\x06\x07')


class TestOpenVpnPacketBase(unittest.TestCase):
    def test_error_not_enough_data(self):
        with self.assertRaises(NotEnoughData) as context_manager:
            OpenVpnPacketBase.parse_header(b'\x00')

        self.assertEqual(context_manager.exception.bytes_needed, OpenVpnPacketBase.HEADER_SIZE - 1)

    def test_error_wrong_packet_type(self):
        with self.assertRaises(InvalidType):
            OpenVpnPacketAckV1.parse_header(b'\x00' * OpenVpnPacketBase.HEADER_SIZE)

    def test_packet_id_array(self):
        header_without_packet_array_dict = collections.OrderedDict([
            ('opcode', b'\x20'),
            ('session_id', b'\x00\x01\x02\x03\x04\x05\x06\x07'),
        ])
        header_without_packet_array_bytes = b''.join(header_without_packet_array_dict.values())

        session_id, packet_id_array, remote_session_id, header_length = OpenVpnPacketControlV1.parse_header(
            header_without_packet_array_bytes + b'\x00'
        )
        self.assertEqual(session_id, 0x0001020304050607)
        self.assertEqual(packet_id_array, [])
        self.assertEqual(remote_session_id, None)
        self.assertEqual(header_length, len(header_without_packet_array_bytes) + 1)

        packet_array_dict = collections.OrderedDict([
            ('packet_id_array_length', b'\x01'),
            ('packet_id_array', b'\x04\x05\x06\x07'),
            ('remote_session_id', b'\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f'),
        ])
        packet_array_bytes = b''.join(packet_array_dict.values())

        session_id, packet_id_array, remote_session_id, header_length = OpenVpnPacketControlV1.parse_header(
            header_without_packet_array_bytes + packet_array_bytes
        )
        self.assertEqual(session_id, 0x0001020304050607)
        self.assertEqual(packet_id_array, [0x04050607])
        self.assertEqual(remote_session_id, 0x08090a0b0c0d0e0f)
        self.assertEqual(header_length, len(header_without_packet_array_bytes) + len(packet_array_bytes))


class TestOpenVpnPacketControlV1(unittest.TestCase):
    def setUp(self):
        self.control_dict = collections.OrderedDict([
            ('opcode', b'\x20'),
            ('session_id', b'\x00\x01\x02\x03\x04\x05\x06\x07'),
            ('packet_id_array_length', b'\x01'),
            ('packet_id_array', b'\x04\x05\x06\x07'),
            ('remote_session_id', b'\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f'),
            ('packet_id', b'\x00\x01\x02\x03'),
            ('payload', b'\x00\x01\x02\x03'),
        ])
        self.control_bytes = b''.join(self.control_dict.values())

        self.control = OpenVpnPacketControlV1(
            session_id=0x0001020304050607,
            packet_id_array=[0x04050607],
            remote_session_id=0x08090a0b0c0d0e0f,
            packet_id=0x00010203,
            payload=b'\x00\x01\x02\x03',
        )

    def test_parse(self):
        control = OpenVpnPacketVariant.parse_exact_size(self.control_bytes)
        self.assertEqual(control.session_id, 0x0001020304050607)
        self.assertEqual(control.packet_id_array, [0x04050607])
        self.assertEqual(control.remote_session_id, 0x08090a0b0c0d0e0f)
        self.assertEqual(control.packet_id, 0x00010203)

    def test_compose(self):
        self.assertEqual(self.control.compose(), self.control_bytes)


class TestOpenVpnPacketAckV1(unittest.TestCase):
    def setUp(self):
        self.ack_dict = collections.OrderedDict([
            ('opcode', b'\x28'),
            ('session_id', b'\x00\x01\x02\x03\x04\x05\x06\x07'),
            ('packet_id_array_length', b'\x01'),
            ('packet_id_array', b'\x04\x05\x06\x07'),
            ('remote_session_id', b'\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f'),
        ])
        self.ack_bytes = b''.join(self.ack_dict.values())

        self.ack = OpenVpnPacketAckV1(
            session_id=0x0001020304050607,
            packet_id_array=[0x04050607],
            remote_session_id=0x08090a0b0c0d0e0f,
        )

    def test_parse(self):
        ack = OpenVpnPacketVariant.parse_exact_size(self.ack_bytes)
        self.assertEqual(ack.session_id, 0x0001020304050607)
        self.assertEqual(ack.packet_id_array, [0x04050607])

    def test_compose(self):
        self.assertEqual(self.ack.compose(), self.ack_bytes)


class TestOpenVpnPacketHardResetClientV2(unittest.TestCase):
    def setUp(self):
        self.hard_reset_client_dict = collections.OrderedDict([
            ('opcode', b'\x38'),
            ('session_id', b'\x00\x01\x02\x03\x04\x05\x06\x07'),
            ('packet_id_array_length', b'\x00'),
            ('packet_id', b'\x00\x01\x02\x03'),
        ])
        self.hard_reset_client_bytes = b''.join(self.hard_reset_client_dict.values())

        self.hard_reset_client = OpenVpnPacketHardResetClientV2(
            session_id=0x0001020304050607,
            packet_id=0x00010203,
        )

    def test_error_non_empty_packet_id_array(self):
        hard_reset_client_dict = collections.OrderedDict([
            ('opcode', b'\x38'),
            ('session_id', b'\x00\x01\x02\x03\x04\x05\x06\x07'),
            ('packet_id_array_length', b'\x01'),
            ('packet_id_array', b'\x00\x01\x02\x03'),
            ('remote_session_id', b'\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f'),
        ])
        hard_reset_client_bytes = b''.join(hard_reset_client_dict.values())
        with self.assertRaises(InvalidValue) as context_manager:
            OpenVpnPacketVariant.parse_exact_size(hard_reset_client_bytes)
        self.assertEqual(context_manager.exception.value, [0x00010203])

    def test_parse(self):
        hard_reset_client = OpenVpnPacketVariant.parse_exact_size(self.hard_reset_client_bytes)
        self.assertEqual(hard_reset_client.session_id, 0x0001020304050607)
        self.assertEqual(hard_reset_client.packet_id_array, [])
        self.assertEqual(hard_reset_client.packet_id, 0x00010203)

    def test_compose(self):
        self.assertEqual(self.hard_reset_client.compose(), self.hard_reset_client_bytes)


class TestOpenVpnPacketHardResetServerV2(unittest.TestCase):
    def setUp(self):
        self.hard_reset_server_dict = collections.OrderedDict([
            ('opcode', b'\x40'),
            ('session_id', b'\x00\x01\x02\x03\x04\x05\x06\x07'),
            ('packet_id_array_length', b'\x01'),
            ('packet_id_array', b'\x04\x05\x06\x07'),
            ('remote_session_id', b'\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f'),
            ('packet_id', b'\x00\x01\x02\x03'),
        ])
        self.hard_reset_server_bytes = b''.join(self.hard_reset_server_dict.values())

        self.hard_reset_server = OpenVpnPacketHardResetServerV2(
            session_id=0x0001020304050607,
            packet_id_array=[0x04050607],
            remote_session_id=0x08090a0b0c0d0e0f,
            packet_id=0x00010203,
        )

    def test_parse(self):
        hard_reset_server = OpenVpnPacketVariant.parse_exact_size(self.hard_reset_server_bytes)
        self.assertEqual(hard_reset_server.session_id, 0x0001020304050607)
        self.assertEqual(hard_reset_server.packet_id_array, [0x04050607])
        self.assertEqual(hard_reset_server.remote_session_id, 0x08090a0b0c0d0e0f)
        self.assertEqual(hard_reset_server.packet_id, 0x00010203)

    def test_compose(self):
        self.assertEqual(self.hard_reset_server.compose(), self.hard_reset_server_bytes)
