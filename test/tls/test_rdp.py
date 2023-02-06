# -*- coding: utf-8 -*-

import unittest
import collections

from cryptodatahub.common.exception import InvalidValue
from cryptoparser.common.exception import NotEnoughData, InvalidType

from cryptoparser.tls.rdp import (
    COTPConnectionConfirm,
    COTPConnectionRequest,
    RDPNegotiationRequest,
    RDPNegotiationRequestFlags,
    RDPNegotiationResponse,
    RDPNegotiationResponseFlags,
    RDPProtocol,
    TPKT,
)


class TestTPKT(unittest.TestCase):
    def setUp(self):
        self.tpkt_dict = collections.OrderedDict([
            ('version', b'\x03'),
            ('reserved', b'\x00'),
            ('packet_length', b'\x00\x14'),
            ('message',
             b'\x00\x01\x02\x03\x04\x05\x06\x07' +
             b'\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f' +
             b'')
        ])
        self.tpkt_bytes = b''.join(self.tpkt_dict.values())

        self.tpkt = TPKT(
            version=3,
            message=b'\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f'
        )

    def test_error(self):
        with self.assertRaises(NotEnoughData) as context_manager:
            TPKT.parse_exact_size(b'')
        self.assertEqual(context_manager.exception.bytes_needed, TPKT.HEADER_SIZE)

        with self.assertRaises(InvalidValue) as context_manager:
            TPKT.parse_exact_size(b'\x01\x00\x00\x00')
        self.assertEqual(context_manager.exception.value, 1)

        with self.assertRaises(NotEnoughData) as context_manager:
            TPKT.parse_exact_size(b'\x03\x00\x00\x05')
        self.assertEqual(context_manager.exception.bytes_needed, 1)

    def test_parse(self):
        tpkt = TPKT.parse_exact_size(self.tpkt_bytes)
        self.assertEqual(tpkt.version, 3)
        self.assertEqual(tpkt.message, self.tpkt_dict['message'])

    def test_compose(self):
        self.assertEqual(self.tpkt.compose(), self.tpkt_bytes)


class TestCOTPConnectionRequest(unittest.TestCase):
    def setUp(self):
        self.cotp_connection_request_dict = collections.OrderedDict([
            ('length', b'\x0e'),
            ('type', b'\xe0'),
            ('src_ref', b'\x01\x02'),
            ('dst_ref', b'\x03\x04'),
            ('class_option', b'\x00'),
            ('user_data', b'\x00\x01\x02\x03\x04\x05\x06\x07'),
        ])
        self.cotp_connection_request_bytes = b''.join(self.cotp_connection_request_dict.values())

        self.cotp_connection_request = COTPConnectionRequest(
            src_ref=0x0102, dst_ref=0x0304, class_option=0x00,
            user_data=b'\x00\x01\x02\x03\x04\x05\x06\x07'
        )

    def test_error(self):
        with self.assertRaises(NotEnoughData) as context_manager:
            COTPConnectionRequest.parse_exact_size(b'')
        self.assertEqual(context_manager.exception.bytes_needed, COTPConnectionRequest.HEADER_SIZE)

        with self.assertRaises(NotEnoughData) as context_manager:
            COTPConnectionRequest.parse_exact_size(b'\x07\xe0\x00\x00\x00\x00\x00')
        self.assertEqual(context_manager.exception.bytes_needed, 1)

        with self.assertRaises(InvalidType) as context_manager:
            COTPConnectionRequest.parse_exact_size(b'\x07\xf0\x00\x00\x00\x00\x00\x00')

        with self.assertRaises(InvalidValue) as context_manager:
            COTPConnectionRequest.parse_exact_size(b'\x07\xe0\x00\x00\x00\x00\x01\x00')
        self.assertEqual(context_manager.exception.value, 1)

    def test_parse(self):
        cotp_connection_request = COTPConnectionRequest.parse_exact_size(self.cotp_connection_request_bytes)
        self.assertEqual(cotp_connection_request.src_ref, self.cotp_connection_request.src_ref)
        self.assertEqual(cotp_connection_request.dst_ref, self.cotp_connection_request.dst_ref)
        self.assertEqual(cotp_connection_request.class_option, self.cotp_connection_request.class_option)
        self.assertEqual(cotp_connection_request.user_data, self.cotp_connection_request.user_data)

    def test_compose(self):
        self.assertEqual(self.cotp_connection_request.compose(), self.cotp_connection_request_bytes)


class TestCOTPConnectionConfirm(unittest.TestCase):
    def setUp(self):
        self.cotp_connection_confirm_dict = collections.OrderedDict([
            ('length', b'\x0e'),
            ('type', b'\xd0'),
            ('src_ref', b'\x01\x02'),
            ('dst_ref', b'\x03\x04'),
            ('class_option', b'\x00'),
            ('user_data', b'\x00\x01\x02\x03\x04\x05\x06\x07'),
        ])
        self.cotp_connection_confirm_bytes = b''.join(self.cotp_connection_confirm_dict.values())

        self.cotp_connection_confirm = COTPConnectionConfirm(
            src_ref=0x0102, dst_ref=0x0304, class_option=0x00,
            user_data=b'\x00\x01\x02\x03\x04\x05\x06\x07'
        )

    def test_parse(self):
        cotp_connection_confirm = COTPConnectionConfirm.parse_exact_size(self.cotp_connection_confirm_bytes)
        self.assertEqual(cotp_connection_confirm.src_ref, self.cotp_connection_confirm.src_ref)
        self.assertEqual(cotp_connection_confirm.dst_ref, self.cotp_connection_confirm.dst_ref)
        self.assertEqual(cotp_connection_confirm.class_option, self.cotp_connection_confirm.class_option)
        self.assertEqual(cotp_connection_confirm.user_data, self.cotp_connection_confirm.user_data)

    def test_compose(self):
        self.assertEqual(self.cotp_connection_confirm.compose(), self.cotp_connection_confirm_bytes)


class TestRDPNegotiationRequest(unittest.TestCase):
    def setUp(self):
        self.rdp_negotiation_request_dict = collections.OrderedDict([
            ('type', b'\x01'),
            ('flags', b'\x03'),
            ('length', b'\x08\x00'),
            ('protocol', b'\x03\x00\x00\x00'),
        ])
        self.rdp_negotiation_request_bytes = b''.join(self.rdp_negotiation_request_dict.values())

        self.rdp_negotiation_request = RDPNegotiationRequest(
            flags={
                RDPNegotiationRequestFlags.RESTRICTED_ADMIN_MODE_REQUIRED,
                RDPNegotiationRequestFlags.REDIRECTED_AUTHENTICATION_MODE_REQUIRED
            },
            protocol={RDPProtocol.SSL, RDPProtocol.HYBRID}
        )

    def test_error(self):
        with self.assertRaises(NotEnoughData) as context_manager:
            RDPNegotiationRequest.parse_exact_size(b'\x01')
        self.assertEqual(context_manager.exception.bytes_needed, RDPNegotiationRequest.PACKET_LENGTH - 1)

        with self.assertRaises(InvalidType) as context_manager:
            RDPNegotiationRequest.parse_exact_size(b'\x02\x03\x08\x00\x00\x00\x00\x00')

        with self.assertRaises(NotEnoughData) as context_manager:
            RDPNegotiationRequest.parse_exact_size(b'\x01\x03\x08\x00\x00\x00')
        self.assertEqual(context_manager.exception.bytes_needed, 2)

        with self.assertRaises(InvalidValue) as context_manager:
            RDPNegotiationRequest.parse_exact_size(b'\x01\x03\x02\x00\x00\x00\x00\x00')
        self.assertEqual(context_manager.exception.value, 2)

    def test_parse(self):
        rdp_negotiation_request = RDPNegotiationRequest.parse_exact_size(self.rdp_negotiation_request_bytes)
        self.assertEqual(rdp_negotiation_request.flags, self.rdp_negotiation_request.flags)
        self.assertEqual(rdp_negotiation_request.protocol, self.rdp_negotiation_request.protocol)

    def test_compose(self):
        self.assertEqual(self.rdp_negotiation_request.compose(), self.rdp_negotiation_request_bytes)


class TestRDPNegotiationResponse(unittest.TestCase):
    def setUp(self):
        self.rdp_negotiation_request_dict = collections.OrderedDict([
            ('type', b'\x02'),
            ('flags', b'\x03'),
            ('length', b'\x08\x00'),
            ('protocol', b'\x03\x00\x00\x00'),
        ])
        self.rdp_negotiation_request_bytes = b''.join(self.rdp_negotiation_request_dict.values())

        self.rdp_negotiation_request = RDPNegotiationResponse(
            flags={
                RDPNegotiationResponseFlags.EXTENDED_CLIENT_DATA_SUPPORTED,
                RDPNegotiationResponseFlags.DYNVC_GFX_PROTOCOL_SUPPORTED
            },
            protocol={RDPProtocol.SSL, RDPProtocol.HYBRID}
        )

    def test_parse(self):
        rdp_negotiation_request = RDPNegotiationResponse.parse_exact_size(self.rdp_negotiation_request_bytes)
        self.assertEqual(rdp_negotiation_request.flags, self.rdp_negotiation_request.flags)
        self.assertEqual(rdp_negotiation_request.protocol, self.rdp_negotiation_request.protocol)

    def test_compose(self):
        self.assertEqual(self.rdp_negotiation_request.compose(), self.rdp_negotiation_request_bytes)
