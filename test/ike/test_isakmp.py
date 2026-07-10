# SPDX-License-Identifier: MPL-2.0

"""
Test ISAKMP header parsing and composition.
"""

import collections
import unittest

from test.ike.classes import Ikev2PayloadBaseTest

from cryptodatahub.common.exception import InvalidValue
from cryptodatahub.ike.algorithm import (
    Ikev1ExchangeType,
    Ikev1PayloadType,
    Ikev2DiffieHellmanGroup,
    Ikev2ExchangeType,
    Ikev2PayloadType,
)
from cryptodatahub.ike.version import IkeVersion

from cryptoparser.common.exception import InvalidType, NotEnoughData
from cryptoparser.ike.ikev1 import Ikev1PayloadKeyExchange, Ikev1PayloadNonce
from cryptoparser.ike.ikev2 import Ikev2PayloadNonce, Ikev2PayloadKeyExchange
from cryptoparser.ike.isakmp import IsakmpFlags, IsakmpMessage
from cryptoparser.ike.version import IsakmpProtocolVersion


class TestISAKMPHeader(unittest.TestCase):
    def setUp(self):
        self.header_dict = collections.OrderedDict([
            ('initiator_cookie', b'\x00' * 8),
            ('responder_cookie', b'\x00' * 8),
            ('next_payload', b'\x00'),  # NONE
            ('protocol_version', b'\x11'),  # ISAKMP v1.1
            ('exchange_type', b'\x01'),  # BASE
            ('flags', b'\x00'),
            ('message_id', b'\x00' * 4),
            ('length', b'\x00\x00\x00\x1c'),  # 28 bytes
        ])
        self.header_bytes = b''.join(self.header_dict.values())
        self.header = IsakmpMessage(
            version=IsakmpProtocolVersion(IkeVersion.V1, 1),
            initiator_spi=0,
            responder_spi=0,
            exchange_type=Ikev1ExchangeType.BASE,
            flags=set(),
            message_id=0,
            payloads=[]
        )

    def test_error(self):
        with self.assertRaises(NotEnoughData) as context_manager:
            IsakmpMessage.parse_exact_size(b'')
        self.assertEqual(context_manager.exception.bytes_needed, IsakmpMessage.HEADER_SIZE)

        with self.assertRaises(InvalidType):
            IsakmpMessage.parse_exact_size(b'\x00' * (IsakmpMessage.HEADER_SIZE - 1) + b'\xff')

    def test_parse(self):
        header = IsakmpMessage.parse_exact_size(self.header_bytes)
        self.assertEqual(header.initiator_spi, 0)
        self.assertEqual(header.responder_spi, 0)
        self.assertEqual(header.version, IsakmpProtocolVersion(IkeVersion.V1, 1))
        self.assertEqual(header.exchange_type, Ikev1ExchangeType.BASE)
        self.assertEqual(header.flags, set())
        self.assertEqual(header.message_id, 0)

    def test_compose(self):
        self.assertEqual(self.header.compose(), self.header_bytes)

    def test_flags(self):
        header_with_flags = IsakmpMessage(
            version=IsakmpProtocolVersion(IkeVersion.V1, 1),
            initiator_spi=0,
            responder_spi=0,
            exchange_type=Ikev1ExchangeType.BASE,
            flags={IsakmpFlags.ENCRYPTION, IsakmpFlags.COMMIT},
            message_id=0,
            payloads=[]
        )
        header_bytes_with_flags = bytearray(self.header_bytes)
        header_bytes_with_flags[19] = 0x03  # Set ENCRYPTION and COMMIT flags
        self.assertEqual(header_with_flags.compose(), bytes(header_bytes_with_flags))

    def test_ikev1_compose_payload_type(self):
        payload = Ikev1PayloadNonce(nonce_data=b'A' * 16)
        message = IsakmpMessage(
            version=IsakmpProtocolVersion(IkeVersion.V1, 0),
            initiator_spi=0,
            responder_spi=0,
            exchange_type=Ikev1ExchangeType.INFORMATIONAL,
            flags=set(),
            message_id=0,
            payloads=[payload],
        )
        composed = message.compose()
        self.assertEqual(composed[16], Ikev1PayloadType.NONCE.value.code)

    def test_ikev2_parsing(self):
        header_dict_v2 = collections.OrderedDict([
            ('initiator_cookie', b'\x00' * 8),
            ('responder_cookie', b'\x00' * 8),
            ('next_payload', b'\x00'),  # NONE
            ('protocol_version', b'\x20'),  # ISAKMP v2.0
            ('exchange_type', b'\x22'),  # IKE_SA_INIT
            ('flags', b'\x00'),
            ('message_id', b'\x00' * 4),
            ('length', b'\x00\x00\x00\x1c'),  # 28 bytes
        ])
        header_bytes_v2 = b''.join(header_dict_v2.values())
        header = IsakmpMessage.parse_exact_size(header_bytes_v2)
        self.assertEqual(header.version, IsakmpProtocolVersion(IkeVersion.V2, 0))
        self.assertEqual(header.exchange_type, Ikev2ExchangeType.IKE_SA_INIT)

    def test_invalid_payload_type_ikev1(self):
        header_dict = collections.OrderedDict([
            ('initiator_cookie', b'\x00' * 8),
            ('responder_cookie', b'\x00' * 8),
            ('next_payload', b'\xff'),  # Invalid payload type
            ('protocol_version', b'\x11'),  # ISAKMP v1.1
            ('exchange_type', b'\x01'),  # BASE
            ('flags', b'\x00'),
            ('message_id', b'\x00' * 4),
            ('length', b'\x00\x00\x00\x1c'),  # 28 bytes
        ])
        header_bytes = b''.join(header_dict.values())
        with self.assertRaises(InvalidValue):
            IsakmpMessage.parse_exact_size(header_bytes)

    def test_ikev2_compose_with_empty_payloads(self):
        header_v2 = IsakmpMessage(
            version=IsakmpProtocolVersion(IkeVersion.V2, 0),
            initiator_spi=0,
            responder_spi=0,
            exchange_type=Ikev2ExchangeType.IKE_SA_INIT,
            flags=set(),
            message_id=0,
            payloads=[]
        )

        with self.assertRaises(IndexError):
            header_v2.compose()

    def test_payload_parsing_with_invalid_next_payload(self):
        header_dict = collections.OrderedDict([
            ('initiator_cookie', b'\x00' * 8),
            ('responder_cookie', b'\x00' * 8),
            ('next_payload', b'\x01'),  # SECURITY_ASSOCIATION
            ('protocol_version', b'\x11'),  # ISAKMP v1.1
            ('exchange_type', b'\x01'),  # BASE
            ('flags', b'\x00'),
            ('message_id', b'\x00' * 4),
            ('length', b'\x00\x00\x00\x20'),  # 32 bytes (header + 4 bytes payload)
        ])
        payload_data = b'\x00\x00\x00\x04'  # Invalid/minimal payload
        header_bytes = b''.join(header_dict.values()) + payload_data
        with self.assertRaises((NotEnoughData, TypeError, AttributeError)):
            IsakmpMessage.parse_exact_size(header_bytes)

    def test_payload_composition_loop(self):
        payload = Ikev2PayloadBaseTest(
            flags=set(),
            test_data=b'\x00\x01\x02\x03'
        )
        message = IsakmpMessage(
            version=IsakmpProtocolVersion(IkeVersion.V2, 0),
            initiator_spi=0,
            responder_spi=0,
            exchange_type=Ikev2ExchangeType.IKE_SA_INIT,
            flags=set(),
            message_id=0,
            payloads=[payload]
        )
        message_bytes = message.compose()
        payload_bytes = payload.compose()
        self.assertEqual(message_bytes[-len(payload_bytes):], payload_bytes)

    def test_payload_parsing_loop(self):
        header_dict = collections.OrderedDict([
            ('initiator_cookie', b'\x00' * 8),
            ('responder_cookie', b'\x00' * 8),
            ('next_payload', b'\x28'),  # NONCE payload type (0x28 = 40 decimal)
            ('protocol_version', b'\x20'),  # ISAKMP v2.0
            ('exchange_type', b'\x22'),  # IKE_SA_INIT
            ('flags', b'\x00'),
            ('message_id', b'\x00' * 4),
            ('length', b'\x00\x00\x00\x30'),  # 48 bytes total (28 header + 20 payload)
        ])
        nonce_payload = (
            b'\x00' +        # Next payload = NONE (0x00)
            b'\x00' +        # Flags = 0 (no critical bit)
            b'\x00\x14' +    # Payload length = 20 bytes (header 4 + data 16)
            b'A' * 16       # 16 bytes of nonce data (minimum required for NONCE)
        )
        header_bytes = b''.join(header_dict.values()) + nonce_payload
        message = IsakmpMessage.parse_exact_size(header_bytes)
        self.assertEqual(len(message.payloads), 1)
        self.assertEqual(message.payloads[0].get_payload_type(), Ikev2PayloadType.NONCE)

    def test_invalid_payload_type_ikev2(self):
        header_dict = collections.OrderedDict([
            ('initiator_cookie', b'\x00' * 8),
            ('responder_cookie', b'\x00' * 8),
            ('next_payload', b'\xff'),  # Invalid payload type
            ('protocol_version', b'\x20'),  # ISAKMP v2.0
            ('exchange_type', b'\x22'),  # IKE_SA_INIT
            ('flags', b'\x00'),
            ('message_id', b'\x00' * 4),
            ('length', b'\x00\x00\x00\x1c'),  # 28 bytes
        ])
        header_bytes = b''.join(header_dict.values())
        with self.assertRaises(InvalidValue):
            IsakmpMessage.parse_exact_size(header_bytes)

    def test_unsupported_payload_type_ikev2(self):
        header_dict = collections.OrderedDict([
            ('initiator_cookie', b'\x00' * 8),
            ('responder_cookie', b'\x00' * 8),
            ('next_payload', bytes([Ikev2PayloadType.IDI.value.code])),  # valid enum, but no parser class registered
            ('protocol_version', b'\x20'),  # ISAKMP v2.0
            ('exchange_type', b'\x22'),  # IKE_SA_INIT
            ('flags', b'\x00'),
            ('message_id', b'\x00' * 4),
            ('length', b'\x00\x00\x00\x1d'),  # 29 bytes (28 header + 1 dummy payload byte)
        ])
        header_bytes = b''.join(header_dict.values()) + b'\x00'
        with self.assertRaises(InvalidType):
            IsakmpMessage.parse_exact_size(header_bytes)

    def test_get_payload_by_type_ikev2(self):
        nonce_payload = Ikev2PayloadNonce(
            flags=set(),
            nonce_data=b'\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f'
        )
        ke_payload = Ikev2PayloadKeyExchange(
            flags=set(),
            dh_group=Ikev2DiffieHellmanGroup.MODP_GROUP_2048_BIT,
            key_exchange_data=b'\x00\x01\x02\x03\x04\x05\x06\x07'
        )
        message = IsakmpMessage(
            version=IsakmpProtocolVersion(IkeVersion.V2, 0),
            initiator_spi=0,
            responder_spi=0,
            exchange_type=Ikev2ExchangeType.IKE_SA_INIT,
            flags=set(),
            message_id=0,
            payloads=[nonce_payload, ke_payload]
        )

        found_nonce = message.get_payload_by_type(Ikev2PayloadType.NONCE)
        self.assertEqual(found_nonce, nonce_payload)
        self.assertEqual(found_nonce.get_payload_type(), Ikev2PayloadType.NONCE)

        found_ke = message.get_payload_by_type(Ikev2PayloadType.KE)
        self.assertEqual(found_ke, ke_payload)
        self.assertEqual(found_ke.get_payload_type(), Ikev2PayloadType.KE)

    def test_get_payload_by_type_ikev1(self):
        ke_payload = Ikev1PayloadKeyExchange(key_exchange_data=b'\x00\x01\x02\x03')
        nonce_payload = Ikev1PayloadNonce(nonce_data=b'\x00\x01\x02\x03\x04\x05\x06\x07\x08')
        message = IsakmpMessage(
            version=IsakmpProtocolVersion(IkeVersion.V1, 1),
            initiator_spi=0,
            responder_spi=0,
            exchange_type=Ikev1ExchangeType.BASE,
            flags=set(),
            message_id=0,
            payloads=[ke_payload, nonce_payload]
        )

        found_ke = message.get_payload_by_type(Ikev1PayloadType.KEY_EXCHANGE)
        self.assertEqual(found_ke, ke_payload)
        self.assertEqual(found_ke.get_payload_type(), Ikev1PayloadType.KEY_EXCHANGE)

        found_nonce = message.get_payload_by_type(Ikev1PayloadType.NONCE)
        self.assertEqual(found_nonce, nonce_payload)
        self.assertEqual(found_nonce.get_payload_type(), Ikev1PayloadType.NONCE)

    def test_get_payload_by_type_not_found(self):
        nonce_payload = Ikev2PayloadNonce(
            flags=set(),
            nonce_data=b'\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f'
        )
        message = IsakmpMessage(
            version=IsakmpProtocolVersion(IkeVersion.V2, 0),
            initiator_spi=0,
            responder_spi=0,
            exchange_type=Ikev2ExchangeType.IKE_SA_INIT,
            flags=set(),
            message_id=0,
            payloads=[nonce_payload]
        )

        with self.assertRaises(KeyError) as context_manager:
            message.get_payload_by_type(Ikev2PayloadType.KE)
        self.assertEqual(context_manager.exception.args[0], Ikev2PayloadType.KE)

    def test_get_payload_by_type_empty_payloads(self):
        message = IsakmpMessage(
            version=IsakmpProtocolVersion(IkeVersion.V2, 0),
            initiator_spi=0,
            responder_spi=0,
            exchange_type=Ikev2ExchangeType.IKE_SA_INIT,
            flags=set(),
            message_id=0,
            payloads=[]
        )

        with self.assertRaises(KeyError) as context_manager:
            message.get_payload_by_type(Ikev2PayloadType.NONCE)
        self.assertEqual(context_manager.exception.args[0], Ikev2PayloadType.NONCE)
