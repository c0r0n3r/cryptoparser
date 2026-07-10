# SPDX-License-Identifier: MPL-2.0

import collections
import unittest

from cryptodatahub.ike.algorithm import (
    Ikev2DiffieHellmanGroup,
    Ikev2NotifyType,
    Ikev2ProtocolId,
    Ikev2TransformAttributeType,
)

from cryptoparser.common.exception import NotEnoughData, TooMuchData
from cryptoparser.ike.ikev2 import (
    Ikev2NotifyPayloadInvalidKe,
    Ikev2PayloadCertificateRequest,
    Ikev2PayloadDelete,
    Ikev2PayloadFlags,
    Ikev2PayloadKeyExchange,
    Ikev2PayloadNonce,
    Ikev2PayloadNotifyAuthenticationFailed,
    Ikev2PayloadNotifyUnparsed,
    Ikev2PayloadType,
    Ikev2PayloadVendorId,
    TransformAttributeKeyLength,

)

from .classes import Ikev2PayloadBaseTest, Ikev2PayloadNotifyNoDataTest


class TestIkev2PayloadBase(unittest.TestCase):
    def setUp(self):
        self.test_data = b'\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f'
        self.test_payload_minimal = Ikev2PayloadBaseTest(
            flags=set(),
            test_data=b'',
        )
        self.test_payload_minimal.next_payload = Ikev2PayloadType.NONE

        self.test_dict_minimal = collections.OrderedDict([
            ('next_payload', b'\x00'),
            ('flags', b'\x00'),
            ('payload_length', b'\x00\x04'),
            ('test_data', b''),
        ])
        self.test_bytes_minimal = b''.join(self.test_dict_minimal.values())

        self.test_payload_with_data = Ikev2PayloadBaseTest(
            flags={Ikev2PayloadFlags.CRITICAL},
            test_data=self.test_data
        )
        self.test_payload_with_data.next_payload = Ikev2PayloadType.NONE

        self.test_dict_with_data = collections.OrderedDict([
            ('next_payload', b'\x00'),
            ('flags', b'\x80'),
            ('payload_length', b'\x00\x14'),
            ('test_data', self.test_data),
        ])
        self.test_bytes_with_data = b''.join(self.test_dict_with_data.values())

    def test_parse(self):
        parsed_payload = Ikev2PayloadBaseTest.parse_exact_size(self.test_bytes_minimal)
        self.assertEqual(parsed_payload.flags, self.test_payload_minimal.flags)
        self.assertEqual(parsed_payload.test_data, self.test_payload_minimal.test_data)
        self.assertEqual(parsed_payload.next_payload, self.test_payload_minimal.next_payload)

        parsed_payload = Ikev2PayloadBaseTest.parse_exact_size(self.test_bytes_with_data)
        self.assertEqual(parsed_payload.flags, self.test_payload_with_data.flags)
        self.assertEqual(parsed_payload.test_data, self.test_payload_with_data.test_data)
        self.assertEqual(parsed_payload.next_payload, self.test_payload_with_data.next_payload)

    def test_compose(self):
        self.assertEqual(self.test_payload_minimal.compose(), self.test_bytes_minimal)
        self.assertEqual(self.test_payload_with_data.compose(), self.test_bytes_with_data)

    def test_error_parse_not_enough_data(self):
        with self.assertRaises(NotEnoughData) as context_manager:
            Ikev2PayloadBaseTest.parse_exact_size(b'\x00')
        self.assertEqual(context_manager.exception.bytes_needed, 3)

    def test_error_payload_validation(self):
        with self.assertRaises(TypeError) as context_manager:
            Ikev2PayloadBaseTest(
                flags={'invalid_flag'},
                test_data=self.test_data
            )
        exception_str = str(context_manager.exception)
        self.assertIn("flags", exception_str)
        self.assertIn("must be", exception_str)
        self.assertIn("Ikev2PayloadFlags", exception_str)

    def test_next_payload(self):
        payload = Ikev2PayloadBaseTest(
            flags={Ikev2PayloadFlags.CRITICAL},
            test_data=self.test_data
        )
        payload.next_payload = Ikev2PayloadType.KE

        composed = payload.compose()
        self.assertEqual(composed[0], Ikev2PayloadType.KE.value.code)

        parsed, _ = Ikev2PayloadBaseTest._parse(composed)  # pylint: disable=protected-access
        self.assertEqual(parsed.next_payload, Ikev2PayloadType.KE)


class TestIkev2PayloadKeyExchange(unittest.TestCase):
    def setUp(self):
        self.dh_group = Ikev2DiffieHellmanGroup.MODP_GROUP_2048_BIT
        self.key_exchange_data = b'\x00\x01\x02\x03\x04\x05\x06\x07'
        self.key_exchange_payload = Ikev2PayloadKeyExchange(
            flags=set(),
            dh_group=self.dh_group,
            key_exchange_data=self.key_exchange_data
        )
        self.key_exchange_payload.next_payload = Ikev2PayloadType.NONE

        self.key_exchange_dict = collections.OrderedDict([
            ('next_payload', b'\x00'),
            ('flags', b'\x00'),
            ('payload_length', b'\x00\x10'),
            ('dh_group', b'\x00\x0e'),
            ('reserved2', b'\x00\x00'),
            ('key_exchange_data', self.key_exchange_data),
        ])
        self.key_exchange_bytes = b''.join(self.key_exchange_dict.values())

    def test_get_payload_type(self):
        self.assertEqual(Ikev2PayloadKeyExchange.get_payload_type(), Ikev2PayloadType.KE)

    def test_parse(self):
        parsed_ke = Ikev2PayloadKeyExchange.parse_exact_size(self.key_exchange_bytes)
        self.assertEqual(parsed_ke.dh_group, self.dh_group)
        self.assertEqual(parsed_ke.key_exchange_data, self.key_exchange_data)

    def test_compose(self):
        composed_bytes = self.key_exchange_payload.compose()
        self.assertGreater(len(composed_bytes), Ikev2PayloadKeyExchange.HEADER_SIZE)

        parsed_ke = Ikev2PayloadKeyExchange.parse_exact_size(composed_bytes)
        self.assertEqual(parsed_ke.key_exchange_data, self.key_exchange_payload.key_exchange_data)

    def test_round_trip(self):
        composed_bytes = self.key_exchange_payload.compose()
        parsed_payload: Ikev2PayloadKeyExchange = Ikev2PayloadKeyExchange.parse_exact_size(composed_bytes)

        self.assertEqual(parsed_payload.dh_group, self.key_exchange_payload.dh_group)
        self.assertEqual(parsed_payload.key_exchange_data, self.key_exchange_payload.key_exchange_data)
        self.assertEqual(parsed_payload.flags, self.key_exchange_payload.flags)
        self.assertEqual(parsed_payload.next_payload, self.key_exchange_payload.next_payload)


class TestIkev2PayloadNonce(unittest.TestCase):  # pylint: disable=too-many-instance-attributes
    def setUp(self):
        self.nonce_data = b'\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f'
        self.nonce_payload = Ikev2PayloadNonce(
            flags=set(),
            nonce_data=self.nonce_data
        )
        self.nonce_payload.next_payload = Ikev2PayloadType.NONE

        self.nonce_dict = collections.OrderedDict([
            ('next_payload', b'\x00'),
            ('flags', b'\x00'),
            ('payload_length', b'\x00\x14'),
            ('nonce_data', self.nonce_data),
        ])
        self.nonce_bytes = b''.join(self.nonce_dict.values())

        self.nonce_dict_too_small = collections.OrderedDict([
            ('next_payload', b'\x00'),
            ('flags', b'\x00'),
            ('payload_length', b'\x00\x13'),
            ('nonce_data', b'\x00' * 15),
        ])
        self.nonce_bytes_too_small = b''.join(self.nonce_dict_too_small.values())

        self.nonce_dict_too_large = collections.OrderedDict([
            ('next_payload', b'\x00'),
            ('flags', b'\x00'),
            ('payload_length', b'\x01\x05'),
            ('nonce_data', b'\x00' * 257),
        ])
        self.nonce_bytes_too_large = b''.join(self.nonce_dict_too_large.values())

    def test_get_payload_type(self):
        self.assertEqual(Ikev2PayloadNonce.get_payload_type(), Ikev2PayloadType.NONCE)

    def test_parse(self):
        parsed_nonce = Ikev2PayloadNonce.parse_exact_size(self.nonce_bytes)
        self.assertEqual(parsed_nonce.nonce_data, self.nonce_data)
        self.assertEqual(parsed_nonce.next_payload, Ikev2PayloadType.NONE)
        self.assertEqual(parsed_nonce.flags, set())

    def test_compose(self):
        composed_bytes = self.nonce_payload.compose()
        self.assertIsInstance(composed_bytes, (bytes, bytearray))
        self.assertGreater(len(composed_bytes), Ikev2PayloadNonce.HEADER_SIZE)

        parsed_nonce = Ikev2PayloadNonce.parse_exact_size(composed_bytes)
        self.assertEqual(parsed_nonce.nonce_data, self.nonce_payload.nonce_data)
        self.assertEqual(parsed_nonce.next_payload, self.nonce_payload.next_payload)
        self.assertEqual(parsed_nonce.flags, self.nonce_payload.flags)

    def test_error_invalid_nonce_data(self):
        with self.assertRaises(Exception) as context_manager:
            Ikev2PayloadNonce(
                flags=set(),
                nonce_data="not_bytes"
            )
        self.assertTrue(len(str(context_manager.exception)) > 0)

    def test_minimal_nonce_data(self):
        nonce_empty = Ikev2PayloadNonce(
            flags=set(),
            nonce_data=b'\x00' * 16
        )
        nonce_empty.next_payload = Ikev2PayloadType.NONE
        composed_bytes = nonce_empty.compose()
        parsed_nonce = Ikev2PayloadNonce.parse_exact_size(composed_bytes)
        self.assertEqual(parsed_nonce.nonce_data, b'\x00' * 16)

    def test_too_small_nonce_data(self):
        with self.assertRaises(NotEnoughData) as context_manager:
            Ikev2PayloadNonce.parse_exact_size(self.nonce_bytes_too_small)
        self.assertEqual(context_manager.exception.bytes_needed, 16 - 15)

    def test_too_large_nonce_data(self):
        with self.assertRaises(TooMuchData) as context_manager:
            Ikev2PayloadNonce.parse_exact_size(self.nonce_bytes_too_large)
        self.assertEqual(context_manager.exception.bytes_needed, 257 - 256)

    def test_error_nonce_data_validation_min_length(self):
        with self.assertRaises(ValueError):
            Ikev2PayloadNonce(flags=set(), nonce_data=b'\x01\x02\x03\x04\x05\x06\x07\x08')

    def test_error_nonce_data_validation_max_length(self):
        with self.assertRaises(ValueError):
            Ikev2PayloadNonce(flags=set(), nonce_data=b'\x01' * 257)

    def test_round_trip(self):
        composed_bytes = self.nonce_payload.compose()
        parsed_payload: Ikev2PayloadNonce = Ikev2PayloadNonce.parse_exact_size(composed_bytes)

        self.assertEqual(parsed_payload.nonce_data, self.nonce_payload.nonce_data)
        self.assertEqual(parsed_payload.flags, self.nonce_payload.flags)
        self.assertEqual(parsed_payload.next_payload, self.nonce_payload.next_payload)


class TestIkev2PayloadDelete(unittest.TestCase):  # pylint: disable=too-many-instance-attributes
    def setUp(self):
        self.protocol_id = Ikev2ProtocolId.IKE
        self.spis = [0x1234567890abcdef, 0xfedcba0987654321]
        self.delete_payload = Ikev2PayloadDelete(
            flags=set(),
            protocol_id=self.protocol_id,
            spis=self.spis
        )
        self.delete_payload.next_payload = Ikev2PayloadType.NONE

        self.delete_dict = collections.OrderedDict([
            ('next_payload', b'\x00'),  # NONE
            ('flags', b'\x00'),
            ('payload_length', b'\x00\x18'),  # 24 bytes (header + protocol_id + spi_size + num_spis + spis)
            ('protocol_id', b'\x01'),  # IKE protocol
            ('spi_size', b'\x10'),  # 16 bytes (2 SPIs * 8 bytes each)
            ('num_spis', b'\x00\x02'),  # 2 SPIs
            ('spis', b'\x12\x34\x56\x78\x90\xab\xcd\xef\xfe\xdc\xba\x09\x87\x65\x43\x21'),
        ])
        self.delete_bytes = b''.join(self.delete_dict.values())

        self.empty_delete_payload = Ikev2PayloadDelete(
            flags={Ikev2PayloadFlags.CRITICAL},
            protocol_id=self.protocol_id,
            spis=[]
        )
        self.empty_delete_payload.next_payload = Ikev2PayloadType.NONE

        self.empty_delete_dict = collections.OrderedDict([
            ('next_payload', b'\x00'),  # NONE
            ('flags', b'\x80'),  # CRITICAL (0x80)
            ('payload_length', b'\x00\x08'),  # 8 bytes (header + protocol_id + spi_size + num_spis)
            ('protocol_id', b'\x01'),  # IKE protocol
            ('spi_size', b'\x00'),
            ('num_spis', b'\x00\x00'),
        ])
        self.empty_delete_bytes = b''.join(self.empty_delete_dict.values())

    def test_get_payload_type(self):
        self.assertEqual(Ikev2PayloadDelete.get_payload_type(), Ikev2PayloadType.DELETE)

    def test_parse(self):
        parsed_delete = Ikev2PayloadDelete.parse_exact_size(self.delete_bytes)
        self.assertEqual(parsed_delete.protocol_id, self.protocol_id)
        self.assertEqual(parsed_delete.spis, self.spis)
        self.assertEqual(parsed_delete.next_payload, Ikev2PayloadType.NONE)
        self.assertEqual(parsed_delete.flags, set())

    def test_compose(self):
        composed_bytes = self.delete_payload.compose()
        self.assertIsInstance(composed_bytes, (bytes, bytearray))
        self.assertGreater(len(composed_bytes), Ikev2PayloadDelete.HEADER_SIZE)

        parsed_delete = Ikev2PayloadDelete.parse_exact_size(composed_bytes)
        self.assertEqual(parsed_delete.protocol_id, self.delete_payload.protocol_id)
        self.assertEqual(parsed_delete.spis, self.delete_payload.spis)
        self.assertEqual(parsed_delete.next_payload, self.delete_payload.next_payload)
        self.assertEqual(parsed_delete.flags, self.delete_payload.flags)

    def test_empty_spis(self):
        composed_bytes = self.empty_delete_payload.compose()
        parsed_delete = Ikev2PayloadDelete.parse_exact_size(composed_bytes)
        self.assertEqual(parsed_delete.spis, [])
        self.assertEqual(parsed_delete.protocol_id, self.protocol_id)
        self.assertEqual(parsed_delete.flags, {Ikev2PayloadFlags.CRITICAL})

    def test_error_parse_not_enough_data(self):
        with self.assertRaises(NotEnoughData) as context_manager:
            Ikev2PayloadDelete.parse_exact_size(b'\x00\x01\x02')
        self.assertEqual(context_manager.exception.bytes_needed, 1)

    def test_error_invalid_protocol_id(self):
        with self.assertRaises(TypeError):
            Ikev2PayloadDelete(
                flags=set(),
                protocol_id="invalid_protocol",
                spis=self.spis
            )

    def test_error_invalid_spis_type(self):
        with self.assertRaises(TypeError):
            Ikev2PayloadDelete(
                flags=set(),
                protocol_id=self.protocol_id,
                spis=["not_an_int"]
            )

    def test_round_trip(self):
        composed_bytes = self.delete_payload.compose()
        parsed_payload: Ikev2PayloadDelete = Ikev2PayloadDelete.parse_exact_size(composed_bytes)

        self.assertEqual(parsed_payload.protocol_id, self.delete_payload.protocol_id)
        self.assertEqual(parsed_payload.spis, self.delete_payload.spis)
        self.assertEqual(parsed_payload.flags, self.delete_payload.flags)
        self.assertEqual(parsed_payload.next_payload, self.delete_payload.next_payload)


class TestIkev2PayloadNotifyNoData(unittest.TestCase):  # pylint: disable=too-many-instance-attributes
    def setUp(self):
        self.protocol_id = Ikev2ProtocolId.IKE
        self.notify_type = Ikev2NotifyType.AUTHENTICATION_FAILED
        self.spi = b'\x00\x01\x02\x03\x04\x05\x06\x07'

        self.notify_payload_minimal = Ikev2PayloadNotifyNoDataTest(
            flags=set(),
            protocol_id=self.protocol_id,
            notify_type=self.notify_type,
            spi=b''
        )
        self.notify_payload_minimal.next_payload = Ikev2PayloadType.NONE

        self.notify_dict_minimal = collections.OrderedDict([
            ('next_payload', b'\x00'),  # NONE
            ('flags', b'\x00'),
            ('payload_length', b'\x00\x08'),  # 8 bytes (header + protocol_id + spi_size + notify_type)
            ('protocol_id', b'\x01'),  # IKE protocol
            ('spi_size', b'\x00'),
            ('notify_type', b'\x00\x18'),  # AUTHENTICATION_FAILED (0x0018)
        ])
        self.notify_bytes_minimal = b''.join(self.notify_dict_minimal.values())

        self.notify_payload_with_spi = Ikev2PayloadNotifyNoDataTest(
            flags={Ikev2PayloadFlags.CRITICAL},
            protocol_id=self.protocol_id,
            notify_type=self.notify_type,
            spi=self.spi
        )
        self.notify_payload_with_spi.next_payload = Ikev2PayloadType.NONE

        self.notify_dict_with_spi = collections.OrderedDict([
            ('next_payload', b'\x00'),  # NONE
            ('flags', b'\x80'),  # CRITICAL (0x80)
            ('payload_length', b'\x00\x10'),  # 16 bytes (header + protocol_id + spi_size + notify_type + spi)
            ('protocol_id', b'\x01'),  # IKE protocol
            ('spi_size', b'\x08'),
            ('notify_type', b'\x00\x18'),  # AUTHENTICATION_FAILED (0x0018)
            ('spi', self.spi),
        ])
        self.notify_bytes_with_spi = b''.join(self.notify_dict_with_spi.values())

    def test_parse(self):
        parsed_notify = Ikev2PayloadNotifyNoDataTest.parse_exact_size(self.notify_bytes_minimal)
        self.assertEqual(parsed_notify.protocol_id, self.protocol_id)
        self.assertEqual(parsed_notify.type, self.notify_type)
        self.assertEqual(parsed_notify.spi, b'')
        self.assertEqual(parsed_notify.next_payload, Ikev2PayloadType.NONE)
        self.assertEqual(parsed_notify.flags, set())

        parsed_notify = Ikev2PayloadNotifyNoDataTest.parse_exact_size(self.notify_bytes_with_spi)
        self.assertEqual(parsed_notify.protocol_id, self.protocol_id)
        self.assertEqual(parsed_notify.type, self.notify_type)
        self.assertEqual(parsed_notify.spi, self.spi)
        self.assertEqual(parsed_notify.next_payload, Ikev2PayloadType.NONE)
        self.assertEqual(parsed_notify.flags, {Ikev2PayloadFlags.CRITICAL})

    def test_compose(self):
        self.assertEqual(self.notify_payload_minimal.compose(), self.notify_bytes_minimal)
        self.assertEqual(self.notify_payload_with_spi.compose(), self.notify_bytes_with_spi)

    def test_error_parse_not_enough_data(self):
        with self.assertRaises(NotEnoughData) as context_manager:
            Ikev2PayloadNotifyNoDataTest.parse_exact_size(b'\x00\x01\x02')
        self.assertEqual(context_manager.exception.bytes_needed, 1)

    def test_error_payload_validation(self):
        with self.assertRaises(TypeError) as context_manager:
            Ikev2PayloadNotifyNoDataTest(
                flags={'invalid_flag'},
                protocol_id=self.protocol_id,
                notify_type=self.notify_type,
                spi=self.spi
            )
        exception_str = str(context_manager.exception)
        self.assertIn("flags", exception_str)
        self.assertIn("must be", exception_str)
        self.assertIn("Ikev2PayloadFlags", exception_str)

    def test_error_invalid_protocol_id(self):
        with self.assertRaises(TypeError):
            Ikev2PayloadNotifyNoDataTest(
                flags=set(),
                protocol_id="invalid_protocol",
                notify_type=self.notify_type,
                spi=self.spi
            )

    def test_error_invalid_notify_type(self):
        with self.assertRaises(TypeError):
            Ikev2PayloadNotifyNoDataTest(
                flags=set(),
                protocol_id=self.protocol_id,
                notify_type="invalid_type",
                spi=self.spi
            )

    def test_error_invalid_spi(self):
        # The spi attribute has converter=bytes, so test with something that can't be converted
        with self.assertRaises((TypeError, ValueError)):
            Ikev2PayloadNotifyNoDataTest(
                flags=set(),
                protocol_id=self.protocol_id,
                notify_type=self.notify_type,
                spi=None
            )


class TestIkev2PayloadNotifyAuthenticationFailed(unittest.TestCase):
    def setUp(self):
        self.protocol_id = Ikev2ProtocolId.IKE

        self.notify_dict_authentication_failed = collections.OrderedDict([
            ('next_payload', b'\x00'),  # NONE
            ('flags', b'\x00'),
            ('payload_length', b'\x00\x08'),  # 8 bytes (header + protocol_id + spi_size + notify_type)
            ('protocol_id', b'\x01'),  # IKE protocol
            ('spi_size', b'\x00'),
            ('notify_type', b'\x00\x18'),  # AUTHENTICATION_FAILED (0x0018)
        ])
        self.notify_bytes_authentication_failed = b''.join(self.notify_dict_authentication_failed.values())

    def test_get_message_type(self):
        self.assertEqual(Ikev2PayloadNotifyAuthenticationFailed._get_message_type(),  # pylint: disable=protected-access
                         Ikev2NotifyType.AUTHENTICATION_FAILED)

    def test_parse_authentication_failed(self):
        parsed_notify = Ikev2PayloadNotifyAuthenticationFailed.parse_exact_size(
            self.notify_bytes_authentication_failed)
        self.assertEqual(parsed_notify.type, Ikev2NotifyType.AUTHENTICATION_FAILED)
        self.assertEqual(parsed_notify.protocol_id, self.protocol_id)


class TestIkev2PayloadNotifyUnparsed(unittest.TestCase):
    def setUp(self):
        self.notify_type = Ikev2NotifyType.INVALID_SYNTAX
        self.notify_data = (
            b'\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f'
            b'\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f'
        )

        self.notify_dict_with_data = collections.OrderedDict([
            ('next_payload', b'\x00'),  # NONE
            ('flags', b'\x00'),
            ('payload_length', b'\x00\x28'),  # 40 bytes (8 header + 32 data)
            ('protocol_id', b'\x01'),  # IKE protocol
            ('spi_size', b'\x00'),
            ('notify_type', b'\x00\x07'),  # INVALID_SYNTAX (0x0007)
        ])
        self.notify_bytes_with_data = b''.join(self.notify_dict_with_data.values()) + self.notify_data

    def test_parse(self):
        parsed_notify: Ikev2PayloadNotifyUnparsed = Ikev2PayloadNotifyUnparsed.parse_exact_size(
            self.notify_bytes_with_data)
        self.assertEqual(parsed_notify.data, self.notify_data)  # pylint: disable=no-member

    def test_compose(self):
        notify_payload = Ikev2PayloadNotifyUnparsed(
            flags=set(),
            protocol_id=Ikev2ProtocolId.IKE,
            type=self.notify_type,
            spi=b'',
            data=self.notify_data
        )
        notify_payload.next_payload = Ikev2PayloadType.NONE

        composed_bytes = notify_payload.compose()
        self.assertEqual(composed_bytes, self.notify_bytes_with_data)

    def test_round_trip(self):
        original_payload = Ikev2PayloadNotifyUnparsed(
            flags=set(),
            protocol_id=Ikev2ProtocolId.IKE,
            type=self.notify_type,
            spi=b'',
            data=self.notify_data
        )
        original_payload.next_payload = Ikev2PayloadType.NONE

        composed_bytes = original_payload.compose()
        parsed_payload: Ikev2PayloadNotifyUnparsed = Ikev2PayloadNotifyUnparsed.parse_exact_size(composed_bytes)

        self.assertEqual(parsed_payload.data, original_payload.data)  # pylint: disable=no-member


class TestIkev2NotifyPayloadInvalidKe(unittest.TestCase):
    def setUp(self):
        self.dh_group = Ikev2DiffieHellmanGroup.MODP_GROUP_2048_BIT

        self.invalid_ke_dict = collections.OrderedDict([
            ('next_payload', b'\x00'),  # NONE
            ('flags', b'\x00'),
            ('payload_length', b'\x00\x0a'),  # 10 bytes (8 header + 2 dh_group)
            ('protocol_id', b'\x01'),  # IKE protocol
            ('spi_size', b'\x00'),
            ('notify_type', b'\x00\x11'),  # INVALID_KE_PAYLOAD (0x0011)
            ('dh_group', b'\x00\x0e'),  # MODP_GROUP_2048_BIT (0x000e)
        ])
        self.invalid_ke_bytes = b''.join(self.invalid_ke_dict.values())
        self.invalid_ke_payload = Ikev2NotifyPayloadInvalidKe(
            flags=set(),
            protocol_id=Ikev2ProtocolId.IKE,
            type=Ikev2NotifyType.INVALID_KE_PAYLOAD,
            spi=b'',
            dh_group=self.dh_group
        )
        self.invalid_ke_payload.next_payload = Ikev2PayloadType.NONE

    def test_get_message_type(self):
        self.assertEqual(Ikev2NotifyPayloadInvalidKe._get_message_type(),  # pylint: disable=protected-access
                         Ikev2NotifyType.INVALID_KE_PAYLOAD)

    def test_parse(self):
        parsed_notify: Ikev2NotifyPayloadInvalidKe = Ikev2NotifyPayloadInvalidKe.parse_exact_size(self.invalid_ke_bytes)
        self.assertEqual(parsed_notify.type, Ikev2NotifyType.INVALID_KE_PAYLOAD)
        self.assertEqual(parsed_notify.protocol_id, Ikev2ProtocolId.IKE)
        self.assertEqual(parsed_notify.dh_group, self.dh_group)  # pylint: disable=no-member

    def test_compose(self):
        composed_bytes = self.invalid_ke_payload.compose()
        self.assertEqual(composed_bytes, self.invalid_ke_bytes)

    def test_round_trip(self):
        composed_bytes = self.invalid_ke_payload.compose()
        parsed_payload: Ikev2NotifyPayloadInvalidKe = Ikev2NotifyPayloadInvalidKe.parse_exact_size(composed_bytes)

        # Verify all attributes are preserved
        self.assertEqual(parsed_payload.dh_group, self.invalid_ke_payload.dh_group)  # pylint: disable=no-member
        self.assertEqual(parsed_payload.flags, self.invalid_ke_payload.flags)
        self.assertEqual(parsed_payload.next_payload, self.invalid_ke_payload.next_payload)
        self.assertEqual(parsed_payload.spi, self.invalid_ke_payload.spi)


class TestIkev2PayloadCertificateRequest(unittest.TestCase):
    def setUp(self):
        self.cert_encoding = 4  # X.509 certificate signature
        self.certificate_data = (
            b'\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f'
            b'\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f'
        )

        self.certreq_dict = collections.OrderedDict([
            ('next_payload', b'\x00'),  # NONE
            ('flags', b'\x00'),
            ('payload_length', b'\x00\x25'),  # 37 bytes (4 header + 1 cert_encoding + 32 data)
            ('cert_encoding', b'\x04'),  # X.509 certificate signature
            ('certificate_data', self.certificate_data),
        ])
        self.certreq_bytes = b''.join(self.certreq_dict.values())

        self.certreq_payload = Ikev2PayloadCertificateRequest(
            flags=set(),
            cert_encoding=self.cert_encoding,
            certificate_data=self.certificate_data
        )
        self.certreq_payload.next_payload = Ikev2PayloadType.NONE

    def test_get_payload_type(self):
        self.assertEqual(Ikev2PayloadCertificateRequest.get_payload_type(), Ikev2PayloadType.CERTREQ)

    def test_parse(self):
        parsed_certreq: Ikev2PayloadCertificateRequest = Ikev2PayloadCertificateRequest.parse_exact_size(
            self.certreq_bytes)
        self.assertEqual(parsed_certreq.next_payload, Ikev2PayloadType.NONE)
        self.assertEqual(parsed_certreq.flags, set())
        self.assertEqual(parsed_certreq.cert_encoding, self.cert_encoding)
        self.assertEqual(parsed_certreq.certificate_data, self.certificate_data)

    def test_compose(self):
        composed_bytes = self.certreq_payload.compose()
        self.assertEqual(composed_bytes, self.certreq_bytes)

    def test_round_trip(self):
        composed_bytes = self.certreq_payload.compose()
        parsed_payload: Ikev2PayloadCertificateRequest = Ikev2PayloadCertificateRequest.parse_exact_size(
            composed_bytes)

        self.assertEqual(parsed_payload.cert_encoding, self.certreq_payload.cert_encoding)
        self.assertEqual(parsed_payload.certificate_data, self.certreq_payload.certificate_data)
        self.assertEqual(parsed_payload.flags, self.certreq_payload.flags)
        self.assertEqual(parsed_payload.next_payload, self.certreq_payload.next_payload)

    def test_error_parse_not_enough_data(self):
        incomplete_data = self.certreq_bytes[:-5]

        with self.assertRaises(NotEnoughData) as context_manager:
            Ikev2PayloadCertificateRequest.parse_exact_size(incomplete_data)
        self.assertEqual(context_manager.exception.bytes_needed, 5)


class TestIkev2PayloadVendorId(unittest.TestCase):
    def setUp(self):
        self.vendor_id = (
            b'\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f'
            b'\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f'
        )

        self.vendor_dict = collections.OrderedDict([
            ('next_payload', b'\x00'),  # NONE
            ('flags', b'\x80'),  # CRITICAL (0x80)
            ('payload_length', b'\x00\x24'),  # 36 bytes (4 header + 32 vendor_id)
            ('vendor_id', self.vendor_id),
        ])
        self.vendor_bytes = b''.join(self.vendor_dict.values())

        self.vendor_payload = Ikev2PayloadVendorId(
            flags={Ikev2PayloadFlags.CRITICAL},
            vendor_id=self.vendor_id
        )
        self.vendor_payload.next_payload = Ikev2PayloadType.NONE

    def test_get_payload_type(self):
        self.assertEqual(Ikev2PayloadVendorId.get_payload_type(), Ikev2PayloadType.VENDOR_ID)

    def test_parse(self):
        parsed_vendor: Ikev2PayloadVendorId = Ikev2PayloadVendorId.parse_exact_size(self.vendor_bytes)
        self.assertEqual(parsed_vendor.next_payload, Ikev2PayloadType.NONE)
        self.assertEqual(parsed_vendor.flags, {Ikev2PayloadFlags.CRITICAL})
        self.assertEqual(parsed_vendor.vendor_id, self.vendor_id)

    def test_compose(self):
        composed_bytes = self.vendor_payload.compose()
        self.assertEqual(composed_bytes, self.vendor_bytes)

    def test_round_trip(self):
        composed_bytes = self.vendor_payload.compose()
        parsed_payload: Ikev2PayloadVendorId = Ikev2PayloadVendorId.parse_exact_size(composed_bytes)

        self.assertEqual(parsed_payload.vendor_id, self.vendor_payload.vendor_id)
        self.assertEqual(parsed_payload.flags, self.vendor_payload.flags)
        self.assertEqual(parsed_payload.next_payload, self.vendor_payload.next_payload)

    def test_error_parse_not_enough_data(self):
        incomplete_data = self.vendor_bytes[:-10]

        with self.assertRaises(NotEnoughData) as context_manager:
            Ikev2PayloadVendorId.parse_exact_size(incomplete_data)
        self.assertEqual(context_manager.exception.bytes_needed, 10)


class TestTransformAttributeKeyLength(unittest.TestCase):
    def setUp(self):
        self.key_length_value = 128
        self.key_length_attribute = TransformAttributeKeyLength(value=self.key_length_value)

    def test_parse(self):
        composed_bytes = self.key_length_attribute.compose()
        parsed_attribute = TransformAttributeKeyLength.parse_exact_size(composed_bytes)

        self.assertEqual(parsed_attribute.value, self.key_length_attribute.value)

    def test_compose(self):
        composed_bytes = self.key_length_attribute.compose()
        self.assertEqual(len(composed_bytes), 4)
        self.assertEqual(composed_bytes[0], 0x80)
        self.assertEqual(composed_bytes[1], Ikev2TransformAttributeType.KEY_LENGTH.value.code)
        self.assertEqual(composed_bytes[2:4], b'\x00\x80')

    def test_round_trip(self):
        composed_bytes = self.key_length_attribute.compose()
        parsed_attribute = TransformAttributeKeyLength.parse_exact_size(composed_bytes)

        self.assertEqual(parsed_attribute.value, self.key_length_attribute.value)

    def test_error_parse_not_enough_data(self):
        incomplete_data = b'\x80\x0e\x00'

        with self.assertRaises(NotEnoughData) as context_manager:
            TransformAttributeKeyLength.parse_exact_size(incomplete_data)
        self.assertEqual(context_manager.exception.bytes_needed, 1)


if __name__ == '__main__':
    unittest.main()
