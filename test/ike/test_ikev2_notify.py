# SPDX-License-Identifier: MPL-2.0
# -*- coding: utf-8 -*-

import collections
import unittest

from cryptodatahub.ike.algorithm import Ikev2NotifyType, Ikev2ProtocolId

from cryptoparser.common.exception import NotEnoughData
from cryptoparser.ike.ikev2 import (
    Ikev2PayloadFlags,
    Ikev2PayloadType,
    Ikev2PayloadNotifyUnparsed,
    Ikev2NotifyPayloadCookie,
    Ikev2NotifyPayloadVariantResponder
)

from .classes import Ikev2PayloadNotifyBaseTest, Ikev2PayloadNotifyNoDataTest


class TestIkev2PayloadNotifyBase(unittest.TestCase):  # pylint: disable=too-many-instance-attributes
    def setUp(self):
        self.protocol_id = Ikev2ProtocolId.IKE
        self.notify_type = Ikev2NotifyType.AUTHENTICATION_FAILED
        self.spi = b'\x00\x01\x02\x03'
        self.test_data = b'\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f'

        self.notify_payload_minimal = Ikev2PayloadNotifyBaseTest(
            flags=set(),
            protocol_id=self.protocol_id,
            notify_type=self.notify_type,
            spi=bytes(),
            test_data=b''
        )
        self.notify_payload_minimal.next_payload = Ikev2PayloadType.NONE

        self.notify_payload_with_data = Ikev2PayloadNotifyBaseTest(
            flags={Ikev2PayloadFlags.CRITICAL},
            protocol_id=self.protocol_id,
            notify_type=self.notify_type,
            spi=self.spi,
            test_data=self.test_data
        )
        self.notify_payload_with_data.next_payload = Ikev2PayloadType.KE

        self.notify_dict_minimal = collections.OrderedDict([
            ('next_payload', b'\x00'),  # NONE
            ('flags', b'\x00'),  # No flags
            ('payload_length', b'\x00\x08'),  # 4 bytes header + 4 bytes notify header + 0 bytes data
            ('protocol_id', b'\x01'),  # IKE
            ('spi_size', b'\x00'),  # 0 bytes SPI
            ('notify_type', b'\x00\x18'),  # AUTHENTICATION_FAILED (0x0018)
        ])
        self.notify_bytes_minimal = b''.join(self.notify_dict_minimal.values())

        self.notify_dict_with_data = collections.OrderedDict([
            ('next_payload', b'\x22'),  # KE
            ('flags', b'\x80'),  # CRITICAL
            ('payload_length', b'\x00\x1c'),  # 4 bytes header + 4 bytes notify header + 4 bytes SPI + 16 bytes data
            ('protocol_id', b'\x01'),  # IKE
            ('spi_size', b'\x04'),  # 4 bytes SPI
            ('notify_type', b'\x00\x18'),  # AUTHENTICATION_FAILED (0x0018)
            ('spi', self.spi),  # SPI data
            ('test_data', self.test_data),  # Notification data
        ])
        self.notify_bytes_with_data = b''.join(self.notify_dict_with_data.values())

    def test_get_payload_type(self):
        self.assertEqual(Ikev2PayloadNotifyBaseTest.get_payload_type(), Ikev2PayloadType.NOTIFY)

    def test_parse(self):
        parsed_minimal: Ikev2PayloadNotifyBaseTest = Ikev2PayloadNotifyBaseTest.parse_exact_size(
            self.notify_bytes_minimal
        )
        self.assertEqual(parsed_minimal.flags, set())
        self.assertEqual(parsed_minimal.next_payload, Ikev2PayloadType.NONE)
        self.assertEqual(parsed_minimal.protocol_id, self.protocol_id)
        self.assertEqual(parsed_minimal.type, self.notify_type)
        self.assertEqual(parsed_minimal.spi, bytes())
        self.assertEqual(parsed_minimal.test_data, b'')

        parsed_with_data: Ikev2PayloadNotifyBaseTest = Ikev2PayloadNotifyBaseTest.parse_exact_size(
            self.notify_bytes_with_data
        )
        self.assertEqual(parsed_with_data.flags, {Ikev2PayloadFlags.CRITICAL})
        self.assertEqual(parsed_with_data.next_payload, Ikev2PayloadType.KE)
        self.assertEqual(parsed_with_data.protocol_id, self.protocol_id)
        self.assertEqual(parsed_with_data.type, self.notify_type)
        self.assertEqual(parsed_with_data.spi, self.spi)
        self.assertEqual(parsed_with_data.test_data, self.test_data)

    def test_compose(self):
        composed_minimal = self.notify_payload_minimal.compose()
        self.assertEqual(composed_minimal, self.notify_bytes_minimal)

        composed_with_data = self.notify_payload_with_data.compose()
        self.assertEqual(composed_with_data, self.notify_bytes_with_data)

    def test_round_trip(self):
        composed_minimal = self.notify_payload_minimal.compose()
        parsed_minimal: Ikev2PayloadNotifyBaseTest = Ikev2PayloadNotifyBaseTest.parse_exact_size(composed_minimal)

        self.assertEqual(parsed_minimal.protocol_id, self.notify_payload_minimal.protocol_id)
        self.assertEqual(parsed_minimal.type, self.notify_payload_minimal.type)
        self.assertEqual(parsed_minimal.spi, self.notify_payload_minimal.spi)
        self.assertEqual(parsed_minimal.test_data, self.notify_payload_minimal.test_data)
        self.assertEqual(parsed_minimal.flags, self.notify_payload_minimal.flags)
        self.assertEqual(parsed_minimal.next_payload, self.notify_payload_minimal.next_payload)

        composed_with_data = self.notify_payload_with_data.compose()
        parsed_with_data: Ikev2PayloadNotifyBaseTest = Ikev2PayloadNotifyBaseTest.parse_exact_size(composed_with_data)

        self.assertEqual(parsed_with_data.protocol_id, self.notify_payload_with_data.protocol_id)
        self.assertEqual(parsed_with_data.type, self.notify_payload_with_data.type)
        self.assertEqual(parsed_with_data.spi, self.notify_payload_with_data.spi)
        self.assertEqual(parsed_with_data.test_data, self.notify_payload_with_data.test_data)
        self.assertEqual(parsed_with_data.flags, self.notify_payload_with_data.flags)
        self.assertEqual(parsed_with_data.next_payload, self.notify_payload_with_data.next_payload)

    def test_error_parse_not_enough_data(self):
        incomplete_data = self.notify_bytes_minimal[:-2]

        with self.assertRaises(NotEnoughData) as context_manager:
            Ikev2PayloadNotifyBaseTest.parse_exact_size(incomplete_data)
        self.assertEqual(context_manager.exception.bytes_needed, 2)

    def test_error_invalid_protocol_id(self):
        with self.assertRaises(TypeError):
            Ikev2PayloadNotifyBaseTest(
                flags=set(),
                protocol_id="invalid",
                notify_type=self.notify_type,
                spi=bytes(),
                test_data=b''
            )

    def test_error_invalid_notify_type(self):
        with self.assertRaises(TypeError):
            Ikev2PayloadNotifyBaseTest(
                flags=set(),
                protocol_id=self.protocol_id,
                notify_type="invalid",
                spi=bytes(),
                test_data=b''
            )

    def test_error_invalid_spi(self):
        with self.assertRaises(TypeError):
            Ikev2PayloadNotifyBaseTest(
                flags=set(),
                protocol_id=self.protocol_id,
                notify_type=self.notify_type,
                spi=None,
                test_data=b''
            )


class TestIkev2PayloadNotifyNoData(unittest.TestCase):
    def setUp(self):
        self.wrong_notify_dict = collections.OrderedDict([
            ('next_payload', b'\x00'),  # NONE
            ('flags', b'\x00'),  # No flags
            ('payload_length', b'\x00\x08'),  # 4 bytes header + 4 bytes notify header
            ('protocol_id', b'\x01'),  # IKE
            ('spi_size', b'\x00'),  # 0 bytes SPI
            ('notify_type', b'\x00\x01'),  # UNSUPPORTED_CRITICAL_PAYLOAD (not AUTHENTICATION_FAILED)
        ])
        self.wrong_notify_bytes = b''.join(self.wrong_notify_dict.values())

    def test_get_message_type(self):
        # pylint: disable=protected-access
        self.assertEqual(Ikev2PayloadNotifyNoDataTest._get_message_type(), Ikev2NotifyType.AUTHENTICATION_FAILED)

    def test_error_invalid_notify_type(self):
        with self.assertRaises(Exception):  # InvalidType from the implementation
            Ikev2PayloadNotifyNoDataTest.parse_exact_size(self.wrong_notify_bytes)


class TestIkev2PayloadNotifyUnparsed(unittest.TestCase):
    def setUp(self):
        self.protocol_id = Ikev2ProtocolId.IKE
        self.notify_type = Ikev2NotifyType.INVALID_SELECTORS  # Different from AUTHENTICATION_FAILED
        self.spi = b'\x00\x01\x02\x03'
        self.data = b'\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f'

        self.notify_payload_with_data = Ikev2PayloadNotifyUnparsed(
            flags={Ikev2PayloadFlags.CRITICAL},
            protocol_id=self.protocol_id,
            type=self.notify_type,
            spi=self.spi,
            data=self.data
        )
        self.notify_payload_with_data.next_payload = Ikev2PayloadType.KE

    def test_any_notify_type_support(self):
        different_notify_types = [
            Ikev2NotifyType.AUTHENTICATION_FAILED,
            Ikev2NotifyType.INVALID_SELECTORS,
            Ikev2NotifyType.UNSUPPORTED_CRITICAL_PAYLOAD,
        ]

        for notify_type in different_notify_types:
            payload = Ikev2PayloadNotifyUnparsed(
                flags=set(),
                protocol_id=self.protocol_id,
                type=notify_type,
                spi=bytes(),
                data=b'\x00\x01\x02\x03'
            )
            self.assertEqual(payload.type, notify_type)
            self.assertEqual(payload.data, b'\x00\x01\x02\x03')

    def test_raw_data_storage(self):
        payload = Ikev2PayloadNotifyUnparsed(
            flags=set(),
            protocol_id=self.protocol_id,
            type=self.notify_type,
            spi=bytes(),
            data=self.data
        )
        self.assertEqual(payload.data, self.data)

        different_data = b'\xff\xfe\xfd\xfc'
        payload_2 = Ikev2PayloadNotifyUnparsed(
            flags=set(),
            protocol_id=self.protocol_id,
            type=self.notify_type,
            spi=bytes(),
            data=different_data
        )
        self.assertEqual(payload_2.data, different_data)

    def test_round_trip_data_preservation(self):
        payload_no_spi = Ikev2PayloadNotifyUnparsed(
            flags=set(),
            protocol_id=self.protocol_id,
            type=self.notify_type,
            spi=bytes(),
            data=self.data
        )
        payload_no_spi.next_payload = Ikev2PayloadType.NONE

        composed_bytes = payload_no_spi.compose()
        parsed_payload: Ikev2PayloadNotifyUnparsed = Ikev2PayloadNotifyUnparsed.parse_exact_size(composed_bytes)

        self.assertEqual(parsed_payload.data, payload_no_spi.data)  # pylint: disable=no-member
        self.assertEqual(parsed_payload.type, payload_no_spi.type)
        self.assertEqual(parsed_payload.spi, payload_no_spi.spi)

    def test_parse_with_spi(self):
        data_with_spi = b'\x00\x01\x02\x03\x04\x05\x06\x07'
        payload_with_spi = Ikev2PayloadNotifyUnparsed(
            flags=set(),
            protocol_id=self.protocol_id,
            type=self.notify_type,
            spi=self.spi,
            data=data_with_spi
        )
        payload_with_spi.next_payload = Ikev2PayloadType.NONE
        composed_bytes = payload_with_spi.compose()
        parsed_payload: Ikev2PayloadNotifyUnparsed = Ikev2PayloadNotifyUnparsed.parse_exact_size(composed_bytes)

        self.assertEqual(parsed_payload.protocol_id, self.protocol_id)
        self.assertEqual(parsed_payload.type, self.notify_type)
        self.assertEqual(parsed_payload.spi, self.spi)
        self.assertEqual(parsed_payload.data, data_with_spi)  # pylint: disable=no-member
        self.assertEqual(parsed_payload.flags, set())
        self.assertEqual(parsed_payload.next_payload, Ikev2PayloadType.NONE)


class TestIkev2NotifyPayloadCookie(unittest.TestCase):
    def setUp(self):
        self.protocol_id = Ikev2ProtocolId.IKE
        self.cookie_data = b'\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f'

        self.cookie_payload = Ikev2NotifyPayloadCookie(
            flags=set(),
            protocol_id=self.protocol_id,
            type=Ikev2NotifyType.COOKIE,
            spi=bytes(),
            cookie=self.cookie_data
        )
        self.cookie_payload.next_payload = Ikev2PayloadType.NONE

    def test_get_message_type(self):
        # pylint: disable=protected-access
        self.assertEqual(Ikev2NotifyPayloadCookie._get_message_type(), Ikev2NotifyType.COOKIE)

    def test_cookie_data_storage(self):
        payload = Ikev2NotifyPayloadCookie(
            flags=set(),
            protocol_id=self.protocol_id,
            type=Ikev2NotifyType.COOKIE,
            spi=bytes(),
            cookie=self.cookie_data
        )
        self.assertEqual(payload.cookie, self.cookie_data)

        different_cookie = b'\xff\xfe\xfd\xfc\xfb\xfa'
        payload_2 = Ikev2NotifyPayloadCookie(
            flags=set(),
            protocol_id=self.protocol_id,
            type=Ikev2NotifyType.COOKIE,
            spi=bytes(),
            cookie=different_cookie
        )
        self.assertEqual(payload_2.cookie, different_cookie)

    def test_round_trip_cookie_preservation(self):
        composed_bytes = self.cookie_payload.compose()
        parsed_payload: Ikev2NotifyPayloadCookie = Ikev2NotifyPayloadCookie.parse_exact_size(composed_bytes)

        self.assertEqual(parsed_payload.cookie, self.cookie_payload.cookie)  # pylint: disable=no-member
        self.assertEqual(parsed_payload.type, self.cookie_payload.type)
        self.assertEqual(parsed_payload.spi, self.cookie_payload.spi)


class TestIkev2NotifyPayloadVariantResponder(unittest.TestCase):
    def setUp(self):
        self.protocol_id = Ikev2ProtocolId.IKE

    def test_parse_other_notify_type(self):
        other_notify = Ikev2PayloadNotifyUnparsed(
            flags=set(),
            protocol_id=self.protocol_id,
            type=Ikev2NotifyType.AUTHENTICATION_FAILED,
            spi=bytes(),
            data=b'\x00\x01\x02\x03'
        )
        other_notify.next_payload = Ikev2PayloadType.NONE
        composed_bytes = other_notify.compose()

        parsed_payload = Ikev2NotifyPayloadVariantResponder.parse_exact_size(composed_bytes)
        self.assertIsInstance(parsed_payload, Ikev2PayloadNotifyUnparsed)
        self.assertEqual(parsed_payload.type, Ikev2NotifyType.AUTHENTICATION_FAILED)
        self.assertEqual(parsed_payload.data, b'\x00\x01\x02\x03')  # pylint: disable=no-member

    def test_compose(self):
        cookie_data = b'\x00\x01\x02\x03'
        cookie_payload = Ikev2NotifyPayloadCookie(
            flags=set(),
            protocol_id=self.protocol_id,
            type=Ikev2NotifyType.COOKIE,
            spi=bytes(),
            cookie=cookie_data
        )
        cookie_payload.next_payload = Ikev2PayloadType.NONE

        variant_parsable = Ikev2NotifyPayloadVariantResponder(variant=cookie_payload)
        composed_bytes = variant_parsable.compose()

        self.assertEqual(composed_bytes, cookie_payload.compose())

    def test_round_trip(self):
        cookie_data = b'\x00\x01\x02\x03\x04\x05'
        cookie_payload = Ikev2NotifyPayloadCookie(
            flags=set(),
            protocol_id=self.protocol_id,
            type=Ikev2NotifyType.COOKIE,
            spi=bytes(),
            cookie=cookie_data
        )
        cookie_payload.next_payload = Ikev2PayloadType.NONE

        variant_parsable = Ikev2NotifyPayloadVariantResponder(variant=cookie_payload)
        composed_bytes = variant_parsable.compose()
        parsed_payload = Ikev2NotifyPayloadVariantResponder.parse_exact_size(composed_bytes)

        self.assertIsInstance(parsed_payload, Ikev2NotifyPayloadCookie)
        self.assertEqual(parsed_payload.cookie, cookie_data)  # pylint: disable=no-member
        self.assertEqual(parsed_payload.type, cookie_payload.type)
        self.assertEqual(parsed_payload.spi, cookie_payload.spi)


if __name__ == '__main__':
    unittest.main()
