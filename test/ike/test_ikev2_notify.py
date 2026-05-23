# SPDX-License-Identifier: MPL-2.0

import collections
import unittest

from cryptodatahub.common.exception import InvalidValue
from cryptodatahub.ike.algorithm import Ikev2NotifyType, Ikev2ProtocolId

from cryptoparser.common.exception import NotEnoughData, InvalidType
from cryptoparser.ike.ikev2 import (
    Ikev2PayloadFlags,
    Ikev2PayloadType,
    Ikev2PayloadNotifyUnparsed,
    Ikev2NotifyPayloadCookie,
    Ikev2NotifyPayloadSetWindowSize,
    Ikev2NotifyPayloadNatDetectionSourceIp,
    Ikev2NotifyPayloadNatDetectionDestinationIp,
    Ikev2NotifyPayloadVariantResponder
)

from . import classes as _ike_test_classes
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
            spi=b'',
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
        self.assertEqual(parsed_minimal.spi, b'')
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
                spi=b'',
                test_data=b''
            )

    def test_error_invalid_notify_type(self):
        with self.assertRaises(TypeError):
            Ikev2PayloadNotifyBaseTest(
                flags=set(),
                protocol_id=self.protocol_id,
                notify_type="invalid",
                spi=b'',
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
        with self.assertRaises(InvalidType):
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
                spi=b'',
                data=b'\x00\x01\x02\x03'
            )
            self.assertEqual(payload.type, notify_type)
            self.assertEqual(payload.data, b'\x00\x01\x02\x03')

    def test_raw_data_storage(self):
        payload = Ikev2PayloadNotifyUnparsed(
            flags=set(),
            protocol_id=self.protocol_id,
            type=self.notify_type,
            spi=b'',
            data=self.data
        )
        self.assertEqual(payload.data, self.data)

        different_data = b'\xff\xfe\xfd\xfc'
        payload_2 = Ikev2PayloadNotifyUnparsed(
            flags=set(),
            protocol_id=self.protocol_id,
            type=self.notify_type,
            spi=b'',
            data=different_data
        )
        self.assertEqual(payload_2.data, different_data)

    def test_round_trip_data_preservation(self):
        payload_no_spi = Ikev2PayloadNotifyUnparsed(
            flags=set(),
            protocol_id=self.protocol_id,
            type=self.notify_type,
            spi=b'',
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
    _PROTOCOL_ID = Ikev2ProtocolId.IKE
    _COOKIE_DATA = b'\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f'

    def test_get_message_type(self):
        # pylint: disable=protected-access
        self.assertEqual(Ikev2NotifyPayloadCookie._get_message_type(), Ikev2NotifyType.COOKIE)

    def test_cookie_data_storage(self):
        payload = Ikev2NotifyPayloadCookie(
            flags=set(),
            protocol_id=self._PROTOCOL_ID,
            type=Ikev2NotifyType.COOKIE,
            spi=b'',
            cookie=self._COOKIE_DATA
        )
        self.assertEqual(payload.cookie, self._COOKIE_DATA)

        different_cookie = b'\xff\xfe\xfd\xfc\xfb\xfa'
        payload_2 = Ikev2NotifyPayloadCookie(
            flags=set(),
            protocol_id=self._PROTOCOL_ID,
            type=Ikev2NotifyType.COOKIE,
            spi=b'',
            cookie=different_cookie
        )
        self.assertEqual(payload_2.cookie, different_cookie)

    def test_round_trip_cookie_preservation(self):
        cookie_payload = Ikev2NotifyPayloadCookie(
            flags=set(),
            protocol_id=self._PROTOCOL_ID,
            type=Ikev2NotifyType.COOKIE,
            spi=b'',
            cookie=self._COOKIE_DATA
        )
        cookie_payload.next_payload = Ikev2PayloadType.NONE
        composed_bytes = cookie_payload.compose()
        parsed_payload: Ikev2NotifyPayloadCookie = Ikev2NotifyPayloadCookie.parse_exact_size(composed_bytes)

        self.assertEqual(parsed_payload.cookie, cookie_payload.cookie)  # pylint: disable=no-member
        self.assertEqual(parsed_payload.type, cookie_payload.type)
        self.assertEqual(parsed_payload.spi, cookie_payload.spi)


class TestIkev2NotifyPayloadSetWindowSize(unittest.TestCase):
    _PROTOCOL_ID = Ikev2ProtocolId.IKE
    _WINDOW_SIZE = 5

    def test_get_message_type(self):
        # pylint: disable=protected-access
        self.assertEqual(Ikev2NotifyPayloadSetWindowSize._get_message_type(), Ikev2NotifyType.SET_WINDOW_SIZE)

    def test_window_size_storage(self):
        payload = Ikev2NotifyPayloadSetWindowSize(
            flags=set(),
            protocol_id=self._PROTOCOL_ID,
            type=Ikev2NotifyType.SET_WINDOW_SIZE,
            spi=b'',
            window_size=self._WINDOW_SIZE
        )
        self.assertEqual(payload.window_size, self._WINDOW_SIZE)

        different_window_size = 10
        payload_2 = Ikev2NotifyPayloadSetWindowSize(
            flags=set(),
            protocol_id=self._PROTOCOL_ID,
            type=Ikev2NotifyType.SET_WINDOW_SIZE,
            spi=b'',
            window_size=different_window_size
        )
        self.assertEqual(payload_2.window_size, different_window_size)

    def test_round_trip_window_size_preservation(self):
        window_size_payload = Ikev2NotifyPayloadSetWindowSize(
            flags=set(),
            protocol_id=self._PROTOCOL_ID,
            type=Ikev2NotifyType.SET_WINDOW_SIZE,
            spi=b'',
            window_size=self._WINDOW_SIZE
        )
        window_size_payload.next_payload = Ikev2PayloadType.NONE
        composed_bytes = window_size_payload.compose()
        parsed_payload: Ikev2NotifyPayloadSetWindowSize = \
            Ikev2NotifyPayloadSetWindowSize.parse_exact_size(composed_bytes)

        self.assertEqual(parsed_payload.window_size, window_size_payload.window_size)  # pylint: disable=no-member
        self.assertEqual(parsed_payload.type, window_size_payload.type)
        self.assertEqual(parsed_payload.spi, window_size_payload.spi)

    def test_error_invalid_notification_data_length(self):
        wrong_length_bytes = bytes.fromhex(
            '00'      # next_payload = NONE
            '00'      # flags = 0
            '000b'    # payload_length = 11 (8 header + 3 data bytes)
            '01'      # protocol_id = IKE
            '00'      # spi_size = 0
            '4001'    # notify_type = SET_WINDOW_SIZE
            'aaaaaa'  # 3 bytes data (must be exactly 4)
        )
        with self.assertRaises(InvalidValue):
            Ikev2NotifyPayloadSetWindowSize.parse_exact_size(wrong_length_bytes)


class TestIkev2NotifyPayloadNatDetectionSourceIp(_ike_test_classes.Ikev2NotifyPayloadNatDetectionBaseTest):
    _NOTIFY_TYPE = Ikev2NotifyType.NAT_DETECTION_SOURCE_IP
    _PAYLOAD_CLASS = Ikev2NotifyPayloadNatDetectionSourceIp
    _NOTIFY_TYPE_BYTES = b'\x40\x04'


class TestIkev2NotifyPayloadNatDetectionDestinationIp(_ike_test_classes.Ikev2NotifyPayloadNatDetectionBaseTest):
    _NOTIFY_TYPE = Ikev2NotifyType.NAT_DETECTION_DESTINATION_IP
    _PAYLOAD_CLASS = Ikev2NotifyPayloadNatDetectionDestinationIp
    _NOTIFY_TYPE_BYTES = b'\x40\x05'


class TestIkev2NotifyPayloadVariantResponder(unittest.TestCase):
    _PROTOCOL_ID = Ikev2ProtocolId.IKE

    def test_parse_other_notify_type(self):
        other_notify = Ikev2PayloadNotifyUnparsed(
            flags=set(),
            protocol_id=self._PROTOCOL_ID,
            type=Ikev2NotifyType.AUTHENTICATION_FAILED,
            spi=b'',
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
            protocol_id=self._PROTOCOL_ID,
            type=Ikev2NotifyType.COOKIE,
            spi=b'',
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
            protocol_id=self._PROTOCOL_ID,
            type=Ikev2NotifyType.COOKIE,
            spi=b'',
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
