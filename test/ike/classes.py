# SPDX-License-Identifier: MPL-2.0
# -*- coding: utf-8 -*-

from cryptodatahub.ike.algorithm import (
    Ikev1PayloadType,
    Ikev2PayloadType,
    Ikev2NotifyType,
    Ikev2ProtocolId,
    Ikev2TransformType,
    Ikev2PseudorandomFunction,
)
from cryptoparser.common.parse import ComposerBinary
from cryptoparser.ike.ikev1 import Ikev1PayloadBase
from cryptoparser.ike.ikev2 import (
    Ikev2PayloadBase,
    Ikev2PayloadNotifyBase,
    Ikev2PayloadNotifyNoData,
    Transform,
    TransformNextPayload,
)


class Ikev1PayloadBaseTest(Ikev1PayloadBase):
    """Concrete implementation of Ikev1PayloadBase for testing."""

    def __init__(self, test_data):
        super().__init__()
        self.test_data = test_data
        self.next_payload = Ikev1PayloadType.NONE

    @classmethod
    def get_payload_type(cls):
        return Ikev1PayloadType.NONE

    @classmethod
    def _parse(cls, parsable):
        parser = cls._parse_header(parsable)
        test_data_length = parser['payload_length'] - cls.HEADER_SIZE
        parser.parse_raw('test_data', test_data_length)

        payload = cls(
            test_data=parser['test_data']
        )
        payload.next_payload = parser['next_payload']

        return payload, parser.parsed_length

    def compose(self):
        composer_payload = ComposerBinary()
        composer_payload.compose_raw(self.test_data)

        composer_header = self.compose_header(composer_payload.composed_length)
        return composer_header.composed_bytes + composer_payload.composed_bytes


class Ikev2PayloadBaseTest(Ikev2PayloadBase):
    """Concrete implementation of Ikev2PayloadBase for testing."""

    def __init__(self, flags, test_data):
        super().__init__(flags=flags)
        self.test_data = test_data
        self.next_payload = Ikev2PayloadType.NONE

    @classmethod
    def get_payload_type(cls):
        return Ikev2PayloadType.NONE

    @classmethod
    def _parse(cls, parsable):
        parser = cls._parse_header(parsable)
        test_data_length = parser['payload_length'] - cls.HEADER_SIZE
        parser.parse_raw('test_data', test_data_length)

        payload = cls(
            flags=parser['flags'],
            test_data=parser['test_data']
        )
        payload.next_payload = parser['next_payload']

        return payload, parser.parsed_length

    def compose(self):
        composer_payload = ComposerBinary()
        composer_payload.compose_raw(self.test_data)

        composer_header = self.compose_header(composer_payload.composed_length)
        return composer_header.composed_bytes + composer_payload.composed_bytes


class Ikev2PayloadNotifyNoDataTest(Ikev2PayloadNotifyNoData):
    """Concrete implementation of Ikev2PayloadNotifyNoData for testing."""

    def __init__(self, flags, protocol_id, notify_type, spi):
        super().__init__(flags=flags, protocol_id=protocol_id, type=notify_type, spi=spi)
        self.next_payload = Ikev2PayloadType.NONE

    @classmethod
    def _get_message_type(cls):
        return Ikev2NotifyType.AUTHENTICATION_FAILED

    @classmethod
    def _parse(cls, parsable):
        parser = cls._parse_header(parsable)

        parser.parse_numeric_enum_coded('protocol_id', Ikev2ProtocolId)
        parser.parse_numeric('spi_size', 1)
        cls._parse_type(parser, 'type')

        if parser['spi_size'] > 0:
            parser.parse_raw('spi', parser['spi_size'])
            spi = parser['spi']
        else:
            spi = bytes()

        del parser['spi_size']
        if 'spi' in parser:
            del parser['spi']

        notification_data_length = parser['payload_length'] - (cls.HEADER_SIZE + 4)

        cls._parse_data(parser, notification_data_length)

        next_payload = parser['next_payload']
        del parser['next_payload']
        del parser['payload_length']

        payload = cls(
            flags=parser['flags'],
            protocol_id=parser['protocol_id'],
            notify_type=parser['type'],
            spi=spi,
        )
        payload.next_payload = next_payload

        return payload, parser.parsed_length


class Ikev2PayloadNotifyBaseTest(Ikev2PayloadNotifyBase):
    """Concrete implementation of Ikev2PayloadNotifyBase for testing."""

    def __init__(  # pylint: disable=too-many-arguments,too-many-positional-arguments
        self, flags, protocol_id, notify_type, spi, test_data
    ):
        super().__init__(flags=flags, protocol_id=protocol_id, type=notify_type, spi=spi)
        self.test_data = test_data
        self.next_payload = Ikev2PayloadType.NONE

    @classmethod
    def _parse_type(cls, parser, name):
        parser.parse_numeric_enum_coded(name, Ikev2NotifyType)

    @classmethod
    def _parse_data(cls, parser, notification_data_length):
        if notification_data_length > 0:
            parser.parse_raw('test_data', notification_data_length)
        else:
            # For empty data, we need to handle it differently since parser is not a dict
            pass

    def _compose_data(self, composer):
        composer.compose_raw(self.test_data)

    @classmethod
    def _parse(cls, parsable):
        parser = cls._parse_header(parsable)

        parser.parse_numeric_enum_coded('protocol_id', Ikev2ProtocolId)
        parser.parse_numeric('spi_size', 1)
        cls._parse_type(parser, 'type')

        if parser['spi_size'] > 0:
            parser.parse_raw('spi', parser['spi_size'])
            spi = parser['spi']
        else:
            spi = bytes()

        del parser['spi_size']
        if 'spi' in parser:
            del parser['spi']

        notification_data_length = parser['payload_length'] - (cls.HEADER_SIZE + 4) - len(spi)

        cls._parse_data(parser, notification_data_length)

        next_payload = parser['next_payload']
        del parser['next_payload']
        del parser['payload_length']

        test_data = parser.get('test_data', b'')
        if 'test_data' in parser:
            del parser['test_data']

        payload = cls(
            flags=parser['flags'],
            protocol_id=parser['protocol_id'],
            notify_type=parser['type'],
            spi=spi,
            test_data=test_data,
        )
        payload.next_payload = next_payload

        return payload, parser.parsed_length


class TransformTest(Transform):
    """Concrete implementation of Transform base class for testing."""

    def __init__(self, transform_id):
        super().__init__(transform_id=transform_id)
        self.next_payload = TransformNextPayload.LAST

    @classmethod
    def get_transform_type(cls):
        return Ikev2TransformType.PRF

    @classmethod
    def _get_transform_id_class(cls):
        return Ikev2PseudorandomFunction

    @classmethod
    def _parse(cls, parsable):
        parser = cls._parse_header(parsable)

        transform = cls(
            transform_id=parser['transform_id'],
        )
        transform.next_payload = parser['next_payload']

        return transform, parser.parsed_length

    def compose(self):
        return self.compose_header(transform_length=0).composed_bytes
