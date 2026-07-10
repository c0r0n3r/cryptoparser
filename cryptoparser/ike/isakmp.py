# SPDX-License-Identifier: MPL-2.0
"""ISAKMP header parser."""

import enum
import typing

import attr

from cryptodatahub.ike.algorithm import Ikev1PayloadType, Ikev2PayloadType, Ikev1ExchangeType, Ikev2ExchangeType
from cryptodatahub.ike.version import IkeVersion

from cryptoparser.common.parse import ParsableBase, ParserBinary, ComposerBinary
from cryptoparser.common.exception import NotEnoughData, InvalidType
from cryptoparser.ike.version import IsakmpProtocolVersion
from cryptoparser.ike.ikev1 import (
    Ikev1PayloadBase,
    IKEV1_PAYLOAD_CLASSES_BY_TYPE,
)
from cryptoparser.ike.ikev2 import (
    Ikev2PayloadBase,
    IKEV2_PAYLOAD_CLASSES_BY_TYPE,
)


class IsakmpFlags(enum.IntFlag):
    """ISAKMP flags."""
    ENCRYPTION = 1 << 0
    COMMIT = 1 << 1
    AUTHENTICATION_ONLY = 1 << 2
    INITIATOR = 1 << 3
    VERSION = 1 << 4
    RESPONSE = 1 << 5


@attr.s
class IsakmpMessage(ParsableBase):
    """ISAKMP message parser.

    .. code-block:: text

                        1                   2                   3
         0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        |                       IKE SA Initiator's SPI                  |
        |                                                               |
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        |                       IKE SA Responder's SPI                  |
        |                                                               |
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        |  Next Payload | MjVer | MnVer | Exchange Type |     Flags     |
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        |                          Message ID                           |
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        |                            Length                             |
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        |                       Payload Data (variable)                 |
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

    :ivar initiator_spi: Initiator SPI
    :ivar responder_spi: Responder SPI
    :ivar exchange_type: Exchange Type
    :ivar flags: Flags
    :ivar message_id: Message ID
    :ivar payloads: Payloads
    :ivar version: Version
    """
    HEADER_SIZE = 28

    version: IsakmpProtocolVersion = attr.ib(validator=attr.validators.instance_of(IsakmpProtocolVersion))
    initiator_spi: int = attr.ib(validator=attr.validators.and_(
        attr.validators.instance_of(int),
        attr.validators.ge(0),
        attr.validators.lt(2**64)
    ))
    responder_spi: int = attr.ib(validator=attr.validators.and_(
        attr.validators.instance_of(int),
        attr.validators.ge(0),
        attr.validators.lt(2**64)))
    exchange_type: typing.Union[Ikev1ExchangeType, Ikev2ExchangeType] = attr.ib(
        validator=attr.validators.instance_of((Ikev1ExchangeType, Ikev2ExchangeType))
    )
    flags: list[IsakmpFlags] = attr.ib(validator=attr.validators.deep_iterable(
        member_validator=attr.validators.instance_of(IsakmpFlags)
    ))
    message_id: int = attr.ib(validator=attr.validators.and_(
        attr.validators.instance_of(int),
        attr.validators.ge(0),
        attr.validators.lt(2**32)
    ))
    payloads: list[typing.Union[Ikev1PayloadBase, Ikev2PayloadBase]] = attr.ib(
        validator=attr.validators.deep_iterable(
            member_validator=attr.validators.instance_of((Ikev1PayloadBase, Ikev2PayloadBase))
        )
    )

    def get_payload_by_type(
        self, payload_type: typing.Union[Ikev1PayloadType, Ikev2PayloadType]
    ) -> typing.Union[Ikev1PayloadBase, Ikev2PayloadBase]:
        for payload in self.payloads:
            if payload.get_payload_type() == payload_type:
                return payload

        raise KeyError(payload_type)

    @classmethod
    def _parse(cls, parsable):
        if len(parsable) < cls.HEADER_SIZE:
            raise NotEnoughData(cls.HEADER_SIZE - len(parsable))

        parser = ParserBinary(parsable)
        parser.parse_numeric('initiator_spi', 8)
        parser.parse_numeric('responder_spi', 8)
        parser.parse_raw('next_payload', 1)
        parser.parse_parsable('version', IsakmpProtocolVersion)
        if parser['version'].major == IkeVersion.V1:
            next_payload_type = Ikev1PayloadType
            parser.parse_numeric_enum_coded('exchange_type', Ikev1ExchangeType)
        elif parser['version'].major == IkeVersion.V2:
            next_payload_type = Ikev2PayloadType
            parser.parse_numeric_enum_coded('exchange_type', Ikev2ExchangeType)
        else:
            raise NotImplementedError(parser['version'])

        next_payload_parser = ParserBinary(parser['next_payload'])
        next_payload_parser.parse_numeric_enum_coded('value', next_payload_type)
        next_payload = next_payload_parser['value']

        parser.parse_numeric_flags('flags', 1, IsakmpFlags)
        parser.parse_numeric('message_id', 4)
        parser.parse_numeric('length', 4)

        version = parser['version']
        if version.major == IkeVersion.V1:
            payload_classes = IKEV1_PAYLOAD_CLASSES_BY_TYPE
            payload_none = Ikev1PayloadType.NONE
        elif version.major == IkeVersion.V2:
            payload_classes = IKEV2_PAYLOAD_CLASSES_BY_TYPE
            payload_none = Ikev2PayloadType.NONE
        else:
            raise NotImplementedError(version)

        payloads = []
        parser_payload = ParserBinary(parsable[parser.parsed_length:parser['length']])
        while parser_payload.unparsed_length > 0 and next_payload != payload_none:
            if next_payload not in payload_classes:
                raise InvalidType(next_payload)
            payload_class = payload_classes[next_payload]
            parser_payload.parse_parsable('payload', payload_class)

            payload = parser_payload['payload']
            payloads.append(payload)

            next_payload = payload.next_payload

        return cls(
            initiator_spi=parser['initiator_spi'],
            responder_spi=parser['responder_spi'],
            version=parser['version'],
            exchange_type=parser['exchange_type'],
            flags=parser['flags'],
            message_id=parser['message_id'],
            payloads=payloads,
        ), parser.parsed_length + parser_payload.parsed_length

    def compose(self):
        header_composer = ComposerBinary()

        header_composer.compose_numeric(self.initiator_spi, 8)
        header_composer.compose_numeric(self.responder_spi, 8)

        if self.version.major == IkeVersion.V1:
            payload_none = Ikev1PayloadType.NONE
            payload_type_security_association = (
                self.payloads[0].get_payload_type()
                if self.payloads
                else payload_none
            )
        elif self.version.major == IkeVersion.V2:
            payload_none = Ikev2PayloadType.NONE
            # First payload can be a cookie notification payload
            payload_type_security_association = self.payloads[0].get_payload_type()
        else:
            raise NotImplementedError(self.version)

        payload_composer = ComposerBinary()
        for i, payload in enumerate(self.payloads):
            payload.next_payload = (
                payload_none
                if i == len(self.payloads) - 1
                else self.payloads[i + 1].get_payload_type()
            )
            payload_composer.compose_parsable(payload)

        header_composer.compose_numeric_enum_coded(payload_type_security_association if self.payloads else payload_none)
        header_composer.compose_parsable(self.version)
        header_composer.compose_numeric_enum_coded(self.exchange_type)
        header_composer.compose_numeric_flags(self.flags, 1)
        header_composer.compose_numeric(self.message_id, 4)
        header_composer.compose_numeric(self.HEADER_SIZE + payload_composer.composed_length, 4)

        return header_composer.composed_bytes + payload_composer.composed_bytes
