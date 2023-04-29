#!/usr/bin/env python
# -*- coding: utf-8 -*-

import abc
import collections
import enum
import six

import attr

from cryptodatahub.common.exception import InvalidValue

from cryptoparser.common.base import VariantParsable
from cryptoparser.common.exception import InvalidType, NotEnoughData
from cryptoparser.common.parse import ParsableBase, ParserBinary, ComposerBinary


class OpenVpnOpCode(enum.IntEnum):
    CONTROL_V1 = 0x04
    ACK_V1 = 0x05
    HARD_RESET_CLIENT_V2 = 0x07
    HARD_RESET_SERVER_V2 = 0x08


class OpenVpnPacketWrapperTcp(ParsableBase):
    def __init__(self, payload):
        self.payload = payload

    @classmethod
    def _parse(cls, parsable):
        parser = ParserBinary(parsable)
        parser.parse_bytes('payload', 2)

        return OpenVpnPacketWrapperTcp(parser['payload']), parser.parsed_length

    def compose(self):
        composer = ComposerBinary()

        composer.compose_bytes(self.payload, 2)

        return composer.composed_bytes


@attr.s
class OpenVpnPacketBase(ParsableBase):
    HEADER_SIZE = 10

    session_id = attr.ib(validator=attr.validators.instance_of(six.integer_types))
    packet_id_array = attr.ib(
        validator=attr.validators.deep_iterable(member_validator=attr.validators.instance_of(six.integer_types))
    )
    remote_session_id = attr.ib(validator=attr.validators.optional(attr.validators.instance_of(six.integer_types)))

    @classmethod
    @abc.abstractmethod
    def get_op_code(cls):
        return NotImplementedError()  # pragma: no cover

    @classmethod
    def parse_header(cls, parsable):
        if len(parsable) < cls.HEADER_SIZE:
            raise NotEnoughData(cls.HEADER_SIZE - len(parsable))

        parser = ParserBinary(parsable)

        parser.parse_numeric('packet_type', 1)
        if parser['packet_type'] >> 3 != cls.get_op_code():
            raise InvalidType()

        parser.parse_numeric('session_id', 8)
        parser.parse_numeric('packet_id_array_length', 1)
        if parser['packet_id_array_length']:
            parser.parse_numeric_array('packet_id_array', parser['packet_id_array_length'], 4)
            parser.parse_numeric('remote_session_id', 8)

            packet_id_array = parser['packet_id_array']
            remote_session_id = parser['remote_session_id']
        else:
            packet_id_array = []
            remote_session_id = None

        return parser['session_id'], packet_id_array, remote_session_id, parser.parsed_length

    def _compose_header(self):
        composer = ComposerBinary()

        composer.compose_numeric(self.get_op_code() << 3, 1)
        composer.compose_numeric(self.session_id, 8)
        composer.compose_numeric(len(self.packet_id_array), 1)
        if self.packet_id_array:
            composer.compose_numeric_array(self.packet_id_array, 4)
            composer.compose_numeric(self.remote_session_id, 8)

        return composer.composed_bytes


@attr.s
class OpenVpnPacketControlV1(OpenVpnPacketBase):
    packet_id = attr.ib(validator=attr.validators.instance_of(six.integer_types))
    payload = attr.ib(validator=attr.validators.instance_of((bytes, bytearray)))

    @classmethod
    def get_op_code(cls):
        return OpenVpnOpCode.CONTROL_V1

    def compose(self):
        composer = ComposerBinary()

        composer.compose_numeric(self.packet_id, 4)
        composer.compose_raw(self.payload)

        return self._compose_header() + composer.composed_bytes

    @classmethod
    def _parse(cls, parsable):
        session_id, packet_id_array, remote_session_id, header_length = cls.parse_header(parsable)

        body_parser = ParserBinary(parsable[header_length:])
        body_parser.parse_numeric('packet_id', 4)
        body_parser.parse_raw('payload', body_parser.unparsed_length)

        return OpenVpnPacketControlV1(
            session_id,
            packet_id_array,
            remote_session_id,
            body_parser['packet_id'],
            body_parser['payload']
        ), header_length + body_parser.parsed_length


@attr.s(init=False)
class OpenVpnPacketAckV1(OpenVpnPacketBase):
    def __init__(self, session_id, remote_session_id, packet_id_array):
        super(OpenVpnPacketAckV1, self).__init__(session_id, packet_id_array, remote_session_id)

    @classmethod
    def get_op_code(cls):
        return OpenVpnOpCode.ACK_V1

    def compose(self):
        return self._compose_header()

    @classmethod
    def _parse(cls, parsable):
        session_id, packet_id_array, remote_session_id, header_length = cls.parse_header(parsable)

        return OpenVpnPacketAckV1(session_id, remote_session_id, packet_id_array), header_length


@attr.s(init=False)
class OpenVpnPacketHardResetClientV2(OpenVpnPacketBase):
    def __init__(self, session_id, packet_id):
        super(OpenVpnPacketHardResetClientV2, self).__init__(session_id, packet_id_array=[], remote_session_id=None)

        self.packet_id = packet_id

    @classmethod
    def get_op_code(cls):
        return OpenVpnOpCode.HARD_RESET_CLIENT_V2

    @classmethod
    def _parse(cls, parsable):
        session_id, packet_id_array, _, header_length = cls.parse_header(parsable)
        if packet_id_array:
            raise InvalidValue(packet_id_array, cls, 'packet_id_array')

        body_parser = ParserBinary(parsable[header_length:])
        body_parser.parse_numeric('packet_id', 4)

        return OpenVpnPacketHardResetClientV2(
            session_id, body_parser['packet_id']
        ), header_length + body_parser.parsed_length

    def compose(self):
        composer = ComposerBinary()

        composer.compose_numeric(self.packet_id, 4)

        return self._compose_header() + composer.composed_bytes


@attr.s(init=False)
class OpenVpnPacketHardResetServerV2(OpenVpnPacketBase):
    def __init__(self, session_id, remote_session_id, packet_id_array, packet_id):
        super(OpenVpnPacketHardResetServerV2, self).__init__(session_id, packet_id_array, remote_session_id)

        self.packet_id = packet_id

    @classmethod
    def get_op_code(cls):
        return OpenVpnOpCode.HARD_RESET_SERVER_V2

    @classmethod
    def _parse(cls, parsable):
        session_id, packet_id_array, remote_session_id, header_length = cls.parse_header(parsable)

        body_parser = ParserBinary(parsable[header_length:])
        body_parser.parse_numeric('packet_id', 4)

        return OpenVpnPacketHardResetServerV2(
            session_id,
            remote_session_id,
            packet_id_array,
            body_parser['packet_id']
        ), header_length + body_parser.parsed_length

    def compose(self):
        composer = ComposerBinary()

        composer.compose_numeric(self.packet_id, 4)

        return self._compose_header() + composer.composed_bytes


class OpenVpnPacketVariant(VariantParsable):
    _VARIANTS = collections.OrderedDict([
        (OpenVpnOpCode.ACK_V1, [OpenVpnPacketAckV1, ]),
        (OpenVpnOpCode.CONTROL_V1, [OpenVpnPacketControlV1, ]),
        (OpenVpnOpCode.HARD_RESET_CLIENT_V2, [OpenVpnPacketHardResetClientV2, ]),
        (OpenVpnOpCode.HARD_RESET_SERVER_V2, [OpenVpnPacketHardResetServerV2, ]),
    ])

    @classmethod
    def _get_variants(cls):
        return cls._VARIANTS
