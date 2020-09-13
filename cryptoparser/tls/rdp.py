# -*- coding: utf-8 -*-

import abc
import enum
import attr

from cryptoparser.common.parse import ParsableBase, ParserBinary, ComposerBinary, ByteOrder
from cryptoparser.common.exception import NotEnoughData, InvalidValue, InvalidType


@attr.s
class TPKT(ParsableBase):
    HEADER_SIZE = 4

    version = attr.ib(validator=attr.validators.instance_of(int))
    message = attr.ib(validator=attr.validators.instance_of((bytes, bytearray)))

    @classmethod
    def _parse(cls, parsable):
        if len(parsable) < cls.HEADER_SIZE:
            raise NotEnoughData(cls.HEADER_SIZE - len(parsable))

        parser = ParserBinary(parsable)

        parser.parse_numeric('version', 1)
        if parser['version'] != 3:
            raise InvalidValue(parser['version'], TPKT, 'version')
        parser.parse_numeric('reserved', 1)
        parser.parse_numeric('packet_length', 2)

        if len(parsable) < parser['packet_length']:
            raise NotEnoughData(parser['packet_length'] - len(parsable))

        parser.parse_raw('message', parser['packet_length'] - 4)

        return TPKT(parser['version'], parser['message']), parser.parsed_length

    def compose(self):
        composer = ComposerBinary()
        composer.compose_numeric(self.version, 1)
        composer.compose_numeric(0, 1)  # reserved
        composer.compose_numeric(len(self.message) + 4, 2)
        composer.compose_raw(self.message)

        return composer.composed_bytes


class COTPType(enum.IntEnum):
    CONNECTION_REQUEST = 0xe
    CONNECTION_CONFIRM = 0xd
    DISCONNECT_REQUEST = 0x8
    DISCONNECT_CONFIRM = 0xc
    DATA = 0xf
    EXPEDITED_DATA = 0x1
    DATA_ACKNOWLEDGEMENT = 0x6
    EXPEDITED_DATA_ANOWLEDGEMENT = 0x2
    REJECT = 0x5


@attr.s
class COTPConnectionBase(ParsableBase):
    HEADER_SIZE = 7

    src_ref = attr.ib(validator=attr.validators.instance_of(int))
    user_data = attr.ib(validator=attr.validators.instance_of((bytes, bytearray)))
    dst_ref = attr.ib(default=0, validator=attr.validators.instance_of(int))
    class_option = attr.ib(default=0)

    @classmethod
    @abc.abstractmethod
    def _get_type(cls):
        raise NotImplementedError()

    @classmethod
    def _parse(cls, parsable):
        if len(parsable) < cls.HEADER_SIZE:
            raise NotEnoughData(cls.HEADER_SIZE - len(parsable))

        parser = ParserBinary(parsable)

        parser.parse_numeric('length_indicator', 1)
        if parser.unparsed_length < parser['length_indicator']:
            raise NotEnoughData(parser['length_indicator'] - parser.unparsed_length)

        parser.parse_numeric('pdu_type', 1)
        pdu_type = parser['pdu_type'] >> 4
        if pdu_type != cls._get_type():
            raise InvalidType()

        parser.parse_numeric('src_ref', 2)
        parser.parse_numeric('dst_ref', 2)
        parser.parse_numeric('class_option', 1)

        parser.parse_raw('user_data', parser['length_indicator'] - parser.parsed_length + 1)

        return COTPConnectionRequest(
            src_ref=parser['src_ref'],
            dst_ref=parser['dst_ref'],
            class_option=parser['class_option'],
            user_data=parser['user_data'],
        ), parser.parsed_length

    def compose(self):
        body_composer = ComposerBinary()

        body_composer.compose_numeric(self._get_type() << 4, 1)
        body_composer.compose_numeric(self.src_ref, 2)
        body_composer.compose_numeric(self.dst_ref, 2)
        body_composer.compose_numeric(self.class_option, 1)
        body_composer.compose_raw(self.user_data)

        body = body_composer.composed_bytes

        header_composer = ComposerBinary()
        header_composer.compose_numeric(len(body), 1)

        return header_composer.composed_bytes + body

    def __attrs_post_init__(self):
        if self.class_option != 0:
            raise InvalidValue(self.class_option, COTPConnectionRequest, 'class_option')


@attr.s
class COTPConnectionRequest(COTPConnectionBase):
    @classmethod
    def _get_type(cls):
        return COTPType.CONNECTION_REQUEST


@attr.s
class COTPConnectionConfirm(COTPConnectionBase):
    @classmethod
    def _get_type(cls):
        return COTPType.CONNECTION_CONFIRM


class RDPProtocol(enum.IntEnum):
    RDP = 0x00000000
    SSL = 0x00000001
    HYBRID = 0x00000002
    RDSTLS = 0x00000004
    HYBRID_EX = 0x00000008


class RDPNegotiationRequestFlags(enum.IntEnum):
    RESTRICTED_ADMIN_MODE_REQUIRED = 0x01
    REDIRECTED_AUTHENTICATION_MODE_REQUIRED = 0x02
    CORRELATION_INFO_PRESENT = 0x08


class RDPNegotiationResponseFlags(enum.IntEnum):
    EXTENDED_CLIENT_DATA_SUPPORTED = 0x01
    DYNVC_GFX_PROTOCOL_SUPPORTED = 0x02
    NEGRSP_FLAG_RESERVED = 0x04
    RESTRICTED_ADMIN_MODE_SUPPORTED = 0x08
    REDIRECTED_AUTHENTICATION_MODE_SUPPORTED = 0x10


class RDPPacketType(enum.IntEnum):
    NEG_REQ = 1
    NEG_RSP = 2


@attr.s
class RDPNegotiationBase(ParsableBase):
    PACKET_LENGTH = 8

    flags = attr.ib(validator=attr.validators.deep_iterable(member_validator=attr.validators.instance_of(
        (RDPNegotiationRequestFlags, RDPNegotiationResponseFlags)
        )))
    protocol = attr.ib(validator=attr.validators.deep_iterable(member_validator=attr.validators.in_(RDPProtocol)))

    @classmethod
    @abc.abstractmethod
    def _get_type(cls):
        raise NotImplementedError()

    @classmethod
    @abc.abstractmethod
    def _get_flag_type(cls):
        raise NotImplementedError()

    @classmethod
    def _parse(cls, parsable):
        if len(parsable) < cls.PACKET_LENGTH:
            raise NotEnoughData(cls.PACKET_LENGTH - len(parsable))

        parser = ParserBinary(parsable, ByteOrder.LITTLE_ENDIAN)

        parser.parse_numeric('type', 1, RDPPacketType)
        if parser['type'] != cls._get_type():
            raise InvalidType()
        parser.parse_numeric_flags('flags', 1, cls._get_flag_type())
        parser.parse_numeric('length', 2)
        if parser['length'] != cls.PACKET_LENGTH:
            raise InvalidValue(parser['length'], cls, 'packet length')
        parser.parse_numeric_flags('protocol', 4, RDPProtocol)

        return cls(parser['flags'], parser['protocol']), parser.parsed_length

    def compose(self):
        composer = ComposerBinary(ByteOrder.LITTLE_ENDIAN)

        composer.compose_numeric(self._get_type(), 1)
        composer.compose_numeric_flags(self.flags, 1)
        composer.compose_numeric(self.PACKET_LENGTH, 2)
        composer.compose_numeric_flags(self.protocol, 4)

        return composer.composed_bytes


@attr.s
class RDPNegotiationRequest(RDPNegotiationBase):
    @classmethod
    def _get_type(cls):
        return RDPPacketType.NEG_REQ

    @classmethod
    def _get_flag_type(cls):
        return RDPNegotiationRequestFlags


@attr.s
class RDPNegotiationResponse(RDPNegotiationBase):
    @classmethod
    def _get_type(cls):
        return RDPPacketType.NEG_RSP

    @classmethod
    def _get_flag_type(cls):
        return RDPNegotiationResponseFlags
