# -*- coding: utf-8 -*-

import abc
import enum
import attr

from cryptoparser.common.base import ParsableBase
from cryptoparser.common.parse import ParserBinary, ComposerBinary


class TlsInvalidType(enum.IntEnum):
    GREASE = 0
    UNKNOWN = 1


@attr.s
class TlsInvalidTypeParams(object):
    code = attr.ib(validator=attr.validators.instance_of(int))
    value_type = attr.ib(validator=attr.validators.in_(TlsInvalidType))


@attr.s
class TlsInvalidTypeBase(ParsableBase):
    code = attr.ib(validator=attr.validators.instance_of(int))
    value = attr.ib(init=False, validator=attr.validators.instance_of(TlsInvalidTypeParams))

    def __attrs_post_init__(self):
        if isinstance(self.code, self.get_grease_enum()):
            value_type = TlsInvalidType.GREASE
            self.code = self.code.value
        elif self.code in set(self.get_grease_enum()):
            value_type = TlsInvalidType.GREASE
        else:
            value_type = TlsInvalidType.UNKNOWN
        self.value = TlsInvalidTypeParams(self.code, value_type)

    @classmethod
    @abc.abstractmethod
    def get_byte_num(cls):
        raise NotImplementedError()

    @classmethod
    @abc.abstractmethod
    def get_grease_enum(cls):
        raise NotImplementedError()

    @classmethod
    def _parse(cls, parsable):
        parser = ParserBinary(parsable)
        parser.parse_numeric('code', cls.get_byte_num())

        code = parser['code']
        return cls(code), parser.parsed_length

    def compose(self):
        composer = ComposerBinary()

        composer.compose_numeric(self.value.code, self.get_byte_num())

        return composer.composed_bytes


class TlsInvalidTypeOneByte(TlsInvalidTypeBase):
    @classmethod
    def get_byte_num(cls):
        return 1

    @classmethod
    def get_grease_enum(cls):
        return TlsGreaseOneByte


class TlsInvalidTypeTwoByte(TlsInvalidTypeBase):
    @classmethod
    def get_byte_num(cls):
        return 2

    @classmethod
    def get_grease_enum(cls):
        return TlsGreaseTwoByte


class TlsGreaseOneByte(enum.IntEnum):
    GREASE_0B = 0x0b
    GREASE_2A = 0x2a
    GREASE_49 = 0x49
    GREASE_68 = 0x68
    GREASE_87 = 0x87
    GREASE_A6 = 0xa6
    GREASE_C5 = 0xc5
    GREASE_E4 = 0xe4


class TlsGreaseTwoByte(enum.IntEnum):
    GREASE_0A0A = 0x0a0a
    GREASE_1A1A = 0x1a1a
    GREASE_2A2A = 0x2a2a
    GREASE_3A3A = 0x3a3a
    GREASE_4A4A = 0x4a4a
    GREASE_5A5A = 0x5a5a
    GREASE_6A6A = 0x6a6a
    GREASE_7A7A = 0x7a7a
    GREASE_8A8A = 0x8a8a
    GREASE_9A9A = 0x9a9a
    GREASE_AAAA = 0xaaaa
    GREASE_BABA = 0xbaba
    GREASE_CACA = 0xcaca
    GREASE_DADA = 0xdada
    GREASE_EAEA = 0xeaea
    GREASE_FAFA = 0xfafa
