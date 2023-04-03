# -*- coding: utf-8 -*-

import abc
import enum
import random

import attr

from cryptodatahub.common.exception import InvalidValue
from cryptodatahub.common.types import CryptoDataEnumCodedBase
from cryptodatahub.tls.algorithm import TlsGreaseOneByte, TlsGreaseTwoByte

from cryptoparser.common.base import ParsableBase
from cryptoparser.common.parse import ParserBinary, ComposerBinary


class TlsInvalidType(enum.IntEnum):
    GREASE = 0
    UNKNOWN = 1


@attr.s
class TlsInvalidTypeParamsBase(object):
    code = attr.ib(validator=attr.validators.instance_of(int))
    value_type = attr.ib(validator=attr.validators.in_(TlsInvalidType))

    @classmethod
    def get_code_size(cls):
        raise NotImplementedError()


class TlsInvalidTypeParamsOneByte(TlsInvalidTypeParamsBase):
    @classmethod
    def get_code_size(cls):
        return 1


class TlsInvalidTypeParamsTwoByte(TlsInvalidTypeParamsBase):
    @classmethod
    def get_code_size(cls):
        return 2


@attr.s
class TlsInvalidTypeBase(ParsableBase):
    code = attr.ib(validator=attr.validators.instance_of((int, CryptoDataEnumCodedBase)))
    value = attr.ib(init=False, validator=attr.validators.instance_of(TlsInvalidTypeParamsBase))

    def __attrs_post_init__(self):
        if isinstance(self.code, self.get_grease_enum()):
            value_type = TlsInvalidType.GREASE
            self.code = self.code.value.code
        elif isinstance(self.code, CryptoDataEnumCodedBase):
            value_type = TlsInvalidType.UNKNOWN
            self.code = self.code.value.code
        else:
            try:
                self.code = self.get_grease_enum().from_code(self.code).value.code
                value_type = TlsInvalidType.GREASE
            except InvalidValue:
                value_type = TlsInvalidType.UNKNOWN
        self.value = self.get_param_class()(self.code, value_type)

    @classmethod
    @abc.abstractmethod
    def get_param_class(cls):
        raise NotImplementedError()

    @classmethod
    @abc.abstractmethod
    def get_grease_enum(cls):
        raise NotImplementedError()

    @classmethod
    def get_byte_num(cls):
        return cls.get_param_class().get_code_size()

    @classmethod
    def _parse(cls, parsable):
        parser = ParserBinary(parsable)
        parser.parse_numeric('code', cls.get_byte_num())

        code = parser['code']
        return cls(code), parser.parsed_length

    def compose(self):
        composer = ComposerBinary()

        composer.compose_numeric(self.code, self.get_byte_num())

        return composer.composed_bytes

    @classmethod
    def from_random(cls):
        grease_enum_type = cls.get_grease_enum()

        return cls(random.choice(list(grease_enum_type)))


class TlsInvalidTypeOneByte(TlsInvalidTypeBase):
    @classmethod
    def get_param_class(cls):
        return TlsInvalidTypeParamsOneByte

    @classmethod
    def get_grease_enum(cls):
        return TlsGreaseOneByte


class TlsInvalidTypeTwoByte(TlsInvalidTypeBase):
    @classmethod
    def get_param_class(cls):
        return TlsInvalidTypeParamsTwoByte

    @classmethod
    def get_grease_enum(cls):
        return TlsGreaseTwoByte
