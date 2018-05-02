#!/usr/bin/env python
# -*- coding: utf-8 -*-

import abc
import enum
import collections

from cryptoparser.common.base import JSONSerializable
from cryptoparser.common.exception import TooMuchData, InvalidValue
from cryptoparser.common.parse import ParserBinary, ParsableBase, ComposerBinary


class NByteParsable(ParsableBase):
    def __init__(self, value):
        if value < 0 or value >= 2 ** (8 * self.get_byte_size()):
            raise ValueError

        self.value = value

    def __int__(self):
        return self.value

    @classmethod
    def _parse(cls, parsable):
        parser = ParserBinary(parsable)

        parser.parse_numeric('value', cls.get_byte_size())

        return cls(parser['value']), cls.get_byte_size()

    def compose(self):
        composer = ComposerBinary()

        composer.compose_numeric(self.value, self.get_byte_size())

        return composer.composed_bytes

    def __repr__(self):
        return '{0:#0{1}x}'.format(self.value, self.get_byte_size() * 2 + 2)

    def __eq__(self, other):
        return self.get_byte_size() == other.get_byte_size() and self.value == other.value

    @classmethod
    def get_byte_size(cls):
        raise NotImplementedError()


class OneByteParsable(NByteParsable):
    @classmethod
    def get_byte_size(cls):
        return 1


class TwoByteParsable(NByteParsable):
    @classmethod
    def get_byte_size(cls):
        return 2


class ConditionalParsable(NByteParsable):
    def __int__(self):
        return self.value

    @classmethod
    def _parse(cls, parsable):
        parser = ParserBinary(parsable)

        parser.parse_numeric('value', cls.get_byte_size())

        cls.check_parsed(parser['value'])

        return cls(parser['value']), cls.get_byte_size()

    def compose(self):
        composer = ComposerBinary()

        composer.compose_numeric(self.value, self.get_byte_size())

        return composer.composed_bytes

    @classmethod
    @abc.abstractmethod
    def check_parsed(cls, value):
        raise NotImplementedError()


class OneByteOddParsable(ConditionalParsable):
    @classmethod
    def get_byte_size(cls):
        return 1

    @classmethod
    def check_parsed(cls, value):
        if value % 2 == 0:
            raise InvalidValue(value, OneByteOddParsable)


class TwoByteEvenParsable(ConditionalParsable):
    @classmethod
    def get_byte_size(cls):
        return 2

    @classmethod
    def check_parsed(cls, value):
        if value % 2 != 0:
            raise InvalidValue(value, TwoByteEvenParsable)


class AlwaysUnknowTypeParsable(ParsableBase):
    @classmethod
    def _parse(cls, parsable):
        raise InvalidValue(parsable, AlwaysUnknowTypeParsable)

    def compose(self):
        raise TooMuchData()


JSONSerializableEnumValue = collections.namedtuple(
    'JSONSerializableEnumValue',
    [
        'code',
    ]
)


class TestObject(object):
    pass


class JSONSerializableSimpleTypes(JSONSerializable):
    def __init__(self):
        self.int_value = 1
        self.float_value = 1.0
        self.bool_value = False
        self.str_value = 'string'
        self.none_value = None


class JSONSerializableIterables(JSONSerializable):
    def __init__(self):
        self.dict_value = dict({'value': 1})
        self.list_value = list(['value', ])
        self.tuple_value = tuple(['value', ])


class JSONSerializableEnum(JSONSerializable, enum.Enum):
    first = JSONSerializableEnumValue(
        code=0x0001,
    )
    second = JSONSerializableEnumValue(
        code=0x0002,
    )


class JSONSerializableStringEnum(JSONSerializable, enum.Enum):
    first = '1'
    second = '2'


class JSONSerializableHidden(JSONSerializable):
    def __init__(self):
        self._invisible_value = None
        self.visible_value = 'value'


class JSONSerializableUnhandled(JSONSerializable):
    def __init__(self):
        self.bytes_value = 1 + 2j


class JSONSerializableRecursive(JSONSerializable):
    def __init__(self):
        self.json_serializable_value = JSONSerializableHidden()
        self.json_serializable_in_list = list([JSONSerializableHidden(), ])
        self.json_serializable_in_tuple = tuple([JSONSerializableHidden(), ])
        self.json_serializable_in_dict = dict({'key': JSONSerializableHidden()})
