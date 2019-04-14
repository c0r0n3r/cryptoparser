# -*- coding: utf-8 -*-

import abc
import enum
import attr
import six

from cryptoparser.common.base import Serializable, TwoByteEnumParsable, TwoByteEnumComposer
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


@attr.s
class SerializableEnumValue(object):
    code = attr.ib(validator=attr.validators.instance_of(int))


class TestObject(object):
    pass


class SerializableSimpleTypes(Serializable):
    def __init__(self):
        self.UPPER = six.u('upper')  # pylint: disable=invalid-name
        self.int_value = 1
        self.float_value = 1.0
        self.bool_value = False
        self.str_value = six.u('string')
        self.none_value = None


class SerializableIterables(Serializable):
    def __init__(self):
        self.dict_value = dict({'value': 1})
        self.list_value = list(['value', ])
        self.tuple_value = tuple(['value', ])


class SerializableEnumFactory(TwoByteEnumParsable):
    @classmethod
    def get_enum_class(cls):
        return SerializableEnum

    @abc.abstractmethod
    def compose(self):
        raise NotImplementedError()


class SerializableEnum(Serializable, TwoByteEnumComposer):
    first = SerializableEnumValue(
        code=0x0001,
    )
    second = SerializableEnumValue(
        code=0x0002,
    )


class SerializableStringEnum(enum.Enum):
    first = '1'
    second = '2'


class SerializableEnums(Serializable):
    def __init__(self):
        self.param_enum = SerializableEnum.first
        self.string_enum = SerializableStringEnum.second


class SerializableHidden(Serializable):
    def __init__(self):
        self._invisible_value = None
        self.visible_value = 'value'


class SerializableSingle(Serializable):
    def _asdict(self):
        return 'single'


class SerializableUnhandled(Serializable):
    def __init__(self):
        self.complex_number = 1 + 2j


@attr.s
class SerializableHumanReadable(Serializable):
    value = attr.ib(default='value', metadata={'human_readable_name': 'Human Readable Name'})


class SerializableRecursive(Serializable):
    def __init__(self):
        self.json_serializable_hidden = SerializableHidden()
        self.json_serializable_single = SerializableSingle()
        self.json_serializable_in_list = list([SerializableHidden(), SerializableSingle()])
        self.json_serializable_in_tuple = tuple([SerializableHidden(), SerializableSingle()])
        self.json_serializable_in_dict = dict({'key1': SerializableHidden(), 'key2': SerializableSingle()})


class SerializableEmptyValues(Serializable):
    def __init__(self):
        self.value = None
        self.list = list()
        self.tuple = tuple()
        self.dict = dict()


class FlagEnum(enum.IntEnum):
    ONE = 1
    TWO = 2
    FOUR = 4
    EIGHT = 8
