# -*- coding: utf-8 -*-

import abc
import collections
import enum
import json
import attr
import six

from cryptoparser.common.base import (
    ListParamParsable,
    ListParsable,
    ParsableBase,
    ParserBinary,
    ComposerBinary,
    Serializable,
    StringEnumParsable,
    TwoByteEnumComposer,
    TwoByteEnumParsable,
    VariantParsable
)
from cryptoparser.common.exception import TooMuchData, InvalidValue, InvalidType
from cryptoparser.common.parse import ParserCRLF


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


class AlwaysInvalidTypeParsable(ParsableBase):
    @classmethod
    def _parse(cls, parsable):
        raise InvalidType()

    def compose(self):
        raise TooMuchData()


class AlwaysInvalidTypeVariantParsable(VariantParsable):
    @classmethod
    def _get_variants(cls):
        return collections.OrderedDict([
            (AlwaysInvalidTypeParsable, (AlwaysInvalidTypeParsable, ))
        ])


class SerializableEnumVariantParsable(VariantParsable):
    @classmethod
    def _get_variants(cls):
        return collections.OrderedDict([
            (SerializableEnum, (SerializableEnum, ))
        ])


class AlwaysTestStringComposer(ParsableBase):
    def __eq__(self, other):
        return isinstance(other, AlwaysTestStringComposer)

    @classmethod
    def _parse(cls, parsable):
        if parsable[:4] != b'test':
            raise InvalidValue(parsable, cls)

        return AlwaysTestStringComposer(), 4

    def compose(self):
        return b'test'


@attr.s
class SerializableEnumValue(Serializable):
    code = attr.ib(validator=attr.validators.instance_of(int))

    def as_json(self):
        return json.dumps({'code': self.code})

    def _as_markdown(self, level):
        return False, self.code


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


class SerializableEnum(TwoByteEnumComposer):
    FIRST = SerializableEnumValue(
        code=0x0001,
    )
    SECOND = SerializableEnumValue(
        code=0x0002,
    )


class SerializableStringEnum(enum.Enum):
    FIRST = '1'
    SECOND = '2'


class SerializableEnums(Serializable):
    def __init__(self):
        self.param_enum = SerializableEnum.FIRST
        self.string_enum = SerializableStringEnum.SECOND


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
    attr_2 = attr.ib(default='value 2', metadata={'human_readable_name': 'Human Readable Name 2'})
    attr_1 = attr.ib(default='value 1', metadata={'human_readable_name': 'Human Readable Name 1'})


@attr.s
class SerializableAttributeOrder(Serializable):
    attr_b = attr.ib(default='b')
    attr_a = attr.ib(default='a')


class Class(object):
    def __init__(self):
        self.attr_b = 'b'
        self.attr_a = 'a'


@attr.s
class ClassAttr(object):
    attr_b = attr.ib(default='b')
    attr_a = attr.ib(default='a')


class ClassAsDict(object):
    def __init__(self):
        self.attr_a = 'a'
        self.attr_b = 'b'

    def _asdict(self):
        return collections.OrderedDict([
            ('attr_b', self.attr_b),
            ('attr_a', self.attr_a),
        ])


@attr.s
class ClassAttrAsDict(object):
    attr_a = attr.ib(default='a')
    attr_b = attr.ib(default='b')

    def _asdict(self):
        return collections.OrderedDict([
            ('attr_b', self.attr_b),
            ('attr_a', self.attr_a),
        ])


class SerializableRecursive(Serializable):  # pylint: disable=too-many-instance-attributes
    def __init__(self):
        self.json_object = Class()
        self.json_attr_object = ClassAttr()
        self.json_attr_as_dict = ClassAttrAsDict()
        self.json_asdict_object = ClassAsDict()
        self.json_serializable_hidden = SerializableHidden()
        self.json_serializable_single = 'single'
        self.json_serializable_in_list = list([SerializableHidden(), 'single'])
        self.json_serializable_in_tuple = tuple([SerializableHidden(), 'single'])
        self.json_serializable_in_dict = dict({'key1': SerializableHidden(), 'key2': 'single'})


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


@attr.s
class StringEnumParams(object):
    code = attr.ib()

    def _check_code(self, code):
        if code != self.code:
            raise InvalidType()


class StringEnum(StringEnumParsable, enum.Enum):
    ONE = StringEnumParams(
        code='one',
    )
    TWO = StringEnumParams(
        code='two',
    )
    THREE = StringEnumParams(
        code='three',
    )


class EnumStringValue(enum.Enum):
    ONE = 'one'
    TWO = 'two'
    THREE = 'three'


class ListParamParsableTest(ListParamParsable):
    pass


class ListParsableTest(ListParsable):
    @classmethod
    def get_param(cls):
        return ListParamParsableTest(
            item_class=AlwaysTestStringComposer,
            fallback_class=None,
            separator_class=ParserCRLF,
        )
