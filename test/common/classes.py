# -*- coding: utf-8 -*-

import abc
import base64
import collections
import enum
import json
import pathlib

import attr

import pyfakefs.fake_filesystem_unittest

from cryptodatahub.common.exception import InvalidValue
from cryptodatahub.common.grade import AttackNamed, AttackType, Grade, GradeableVulnerabilities, Vulnerability
from cryptodatahub.common.types import CryptoDataEnumBase, CryptoDataParamsNamed

from cryptoparser.common.base import (
    ComposerBinary,
    FourByteEnumComposer,
    FourByteEnumParsable,
    ListParamParsable,
    ListParsable,
    NumericRangeParsableBase,
    OneByteEnumComposer,
    OneByteEnumParsable,
    OpaqueEnumComposer,
    OpaqueEnumParsable,
    OpaqueParam,
    ParsableBase,
    ParserBinary,
    Serializable,
    SerializableTextEncoder,
    StringEnumCaseInsensitiveParsable,
    StringEnumParsable,
    ThreeByteEnumComposer,
    ThreeByteEnumParsable,
    TwoByteEnumComposer,
    TwoByteEnumParsable,
    VariantParsable,
    VariantParsableExact,
)
from cryptoparser.common.exception import TooMuchData, InvalidType
from cryptoparser.common.field import (
    FieldsJson,
    FieldsSemicolonSeparated,
    FieldValueStringEnum,
    FieldValueComponentBool,
    FieldValueComponentFloat,
    FieldValueComponentNumber,
    FieldValueComponentOption,
    FieldValueComponentPercent,
    FieldValueComponentQuotedString,
    FieldValueComponentString,
    FieldValueComponentStringBase64,
    FieldValueComponentStringEnum,
    FieldValueComponentStringEnumParams,
    FieldValueComponentTimeDelta,
    FieldValueComponentUrl,
    FieldValueStringEnumParams,
    FieldValueTimeDelta,
    NameValuePairListSemicolonSeparated,
)
from cryptoparser.common.parse import ParserCRLF
from cryptoparser.common.x509 import PublicKeyX509


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
        return f'0x{self.value:>0{self.get_byte_size() * 2}x}'

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

    @classmethod
    def get_code_size(cls):
        return 2


class OpaqueEnumFactory(OpaqueEnumParsable):
    @classmethod
    def get_enum_class(cls):
        return OpaqueEnum

    @classmethod
    def get_param(cls):
        return OpaqueParam(
            min_byte_num=1, max_byte_num=32
        )


@attr.s
class OpaqueEnumParams():
    code = attr.ib(validator=attr.validators.instance_of(str))


class OpaqueEnum(OpaqueEnumComposer):
    ALPHA = OpaqueEnumParams(code='άλφα')
    BETA = OpaqueEnumParams(code='βήτα')
    GAMMA = OpaqueEnumParams(code='γάμμα')


class TestObject():
    pass


class SerializableSimpleTypes(Serializable):  # pylint: disable=too-many-instance-attributes
    def __init__(self):
        self.int_value = 1
        self.float_value = 1.0
        self.bool_value = False
        self.str_value = 'string'
        self.bytearray_value = bytearray(b'\x00\x01\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f')
        self.none_value = None


class SerializableIterables(Serializable):
    def __init__(self):
        self.dict_key = collections.OrderedDict([
            (1, 'int'),
            ('str', 'string'),
            (SerializableStringEnum.FIRST, 'enum'),
        ])
        self.dict_value = collections.OrderedDict([
            ('int', 1),
            ('string', 'str'),
            ('enum', SerializableStringEnum.FIRST),
        ])
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
class SerializableHumanFriendly(Serializable):
    human_friendly = attr.ib(default='human-friendly', metadata={'human_friendly': True})
    human_friendly_by_default = attr.ib(default='human-friendly-by-default')
    non_human_friendly = attr.ib(default='non-human-friendly', metadata={'human_friendly': False})


@attr.s
class SerializableAttributeOrder(Serializable):
    attr_b = attr.ib(default='b')
    attr_a = attr.ib(default='a')


class Class():
    def __init__(self):
        self.attr_b = 'b'
        self.attr_a = 'a'


@attr.s
class ClassAttr():
    attr_b = attr.ib(default='b')
    attr_a = attr.ib(default='a')


class ClassAsDict():
    def __init__(self):
        self.attr_a = 'a'
        self.attr_b = 'b'

    def _asdict(self):
        return collections.OrderedDict([
            ('attr_b', self.attr_b),
            ('attr_a', self.attr_a),
        ])


@attr.s
class ClassAttrAsDict():
    attr_a = attr.ib(default='a')
    attr_b = attr.ib(default='b')

    def _asdict(self):
        return collections.OrderedDict([
            ('attr_b', self.attr_b),
            ('attr_a', self.attr_a),
        ])


class ClassCryptoDataEnum(CryptoDataEnumBase):
    ONE = CryptoDataParamsNamed('one', 'long one')


class ClassGradeable(GradeableVulnerabilities):
    @classmethod
    def get_gradeable_name(cls):
        return 'gradeable'

    def __str__(self):
        return 'value'


class SerializableRecursive(Serializable):  # pylint: disable=too-many-instance-attributes
    def __init__(self):
        self.json_object = Class()
        self.json_attr_object = ClassAttr()
        self.json_attr_as_dict = ClassAttrAsDict()
        self.json_asdict_object = ClassAsDict()
        self.json_crypto_data_hub_enum = ClassCryptoDataEnum.ONE
        self.json_gradeable = ClassGradeable([
            Vulnerability(AttackType.MITM, Grade.INSECURE, AttackNamed.NOFS)
        ])
        self.json_serializable_hidden = SerializableHidden()
        self.json_serializable_single = 'single'
        self.json_serializable_in_list = list([SerializableHidden(), 'single'])
        self.json_serializable_in_tuple = tuple([SerializableHidden(), 'single'])
        self.json_serializable_in_dict = dict({'key1': SerializableHidden(), 'key2': 'single'})


class SerializableEmptyValues(Serializable):
    def __init__(self):
        self.value = None
        self.list = []
        self.tuple = tuple()
        self.dict = {}


class FlagEnum(enum.IntEnum):
    ONE = 1
    TWO = 2
    FOUR = 4
    EIGHT = 8


@attr.s
class StringEnumParams():
    code = attr.ib()

    def _check_code(self, code):
        if code != self.code:
            raise InvalidType()

    @classmethod
    def get_code_size(cls):
        return 2


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


class StringEnumA(StringEnumParsable, enum.Enum):
    A = StringEnumParams(code='a')


class StringEnumAA(StringEnumParsable, enum.Enum):
    AA = StringEnumParams(code='aa')


class StringEnumAAA(StringEnumParsable, enum.Enum):
    AAA = StringEnumParams(code='aaa')


class VariantParsableTest(VariantParsable):
    @classmethod
    def _get_variants(cls):
        return collections.OrderedDict([
            (StringEnumA, [StringEnumA, ]),
            (StringEnumAA, [StringEnumAA, ]),
            (StringEnumAAA, [StringEnumAAA, ]),
        ])


class VariantParsableExactTest(VariantParsableExact):
    @classmethod
    def _get_variants(cls):
        return collections.OrderedDict([
            (StringEnumA, [StringEnumA, ]),
            (StringEnumAA, [StringEnumAA, ]),
            (StringEnumAAA, [StringEnumAAA, ]),
        ])


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


@attr.s
class NByteEnumParam():
    code = attr.ib(validator=attr.validators.instance_of(int))


class NByteEnumTest(enum.Enum):
    ONE = NByteEnumParam(code=1)
    TWO = NByteEnumParam(code=2)
    THREE = NByteEnumParam(code=3)
    FOUR = NByteEnumParam(code=4)


class OneByteEnumParsableTest(OneByteEnumParsable):
    @classmethod
    def get_enum_class(cls):
        return NByteEnumTest

    @abc.abstractmethod
    def compose(self):
        raise NotImplementedError()


class OneByteEnumComposerTest(OneByteEnumComposer, enum.Enum):
    ONE = NByteEnumParam(code=1)
    TWO = NByteEnumParam(code=2)
    THREE = NByteEnumParam(code=3)
    FOUR = NByteEnumParam(code=4)


class TwoByteEnumParsableTest(TwoByteEnumParsable):
    @classmethod
    def get_enum_class(cls):
        return NByteEnumTest

    @abc.abstractmethod
    def compose(self):
        raise NotImplementedError()


class TwoByteEnumComposerTest(TwoByteEnumComposer, enum.Enum):
    ONE = NByteEnumParam(code=1)
    TWO = NByteEnumParam(code=2)
    THREE = NByteEnumParam(code=3)
    FOUR = NByteEnumParam(code=4)


class ThreeByteEnumParsableTest(ThreeByteEnumParsable):
    @classmethod
    def get_enum_class(cls):
        return NByteEnumTest

    @abc.abstractmethod
    def compose(self):
        raise NotImplementedError()


class ThreeByteEnumComposerTest(ThreeByteEnumComposer, enum.Enum):
    ONE = NByteEnumParam(code=1)
    TWO = NByteEnumParam(code=2)
    THREE = NByteEnumParam(code=3)
    FOUR = NByteEnumParam(code=4)


class FourByteEnumParsableTest(FourByteEnumParsable):
    @classmethod
    def get_enum_class(cls):
        return NByteEnumTest

    @abc.abstractmethod
    def compose(self):
        raise NotImplementedError()


class FourByteEnumComposerTest(FourByteEnumComposer, enum.Enum):
    ONE = NByteEnumParam(code=1)
    TWO = NByteEnumParam(code=2)
    THREE = NByteEnumParam(code=3)
    FOUR = NByteEnumParam(code=4)


class FieldValueTimeDeltaTest(FieldValueTimeDelta):
    @classmethod
    def get_name(cls):
        return 'testTimeDelta'


class FieldValueEnumTest(StringEnumCaseInsensitiveParsable, enum.Enum):
    FIRST = FieldValueStringEnumParams(code='first', human_readable_name='FiRsT')
    SECOND = FieldValueStringEnumParams(code='second')


class FieldValueStringEnumTest(FieldValueStringEnum):
    @classmethod
    def _get_value_type(cls):
        return FieldValueEnumTest


class FieldValueComponentOptionTest(FieldValueComponentOption):
    @classmethod
    def get_canonical_name(cls):
        return 'testOption'


class FieldValueComponentStringTest(FieldValueComponentString):
    @classmethod
    def get_canonical_name(cls):
        return 'testString'


class FieldValueComponentUrlTest(FieldValueComponentUrl):
    @classmethod
    def get_canonical_name(cls):
        return 'testUrl'


class ComponentStringEnumTest(StringEnumParsable, enum.Enum):
    ONE = FieldValueComponentStringEnumParams(
        code='one'
    )
    TWO = FieldValueComponentStringEnumParams(
        code='two'
    )
    THREE = FieldValueComponentStringEnumParams(
        code='three'
    )


class FieldValueComponentStringBase64Test(FieldValueComponentStringBase64):
    @classmethod
    def get_canonical_name(cls):
        return 'testStringBase64'


class FieldValueComponentBoolTest(FieldValueComponentBool):
    @classmethod
    def get_canonical_name(cls):
        return 'testBool'


class FieldValueComponentFloatTest(FieldValueComponentFloat):
    @classmethod
    def get_canonical_name(cls):
        return 'testFloat'


class FieldValueComponentStringEnumTest(FieldValueComponentStringEnum):
    @classmethod
    def get_canonical_name(cls):
        return 'testStringEnum'

    @classmethod
    def _get_value_type(cls):
        return ComponentStringEnumTest


class FieldValueComponentOptionalStringTest(FieldValueComponentQuotedString):
    @classmethod
    def get_canonical_name(cls):
        return 'testOptionalString'


class FieldValueComponentQuotedStringTest(FieldValueComponentQuotedString):
    @classmethod
    def get_canonical_name(cls):
        return 'testQuotedString'


class FieldValueComponentNumberTest(FieldValueComponentNumber):
    @classmethod
    def get_canonical_name(cls):
        return 'testNumber'


class FieldValueComponentPercentTest(FieldValueComponentPercent):
    @classmethod
    def get_canonical_name(cls):
        return 'testPercent'


class FieldValueComponentTimeDeltaTest(FieldValueComponentTimeDelta):
    @classmethod
    def get_canonical_name(cls):
        return 'testTimeDelta'


@attr.s
class FieldValueComplexTestBase():  # pylint: disable=too-many-instance-attributes
    time_delta = attr.ib(
        converter=FieldValueComponentTimeDeltaTest.convert,
        validator=attr.validators.instance_of(FieldValueComponentTimeDeltaTest)
    )
    string = attr.ib(
        converter=FieldValueComponentStringTest.convert,
        validator=attr.validators.instance_of(FieldValueComponentStringTest),
        default='default'
    )
    url = attr.ib(
        converter=FieldValueComponentUrlTest.convert,
        validator=attr.validators.instance_of(FieldValueComponentUrlTest),
        default='https://example.com'
    )
    base64_string = attr.ib(
        converter=FieldValueComponentStringBase64Test.convert,
        validator=attr.validators.instance_of(FieldValueComponentStringBase64Test),
        default=base64.b64encode('default'.encode('ascii')).decode('ascii')
    )
    number = attr.ib(
        converter=FieldValueComponentNumberTest.convert,
        validator=attr.validators.instance_of(FieldValueComponentNumberTest),
        default=0
    )
    percent = attr.ib(
        converter=FieldValueComponentPercentTest.convert,
        validator=attr.validators.instance_of(FieldValueComponentPercentTest),
        default=100
    )


@attr.s
class FieldValueMultipleTest(  # pylint: disable=too-many-instance-attributes
        FieldsSemicolonSeparated, FieldValueComplexTestBase):
    option = attr.ib(
        converter=FieldValueComponentOptionTest.convert,
        validator=attr.validators.instance_of(FieldValueComponentOptionTest),
        default=False
    )
    optional_string = attr.ib(
        converter=attr.converters.optional(FieldValueComponentOptionalStringTest.convert),
        validator=attr.validators.optional(
            attr.validators.instance_of(FieldValueComponentOptionalStringTest)
        ),
        default=None
    )


class FieldValueJsonTest(  # pylint: disable=too-many-instance-attributes
        FieldsJson, FieldValueComplexTestBase):
    pass


@attr.s
class FieldValueMultipleExtendableTest(FieldValueMultipleTest):
    extensions = attr.ib(
        default=None,
        validator=attr.validators.optional(attr.validators.instance_of(NameValuePairListSemicolonSeparated)),
        metadata={'extension': True},
    )


class SerializableUpperCaseEncoder(SerializableTextEncoder):
    def __call__(self, obj, level):
        _, string_result = super().__call__(obj, level)

        return False, string_result.upper()


class TestClasses:
    class TestKeyBase(pyfakefs.fake_filesystem_unittest.TestCase):
        def setUp(self):
            self.setUpPyfakefs()

            self.__certs_dir = pathlib.PurePath(__file__).parent.parent / 'common' / 'certs'
            self.fs.add_real_directory(str(self.__certs_dir))

        def _get_pem_str(self, public_key_file_name):
            public_key_path = self.__certs_dir / public_key_file_name
            with open(str(public_key_path), 'r', encoding='ascii') as pem_file:
                return pem_file.read()

        def _get_public_key_x509(self, public_key_file_name):
            return PublicKeyX509.from_pem(self._get_pem_str(public_key_file_name))


class NumericRangeParsableTest(NumericRangeParsableBase):
    @classmethod
    def _get_value_min(cls):
        return 0x01

    @classmethod
    def _get_value_max(cls):
        return 0xfe

    @classmethod
    def _get_value_length(cls):
        return 1
