# -*- coding: utf-8 -*-

import json
import unittest


from cryptodatahub.common.exception import InvalidValue

from cryptoparser.common.exception import NotEnoughData, TooMuchData
from cryptoparser.common.base import (
    Opaque,
    OpaqueEnumParsable,
    OpaqueParam,
    ProtocolVersionMajorMinorBase,
    Serializable,
    SerializableTextEncoder,
    Vector,
    VectorEnumCodeString,
    VectorParamEnumCodeString,
    VectorParamNumeric,
    VectorParamParsable,
    VectorParamString,
    VectorParsable,
    VectorParsableDerived,
    VectorString,
)
from cryptoparser.common.parse import ComposerBinary

from .classes import (
    AlwaysTestStringComposer,
    ConditionalParsable,
    EnumStringValue,
    FourByteEnumComposerTest,
    FourByteEnumParsableTest,
    ListParsableTest,
    NByteEnumTest,
    NumericRangeParsableTest,
    OneByteEnumComposerTest,
    OneByteEnumParsableTest,
    OneByteOddParsable,
    OneByteParsable,
    OpaqueEnum,
    OpaqueEnumFactory,
    SerializableAttributeOrder,
    SerializableEmptyValues,
    SerializableEnums,
    SerializableHidden,
    SerializableHumanFriendly,
    SerializableHumanReadable,
    SerializableIterables,
    SerializableRecursive,
    SerializableSimpleTypes,
    SerializableSingle,
    SerializableUnhandled,
    SerializableUpperCaseEncoder,
    StringEnum,
    StringEnumA,
    StringEnumAA,
    StringEnumAAA,
    TestObject,
    ThreeByteEnumComposerTest,
    ThreeByteEnumParsableTest,
    TwoByteEnumComposerTest,
    TwoByteEnumParsableTest,
    TwoByteEvenParsable,
    TwoByteParsable,
    VariantParsableTest,
    VariantParsableExactTest,
)


class TestProtocolVersionMajorMinorBase(unittest.TestCase):
    def setUp(self):
        self.protocol_version = ProtocolVersionMajorMinorBase(1, 2)
        self.protocol_version_bytes = b'\x01\x02'

    def test_error(self):
        with self.assertRaises(NotEnoughData) as context_manager:
            ProtocolVersionMajorMinorBase.parse_exact_size(b'\x00')
        self.assertEqual(context_manager.exception.bytes_needed, 1)

    def test_parse(self):
        self.assertEqual(
            ProtocolVersionMajorMinorBase.parse_exact_size(self.protocol_version_bytes),
            self.protocol_version
        )

    def test_compose(self):
        self.assertEqual(self.protocol_version.compose(), self.protocol_version_bytes)

    def test_identifier(self):
        self.assertEqual(self.protocol_version.identifier, '1_2')

    def test_markdown(self):
        self.assertEqual(self.protocol_version.as_markdown(), '1.2')

    def test_str(self):
        self.assertEqual(str(self.protocol_version), '1.2')


class VectorNumericTestErrors(Vector):
    @classmethod
    def get_param(cls):
        return VectorParamNumeric(item_size=2, min_byte_num=4, max_byte_num=6)


class VectorNumericTest(Vector):
    @classmethod
    def get_param(cls):
        return VectorParamNumeric(item_size=2, min_byte_num=0, max_byte_num=0xff)


class VectorStringTest(VectorString):
    @classmethod
    def get_param(cls):
        return VectorParamString(
            min_byte_num=0,
            max_byte_num=16,
            separator=';',
            item_class=StringEnum,
            fallback_class=str
        )


class VectorOneByteParsableTest(VectorParsable):
    @classmethod
    def get_param(cls):
        return VectorParamParsable(item_class=OneByteParsable, min_byte_num=0, max_byte_num=0xff, fallback_class=None)


class VectorTwoByteParsableTest(VectorParsable):
    @classmethod
    def get_param(cls):
        return VectorParamParsable(item_class=TwoByteParsable, min_byte_num=0, max_byte_num=0xffff, fallback_class=None)


class VectorConsditionalParsableTest(VectorParsableDerived):
    @classmethod
    def get_param(cls):
        return VectorParamParsable(
            item_class=ConditionalParsable,
            min_byte_num=0,
            max_byte_num=0xff,
            fallback_class=None
        )


class VectorFallbackParsableTest(VectorParsableDerived):
    @classmethod
    def get_param(cls):
        return VectorParamParsable(
            item_class=OneByteOddParsable,
            min_byte_num=0,
            max_byte_num=0xff,
            fallback_class=TwoByteEvenParsable
        )


class OpaqueTest(Opaque):
    @classmethod
    def get_param(cls):
        return OpaqueParam(min_byte_num=3, max_byte_num=3)


class TestVectorNumeric(unittest.TestCase):
    def test_error(self):
        with self.assertRaises(NotEnoughData) as context_manager:
            VectorNumericTestErrors(items=[1, ])
        self.assertEqual(context_manager.exception.bytes_needed, VectorNumericTestErrors.get_param().min_byte_num)

        with self.assertRaises(TooMuchData) as context_manager:
            VectorNumericTestErrors(items=[1, 2, 3, 4, ])
        self.assertEqual(context_manager.exception.bytes_needed, VectorNumericTestErrors.get_param().max_byte_num)

        vector = VectorNumericTestErrors(items=[1, 2, ])
        with self.assertRaises(NotEnoughData) as context_manager:
            del vector[0]
        self.assertEqual(context_manager.exception.bytes_needed, VectorNumericTestErrors.get_param().min_byte_num)

        vector = VectorNumericTestErrors(items=[1, 2, 3])
        with self.assertRaises(TooMuchData) as context_manager:
            vector.append(0xff)
        self.assertEqual(context_manager.exception.bytes_needed, VectorNumericTestErrors.get_param().max_byte_num)

    def test_parse(self):
        self.assertEqual(len(VectorNumericTest.parse_exact_size(b'\x00')), 0)

        self.assertEqual(
            [1, 2, ],
            list(VectorNumericTest.parse_exact_size(b'\x04\x00\x01\x00\x02'))
        )

    def test_compose(self):
        self.assertEqual(
            b'\x00',
            VectorNumericTest([]).compose(),
        )

        self.assertEqual(
            b'\x04\x00\x01\x00\x02',
            VectorNumericTest([1, 2, ]).compose(),
        )

    def test_container(self):
        vector = VectorNumericTest(items=[])

        vector.append(1)
        self.assertEqual(vector[0], 1)
        self.assertEqual(len(vector), 1)
        self.assertEqual(str(vector), '[1]')

        vector.insert(0, 0)
        self.assertEqual(vector[0], 0)
        self.assertEqual(len(vector), 2)
        self.assertEqual(str(vector), '[0, 1]')

        del vector[0]
        self.assertEqual(vector[0], 1)
        self.assertEqual(len(vector), 1)
        self.assertEqual(str(vector), '[1]')

        vector[0] = 0
        self.assertEqual(vector[0], 0)
        self.assertEqual(len(vector), 1)
        self.assertEqual(str(vector), '[0]')


class TestVectorString(unittest.TestCase):
    def test_error(self):
        pass

    def test_parse(self):
        self.assertEqual(len(VectorStringTest.parse_exact_size(b'\x00')), 0)

        self.assertEqual(
            [StringEnum.ONE, StringEnum.TWO, StringEnum.THREE, ],
            list(VectorStringTest.parse_exact_size(b'\x0fone;two;three'))
        )
        self.assertEqual(
            [StringEnum.ONE, StringEnum.TWO, StringEnum.THREE, 'four', ],
            list(VectorStringTest.parse_exact_size(b'\x14one;two;three;four'))
        )

    def test_compose(self):
        self.assertEqual(
            b'\x00',
            VectorStringTest([]).compose(),
        )

        self.assertEqual(
            b'\x07one;two',
            VectorStringTest([StringEnum.ONE, StringEnum.TWO, ]).compose(),
        )

    def test_json(self):
        self.assertEqual('[]', VectorStringTest([]).as_json())

        self.assertEqual(
            VectorStringTest([StringEnum.ONE, StringEnum.TWO, ]).as_json(),
            '[{"ONE": {"code": "one"}}, {"TWO": {"code": "two"}}]',
        )

    def test_markdown(self):
        self.assertEqual('-', VectorStringTest([]).as_markdown())

        self.assertEqual(
            VectorStringTest([StringEnum.ONE, StringEnum.TWO, ]).as_markdown(),
            '\n'.join([
                '1. ONE',
                '2. TWO',
                '',
            ])
        )


class StringEnumFactory(OpaqueEnumParsable):
    @classmethod
    def get_enum_class(cls):
        return StringEnum

    @classmethod
    def get_param(cls):
        return OpaqueParam(
            min_byte_num=1, max_byte_num=2 ** 8 - 1
        )


class VectorEnumCodeStringTest(VectorEnumCodeString):
    @classmethod
    def get_param(cls):
        return VectorParamEnumCodeString(
            item_class=StringEnumFactory,
            min_byte_num=0, max_byte_num=2 ** 16 - 1
        )


class TestVectorEnumCodeString(unittest.TestCase):
    def test_error(self):
        pass

    def test_parse(self):
        self.assertEqual(
            [StringEnum.ONE, StringEnum.TWO, StringEnum.THREE, ],
            list(VectorEnumCodeStringTest.parse_exact_size(b'\x00\x0e\x03one\x03two\x05three'))
        )

    def test_compose(self):
        self.assertEqual(
            b'\x00\x00',
            VectorEnumCodeStringTest([]).compose(),
        )

        self.assertEqual(
            b'\x00\x08\x03one\x03two',
            VectorEnumCodeStringTest([StringEnum.ONE, StringEnum.TWO, ]).compose(),
        )

    def test_json(self):
        self.assertEqual('[]', VectorEnumCodeStringTest([]).as_json())

        self.assertEqual(
            VectorEnumCodeStringTest([StringEnum.ONE, StringEnum.TWO, ]).as_json(),
            '[{"ONE": {"code": "one"}}, {"TWO": {"code": "two"}}]',
        )

    def test_markdown(self):
        self.assertEqual('-', VectorEnumCodeStringTest([]).as_markdown())

        self.assertEqual(
            VectorEnumCodeStringTest([StringEnum.ONE, StringEnum.TWO, ]).as_markdown(),
            '\n'.join([
                '1. ONE',
                '2. TWO',
                '',
            ])
        )


class TestVectorParsable(unittest.TestCase):
    def test_error(self):
        with self.assertRaises(NotEnoughData) as context_manager:
            VectorOneByteParsableTest.parse_exact_size(b'')
        self.assertEqual(context_manager.exception.bytes_needed, 1)

        with self.assertRaises(NotEnoughData) as context_manager:
            VectorTwoByteParsableTest.parse_exact_size(b'\x00')
        self.assertEqual(context_manager.exception.bytes_needed, 1)

        with self.assertRaises(NotEnoughData) as context_manager:
            VectorOneByteParsableTest.parse_exact_size(b'\x03')
        self.assertEqual(context_manager.exception.bytes_needed, 3)

        with self.assertRaises(NotEnoughData) as context_manager:
            VectorTwoByteParsableTest.parse_exact_size(b'\x00\x03')
        self.assertEqual(context_manager.exception.bytes_needed, 3)

    def test_parse(self):
        self.assertEqual(len(VectorOneByteParsableTest.parse_exact_size(b'\x00')), 0)
        self.assertEqual(len(VectorTwoByteParsableTest.parse_exact_size(b'\x00\x00')), 0)

        self.assertEqual(
            [0, 1, 0, 2, ],
            list(map(int, VectorOneByteParsableTest.parse_exact_size(b'\x04\x00\x01\x00\x02')))
        )
        self.assertEqual(
            [1, 2, ],
            list(map(int, VectorTwoByteParsableTest.parse_exact_size(b'\x00\x04\x00\x01\x00\x02')))
        )

        self.assertEqual(
            [0x01, 0x0200],
            list(map(int, VectorFallbackParsableTest.parse_exact_size(b'\x03\x01\x02\x00')))
        )

    def test_compose(self):
        self.assertEqual(b'\x00', VectorOneByteParsableTest([]).compose())
        self.assertEqual(b'\x00\x00', VectorTwoByteParsableTest([]).compose())

        self.assertEqual(
            b'\x04\x00\x01\x00\x02',
            VectorOneByteParsableTest([
                OneByteParsable(0),
                OneByteParsable(1),
                OneByteParsable(0),
                OneByteParsable(2)
            ]).compose(),
        )
        self.assertEqual(
            b'\x00\x04\x00\x01\x00\x02',
            VectorTwoByteParsableTest([
                TwoByteParsable(1),
                TwoByteParsable(2)
            ]).compose(),
        )

    def test_container(self):
        vector = VectorOneByteParsableTest(items=[])

        vector.append(OneByteParsable(1))
        self.assertEqual(vector[0], OneByteParsable(1))
        self.assertNotEqual(vector[0], TwoByteParsable(1))
        self.assertEqual(len(vector), 1)
        self.assertEqual(str(vector), '[0x01]')

        vector.insert(0, TwoByteParsable(0))
        self.assertEqual(vector[0], TwoByteParsable(0))
        self.assertNotEqual(vector[0], OneByteParsable(0))
        self.assertEqual(len(vector), 2)
        self.assertEqual(str(vector), '[0x0000, 0x01]')

        del vector[0]
        self.assertEqual(vector[0], OneByteParsable(1))
        self.assertNotEqual(vector[0], TwoByteParsable(1))
        self.assertEqual(len(vector), 1)
        self.assertEqual(str(vector), '[0x01]')

        vector[0] = TwoByteParsable(0)
        self.assertEqual(vector[0], TwoByteParsable(0))
        self.assertNotEqual(vector[0], OneByteParsable(0))
        self.assertEqual(len(vector), 1)
        self.assertEqual(str(vector), '[0x0000]')


class TestVectorDerived(unittest.TestCase):
    def test_error(self):
        with self.assertRaises(NotEnoughData) as context_manager:
            VectorConsditionalParsableTest.parse_exact_size(b'\x05\x01\x02\x00')
        self.assertEqual(context_manager.exception.bytes_needed, 2)

    def test_parse(self):
        self.assertEqual(
            [0x01, 0x0200],
            list(map(int, VectorConsditionalParsableTest.parse_exact_size(b'\x03\x01\x02\x00')))
        )
        self.assertEqual(
            [0x0200, 0x01],
            list(map(int, VectorConsditionalParsableTest.parse_exact_size(b'\x03\x02\x00\x01')))
        )

    def test_compose(self):
        self.assertEqual(
            b'\x03\x01\x00\x02',
            VectorConsditionalParsableTest([
                OneByteParsable(1),
                TwoByteParsable(2),
            ]).compose()
        )
        self.assertEqual(
            b'\x03\x00\x02\x01',
            VectorConsditionalParsableTest([
                TwoByteParsable(2),
                OneByteParsable(1),
            ]).compose()
        )


class TestOpaque(unittest.TestCase):
    def test_error(self):
        with self.assertRaises(NotEnoughData) as context_manager:
            OpaqueTest.parse_exact_size(b'\x03\x01\x02')
        self.assertEqual(context_manager.exception.bytes_needed, 1)

    def test_parse(self):
        self.assertEqual(
            [1, 2, 3],
            list(OpaqueTest.parse_exact_size(b'\x03\x01\x02\x03'))
        )

    def test_compose(self):
        self.assertEqual(
            b'\x03\x01\x02\x03',
            OpaqueTest([1, 2, 3]).compose()
        )
        self.assertEqual(
            b'\x03\x01\x02\x03',
            OpaqueTest(b'\x01\x02\x03').compose()
        )
        self.assertEqual(
            b'\x03\x01\x02\x03',
            OpaqueTest(bytearray(b'\x01\x02\x03')).compose()
        )


class TestOpaqueEnum(unittest.TestCase):
    def test_error(self):
        with self.assertRaises(InvalidValue) as context_manager:
            OpaqueEnumFactory.parse_exact_size(b'\x0a' + 'δέλτα'.encode('utf-8'))
        self.assertEqual(context_manager.exception.value, 'δέλτα')

    def test_parse(self):
        self.assertEqual(
            OpaqueEnum.ALPHA,
            OpaqueEnumFactory.parse_exact_size(b'\x08' + 'άλφα'.encode('utf-8'))
        )

    def test_compose(self):
        self.assertEqual(
            b'\x0a' + 'γάμμα'.encode('utf-8'),
            OpaqueEnum.GAMMA.compose()  # pylint: disable=no-member
        )

    def test_repr(self):
        self.assertEqual(
            repr(OpaqueEnum.GAMMA),
            'OpaqueEnum.GAMMA'
        )


class TestNByteEnumParsable(unittest.TestCase):
    def test_compose(self):
        composer = ComposerBinary()
        composer.compose_parsable(OneByteEnumComposerTest.ONE)
        self.assertEqual(composer.composed_bytes, b'\x01')

        composer = ComposerBinary()
        composer.compose_parsable(TwoByteEnumComposerTest.TWO)
        self.assertEqual(composer.composed_bytes, b'\x00\x02')

        composer = ComposerBinary()
        composer.compose_parsable(ThreeByteEnumComposerTest.THREE)
        self.assertEqual(composer.composed_bytes, b'\x00\x00\x03')

        composer = ComposerBinary()
        composer.compose_parsable(FourByteEnumComposerTest.FOUR)
        self.assertEqual(composer.composed_bytes, b'\x00\x00\x00\x04')

    def test_parse(self):
        self.assertEqual(
            OneByteEnumParsableTest.parse_exact_size(b'\x01'),
            NByteEnumTest.ONE
        )
        self.assertEqual(
            TwoByteEnumParsableTest.parse_exact_size(b'\x00\x02'),
            NByteEnumTest.TWO
        )
        self.assertEqual(
            ThreeByteEnumParsableTest.parse_exact_size(b'\x00\x00\x03'),
            NByteEnumTest.THREE
        )
        self.assertEqual(
            FourByteEnumParsableTest.parse_exact_size(b'\x00\x00\x00\x04'),
            NByteEnumTest.FOUR
        )


class TestEnumString(unittest.TestCase):
    def test_error(self):
        with self.assertRaises(InvalidValue) as context_manager:
            StringEnum.parse_exact_size(b'four')
        self.assertEqual(context_manager.exception.value, b'four')

        with self.assertRaises(InvalidValue) as context_manager:
            StringEnum.parse_exact_size(b'\xffthree')
        self.assertEqual(context_manager.exception.value, b'\xffthree')

    def test_parse(self):
        self.assertEqual(StringEnum.parse_exact_size(b'one'), StringEnum.ONE)

    def test_compose(self):
        self.assertEqual(StringEnum.ONE.compose(), b'one')


class TestSerializable(unittest.TestCase):
    def test_json(self):
        self.assertEqual(
            SerializableSimpleTypes().as_json(),
            '{' +
            '"bool_value": false, ' +
            '"bytearray_value": "00:01:01:02:03:04:05:06:07:08:09:0A:0B:0C:0D:0E:0F", ' +
            '"float_value": 1.0, ' +
            '"int_value": 1, ' +
            '"none_value": null, ' +
            '"str_value": "string"' +
            '}'
        )
        self.assertEqual(
            SerializableIterables().as_json(),
            '{' +
            '"dict_key": ' +
            '{' +
            '"1": "int", ' +
            '"str": "string", ' +
            '"FIRST": "enum"' +
            '}, ' +
            '"dict_value": ' +
            '{' +
            '"int": 1, ' +
            '"string": "str", ' +
            '"enum": {"FIRST": "1"}' +
            '}, ' +
            '"list_value": ["value"], ' +
            '"tuple_value": ["value"]' +
            '}'
        )
        self.assertEqual(
            SerializableEnums().as_json(),
            '{"param_enum": {"FIRST": {"code": 1}}, "string_enum": {"SECOND": "2"}}'
        )
        self.assertEqual(
            SerializableSingle().as_json(),
            '"single"'
        )
        self.assertEqual(
            SerializableHidden().as_json(),
            '{"visible_value": "value"}'
        )
        self.assertEqual(
            SerializableUnhandled().as_json(),
            '{"complex_number": "(1+2j)"}'
        )
        self.assertEqual(
            SerializableHumanFriendly().as_json(),
            '{' +
            '"human_friendly": "human-friendly", ' +
            '"human_friendly_by_default": "human-friendly-by-default", ' +
            '"non_human_friendly": "non-human-friendly"' +
            '}'
        )
        self.assertEqual(
            SerializableRecursive().as_json(),
            '{' +
            '"json_asdict_object": {"attr_b": "b", "attr_a": "a"}, ' +
            '"json_attr_as_dict": {"attr_b": "b", "attr_a": "a"}, ' +
            '"json_attr_object": {"attr_b": "b", "attr_a": "a"}, ' +
            '"json_crypto_data_hub_enum": "ONE", ' +
            '"json_gradeable": {"vulnerabilities": [{"attack_type": "MITM", "grade": "INSECURE", "named": "NOFS"}]}, ' +
            '"json_object": {"attr_a": "a", "attr_b": "b"}, ' +
            '"json_serializable_hidden": {"visible_value": "value"}, ' +
            '"json_serializable_in_dict": {"key1": {"visible_value": "value"}, "key2": "single"}, ' +
            '"json_serializable_in_list": [{"visible_value": "value"}, "single"], ' +
            '"json_serializable_in_tuple": [{"visible_value": "value"}, "single"], ' +
            '"json_serializable_single": "single"' +
            '}'
        )
        self.assertEqual(json.dumps(TestObject()), '{}')
        self.assertEqual(
            json.dumps(EnumStringValue.ONE),
            '{"ONE": "one"}'
        )

    def test_markdown(self):
        self.assertEqual(
            SerializableSimpleTypes().as_markdown(),
            '\n'.join([
                '* Bool Value: no',
                '* Bytearray Value: 00:01:01:02:03:04:05:06:07:08:09:0A:0B:0C:0D:0E:0F',
                '* Float Value: 1.0',
                '* Int Value: 1',
                '* None Value: n/a',
                '* Str Value: string',
                ''
            ])
        )
        self.assertEqual(
            SerializableIterables().as_markdown(),
            '\n'.join([
                '* Dict Key:',
                '    * 1: int',
                '    * Str: string',
                '    * FIRST: enum',
                '* Dict Value:',
                '    * Int: 1',
                '    * String: str',
                '    * Enum: FIRST',
                '* List Value:',
                '    1. value',
                '* Tuple Value:',
                '    1. value',
                ''
            ])
        )
        self.assertEqual(
            SerializableEnums().as_markdown(),
            '\n'.join([
                '* Param Enum: 1',
                '* String Enum: SECOND',
                ''
            ])
        )
        self.assertEqual(
            SerializableHidden().as_markdown(),
            '* Visible Value: value\n'
        )
        self.assertEqual(
            SerializableUnhandled().as_markdown(),
            '* Complex Number: (1+2j)\n'
        )
        self.assertEqual(
            SerializableHumanReadable().as_markdown(),
            '* Human Readable Name 2: value 2\n'
            '* Human Readable Name 1: value 1\n'
        )
        self.assertEqual(
            SerializableHumanFriendly().as_markdown(),
            '* Human Friendly: human-friendly\n'
            '* Human Friendly By Default: human-friendly-by-default\n'
        )
        self.assertEqual(
            SerializableAttributeOrder().as_markdown(),
            '\n'.join([
                '* Attr B: b',
                '* Attr A: a'
            ]) + '\n'
        )
        self.assertEqual(
            SerializableEmptyValues().as_markdown(),
            '\n'.join([
                '* Dict: -',
                '* List: -',
                '* Tuple: -',
                '* Value: n/a',
                '',
            ])
        )
        self.assertEqual(
            SerializableRecursive().as_markdown(),
            '\n'.join([
                '* Json Asdict Object:',
                '    * Attr B: b',
                '    * Attr A: a',
                '* Json Attr As Dict:',
                '    * Attr B: b',
                '    * Attr A: a',
                '* Json Attr Object:',
                '    * Attr B: b',
                '    * Attr A: a',
                '* Json Crypto Data Hub Enum: one',
                '* Json Gradeable: value',
                '* Json Object:',
                '    * Attr A: a',
                '    * Attr B: b',
                '* Json Serializable Hidden:',
                '    * Visible Value: value',
                '* Json Serializable In Dict:',
                '    * Key1:',
                '        * Visible Value: value',
                '    * Key2: single',
                '* Json Serializable In List:',
                '    1.',
                '        * Visible Value: value',
                '    2. single',
                '* Json Serializable In Tuple:',
                '    1.',
                '        * Visible Value: value',
                '    2. single',
                '* Json Serializable Single: single',
                '',
            ])
        )

        Serializable.post_text_encoder = SerializableUpperCaseEncoder()
        self.assertEqual(
            SerializableRecursive().as_markdown(),
            '\n'.join([
                '* Json Asdict Object:',
                '    * Attr B: B',
                '    * Attr A: A',
                '* Json Attr As Dict:',
                '    * Attr B: B',
                '    * Attr A: A',
                '* Json Attr Object:',
                '    * Attr B: B',
                '    * Attr A: A',
                '* Json Crypto Data Hub Enum: ONE',
                '* Json Gradeable: VALUE',
                '* Json Object:',
                '    * Attr A: A',
                '    * Attr B: B',
                '* Json Serializable Hidden:',
                '    * Visible Value: VALUE',
                '* Json Serializable In Dict:',
                '    * Key1:',
                '        * Visible Value: VALUE',
                '    * Key2: SINGLE',
                '* Json Serializable In List:',
                '    1.',
                '        * Visible Value: VALUE',
                '    2. SINGLE',
                '* Json Serializable In Tuple:',
                '    1.',
                '        * Visible Value: VALUE',
                '    2. SINGLE',
                '* Json Serializable Single: SINGLE',
                '',
            ])
        )
        Serializable.post_text_encoder = SerializableTextEncoder()


class TestListParsable(unittest.TestCase):
    def test_error(self):
        with self.assertRaises(NotEnoughData) as context_manager:
            ListParsableTest.parse_exact_size(b'')
        self.assertEqual(context_manager.exception.bytes_needed, 2)

        with self.assertRaises(InvalidValue) as context_manager:
            ListParsableTest.parse_exact_size(b'test')
        self.assertEqual(context_manager.exception.value, b'test')

        with self.assertRaises(InvalidValue) as context_manager:
            ListParsableTest.parse_exact_size(b'nottest\r\n\r\n')
        self.assertEqual(context_manager.exception.value, b'nottest\r\n\r\n')

        with self.assertRaises(InvalidValue) as context_manager:
            ListParsableTest.parse_exact_size(b'test\r\n\r\ntest\r\n\r\n')
        self.assertEqual(context_manager.exception.value, b'test\r\n\r\ntest\r\n\r\n')

    def test_parse(self):
        list_parsable = ListParsableTest.parse_exact_size(b'\r\n')
        self.assertEqual(list_parsable, ListParsableTest([]))

        list_parsable = ListParsableTest.parse_exact_size(b'test\r\n\r\n')
        self.assertEqual(list_parsable, ListParsableTest([AlwaysTestStringComposer(), ]))

        list_parsable = ListParsableTest.parse_exact_size(b'test\r\ntest\r\n\r\n')
        self.assertEqual(list_parsable, ListParsableTest([AlwaysTestStringComposer(), AlwaysTestStringComposer()]))

    def test_compose(self):
        self.assertEqual(
            ListParsableTest([]).compose(),
            b'\r\n'
        )
        self.assertEqual(
            ListParsableTest([AlwaysTestStringComposer(), ]).compose(),
            b'test\r\n\r\n'
        )
        self.assertEqual(
            ListParsableTest([AlwaysTestStringComposer(), AlwaysTestStringComposer(), ]).compose(),
            b'test\r\ntest\r\n\r\n'
        )


class TestVariantParsable(unittest.TestCase):
    def test_error(self):
        with self.assertRaises(TooMuchData) as context_manager:
            VariantParsableTest.parse_exact_size(b'aaaa')
        self.assertEqual(context_manager.exception.bytes_needed, 1)

    def test_parse(self):
        parsable = bytearray(b'a')
        self.assertEqual(VariantParsableTest.parse_mutable(parsable), StringEnumA.A)
        self.assertEqual(parsable, b'')

        parsable = bytearray(b'aa')
        self.assertEqual(VariantParsableTest.parse_mutable(parsable), StringEnumA.A)
        self.assertEqual(parsable, b'a')

        parsable = bytearray(b'aaa')
        self.assertEqual(VariantParsableTest.parse_mutable(parsable), StringEnumA.A)
        self.assertEqual(parsable, b'aa')


class TestVariantParsableExact(unittest.TestCase):
    def test_error(self):
        with self.assertRaises(InvalidValue) as context_manager:
            VariantParsableExactTest.parse_exact_size(b'aaaa')
        self.assertEqual(context_manager.exception.value, b'aaaa')

    def test_parse(self):
        parsable = bytearray(b'a')
        self.assertEqual(VariantParsableExactTest.parse_mutable(parsable), StringEnumA.A)
        self.assertEqual(parsable, b'')

        parsable = bytearray(b'aa')
        self.assertEqual(VariantParsableExactTest.parse_mutable(parsable), StringEnumAA.AA)
        self.assertEqual(parsable, b'')

        parsable = bytearray(b'aaa')
        self.assertEqual(VariantParsableExactTest.parse_mutable(parsable), StringEnumAAA.AAA)
        self.assertEqual(parsable, b'')


class TestNumericRangeParsable(unittest.TestCase):
    def test_error(self):
        with self.assertRaises(InvalidValue) as context_manager:
            NumericRangeParsableTest.parse_exact_size(b'\x00')
        self.assertEqual(context_manager.exception.value, 0x00)

        with self.assertRaises(InvalidValue) as context_manager:
            NumericRangeParsableTest.parse_exact_size(b'\xff')
        self.assertEqual(context_manager.exception.value, 0xff)

    def test_parse(self):
        self.assertEqual(NumericRangeParsableTest.parse_exact_size(b'\x01'), NumericRangeParsableTest(1))
        self.assertEqual(NumericRangeParsableTest(1).compose(), b'\x01')

    def test_str(self):
        self.assertEqual(str(NumericRangeParsableTest(1)), '1')

    def test_as_markdown(self):
        self.assertEqual(NumericRangeParsableTest(1).as_markdown(), '1')
