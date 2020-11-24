# -*- coding: utf-8 -*-

import unittest

from cryptoparser.common.exception import NotEnoughData, TooMuchData, InvalidValue
from cryptoparser.common.parse import ParserBinary, ParsableBase, ComposerBinary, ByteOrder
from cryptoparser.tls.ciphersuite import TlsCipherSuiteFactory

from .classes import (
    AlwaysInvalidTypeVariantParsable,
    ConditionalParsable,
    FlagEnum,
    OneByteOddParsable,
    OneByteParsable,
    SerializableEnum,
    SerializableEnumFactory,
    SerializableEnumVariantParsable,
    TwoByteParsable,
)


class TestParsable(unittest.TestCase):
    def test_error(self):
        with self.assertRaises(TooMuchData) as context_manager:
            OneByteParsable.parse_exact_size(b'\x01\x02')
        self.assertEqual(context_manager.exception.bytes_needed, 1)

        with self.assertRaises(NotEnoughData) as context_manager:
            OneByteParsable.parse_immutable(b'')
        self.assertEqual(context_manager.exception.bytes_needed, 1)

        with self.assertRaises(TypeError):
            # pylint: disable=protected-access,abstract-class-instantiated
            ParsableBase()._parse(b'')

        with self.assertRaises(TypeError):
            # pylint: disable=abstract-class-instantiated
            ParsableBase().compose()

        parser = ParserBinary(b'\xff\xff')
        with self.assertRaises(InvalidValue):
            parser.parse_parsable('cipher_suite', TlsCipherSuiteFactory)

        with self.assertRaises(InvalidValue) as context_manager:
            AlwaysInvalidTypeVariantParsable.parse_exact_size(b'\x01\x02\x03\x04')
        self.assertEqual(context_manager.exception.value, b'\x01\x02\x03\x04')

        with self.assertRaises(InvalidValue) as context_manager:
            AlwaysInvalidTypeVariantParsable(0)
        self.assertEqual(context_manager.exception.value, 0)

    def test_parse(self):
        _, unparsed_bytes = OneByteParsable.parse_immutable(b'\x01\x02')
        self.assertEqual(unparsed_bytes, b'\x02')

        parsable = bytearray([0x01, 0x02])
        OneByteParsable.parse_mutable(parsable)
        self.assertEqual(parsable, b'\x02')

        parsed_value, unparsed_bytes = SerializableEnumFactory.parse_immutable(b'\x00\x01')
        self.assertEqual(parsed_value, SerializableEnum.first)

    def test_repr(self):
        self.assertEqual(repr(SerializableEnum.first), 'SerializableEnum.first')
        AlwaysInvalidTypeVariantParsable.register_variant_parser(SerializableEnumFactory, SerializableEnumFactory)


class TestParserBinary(unittest.TestCase):
    def test_error(self):
        parser = ParserBinary(b'\x00')
        parser.parse_numeric('one_byte', 1)
        with self.assertRaises(NotEnoughData) as context_manager:
            parser.parse_numeric('one_byte', 1)
        self.assertEqual(context_manager.exception.bytes_needed, 1)

        parser = ParserBinary(b'\x00\x00\x00\x00')
        parser.parse_numeric('one_byte', 1)
        with self.assertRaises(NotEnoughData) as context_manager:
            parser.parse_numeric_array('four_byte_array', item_num=2, item_size=3)
        self.assertEqual(context_manager.exception.bytes_needed, 3)

        parser = ParserBinary(b'\x00\x00\x00\x00')
        parser.parse_numeric('one_byte', 1)
        with self.assertRaises(NotEnoughData) as context_manager:
            parser.parse_bytes('four_byte_array', 4)
        self.assertEqual(context_manager.exception.bytes_needed, 1)

        parser = ParserBinary(b'\x00\x00\x00\x00\x00')
        with self.assertRaises(NotImplementedError):
            parser.parse_numeric('five_byte_numeric', 5)

        parser = ParserBinary(b'\xff\xff')
        with self.assertRaises(InvalidValue):
            parser.parse_numeric('two_byte_numeric', 2, OneByteParsable)

        parser = ParserBinary(b'\x10')
        with self.assertRaises(InvalidValue):
            parser.parse_numeric('flags', 1, FlagEnum)

        with self.assertRaises(InvalidValue) as context_manager:
            AlwaysInvalidTypeVariantParsable.parse_immutable(b'\x00\x00')

        AlwaysInvalidTypeVariantParsable.register_variant_parser(SerializableEnumFactory, SerializableEnumFactory)
        with self.assertRaises(InvalidValue) as context_manager:
            AlwaysInvalidTypeVariantParsable.parse_exact_size(b'\x01\x02')
        self.assertEqual(context_manager.exception.value, 0x0102)

    def test_parse_numeric(self):
        parser = ParserBinary(b'\x01\x02')
        parser.parse_numeric('first_byte', 1)
        parser.parse_numeric('second_byte', 1)
        self.assertEqual(parser['first_byte'], 0x01)
        self.assertEqual(parser['second_byte'], 0x02)

        parser = ParserBinary(b'\x01\x02')
        parser.parse_numeric('first_two_bytes', 2)
        self.assertEqual(parser['first_two_bytes'], 0x0102)

        parser = ParserBinary(b'\x01\x02\x03')
        parser.parse_numeric('first_two_bytes', 3)
        self.assertEqual(parser['first_two_bytes'], 0x010203)

        parser = ParserBinary(b'\x01\x02\x03\x04')
        parser.parse_numeric('first_four_bytes', 4)
        self.assertEqual(parser['first_four_bytes'], 0x01020304)

    def test_parse_byte_order(self):
        parser = ParserBinary(b'\x01\x02\x03\x04', byte_order=ByteOrder.BIG_ENDIAN)
        parser.parse_numeric('number', 4)
        self.assertEqual(parser['number'], 0x01020304)

        parser = ParserBinary(b'\x01\x02\x03\x04', byte_order=ByteOrder.LITTLE_ENDIAN)
        parser.parse_numeric('number', 4)
        self.assertEqual(parser['number'], 0x04030201)

        parser = ParserBinary(b'\x01\x02\x03\x04', byte_order=ByteOrder.NETWORK)
        parser.parse_numeric('number', 4)
        self.assertEqual(parser['number'], 0x01020304)

    def test_parse_numeric_flags(self):
        parser = ParserBinary(b'\x01')
        parser.parse_numeric_flags('flags', 1, FlagEnum)
        self.assertEqual(parser['flags'], [FlagEnum.ONE, ])

        parser = ParserBinary(b'\x03')
        parser.parse_numeric_flags('flags', 1, FlagEnum)
        self.assertEqual(parser['flags'], [FlagEnum.ONE, FlagEnum.TWO])

    def test_parse_numeric_array(self):
        parser = ParserBinary(b'\x01\x02')
        parser.parse_numeric_array('one_byte_array', item_num=2, item_size=1)
        self.assertEqual(parser['one_byte_array'], [1, 2])

        parser = ParserBinary(b'\x00\x01\x00\x02')
        parser.parse_numeric_array('two_byte_array', item_num=2, item_size=2)
        self.assertEqual(parser['two_byte_array'], [1, 2])

        parser = ParserBinary(b'\x00\x00\x01\x00\x00\x02')
        parser.parse_numeric_array('three_byte_array', item_num=2, item_size=3)
        self.assertEqual(parser['three_byte_array'], [1, 2])

        parser = ParserBinary(b'\x00\x00\x00\x01\x00\x00\x00\x02')
        parser.parse_numeric_array('four_byte_array', item_num=2, item_size=4)
        self.assertEqual(parser['four_byte_array'], [1, 2])

    def test_parse_byte_array(self):
        parser = ParserBinary(b'\x01\x02')
        parser.parse_bytes('two_byte_array', size=2)
        self.assertEqual(parser['two_byte_array'], b'\x01\x02')

    def test_parse_parsable(self):
        parser = ParserBinary(b'\x01\x02\x03\x04')

        parser.parse_parsable('first_byte', OneByteParsable)
        self.assertEqual(
            b'\x01',
            parser['first_byte'].compose()
        )

        parser.parse_parsable('second_byte', OneByteParsable)
        self.assertEqual(
            b'\x02',
            parser['second_byte'].compose()
        )

    def test_parse_parsable_array(self):
        parser = ParserBinary(b'\x01\x02\x03\x04')
        parser.parse_parsable_array('array', items_size=4, item_class=OneByteParsable)
        self.assertEqual(
            [0x01, 0x02, 0x03, 0x04],
            list(map(int, parser['array']))
        )

        parser = ParserBinary(b'\x01\x02\x03\x04')
        parser.parse_parsable_array('array', items_size=4, item_class=TwoByteParsable)
        self.assertEqual(
            [0x0102, 0x0304],
            list(map(int, parser['array']))
        )

        parser = ParserBinary(b'\x01\x02')
        with self.assertRaises(InvalidValue):
            parser.parse_parsable_array('array', items_size=2, item_class=OneByteOddParsable)

        parser = ParserBinary(b'\x00')
        with self.assertRaises(NotEnoughData) as context_manager:
            parser.parse_parsable_array('array', items_size=3, item_class=OneByteOddParsable)
        self.assertEqual(context_manager.exception.bytes_needed, 2)

    def test_parse_parsable_derived_array(self):
        parser = ParserBinary(b'\x01\x02\x00')
        parser.parse_parsable_derived_array(
            'array',
            items_size=3,
            item_base_class=ConditionalParsable,
            fallback_class=None
        )
        self.assertEqual(
            [0x01, 0x0200],
            list(map(int, parser['array']))
        )
        self.assertEqual(parser.unparsed_length, 0)
        self.assertEqual(parser.unparsed, b'')

        parser = ParserBinary(b'\x00\x01')
        with self.assertRaises(InvalidValue):
            parser.parse_parsable_derived_array(
                'array',
                items_size=2,
                item_base_class=ConditionalParsable,
                fallback_class=None
            )

        parser = ParserBinary(b'\x00\x01')
        parser.parse_parsable_derived_array(
            'array',
            items_size=2,
            item_base_class=ConditionalParsable,
            fallback_class=TwoByteParsable
        )
        self.assertEqual(
            [0x01, ],
            list(map(int, parser['array']))
        )
        self.assertEqual(parser.unparsed_length, 0)
        self.assertEqual(parser.unparsed, b'')

    def test_parse_variant_parsable(self):
        AlwaysInvalidTypeVariantParsable.register_variant_parser(SerializableEnumFactory, SerializableEnumFactory)
        self.assertEqual(
            AlwaysInvalidTypeVariantParsable.parse_exact_size(b'\x00\x01').value,
            AlwaysInvalidTypeVariantParsable(SerializableEnum.first).variant.value
        )


class TestComposerBinary(unittest.TestCase):
    def test_error(self):
        composer = ComposerBinary()

        for size in (1, 2, 4):
            min_value = 0
            max_value = 2 ** (size * 8)

            with self.assertRaises(InvalidValue) as context_manager:
                composer.compose_numeric(max_value + 1, size)
            self.assertEqual(context_manager.exception.value, max_value + 1)

            with self.assertRaises(InvalidValue) as context_manager:
                composer.compose_numeric(min_value - 1, size)
            self.assertEqual(context_manager.exception.value, min_value - 1)

    def test_compose_numeric_to_right_size(self):
        composer = ComposerBinary()
        composer.compose_numeric(0x01, 1)
        self.assertEqual(composer.composed_bytes, b'\x01')

        composer = ComposerBinary()
        composer.compose_numeric(0x01, 2)
        self.assertEqual(composer.composed_bytes, b'\x00\x01')

        composer = ComposerBinary()
        composer.compose_numeric(0x01, 3)
        self.assertEqual(composer.composed_bytes, b'\x00\x00\x01')

        composer = ComposerBinary()
        composer.compose_numeric(0x01, 4)
        self.assertEqual(composer.composed_bytes, b'\x00\x00\x00\x01')

    def test_compose_numeric_to_rigth_order(self):
        composer = ComposerBinary()
        composer.compose_numeric(0x01, 1)
        self.assertEqual(composer.composed_bytes, b'\x01')

        composer = ComposerBinary()
        composer.compose_numeric(0x0102, 2)
        self.assertEqual(composer.composed_bytes, b'\x01\x02')

        composer = ComposerBinary()
        composer.compose_numeric(0x010203, 3)
        self.assertEqual(composer.composed_bytes, b'\x01\x02\x03')

        composer = ComposerBinary()
        composer.compose_numeric(0x01020304, 4)
        self.assertEqual(composer.composed_bytes, b'\x01\x02\x03\x04')

    def test_compose_byte_order(self):
        composer = ComposerBinary(byte_order=ByteOrder.BIG_ENDIAN)
        composer.compose_numeric(0x01020304, 4)
        self.assertEqual(composer.composed_bytes, b'\x01\x02\x03\x04')

        composer = ComposerBinary(byte_order=ByteOrder.LITTLE_ENDIAN)
        composer.compose_numeric(0x01020304, 4)
        self.assertEqual(composer.composed_bytes, b'\x04\x03\x02\x01')

        composer = ComposerBinary(byte_order=ByteOrder.NETWORK)
        composer.compose_numeric(0x01020304, 4)
        self.assertEqual(composer.composed_bytes, b'\x01\x02\x03\x04')

    def test_compose_numeric_array(self):
        composer = ComposerBinary()
        composer.compose_numeric_array(values=[1, 2, 3, 4], item_size=1)
        self.assertEqual(composer.composed_bytes, b'\x01\x02\x03\x04')

        composer = ComposerBinary()
        composer.compose_numeric_array(values=[1, 2, 3, 4], item_size=2)
        self.assertEqual(composer.composed_bytes, b'\x00\x01\x00\x02\x00\x03\x00\x04')

        composer = ComposerBinary()
        composer.compose_numeric_array(values=[1, 2, 3, 4], item_size=3)
        self.assertEqual(composer.composed_bytes, b'\x00\x00\x01\x00\x00\x02\x00\x00\x03\x00\x00\x04')

        composer = ComposerBinary()
        composer.compose_numeric_array(values=[1, 2, 3, 4], item_size=4)
        self.assertEqual(composer.composed_bytes, b'\x00\x00\x00\x01\x00\x00\x00\x02\x00\x00\x00\x03\x00\x00\x00\x04')

    def test_compose_numeric_flags(self):
        composer = ComposerBinary()
        composer.compose_numeric_flags([FlagEnum.ONE, ], 1)
        self.assertEqual(composer.composed_bytes, b'\x01')

        composer = ComposerBinary()
        composer.compose_numeric_flags([FlagEnum.ONE, FlagEnum.TWO, ], 1)
        self.assertEqual(composer.composed_bytes, b'\x03')

    def test_compose_bytes(self):
        composer = ComposerBinary()

        composer.compose_bytes(b'\x01\x02\x03\x04')

        self.assertEqual(composer.composed_bytes, b'\x01\x02\x03\x04')

    def test_compose_multiple(self):
        composer = ComposerBinary()

        one_byte_parsable = OneByteParsable(0x01)
        composer.compose_parsable(one_byte_parsable)
        self.assertEqual(composer.composed_bytes, b'\x01')

        composer.compose_numeric(0x02, 1)
        self.assertEqual(composer.composed_bytes, b'\x01\x02')
        self.assertEqual(composer.composed_length, 2)

        composer.compose_numeric(0x0304, 2)
        self.assertEqual(composer.composed_bytes, b'\x01\x02\x03\x04')
        self.assertEqual(composer.composed_length, 4)

        composer.compose_numeric(0x050607, 3)
        self.assertEqual(composer.composed_bytes, b'\x01\x02\x03\x04\x05\x06\x07')
        self.assertEqual(composer.composed_length, 7)

        composer.compose_numeric(0x08090a0b, 4)
        self.assertEqual(composer.composed_bytes, b'\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b')
        self.assertEqual(composer.composed_length, 11)

    def test_compose_parsable_array(self):
        composer = ComposerBinary()
        parsable_array = [OneByteParsable(0x01), TwoByteParsable(0x0203), ]
        composer.compose_parsable_array(parsable_array)

        self.assertEqual(
            b'\x01\x02\x03',
            composer.composed_bytes
        )

    def test_compose_enum(self):
        composer = ComposerBinary()
        composer.compose_parsable(SerializableEnum.second)
        self.assertEqual(b'\x00\x02', composer.composed_bytes)

    def test_compose_variant_parsable(self):
        composer = ComposerBinary()
        composer.compose_parsable(SerializableEnumVariantParsable(SerializableEnum.first))
        self.assertEqual(b'\x00\x01', composer.composed_bytes)
