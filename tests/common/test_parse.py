#!/usr/bin/env python
# -*- coding: utf-8 -*-

import unittest

from cryptoparser.common.exception import NotEnoughData, TooMuchData, InvalidValue
from cryptoparser.common.parse import ParserBinary, ParserText, ParsableBase, ComposerBinary, ComposerText

from tests.common.classes import OneByteParsable, TwoByteParsable, ConditionalParsable, OneByteOddParsable


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

    def test_parse(self):
        _, unparsed_bytes = OneByteParsable.parse_immutable(b'\x01\x02')
        self.assertEqual(unparsed_bytes, b'\x02')

        parsable = bytearray([0x01, 0x02])
        OneByteParsable.parse_mutable(parsable)
        self.assertEqual(parsable, b'\x02')


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
        self.assertEqual(context_manager.exception.bytes_needed, 5)

        parser = ParserBinary(b'\x00\x00\x00\x00\x00')
        with self.assertRaises(NotImplementedError):
            parser.parse_numeric('five_byte_numeric', 5)

        parser = ParserBinary(b'\xff\xff')
        with self.assertRaises(InvalidValue):
            parser.parse_numeric('two_byte_numeric', 2, OneByteParsable)

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

    def test_parse_parsable_derived(self):
        parser = ParserBinary(b'\x01')
        parser.parse_parsable_derived(
            'parsable',
            item_base_class=ConditionalParsable,
            fallback_class=None
        )
        self.assertEqual(OneByteOddParsable(0x01), parser['parsable'])
        self.assertEqual(parser.unparsed_length, 0)

        parser = ParserBinary(b'\x00\x01')
        with self.assertRaises(InvalidValue):
            parser.parse_parsable_derived(
                'array',
                item_base_class=ConditionalParsable,
                fallback_class=None
            )

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


class TestParserText(unittest.TestCase):
    _ALPHA_BETA_GAMMA_HASHMARK = bytes(u'αβγ#', 'utf-8')

    def test_error(self):
        pass

    def test_separator(self):
        parser = ParserText(b';')
        self.assertEqual(parser.unparsed_length, 1)

        parser.parse_separator(';')
        self.assertEqual(parser.unparsed_length, 0)

        parser = ParserText(b';;')
        with self.assertRaises(InvalidValue) as context_manager:
            parser.parse_separator(';', max_length=1)
        self.assertEqual(context_manager.exception.value, b';;')
        with self.assertRaises(InvalidValue) as context_manager:
            parser.parse_separator(';', min_length=3)
        self.assertEqual(context_manager.exception.value, b';;')

    def test_parse_numeric(self):
        parser = ParserText(b'1#')
        parser.parse_numeric('number')
        self.assertEqual(parser['number'], 1)

        parser = ParserText(b'NaN')
        with self.assertRaises(InvalidValue) as context_manager:
            parser.parse_numeric('number')
        self.assertEqual(context_manager.exception.value, b'NaN')

        parser = ParserText(b'1a')
        parser.parse_numeric('number')
        self.assertEqual(parser['number'], 1)
        self.assertEqual(parser.unparsed_length, 1)

        parser = ParserText(b'1.2#')
        parser.parse_numeric_array('number', 2, '.')
        self.assertEqual(parser['number'], [1, 2])

        parser = ParserText(b'1#')
        with self.assertRaises(InvalidValue) as context_manager:
            parser.parse_numeric_array('number', 2, '.')
        self.assertEqual(context_manager.exception.value, b'1')

    def test_parse_string_until_separator(self):
        parser = ParserText(b'a#')
        parser.parse_string_until_separator('string', '#')
        self.assertEqual(parser['string'], 'a')
        self.assertEqual(parser.unparsed_length, 1)

        parser = ParserText(b'12#')
        parser.parse_string_until_separator('number', '#', int)
        self.assertEqual(parser['number'], 12)
        self.assertEqual(parser.unparsed_length, 1)

        parser = ParserText(self._ALPHA_BETA_GAMMA_HASHMARK, 'utf-8')
        parser.parse_string_until_separator('alphabet', '#')
        self.assertEqual(parser['alphabet'], u'αβγ')
        self.assertEqual(parser.unparsed_length, 1)

        parser = ParserText(b'ab')
        with self.assertRaises(InvalidValue) as context_manager:
            parser.parse_string_until_separator('string', '#')
        self.assertEqual(context_manager.exception.value, b'ab')

        parser = ParserText(b'ab')
        with self.assertRaises(InvalidValue) as context_manager:
            parser.parse_string_until_separator('string', '#')
        self.assertEqual(context_manager.exception.value, b'ab')

        parser = ParserText(b'12a#')
        with self.assertRaises(InvalidValue) as context_manager:
            parser.parse_string_until_separator('string', '#', int)
        self.assertEqual(context_manager.exception.value, b'12a#')

        parser = ParserText(self._ALPHA_BETA_GAMMA_HASHMARK, 'ascii')
        with self.assertRaises(InvalidValue) as context_manager:
            parser.parse_string_until_separator('alphabet', '#')
        self.assertEqual(context_manager.exception.value, self._ALPHA_BETA_GAMMA_HASHMARK)

    def test_parse_string_until_separator_or_end(self):
        parser = ParserText(b'ab')
        parser.parse_string_until_separator_or_end('string', '#')
        self.assertEqual(parser['string'], 'ab')
        self.assertEqual(parser.unparsed_length, 0)

        parser = ParserText(b'12')
        parser.parse_string_until_separator_or_end('number', '#', int)
        self.assertEqual(parser['number'], 12)
        self.assertEqual(parser.unparsed_length, 0)

        parser = ParserText(b'a#b')
        parser.parse_string_until_separator_or_end('string', '#')
        self.assertEqual(parser['string'], 'a')
        self.assertEqual(parser.unparsed_length, 2)

    def test_parse_string_by_length(self):
        parser = ParserText(b'abc')
        parser.parse_string_by_length('string', 1, None)
        self.assertEqual(parser['string'], 'abc')
        self.assertEqual(parser.unparsed_length, 0)

        parser = ParserText(b'12')
        parser.parse_string_by_length('number', 1, None, int)
        self.assertEqual(parser['number'], 12)
        self.assertEqual(parser.unparsed_length, 0)

        parser = ParserText(b'12ab')
        parser.parse_string_by_length('string', 1, 2, int)
        self.assertEqual(parser['string'], 12)
        self.assertEqual(parser.unparsed_length, 2)

        parser = ParserText(b'12')
        with self.assertRaises(NotEnoughData) as context_manager:
            parser.parse_string_by_length('string', 3, 3)
        self.assertEqual(context_manager.exception.bytes_needed, 1)

        parser = ParserText(b'12ab')
        with self.assertRaises(InvalidValue) as context_manager:
            parser.parse_string_by_length('string', 3, 4, int)
        self.assertEqual(context_manager.exception.value, b'12ab')

        parser = ParserText(self._ALPHA_BETA_GAMMA_HASHMARK, 'ascii')
        with self.assertRaises(InvalidValue) as context_manager:
            parser.parse_string_by_length('alphabet')
        self.assertEqual(context_manager.exception.value, self._ALPHA_BETA_GAMMA_HASHMARK)

    def test_parse_string_array(self):
        parser = ParserText(b'a,b')
        parser.parse_string_array('array', ',')
        self.assertEqual(parser['array'], ['a', 'b'])
        self.assertEqual(parser.unparsed_length, 0)


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
        self.assertEqual(composer.composed, b'\x01')

        composer = ComposerBinary()
        composer.compose_numeric(0x01, 2)
        self.assertEqual(composer.composed, b'\x00\x01')

        composer = ComposerBinary()
        composer.compose_numeric(0x01, 3)
        self.assertEqual(composer.composed, b'\x00\x00\x01')

        composer = ComposerBinary()
        composer.compose_numeric(0x01, 4)
        self.assertEqual(composer.composed, b'\x00\x00\x00\x01')

    def test_compose_numeric_to_rigth_order(self):
        composer = ComposerBinary()
        composer.compose_numeric(0x01, 1)
        self.assertEqual(composer.composed, b'\x01')

        composer = ComposerBinary()
        composer.compose_numeric(0x0102, 2)
        self.assertEqual(composer.composed, b'\x01\x02')

        composer = ComposerBinary()
        composer.compose_numeric(0x010203, 3)
        self.assertEqual(composer.composed, b'\x01\x02\x03')

        composer = ComposerBinary()
        composer.compose_numeric(0x01020304, 4)
        self.assertEqual(composer.composed, b'\x01\x02\x03\x04')

    def test_compose_numeric_array(self):
        composer = ComposerBinary()
        composer.compose_numeric_array(values=[1, 2, 3, 4], item_size=1)
        self.assertEqual(composer.composed, b'\x01\x02\x03\x04')

        composer = ComposerBinary()
        composer.compose_numeric_array(values=[1, 2, 3, 4], item_size=2)
        self.assertEqual(composer.composed, b'\x00\x01\x00\x02\x00\x03\x00\x04')

        composer = ComposerBinary()
        composer.compose_numeric_array(values=[1, 2, 3, 4], item_size=3)
        self.assertEqual(composer.composed, b'\x00\x00\x01\x00\x00\x02\x00\x00\x03\x00\x00\x04')

        composer = ComposerBinary()
        composer.compose_numeric_array(values=[1, 2, 3, 4], item_size=4)
        self.assertEqual(composer.composed, b'\x00\x00\x00\x01\x00\x00\x00\x02\x00\x00\x00\x03\x00\x00\x00\x04')

    def test_compose_bytes(self):
        composer = ComposerBinary()

        composer.compose_bytes(b'\x01\x02\x03\x04')

        self.assertEqual(composer.composed, b'\x01\x02\x03\x04')

    def test_compose_multiple(self):
        composer = ComposerBinary()

        one_byte_parsable = OneByteParsable(0x01)
        composer.compose_parsable(one_byte_parsable)
        self.assertEqual(composer.composed, b'\x01')

        composer.compose_numeric(0x02, 1)
        self.assertEqual(composer.composed, b'\x01\x02')
        self.assertEqual(composer.composed_length, 2)

        composer.compose_numeric(0x0304, 2)
        self.assertEqual(composer.composed, b'\x01\x02\x03\x04')
        self.assertEqual(composer.composed_length, 4)

        composer.compose_numeric(0x050607, 3)
        self.assertEqual(composer.composed, b'\x01\x02\x03\x04\x05\x06\x07')
        self.assertEqual(composer.composed_length, 7)

        composer.compose_numeric(0x08090a0b, 4)
        self.assertEqual(composer.composed, b'\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b')
        self.assertEqual(composer.composed_length, 11)

    def test_compose_parsable_array(self):
        composer = ComposerBinary()
        parsable_array = [OneByteParsable(0x01), TwoByteParsable(0x0203), ]
        composer.compose_parsable_array(parsable_array)

        self.assertEqual(
            b'\x01\x02\x03',
            composer.composed
        )


class TestComposerText(unittest.TestCase):
    _ALPHA_BETA_GAMMA_HASHMARK = u'αβγ'

    def test_compose_numeric(self):
        composer = ComposerText()

        composer.compose_numeric(1)
        self.assertEqual(composer.composed, b'1')

        composer.compose_numeric(2)
        self.assertEqual(composer.composed, b'12')
        self.assertEqual(composer.composed_length, 2)

    def test_compose_numeric_array(self):
        composer = ComposerText()

        composer.compose_numeric_array([1, 2], separator=',')
        self.assertEqual(composer.composed, b'1,2')
        self.assertEqual(composer.composed_length, 3)

    def test_compose_string(self):
        composer = ComposerText()

        composer.compose_string('abc')
        self.assertEqual(composer.composed, b'abc')
        self.assertEqual(composer.composed_length, 3)

        composer = ComposerText('utf-8')
        for index, char in enumerate(self._ALPHA_BETA_GAMMA_HASHMARK):
            composer.compose_string(char)
            expected_composed = bytes(self._ALPHA_BETA_GAMMA_HASHMARK[0:index + 1], 'utf-8')
            self.assertEqual(composer.composed, expected_composed)
            self.assertEqual(composer.composed_length, (index + 1) * 2)

        composer = ComposerText()
        with self.assertRaises(InvalidValue) as context_manager:
            composer.compose_string(self._ALPHA_BETA_GAMMA_HASHMARK)

    def test_compose_string_array(self):
        composer = ComposerText()

        composer.compose_string_array(['a', 'b', 'c'], '#')
        self.assertEqual(composer.composed, b'a#b#c')
        self.assertEqual(composer.composed_length, 5)

        composer = ComposerText('utf-8')
        composer.compose_string_array(list(self._ALPHA_BETA_GAMMA_HASHMARK), '')
        self.assertEqual(composer.composed, bytes(self._ALPHA_BETA_GAMMA_HASHMARK, 'utf-8'))
        self.assertEqual(composer.composed_length, len(self._ALPHA_BETA_GAMMA_HASHMARK) * 2)

    def test_compose_separator(self):
        composer = ComposerText()

        composer.compose_separator('#')
        self.assertEqual(composer.composed, b'#')
        composer.compose_separator('string')
        self.assertEqual(composer.composed, b'#string')
        composer.compose_separator('#')
        self.assertEqual(composer.composed, b'#string#')

        composer = ComposerText('utf-8')

        composer.compose_separator(self._ALPHA_BETA_GAMMA_HASHMARK)
        self.assertEqual(composer.composed, bytes(self._ALPHA_BETA_GAMMA_HASHMARK, 'utf-8'))
