# -*- coding: utf-8 -*-
# pylint: disable=too-many-lines

import datetime
import unittest
from unittest import mock

import asn1crypto.x509

from cryptodatahub.common.exception import InvalidValue
from cryptoparser.common.exception import NotEnoughData, TooMuchData, InvalidType
from cryptoparser.common.parse import ParserBinary, ParserText, ParsableBase, ComposerBinary, ComposerText, ByteOrder
from cryptoparser.tls.ciphersuite import TlsCipherSuiteFactory

from .classes import (
    AlwaysInvalidTypeVariantParsable,
    AlwaysTestStringComposer,
    ConditionalParsable,
    FlagEnum,
    OneByteOddParsable,
    OneByteParsable,
    SerializableEnum,
    SerializableEnumFactory,
    SerializableEnumVariantParsable,
    StringEnum,
    TwoByteParsable,
)


class TestParsableBase(unittest.TestCase):
    _ALPHA_BETA_GAMMA = 'αβγ'
    _ALPHA_BETA_GAMMA_BYTES = 'αβγ'.encode('utf-8')
    _ALPHA_BETA_GAMMA_LEN_BYTES = bytes((len(_ALPHA_BETA_GAMMA_BYTES),))

    _ALPHA_BETA_GAMMA_HASHMARK_BYTES = 'αβγ#'.encode('utf-8')


class TestParsable(TestParsableBase):
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
        _, parsed_length = OneByteParsable.parse_immutable(b'\x01\x02')
        self.assertEqual(parsed_length, 1)

        parsable = bytearray([0x01, 0x02])
        OneByteParsable.parse_mutable(parsable)
        self.assertEqual(parsable, b'\x02')

        parsed_value, parsed_length = SerializableEnumFactory.parse_immutable(b'\x00\x01')
        self.assertEqual(parsed_value, SerializableEnum.FIRST)
        self.assertEqual(parsed_length, 2)

    def test_repr(self):
        self.assertEqual(repr(SerializableEnum.FIRST), 'SerializableEnum.FIRST')
        AlwaysInvalidTypeVariantParsable.register_variant_parser(SerializableEnumFactory, SerializableEnumFactory)


class TestParserBase(TestParsableBase):
    def test_mapping(self):
        parser = ParserBinary(b'\x01\x02')
        self.assertEqual(len(parser), 0)
        self.assertEqual(parser.parsed_length, 0)
        self.assertEqual(parser.unparsed_length, 2)
        self.assertEqual(dict(parser), {})

        parser.parse_numeric('first_byte', 1)
        self.assertEqual(len(parser), 1)
        self.assertEqual(parser.parsed_length, 1)
        self.assertEqual(parser.unparsed_length, 1)
        self.assertEqual(dict(parser), {'first_byte': 1})

        parser.parse_numeric('second_byte', 1)
        self.assertEqual(len(parser), 2)
        self.assertEqual(parser.parsed_length, 2)
        self.assertEqual(parser.unparsed_length, 0)
        self.assertEqual(dict(parser), {'first_byte': 1, 'second_byte': 2})


class TestParserBinary(TestParsableBase):
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

        parser = ParserBinary(b'\x01\xff')
        with self.assertRaises(InvalidValue) as context_manager:
            parser.parse_bytes('one_byte_array', 1, converter=mock.Mock(name='mock', side_effect=ValueError))
        self.assertEqual(context_manager.exception.value, 1)

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

        parser = ParserBinary(b'\x01\x02\x03', byte_order=ByteOrder.BIG_ENDIAN)
        parser.parse_numeric('number', 3)
        self.assertEqual(parser['number'], 0x010203)

        parser = ParserBinary(b'\x01\x02\x03', byte_order=ByteOrder.LITTLE_ENDIAN)
        parser.parse_numeric('number', 3)
        self.assertEqual(parser['number'], 0x030201)

        parser = ParserBinary(b'\x01\x02\x03', byte_order=ByteOrder.NETWORK)
        parser.parse_numeric('number', 3)
        self.assertEqual(parser['number'], 0x010203)

    def test_parse_numeric_flags(self):
        parser = ParserBinary(b'\x01')
        parser.parse_numeric_flags('flags', 1, FlagEnum)
        self.assertEqual(parser['flags'], {FlagEnum.ONE, })

        parser = ParserBinary(b'\x03')
        parser.parse_numeric_flags('flags', 1, FlagEnum)
        self.assertEqual(parser['flags'], {FlagEnum.ONE, FlagEnum.TWO})

    def test_parse_mpint(self):
        parser = ParserBinary(b'\x00\x00\x00\x00')
        parser.parse_mpint('mpint', 4)
        self.assertEqual(parser['mpint'], 0)

        parser = ParserBinary(b'\x09\xa3\x78\xf9\xb2\xe3\x32\xa7')
        parser.parse_mpint('mpint', 8)
        self.assertEqual(parser['mpint'], 0x9a378f9b2e332a7)

        parser = ParserBinary(b'\x00\x80')
        parser.parse_mpint('mpint', 2)
        self.assertEqual(parser['mpint'], 0x80)

        parser = ParserBinary(b'\xed\xcc')
        parser.parse_mpint('mpint', 2)
        self.assertEqual(parser['mpint'], 0xedcc)

        parser = ParserBinary(b'\xff\x21\x52\x41\x11')
        parser.parse_mpint('mpint', 5)
        self.assertEqual(parser['mpint'], 0xff21524111)

    def test_parse_ssh_mpint(self):
        parser = ParserBinary(b'\x00')
        with self.assertRaises(NotEnoughData) as context_manager:
            parser.parse_ssh_mpint('mpint')
        self.assertEqual(context_manager.exception.bytes_needed, 3)

        parser = ParserBinary(b'\x00\x00\x00\x00')
        parser.parse_ssh_mpint('mpint')
        self.assertEqual(parser['mpint'], 0)

        parser = ParserBinary(b'\x00\x00\x00\x08\x09\xa3\x78\xf9\xb2\xe3\x32\xa7')
        parser.parse_ssh_mpint('mpint')
        self.assertEqual(parser['mpint'], 0x9a378f9b2e332a7)

        parser = ParserBinary(b'\x00\x00\x00\x02\x00\x80')
        parser.parse_ssh_mpint('mpint')
        self.assertEqual(parser['mpint'], 0x80)

        parser = ParserBinary(b'\x00\x00\x00\x02\xed\xcc')
        parser.parse_ssh_mpint('mpint')
        self.assertEqual(parser['mpint'], -0x1234)

        parser = ParserBinary(b'\x00\x00\x00\x05\xff\x21\x52\x41\x11')
        parser.parse_ssh_mpint('mpint')
        self.assertEqual(parser['mpint'], -0xdeadbeef)

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
        parser.parse_raw('two_byte_array', size=2)
        self.assertEqual(parser['two_byte_array'], b'\x01\x02')

        parser = ParserBinary(b'not X.509 certificate')
        with self.assertRaises(InvalidValue) as context_manager:
            parser.parse_raw('name', 21, asn1crypto.x509.Certificate.load)
        self.assertEqual(context_manager.exception.value, b'not X.509 certificate')

    def test_parse_string(self):
        parser = ParserBinary(b'\x02\xff\xff')
        with self.assertRaises(InvalidValue):
            parser.parse_string('non-utf-8-string', 1, 'utf-8')

        parser = ParserBinary(self._ALPHA_BETA_GAMMA_LEN_BYTES + self._ALPHA_BETA_GAMMA_BYTES)
        parser.parse_string('utf-8-string', 1, 'utf-8')
        self.assertEqual(parser['utf-8-string'], self._ALPHA_BETA_GAMMA)

    def test_parse_string_null_terminated(self):
        parser = ParserBinary(b'non-null-terminated-string')
        with self.assertRaises(InvalidValue) as context_manager:
            parser.parse_string_null_terminated('non-utf-8-string', 1, 'utf-8')
        self.assertEqual(context_manager.exception.value, b'non-null-terminated-string')

        parser = ParserBinary(b'1\x00')
        parser.parse_string_null_terminated('one-byte-string', 'utf-8', int)
        self.assertEqual(parser['one-byte-string'], 1)

        parser = ParserBinary(self._ALPHA_BETA_GAMMA_BYTES + b'\x00remaining-data')
        parser.parse_string_null_terminated('utf-8-string', 'utf-8')
        self.assertEqual(parser['utf-8-string'], self._ALPHA_BETA_GAMMA)
        self.assertEqual(parser.unparsed, b'remaining-data')

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

        parser = ParserBinary(b'\x01\x02')
        parser.parse_parsable('byte', OneByteParsable, 1)
        self.assertEqual(
            b'\x02',
            parser['byte'].compose()
        )

        parser = ParserBinary(b'\x02\x01\x02')
        with self.assertRaises(TooMuchData) as context_manager:
            parser.parse_parsable('byte', OneByteParsable, 1)
        self.assertEqual(context_manager.exception.bytes_needed, 1)

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
            AlwaysInvalidTypeVariantParsable(SerializableEnum.FIRST).variant.value
        )

    def test_parse_timestamp(self):
        parser = ParserBinary(b'\x00\x00\x00\x00\x00\x00\x00\x00')
        parser.parse_timestamp('timestamp')
        self.assertEqual(parser['timestamp'], datetime.datetime.fromtimestamp(0, datetime.timezone.utc))

        parser = ParserBinary(b'\x00\x00\x00\x00')
        parser.parse_timestamp('timestamp', item_size=4)
        self.assertEqual(parser['timestamp'], datetime.datetime.fromtimestamp(0, datetime.timezone.utc))

        parser = ParserBinary(b'\x00\x00\x00\x00\x00\x00\x00\xff')
        parser.parse_timestamp('timestamp', milliseconds=True)
        self.assertEqual(
            parser['timestamp'],
            datetime.datetime.fromtimestamp(0, datetime.timezone.utc) + datetime.timedelta(microseconds=255000)
        )

        parser = ParserBinary(b'\x00\x00\x00\xff')
        parser.parse_timestamp('timestamp', milliseconds=True, item_size=4)
        self.assertEqual(
            parser['timestamp'],
            datetime.datetime.fromtimestamp(0, datetime.timezone.utc) + datetime.timedelta(microseconds=255000)
        )

        parser = ParserBinary(b'\xff\xff\xff\xff\xff\xff\xff\xff')
        parser.parse_timestamp('timestamp')
        self.assertEqual(parser['timestamp'], None)

        parser = ParserBinary(b'\xff\xff\xff\xff')
        parser.parse_timestamp('timestamp', item_size=4)
        self.assertEqual(parser['timestamp'], None)

        parser = ParserBinary(b'\x00\x00\x00\x00\xff\xff\xff\xff')
        parser.parse_timestamp('timestamp')
        self.assertEqual(parser['timestamp'], datetime.datetime.fromtimestamp(0xffffffff, datetime.timezone.utc))

        parser = ParserBinary(b'\x00\x00\xff\xff')
        parser.parse_timestamp('timestamp', item_size=4)
        self.assertEqual(parser['timestamp'], datetime.datetime.fromtimestamp(0x0000ffff, datetime.timezone.utc))


class TestParserText(TestParsableBase):
    def test_error(self):
        parser = ParserText(b'\xff')
        with self.assertRaises(InvalidValue) as context_manager:
            parser.parse_string_until_separator('string', '#')
        self.assertEqual(context_manager.exception.value, b'\xff')

    def test_separator(self):
        parser = ParserText(b';')
        self.assertEqual(parser.unparsed_length, 1)

        parser.parse_separator(';')
        self.assertEqual(parser.unparsed_length, 0)

        parser = ParserText(b';;test;;')
        parser.parse_separator(';', max_length=None)
        self.assertEqual(parser.unparsed_length, 6)

        parser.parse_string_by_length('test', 4, 4)
        self.assertEqual(parser.unparsed_length, 2)

        parser.parse_separator(';', max_length=None)
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

    def test_parse_float(self):
        parser = ParserText(b'1.2#')
        parser.parse_float('number')
        self.assertEqual(parser['number'], 1.2)

        parser = ParserText(b'1.#')
        parser.parse_float('number')
        self.assertEqual(parser['number'], 1.0)

        parser = ParserText(b'1#')
        parser.parse_float('number')
        self.assertEqual(parser['number'], 1.0)

        parser = ParserText(b'NaN')
        with self.assertRaises(InvalidValue) as context_manager:
            parser.parse_float('number')
        self.assertEqual(context_manager.exception.value, b'NaN')

    def test_parse_string_until_separator(self):
        parser = ParserText(b'a#')
        parser.parse_string_until_separator('string', '#')
        self.assertEqual(parser['string'], 'a')
        self.assertEqual(parser.unparsed_length, 1)

        parser = ParserText(b'12#')
        parser.parse_string_until_separator('number', '#', int)
        self.assertEqual(parser['number'], 12)
        self.assertEqual(parser.unparsed_length, 1)

        parser = ParserText(b'three#one')
        parser.parse_string_until_separator('number', '#', StringEnum)
        self.assertEqual(parser['number'], StringEnum.THREE)
        self.assertEqual(parser.unparsed_length, 4)

        parser = ParserText(self._ALPHA_BETA_GAMMA_HASHMARK_BYTES, 'utf-8')
        parser.parse_string_until_separator('alphabet', '#')
        self.assertEqual(parser['alphabet'], 'αβγ')
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

        parser = ParserText(self._ALPHA_BETA_GAMMA_HASHMARK_BYTES, 'ascii')
        with self.assertRaises(InvalidValue) as context_manager:
            parser.parse_string_until_separator('alphabet', '#')
        self.assertEqual(context_manager.exception.value, self._ALPHA_BETA_GAMMA_HASHMARK_BYTES)

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

    def test_parse_string(self):
        parser = ParserText(b'abc')
        parser.parse_string('string', 'abc')
        self.assertEqual(parser['string'], 'abc')

        parser = ParserText(b'abcd')
        with self.assertRaises(InvalidValue) as context_manager:
            parser.parse_string('string', 'bcd')
        self.assertEqual(context_manager.exception.value, b'abc')

        parser = ParserText(b'abc')
        with self.assertRaises(InvalidValue) as context_manager:
            parser.parse_string('string', 'abcd')
        self.assertEqual(context_manager.exception.value, b'abc')

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
        self.assertEqual(context_manager.exception.value, '12ab')

        parser = ParserText(self._ALPHA_BETA_GAMMA_HASHMARK_BYTES, 'ascii')
        with self.assertRaises(InvalidValue) as context_manager:
            parser.parse_string_by_length('alphabet')
        self.assertEqual(context_manager.exception.value, self._ALPHA_BETA_GAMMA_HASHMARK_BYTES)

    def test_parse_bool(self):
        parser = ParserText(b'yes')
        parser.parse_bool('bool')
        self.assertEqual(parser['bool'], True)
        self.assertEqual(parser.unparsed_length, 0)

        parser = ParserText(b'no')
        parser.parse_bool('bool')
        self.assertEqual(parser['bool'], False)
        self.assertEqual(parser.unparsed_length, 0)

        parser = ParserText(b'abcd')
        with self.assertRaises(InvalidValue) as context_manager:
            parser.parse_bool('bool')
        self.assertEqual(context_manager.exception.value, b'abcd')


class TestParserTextStringArray(TestParsableBase):
    def test_empty(self):
        parser = ParserText(b'')
        parser.parse_string_array('array', ',', skip_empty=True)
        self.assertEqual(parser['array'], [])
        self.assertEqual(parser.unparsed_length, 0)

        parser = ParserText(b'')
        with self.assertRaises(InvalidValue) as context_manager:
            parser.parse_string_array('array', ',', skip_empty=False)
        self.assertEqual(context_manager.exception.value, b'')
        self.assertEqual(parser.unparsed_length, 0)

    def test_separator_only(self):
        parser = ParserText(b',,,')
        parser.parse_string_array('array', ',', skip_empty=True)
        self.assertEqual(parser['array'], [])
        self.assertEqual(parser.unparsed_length, 0)

        parser = ParserText(b',,,')
        with self.assertRaises(InvalidValue) as context_manager:
            parser.parse_string_array('array', ',', skip_empty=False)
        self.assertEqual(context_manager.exception.value, b',,,')
        self.assertEqual(parser.unparsed_length, 3)

    def test_space_only(self):
        parser = ParserText(b'  ')
        parser.parse_string_array('array', ',', separator_spaces=' ', skip_empty=True)
        self.assertEqual(parser['array'], [])
        self.assertEqual(parser.unparsed_length, 0)

        parser = ParserText(b'   ')
        with self.assertRaises(InvalidValue) as context_manager:
            parser.parse_string_array('array', ',', separator_spaces=' ')
        self.assertEqual(context_manager.exception.value, b'')
        self.assertEqual(parser.unparsed_length, 3)

    def test_separator_and_spaces(self):
        parser = ParserText(b'  ,  ,,  ,,,')
        parser.parse_string_array('array', ',', separator_spaces=' ', skip_empty=True)
        self.assertEqual(parser['array'], [])
        self.assertEqual(parser.unparsed_length, 0)

        parser = ParserText(b'  ,  ,,  ,,,')
        with self.assertRaises(InvalidValue) as context_manager:
            parser.parse_string_array('array', ',', separator_spaces=' ')
        self.assertEqual(context_manager.exception.value, b',  ,,  ,,,')
        self.assertEqual(parser.unparsed_length, 12)

    def test_one_character_separator(self):
        parser = ParserText(b'a,b')
        parser.parse_string_array('array', ',')
        self.assertEqual(parser['array'], ['a', 'b'])
        self.assertEqual(parser.unparsed_length, 0)

        parser = ParserText(b'a,b')
        parser.parse_string_array('array', ',', item_class=ord)
        self.assertEqual(parser['array'], [ord('a'), ord('b')])
        self.assertEqual(parser.unparsed_length, 0)

        parser = ParserText(b'one,two')
        parser.parse_string_array('array', ',', item_class=StringEnum)
        self.assertEqual(parser['array'], [StringEnum.ONE, StringEnum.TWO])
        self.assertEqual(parser.unparsed_length, 0)

    def test_separator_spaces(self):
        parser = ParserText(b' a; \tb\t;\t c')
        parser.parse_string_array('array', ';', separator_spaces=' \t')
        self.assertEqual(parser['array'], ['a', 'b', 'c'])
        self.assertEqual(parser.unparsed_length, 0)

        parser = ParserText(b' one; \ttwo\t;\t three')
        parser.parse_string_array('array', ';', item_class=StringEnum, separator_spaces=' \t')
        self.assertEqual(parser['array'], [StringEnum.ONE, StringEnum.TWO, StringEnum.THREE])
        self.assertEqual(parser.unparsed_length, 0)

        parser = ParserText(b' a \t b ; \tc')
        parser.parse_string_array('array', ';', separator_spaces='\t')
        self.assertEqual(parser['array'], [' a \t b ', ' \tc'])
        self.assertEqual(parser.unparsed_length, 0)

        parser = ParserText(b' a ')
        parser.parse_string_array('array', ';', separator_spaces=' ')
        self.assertEqual(parser['array'], ['a', ])
        self.assertEqual(parser.unparsed_length, 0)

        parser = ParserText(b' one ')
        parser.parse_string_array('array', ';', item_class=StringEnum, separator_spaces=' ')
        self.assertEqual(parser['array'], [StringEnum.ONE, ])
        self.assertEqual(parser.unparsed_length, 0)

    def test_starts_with_separator(self):
        parser = ParserText(b'; a; b; c')
        parser.parse_string_array('array', ';', separator_spaces=' ', skip_empty=True)
        self.assertEqual(parser['array'], ['a', 'b', 'c'])
        self.assertEqual(parser.unparsed_length, 0)

        parser = ParserText(b'; a; b; c')
        with self.assertRaises(InvalidValue) as context_manager:
            parser.parse_string_array('array', ';', separator_spaces=' ')
        self.assertEqual(context_manager.exception.value, b'; a; b; c')
        self.assertEqual(parser.unparsed_length, 9)

    def test_ends_with_separator(self):
        parser = ParserText(b'a; b; c; ')
        parser.parse_string_array('array', ';', separator_spaces=' ', skip_empty=True)
        self.assertEqual(parser['array'], ['a', 'b', 'c'])
        self.assertEqual(parser.unparsed_length, 0)

        parser = ParserText(b'one; two; three; ')
        parser.parse_string_array('array', ';', item_class=StringEnum, separator_spaces=' ', skip_empty=True)
        self.assertEqual(parser['array'], [StringEnum.ONE, StringEnum.TWO, StringEnum.THREE])
        self.assertEqual(parser.unparsed_length, 0)

    def test_ends_without_separator(self):
        parser = ParserText(b'a; b; c')
        parser.parse_string_array('array', ';', separator_spaces=' ', max_item_num=2)
        self.assertEqual(parser['array'], ['a', 'b'])
        self.assertEqual(parser.unparsed_length, 1)

        parser = ParserText(b'one; two; three')
        parser.parse_string_array('array', ';', item_class=StringEnum, separator_spaces=' ', max_item_num=2)
        self.assertEqual(parser['array'], [StringEnum.ONE, StringEnum.TWO])
        self.assertEqual(parser.unparsed_length, 5)


class TestParserTextDateTime(TestParsableBase):
    def test_parse_date_time(self):
        parser = ParserText(b'Wed, 21 Oct 2015 07:28:00 GMT')
        parser.parse_date_time('datetime')
        self.assertEqual(
            parser['datetime'],
            datetime.datetime(2015, 10, 21, 7, 28, tzinfo=datetime.timezone.utc)
        )
        self.assertEqual(parser.unparsed_length, 0)

        datetime_value = b'not a date'
        parser = ParserText(datetime_value)
        with self.assertRaises(InvalidValue) as context_manager:
            parser.parse_date_time('datetime')
        self.assertEqual(context_manager.exception.value, datetime_value)
        self.assertEqual(parser.unparsed_length, len(datetime_value))


class TestParserTextTimeDelta(TestParsableBase):
    def test_parse_time_delta(self):
        parser = ParserText(b'86400')
        parser.parse_time_delta('timedelta')
        self.assertEqual(parser['timedelta'], datetime.timedelta(1))
        self.assertEqual(parser.unparsed_length, 0)

        timedelta_value = str(int(datetime.timedelta.max.total_seconds())).encode('ascii')
        parser = ParserText(timedelta_value)
        with self.assertRaises(InvalidValue) as context_manager:
            parser.parse_time_delta('timedelta')
        self.assertEqual(
            context_manager.exception.value,
            int(datetime.timedelta.max.total_seconds())
        )
        self.assertEqual(parser.unparsed_length, len(timedelta_value))


class TestComposerBinary(TestParsableBase):
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

        composer = ComposerBinary(byte_order=ByteOrder.BIG_ENDIAN)
        composer.compose_numeric(0x010203, 3)
        self.assertEqual(composer.composed_bytes, b'\x01\x02\x03')

        composer = ComposerBinary(byte_order=ByteOrder.LITTLE_ENDIAN)
        composer.compose_numeric(0x010203, 3)
        self.assertEqual(composer.composed_bytes, b'\x03\x02\x01')

        composer = ComposerBinary(byte_order=ByteOrder.NETWORK)
        composer.compose_numeric(0x010203, 3)
        self.assertEqual(composer.composed_bytes, b'\x01\x02\x03')

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

    def test_compose_numeric_enum_coded(self):
        composer = ComposerBinary()
        composer.compose_numeric_enum_coded(SerializableEnum.FIRST)
        self.assertEqual(composer.composed_bytes, b'\x00\x01')

    def test_compose_numeric_array_enum_coded(self):
        composer = ComposerBinary()
        composer.compose_numeric_array_enum_coded(values=[])
        self.assertEqual(composer.composed_bytes, b'')

        composer = ComposerBinary()
        composer.compose_numeric_array_enum_coded(values=[
            SerializableEnum.FIRST,
            SerializableEnum.SECOND,
        ])
        self.assertEqual(composer.composed_bytes, b'\x00\x01\x00\x02')

    def test_compose_numeric_flags(self):
        composer = ComposerBinary()
        composer.compose_numeric_flags([FlagEnum.ONE, ], 1)
        self.assertEqual(composer.composed_bytes, b'\x01')

        composer = ComposerBinary()
        composer.compose_numeric_flags([FlagEnum.ONE, FlagEnum.TWO, ], 1)
        self.assertEqual(composer.composed_bytes, b'\x03')

    def test_compose_mpint(self):
        composer = ComposerBinary()
        with self.assertRaises(InvalidValue) as context_manager:
            composer.compose_mpint(1024, 1)
        self.assertEqual(context_manager.exception.value, 1)

        composer = ComposerBinary()
        composer.compose_mpint(1024, 2)
        self.assertEqual(composer.composed_bytes, b'\x04\x00')

        composer = ComposerBinary()
        composer.compose_mpint(1024, 10)
        self.assertEqual(composer.composed_bytes, b'\x00\x00\x00\x00\x00\x00\x00\x00\x04\x00')

        composer = ComposerBinary()
        composer.compose_mpint(-1024, 10)
        self.assertEqual(composer.composed_bytes, b'\xff\xff\xff\xff\xff\xff\xff\xff\xfc\x00')

        composer = ComposerBinary(byte_order=ByteOrder.LITTLE_ENDIAN)
        composer.compose_mpint(1000, 2)
        self.assertEqual(composer.composed_bytes, b'\xe8\x03')

        composer = ComposerBinary(byte_order=ByteOrder.LITTLE_ENDIAN)
        composer.compose_mpint(1000, 10)
        self.assertEqual(composer.composed_bytes, b'\xe8\x03\x00\x00\x00\x00\x00\x00\x00\x00')

        composer = ComposerBinary(byte_order=ByteOrder.LITTLE_ENDIAN)
        composer.compose_mpint(-1000, 10)
        self.assertEqual(composer.composed_bytes, b'\x18\xfc\xff\xff\xff\xff\xff\xff\xff\xff')

    def test_compose_ssh_mpint(self):
        composer = ComposerBinary()
        composer.compose_ssh_mpint(0)
        self.assertEqual(composer.composed_bytes, b'\x00\x00\x00\x00')

        composer = ComposerBinary()
        composer.compose_ssh_mpint(0x9a378f9b2e332a7)
        self.assertEqual(composer.composed_bytes, b'\x00\x00\x00\x08\x09\xa3\x78\xf9\xb2\xe3\x32\xa7')

        composer = ComposerBinary()
        composer.compose_ssh_mpint(0x80)
        self.assertEqual(composer.composed_bytes, b'\x00\x00\x00\x02\x00\x80')

        composer = ComposerBinary()
        composer.compose_ssh_mpint(-0x1234)
        self.assertEqual(composer.composed_bytes, b'\x00\x00\x00\x02\xed\xcc')

        composer = ComposerBinary()
        composer.compose_ssh_mpint(-0xdeadbeef)
        self.assertEqual(composer.composed_bytes, b'\x00\x00\x00\x05\xff\x21\x52\x41\x11')

    def test_compose_raw(self):
        composer = ComposerBinary()

        composer.compose_raw(b'\x01\x02\x03\x04')

        self.assertEqual(composer.composed_bytes, b'\x01\x02\x03\x04')

    def test_compose_string(self):
        composer = ComposerBinary()
        with self.assertRaises(InvalidValue) as context_manager:
            composer.compose_string(self._ALPHA_BETA_GAMMA, 'ascii', 1)
        self.assertEqual(context_manager.exception.value, self._ALPHA_BETA_GAMMA)

        composer = ComposerBinary()
        composer.compose_string(self._ALPHA_BETA_GAMMA, 'utf-8', 1)
        self.assertEqual(composer.composed_bytes[1:], self._ALPHA_BETA_GAMMA_BYTES)

    def test_compose_string_null_terminated(self):
        composer = ComposerBinary()
        with self.assertRaises(InvalidValue) as context_manager:
            composer.compose_string_null_terminated(self._ALPHA_BETA_GAMMA, 'ascii')
        self.assertEqual(context_manager.exception.value, self._ALPHA_BETA_GAMMA)

        composer = ComposerBinary()
        composer.compose_string_null_terminated(self._ALPHA_BETA_GAMMA, 'utf-8')
        self.assertEqual(composer.composed_bytes, self._ALPHA_BETA_GAMMA_BYTES + b'\x00')

    def test_compose_string_enum_coded(self):
        composer = ComposerBinary()
        composer.compose_string_enum_coded(StringEnum.ONE, 2)
        self.assertEqual(composer.composed_bytes, b'\x00\x03one')

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

    def test_compose_parsable(self):
        composer = ComposerText()
        composer.compose_parsable(StringEnum.THREE)
        composer.compose_parsable(StringEnum.ONE)
        self.assertEqual(composer.composed, b'threeone')

        composer = ComposerBinary()
        composer.compose_parsable(OneByteParsable(0x01))
        composer.compose_parsable(TwoByteParsable(0x0203))
        self.assertEqual(
            b'\x01\x02\x03',
            composer.composed_bytes
        )

    def test_compose_parsable_array(self):
        composer = ComposerText()
        with self.assertRaises(InvalidType):
            composer.compose_parsable_array([
                StringEnum.THREE,
                StringEnum.ONE,
                'four'
            ])

        composer = ComposerText()
        with self.assertRaises(InvalidType):
            composer.compose_parsable_array([
                StringEnum.THREE,
                StringEnum.ONE,
                'four'
            ], fallback_class=int)

        composer = ComposerText()
        composer.compose_parsable_array([
            StringEnum.THREE,
            StringEnum.ONE,
            'four'
        ], fallback_class=str)
        self.assertEqual(composer.composed, b'three,one,four')

        composer = ComposerBinary()
        parsable_array = [OneByteParsable(0x01), TwoByteParsable(0x0203), ]
        composer.compose_parsable_array(parsable_array)

        self.assertEqual(
            b'\x01\x02\x03',
            composer.composed_bytes
        )

    def test_compose_enum(self):
        composer = ComposerBinary()
        composer.compose_parsable(SerializableEnum.SECOND)
        self.assertEqual(b'\x00\x02', composer.composed_bytes)

        composer = ComposerBinary()
        composer.compose_parsable(SerializableEnum.FIRST, item_size=1)
        self.assertEqual(b'\x02\x00\x01', composer.composed_bytes)

    def test_compose_variant_parsable(self):
        composer = ComposerBinary()
        composer.compose_parsable(SerializableEnumVariantParsable(SerializableEnum.FIRST))
        self.assertEqual(b'\x00\x01', composer.composed_bytes)

    def test_compose_timestamp(self):
        composer = ComposerBinary()
        date_time = datetime.datetime.fromtimestamp(0, datetime.timezone.utc)
        composer.compose_timestamp(date_time)
        self.assertEqual(b'\x00\x00\x00\x00\x00\x00\x00\x00', composer.composed_bytes)

        composer = ComposerBinary()
        date_time = datetime.datetime.fromtimestamp(0, datetime.timezone.utc) + datetime.timedelta(microseconds=255000)
        composer.compose_timestamp(date_time, milliseconds=True)
        self.assertEqual(b'\x00\x00\x00\x00\x00\x00\x00\xff', composer.composed_bytes)

        composer = ComposerBinary()
        date_time = datetime.datetime.fromtimestamp(0xffffffff, datetime.timezone.utc)
        date_time.replace(tzinfo=None)
        composer.compose_timestamp(date_time)
        self.assertEqual(b'\x00\x00\x00\x00\xff\xff\xff\xff', composer.composed_bytes)

        composer = ComposerBinary()
        composer.compose_timestamp(None)
        self.assertEqual(b'\xff\xff\xff\xff\xff\xff\xff\xff', composer.composed_bytes)


class TestComposerText(TestParsableBase):
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
        for index, char in enumerate(self._ALPHA_BETA_GAMMA):
            composer.compose_string(char)
            expected_composed = self._ALPHA_BETA_GAMMA[0:index + 1].encode('utf-8')
            self.assertEqual(composer.composed, expected_composed)
            self.assertEqual(composer.composed_length, (index + 1) * 2)

        composer = ComposerText()
        with self.assertRaises(InvalidValue) as context_manager:
            composer.compose_string(self._ALPHA_BETA_GAMMA)
        self.assertEqual(context_manager.exception.value, self._ALPHA_BETA_GAMMA)

    def test_compose_string_array(self):
        composer = ComposerText()

        composer.compose_string_array(['a', 'b', 'c'], '#')
        self.assertEqual(composer.composed, b'a#b#c')
        self.assertEqual(composer.composed_length, 5)

        composer = ComposerText('utf-8')
        composer.compose_string_array(list(self._ALPHA_BETA_GAMMA), '')
        self.assertEqual(composer.composed, self._ALPHA_BETA_GAMMA.encode('utf-8'))
        self.assertEqual(composer.composed_length, len(self._ALPHA_BETA_GAMMA) * 2)

        composer = ComposerText()

        composer.compose_string_array(
            [AlwaysTestStringComposer(), AlwaysTestStringComposer(), AlwaysTestStringComposer()], '#'
        )
        self.assertEqual(composer.composed, b'test#test#test')
        self.assertEqual(composer.composed_length, len(AlwaysTestStringComposer().compose()) * 3 + 2)

    def test_compose_separator(self):
        composer = ComposerText()

        composer.compose_separator('#')
        self.assertEqual(composer.composed, b'#')
        composer.compose_separator('string')
        self.assertEqual(composer.composed, b'#string')
        composer.compose_separator('#')
        self.assertEqual(composer.composed, b'#string#')

        composer = ComposerText('utf-8')

        composer.compose_separator(self._ALPHA_BETA_GAMMA)
        self.assertEqual(composer.composed, self._ALPHA_BETA_GAMMA.encode('utf-8'))

    def test_compose_date_time(self):
        composer = ComposerText()
        composer.compose_date_time(datetime.datetime(2015, 10, 21, 7, 28), '%a, %d %b %Y %H:%M:%S GMT')
        self.assertEqual(composer.composed, b'Wed, 21 Oct 2015 07:28:00 GMT')

    def test_compose_time_delta(self):
        composer = ComposerText()
        composer.compose_time_delta(datetime.timedelta(1))
        self.assertEqual(composer.composed, b'86400')

    def test_compose_bool(self):
        composer = ComposerText()
        composer.compose_bool(True)
        self.assertEqual(composer.composed, b'yes')

        composer = ComposerText()
        composer.compose_bool(False)
        self.assertEqual(composer.composed, b'no')
