# -*- coding: utf-8 -*-

import json
import unittest

from cryptoparser.common.exception import NotEnoughData, TooMuchData
from cryptoparser.common.base import Vector, VectorParamNumeric
from cryptoparser.common.base import VectorParsable, VectorParamParsable
from cryptoparser.common.base import VectorParsableDerived, Opaque

from cryptoparser.tls.ciphersuite import TlsCipherSuite, SslCipherKind

from .classes import OneByteParsable, TwoByteParsable, OneByteOddParsable, TwoByteEvenParsable
from .classes import ConditionalParsable
from .classes import TestObject
from .classes import SerializableSimpleTypes, SerializableIterables, SerializableEnum
from .classes import SerializableHidden, SerializableUnhandled, SerializableRecursive


class VectorNumericTestErrors(Vector):
    @classmethod
    def get_param(cls):
        return VectorParamNumeric(item_size=2, min_byte_num=4, max_byte_num=6)


class VectorNumericTest(Vector):
    @classmethod
    def get_param(cls):
        return VectorParamNumeric(item_size=2, min_byte_num=0, max_byte_num=0xff)


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
    def get_byte_num(cls):
        return 3


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
            OpaqueTest.parse_exact_size(b'\x01\x02')
        self.assertEqual(context_manager.exception.bytes_needed, 3)

    def test_parse(self):
        self.assertEqual(
            [1, 2, 3],
            list(OpaqueTest.parse_exact_size(b'\x01\x02\x03'))
        )

    def test_compose(self):
        self.assertEqual(
            b'\x01\x02\x03',
            OpaqueTest([1, 2, 3]).compose()
        )


class TestEnum(unittest.TestCase):
    def test_compose(self):
        self.assertEqual(len(TlsCipherSuite.TLS_NULL_WITH_NULL_NULL.compose()), TlsCipherSuite.get_byte_num())
        self.assertEqual(len(SslCipherKind.RC4_128_WITH_MD5.compose()), SslCipherKind.get_byte_num())


class TestSerializable(unittest.TestCase):
    def test_simple_types(self):
        self.assertEqual(
            json.dumps(SerializableSimpleTypes()),
            '{"bool_value": false, "float_value": 1.0, "int_value": 1, "none_value": null, "str_value": "string"}'
        )
        self.assertEqual(
            json.dumps(SerializableIterables()),
            '{"dict_value": {"value": 1}, "list_value": ["value"], "tuple_value": ["value"]}'
        )
        self.assertEqual(
            json.dumps(SerializableEnum.first),
            '{"first": {"code": 1}}'
        )
        self.assertEqual(
            json.dumps(SerializableHidden()),
            '{"visible_value": "value"}'
        )
        self.assertEqual(
            json.dumps(SerializableUnhandled()),
            '{"bytes_value": "(1+2j)"}'
        )
        self.assertEqual(
            json.dumps(SerializableRecursive()),
            '{' +
            '"json_serializable_in_dict": {"key": {"visible_value": "value"}}, ' +
            '"json_serializable_in_list": [{"visible_value": "value"}], ' +
            '"json_serializable_in_tuple": [{"visible_value": "value"}], ' +
            '"json_serializable_value": {"visible_value": "value"}' +
            '}'
        )
        self.assertEqual(json.dumps(TestObject()), '{}')
