#!/usr/bin/env python
# -*- coding: utf-8 -*-

import unittest

import datetime

from collections import OrderedDict

import attr
import urllib3

from cryptodatahub.common.exception import InvalidValue

from cryptoparser.common.exception import InvalidType
from cryptoparser.common.field import (
    FieldValueDateTime,
    FieldValueString,
    NameValuePair,
    NameValuePairListSemicolonSeparated,
)

from .classes import (
    ComponentStringEnumTest,
    FieldValueJsonTest,
    FieldValueMultipleTest,
    FieldValueMultipleExtendableTest,
    FieldValueEnumTest,
    FieldValueStringEnumTest,
    FieldValueComponentBoolTest,
    FieldValueComponentFloatTest,
    FieldValueComponentNumberTest,
    FieldValueComponentOptionTest,
    FieldValueComponentQuotedStringTest,
    FieldValueComponentPercentTest,
    FieldValueComponentStringEnumTest,
    FieldValueComponentStringTest,
    FieldValueComponentTimeDeltaTest,
    FieldValueComponentUrlTest,
    FieldValueTimeDeltaTest,
)


class TestFieldValueString(unittest.TestCase):
    def test_parse(self):
        self.assertEqual(FieldValueString.parse_exact_size(b'value').value, 'value')

    def test_compose(self):
        self.assertEqual(FieldValueString('value').compose(), b'value')

    def test_convert(self):
        self.assertEqual(FieldValueString.convert(None), None)
        self.assertEqual(FieldValueString.convert(bytearray(b'non-string-value')), bytearray(b'non-string-value'))
        self.assertEqual(FieldValueString.convert('value'), FieldValueString('value'))

    def test_markdown(self):
        self.assertEqual(FieldValueString('value').as_markdown(), 'value')


class TestFieldValueStringEnum(unittest.TestCase):
    def test_error(self):
        with self.assertRaises(InvalidValue) as context_manager:
            FieldValueStringEnumTest('value not in enum')
        self.assertEqual(context_manager.exception.value, 'value not in enum')

        with self.assertRaises(InvalidValue) as context_manager:
            FieldValueStringEnumTest.parse_exact_size(b'value not in enum')
        self.assertEqual(context_manager.exception.value, 'value not in enum')

    def test_parse(self):
        self.assertEqual(
            FieldValueStringEnumTest.parse_exact_size(b'first'),
            FieldValueStringEnumTest(FieldValueEnumTest.FIRST)
        )
        self.assertEqual(
            FieldValueStringEnumTest.parse_exact_size(b'FIRST'),
            FieldValueStringEnumTest(FieldValueEnumTest.FIRST)
        )

    def test_compose(self):
        self.assertEqual(
            FieldValueStringEnumTest(FieldValueEnumTest.SECOND).compose(),
            b'second'
        )

    def test_markdown(self):
        self.assertEqual(
            FieldValueStringEnumTest(FieldValueEnumTest.FIRST).as_markdown(),
            'FiRsT'
        )
        self.assertEqual(
            FieldValueEnumTest.FIRST.value.as_markdown(),
            'FiRsT'
        )

        self.assertEqual(
            FieldValueStringEnumTest(FieldValueEnumTest.SECOND).as_markdown(),
            'second'
        )
        self.assertEqual(
            FieldValueEnumTest.SECOND.value.as_markdown(),
            'second'
        )


class TestFieldValueComponentOption(unittest.TestCase):
    def test_parse(self):
        component, _ = FieldValueComponentOptionTest.parse_immutable(b'option')
        self.assertEqual(component.value, False)

        component, _ = FieldValueComponentOptionTest.parse_immutable(b'testOption')
        self.assertEqual(component.value, True)

    def test_compose(self):
        self.assertEqual(FieldValueComponentOptionTest(False).compose(), b'')
        self.assertEqual(FieldValueComponentOptionTest(True).compose(), b'testOption')

    def test_as_markdown(self):
        self.assertEqual(FieldValueComponentOptionTest(False).as_markdown(), 'no')
        self.assertEqual(FieldValueComponentOptionTest(True).as_markdown(), 'yes')


class TestFieldValueComponentString(unittest.TestCase):
    def test_error(self):
        with self.assertRaises(InvalidType):
            FieldValueComponentStringTest.parse_exact_size(b'shortNam')

        with self.assertRaises(InvalidType):
            FieldValueComponentStringTest.parse_exact_size(b'wrongName=value')

    def test_parse(self):
        component = FieldValueComponentStringTest.parse_exact_size(b'testString=value')
        self.assertEqual(component.value, 'value')

    def test_compose(self):
        self.assertEqual(FieldValueComponentStringTest('value').compose(), b'testString=value')

    def test_as_markdown(self):
        self.assertEqual(FieldValueComponentStringTest('value').as_markdown(), 'value')


class TestFieldValueComponentUrl(unittest.TestCase):
    _component_url_https = FieldValueComponentUrlTest('https://example.com')
    _component_url_https_bytes = b'testUrl=https://example.com'
    _component_url_mailto = FieldValueComponentUrlTest('mailto:user@example.com')
    _component_url_mailto_bytes = b'testUrl=mailto:user@example.com'

    def test_error_invalid_value(self):
        with self.assertRaises(InvalidValue) as context_manager:
            FieldValueComponentUrlTest.parse_exact_size(b'testUrl=https://example.com:port')
        self.assertEqual(context_manager.exception.value, 'https://example.com:port')

        with self.assertRaises(InvalidValue) as context_manager:
            FieldValueComponentUrlTest(None)
        self.assertEqual(context_manager.exception.value, None)

    def test_parse(self):
        component = FieldValueComponentUrlTest.parse_exact_size(b'testUrl=https://example.com')
        self.assertEqual(component.value, urllib3.util.parse_url('https://example.com'))

        component = FieldValueComponentUrlTest.parse_exact_size(b'testUrl=mailto:user@example.com')
        self.assertEqual(component.value, urllib3.util.parse_url('mailto:user@example.com'))

    def test_compose(self):
        self.assertEqual(
            FieldValueComponentUrlTest('https://example.com').compose(),
            b'testUrl=https://example.com'
        )
        self.assertEqual(
            FieldValueComponentUrlTest('mailto:user@example.com').compose(),
            b'testUrl=mailto:user@example.com'
        )

    def test_as_markdown(self):
        self.assertEqual(self._component_url_https.as_markdown(), 'https://example.com')
        self.assertEqual(self._component_url_mailto.as_markdown(), 'mailto:user@example.com')


class TestFieldValueComponentStringEnum(unittest.TestCase):
    def test_error(self):
        with self.assertRaises(InvalidValue) as context_manager:
            FieldValueComponentStringEnumTest.parse_exact_size(  # pylint: disable=expression-not-assigned
                b'testStringEnum=non-existing-value'
            )
        self.assertEqual(context_manager.exception.value, 'non-existing-value')

        with self.assertRaises(InvalidValue) as context_manager:
            FieldValueComponentStringEnumTest('non-existing-value')
        self.assertEqual(context_manager.exception.value, 'non-existing-value')

    def test_parse(self):
        self.assertEqual(
            FieldValueComponentStringEnumTest.parse_exact_size(b'testStringEnum=one'),
            FieldValueComponentStringEnumTest(ComponentStringEnumTest.ONE)
        )

    def test_compose(self):
        self.assertEqual(
            FieldValueComponentStringEnumTest(ComponentStringEnumTest.TWO).compose(),
            b'testStringEnum=two'
        )


class TestFieldValueComponentQuotedString(unittest.TestCase):
    def test_error(self):
        component = FieldValueComponentQuotedStringTest.parse_exact_size(b'testQuotedString="value')
        self.assertEqual(component.value, 'value')

        component = FieldValueComponentQuotedStringTest.parse_exact_size(b'testQuotedString=value"')
        self.assertEqual(component.value, 'value')

        component = FieldValueComponentQuotedStringTest.parse_exact_size(b'testQuotedString=""value"')
        self.assertEqual(component.value, 'value')

        component = FieldValueComponentQuotedStringTest.parse_exact_size(b'testQuotedString="value""')
        self.assertEqual(component.value, 'value')

    def test_parse(self):
        component = FieldValueComponentQuotedStringTest.parse_exact_size(b'testQuotedString=value')
        self.assertEqual(component.value, 'value')

        component = FieldValueComponentQuotedStringTest.parse_exact_size(b'testQuotedString="value"')
        self.assertEqual(component.value, 'value')

    def test_compose(self):
        self.assertEqual(FieldValueComponentQuotedStringTest('value').compose(), b'testQuotedString="value"')

    def test_markdown(self):
        self.assertEqual(FieldValueComponentQuotedStringTest('value').as_markdown(), 'value')


class TestFieldValueComponentBool(unittest.TestCase):
    def test_error(self):
        with self.assertRaises(InvalidValue) as context_manager:
            FieldValueComponentBoolTest.parse_exact_size(b'testBool=str')
        self.assertEqual(context_manager.exception.value, b'str')

    def test_parse(self):
        component = FieldValueComponentBoolTest.parse_exact_size(b'testBool=yes')
        self.assertTrue(component.value)

        component = FieldValueComponentBoolTest.parse_exact_size(b'testBool=no')
        self.assertFalse(component.value)

    def test_compose(self):
        self.assertEqual(FieldValueComponentBoolTest(True).compose(), b'testBool=yes')
        self.assertEqual(FieldValueComponentBoolTest(False).compose(), b'testBool=no')

    def test_as_markdown(self):
        self.assertEqual(FieldValueComponentBoolTest(True).as_markdown(), 'yes')
        self.assertEqual(FieldValueComponentBoolTest(False).as_markdown(), 'no')


class TestFieldValueComponentFloat(unittest.TestCase):
    def test_error(self):
        with self.assertRaises(InvalidValue) as context_manager:
            FieldValueComponentFloatTest.parse_exact_size(b'testFloat=str')
        self.assertEqual(context_manager.exception.value, b'str')

    def test_parse(self):
        component = FieldValueComponentFloatTest.parse_exact_size(b'testFloat=1')
        self.assertEqual(component.value, 1.0)

        component = FieldValueComponentFloatTest.parse_exact_size(b'testFloat=1.0')
        self.assertEqual(component.value, 1.0)

    def test_compose(self):
        self.assertEqual(FieldValueComponentFloatTest(1).compose(), b'testFloat=1.0')
        self.assertEqual(FieldValueComponentFloatTest(1.0).compose(), b'testFloat=1.0')

    def test_as_markdown(self):
        self.assertEqual(FieldValueComponentFloatTest(1).as_markdown(), '1.0')
        self.assertEqual(FieldValueComponentFloatTest(1.0).as_markdown(), '1.0')


class TestFieldValueComponentNumber(unittest.TestCase):
    def test_error(self):
        with self.assertRaises(InvalidValue) as context_manager:
            FieldValueComponentNumberTest.parse_exact_size(b'testNumber=notnumeric')
        self.assertEqual(context_manager.exception.value, b'notnumeric')

    def test_parse(self):
        component = FieldValueComponentNumberTest.parse_exact_size(b'testNumber=1234')
        self.assertEqual(component.value, 1234)

    def test_compose(self):
        self.assertEqual(FieldValueComponentNumberTest(1234).compose(), b'testNumber=1234')

    def test_as_markdown(self):
        self.assertEqual(FieldValueComponentNumberTest(1234).as_markdown(), '1234')


class TestFieldValueComponentPercent(unittest.TestCase):
    def test_error(self):
        with self.assertRaises(InvalidValue) as context_manager:
            FieldValueComponentPercentTest.parse_exact_size(b'testPercent=101')
        self.assertEqual(context_manager.exception.value, 101)


class TestFieldValueComponentTimeDelta(unittest.TestCase):
    def test_error(self):
        with self.assertRaises(InvalidValue) as context_manager:
            FieldValueComponentTimeDeltaTest.parse_exact_size(b'testTimeDelta=notnumeric')
        self.assertEqual(context_manager.exception.value, b'notnumeric')

        with self.assertRaises(InvalidValue) as context_manager:
            FieldValueComponentTimeDeltaTest.parse_exact_size(
                b'testTimeDelta=' + str(2 ** 48).encode('ascii')
            )
        self.assertEqual(context_manager.exception.value, 2 ** 48)

    def test_parse(self):
        component = FieldValueComponentTimeDeltaTest.parse_exact_size(b'testTimeDelta=86401')
        self.assertEqual(component.value, datetime.timedelta(days=1, seconds=1))

    def test_compose(self):
        self.assertEqual(
            FieldValueComponentTimeDeltaTest(datetime.timedelta(days=1, seconds=1)).compose(),
            b'testTimeDelta=86401'
        )

    def test_as_markdown(self):
        self.assertEqual(
            FieldValueComponentTimeDeltaTest(datetime.timedelta(days=1, seconds=1)).as_markdown(),
            '1 day, 0:00:01'
        )


class TestFieldJson(unittest.TestCase):
    def test_error(self):
        with self.assertRaises(InvalidValue) as context_manager:
            FieldValueJsonTest.parse_exact_size(b'not-a-valid-json')
        self.assertEqual(context_manager.exception.value, 'not-a-valid-json')

    def test_parse(self):
        header_field = FieldValueJsonTest.parse_exact_size(b'{"testTimeDelta": 1}')
        self.assertEqual(
            header_field,
            FieldValueJsonTest(datetime.timedelta(seconds=1))
        )
        self.assertEqual(
            header_field.string.value,  # pylint: disable=no-member
            attr.fields_dict(FieldValueJsonTest)['string'].default
        )
        self.assertEqual(
            header_field.number.value,  # pylint: disable=no-member
            attr.fields_dict(FieldValueJsonTest)['number'].default
        )

        parsed_header_field = FieldValueJsonTest.parse_exact_size(
            b'{"testTimeDelta": 1, "testString": "string", "testNumber": 1}'
        )
        header_field = FieldValueJsonTest(
            time_delta=datetime.timedelta(seconds=1),
            string='string',
            number=1
        )
        self.assertEqual(parsed_header_field, header_field)

        parsed_header_field = FieldValueJsonTest.parse_exact_size(b'{' + b', '.join([
            b'"testTimeDelta": 1',
            b'"testString": "string"',
            b'"testStringBase64": "ZGVmYXVsdA=="',
            b'"optional_string": "optional_string"',
            b'"testNumber": 1',
        ]) + b'}')
        header_field = FieldValueJsonTest(
            time_delta=datetime.timedelta(seconds=1),
            string='string',
            number=1
        )
        self.assertEqual(parsed_header_field, header_field)

    def test_compose(self):
        header_field = FieldValueJsonTest(datetime.timedelta(seconds=1))
        self.assertEqual(
            header_field.compose(),
            b'{' + b', '.join([
                b'"testTimeDelta": 1',
                b'"testString": "default"',
                b'"testUrl": "https://example.com"',
                b'"testStringBase64": "ZGVmYXVsdA=="',
                b'"testNumber": 0',
                b'"testPercent": 100',
            ]) + b'}'
        )


class TestFieldValueMultiple(unittest.TestCase):
    def test_error(self):
        with self.assertRaises(InvalidValue) as context_manager:
            FieldValueMultipleTest.parse_exact_size(b'')
        self.assertEqual(context_manager.exception.value, None)

    def test_init_param_default(self):
        header_field = FieldValueMultipleTest(datetime.timedelta(1))
        self.assertEqual(header_field.option.value, False)
        self.assertEqual(header_field.number.value, 0)
        self.assertEqual(header_field.string.value, 'default')

    def test_init_param_convert(self):
        header_field_from_value = FieldValueMultipleTest(
            time_delta=datetime.timedelta(1),
        )
        header_field_from_component = FieldValueMultipleTest(
            time_delta=FieldValueComponentTimeDeltaTest(datetime.timedelta(1))
        )
        self.assertEqual(header_field_from_value, header_field_from_component)

    def test_parse(self):
        header_field = FieldValueMultipleTest.parse_exact_size(b'testTimeDelta=1')
        self.assertEqual(
            header_field,
            FieldValueMultipleTest(datetime.timedelta(seconds=1))
        )
        self.assertEqual(
            header_field.option.value,  # pylint: disable=no-member
            attr.fields_dict(FieldValueMultipleTest)['option'].default
        )
        self.assertEqual(
            header_field.string.value,  # pylint: disable=no-member
            attr.fields_dict(FieldValueMultipleTest)['string'].default
        )
        self.assertEqual(
            header_field.number.value,  # pylint: disable=no-member
            attr.fields_dict(FieldValueMultipleTest)['number'].default
        )

        parsed_header_field = FieldValueMultipleTest.parse_exact_size(
            b'testTimeDelta=1; testOption; testString=string; testNumber=1'
        )
        header_field = FieldValueMultipleTest(
            time_delta=datetime.timedelta(seconds=1),
            option=True,
            string='string',
            number=1
        )
        self.assertEqual(parsed_header_field, header_field)

        parsed_header_field = FieldValueMultipleTest.parse_exact_size(b'; '.join([
            b'testTimeDelta=1',
            b'testOption',
            b'testString=string',
            b'testStringBase64="ZGVmYXVsdA=="',
            b'testOptionalString=optional_string',
            b'testNumber=1',
        ]))
        header_field = FieldValueMultipleTest(
            time_delta=datetime.timedelta(seconds=1),
            option=True,
            string='string',
            optional_string='optional_string',
            number=1
        )
        self.assertEqual(parsed_header_field, header_field)

    def test_compose(self):
        header_field = FieldValueMultipleTest(datetime.timedelta(seconds=1))
        self.assertEqual(
            header_field.compose(),
            b'; '.join([
                b'testTimeDelta=1',
                b'testString=default',
                b'testUrl=https://example.com',
                b'testStringBase64="ZGVmYXVsdA=="',
                b'testNumber=0',
                b'testPercent=100',
            ])
        )

        header_field.option.value = True
        self.assertEqual(
            header_field.compose(),
            b'; '.join([
                b'testTimeDelta=1',
                b'testString=default',
                b'testUrl=https://example.com',
                b'testStringBase64="ZGVmYXVsdA=="',
                b'testNumber=0',
                b'testPercent=100',
                b'testOption',
            ])
        )


class TestFieldValueMultipleExtendable(unittest.TestCase):
    def test_parse(self):
        parsed_header_field = FieldValueMultipleExtendableTest.parse_exact_size(
            b'testTimeDelta=1; testExtension1=value1; testExtension2=value2'
        )
        header_field = FieldValueMultipleExtendableTest(
            time_delta=datetime.timedelta(seconds=1),
            extensions=NameValuePairListSemicolonSeparated(
                OrderedDict([('testExtension1', 'value1'), ('testExtension2', 'value2')])
            )
        )
        self.assertEqual(parsed_header_field, header_field)

    def test_compose(self):
        header_field = FieldValueMultipleExtendableTest(
            datetime.timedelta(seconds=1),
            extensions=NameValuePairListSemicolonSeparated(
                OrderedDict([('testExtension1', 'value1'), ('testExtension2', 'value2')])
            )
        )
        self.assertEqual(
            header_field.compose(),
            b'; '.join([
                b'testTimeDelta=1',
                b'testString=default',
                b'testUrl=https://example.com',
                b'testStringBase64="ZGVmYXVsdA=="',
                b'testNumber=0',
                b'testPercent=100',
                b'testExtension1=value1',
                b'testExtension2=value2',
            ])
        )


class TestFieldValueComponentKeyValue(unittest.TestCase):
    def test_parse_error(self):
        component = NameValuePair.parse_exact_size(b'name="')
        self.assertEqual(component.name, 'name')
        self.assertEqual(component.value, '')

        component = NameValuePair.parse_exact_size(b'name="value')
        self.assertEqual(component.name, 'name')
        self.assertEqual(component.value, 'value')

    def test_parse(self):
        component = NameValuePair.parse_exact_size(b'name=value')
        self.assertEqual(component.name, 'name')
        self.assertEqual(component.value, 'value')

        component = NameValuePair.parse_exact_size(b'name=')
        self.assertEqual(component.name, 'name')
        self.assertEqual(component.value, '')

    def test_parse_quoted(self):
        component = NameValuePair.parse_exact_size(b'name=""')
        self.assertEqual(component.name, 'name')
        self.assertEqual(component.value, '')

        component = NameValuePair.parse_exact_size(b'name="value"')
        self.assertEqual(component.name, 'name')
        self.assertEqual(component.value, 'value')

    def test_compose(self):
        self.assertEqual(NameValuePair('name', 'value').compose(), b'name=value')

    def test_compose_quoted(self):
        self.assertEqual(NameValuePair('name', 'value', quoted=True).compose(), b'name="value"')


class TestFieldValueDateTime(unittest.TestCase):
    def test_parse(self):
        http_header_field = FieldValueDateTime.parse_exact_size(b'Wed, 21 Oct 2015 07:28:00 GMT')
        self.assertEqual(
            http_header_field.value,
            datetime.datetime(2015, 10, 21, 7, 28, tzinfo=datetime.timezone.utc)
        )

        http_header_field = FieldValueDateTime.parse_exact_size(b'Wed, 21 Oct 2015 07:28:00 +01:00')
        self.assertEqual(
            http_header_field.value,
            datetime.datetime(2015, 10, 21, 7, 28, tzinfo=datetime.timezone(datetime.timedelta(hours=1)))
        )

    def test_compose(self):
        self.assertEqual(
            FieldValueDateTime(
                datetime.datetime(2015, 10, 21, 7, 28, tzinfo=datetime.timezone.utc)
            ).compose(),
            b'Wed, 21 Oct 2015 07:28:00 GMT'
        )


class TestFieldValueTimeDelta(unittest.TestCase):
    def test_parse(self):
        http_header_field = FieldValueTimeDeltaTest.parse_exact_size(b'86401')
        self.assertEqual(http_header_field.value, datetime.timedelta(days=1, seconds=1))

    def test_compose(self):
        self.assertEqual(
            FieldValueTimeDeltaTest(datetime.timedelta(days=1, seconds=1)).compose(),
            b'86401'
        )


class TestNameValuePairList(unittest.TestCase):
    _EMPTY_BYTES = b''
    _EMPTY = NameValuePairListSemicolonSeparated(OrderedDict([]))

    _OPTION_BYTES = b'option'
    _OPTION = NameValuePairListSemicolonSeparated(OrderedDict([('option', None)]))

    _KEY_VALUE_BYTES = b'key=value'
    _KEY_VALUE = NameValuePairListSemicolonSeparated(OrderedDict([('key', 'value')]))

    _KEY_VALUE_OPTION_BYTES = b'key=value; option'
    _KEY_VALUE_OPTION = NameValuePairListSemicolonSeparated(OrderedDict([('key', 'value'), ('option', None)]))

    _OPTION_KEY_VALUE_BYTES = b'option; key=value'
    _OPTION_KEY_VALUE = NameValuePairListSemicolonSeparated(OrderedDict([('option', None), ('key', 'value')]))

    def test_error(self):
        self.assertEqual(
            NameValuePairListSemicolonSeparated.parse_exact_size(b';;;option'),
            self._OPTION
        )
        self.assertEqual(
            NameValuePairListSemicolonSeparated.parse_exact_size(b'option;;;'),
            self._OPTION
        )

    def test_markdown(self):
        self.assertEqual(self._EMPTY.as_markdown(), '-')
        self.assertEqual(self._OPTION.as_markdown(), '* Option: n/a\n')
        self.assertEqual(self._KEY_VALUE.as_markdown(), '* Key: value\n')
        self.assertEqual(self._KEY_VALUE_OPTION.as_markdown(), '* Key: value\n* Option: n/a\n')
        self.assertEqual(self._OPTION_KEY_VALUE.as_markdown(), '* Option: n/a\n* Key: value\n')

    def test_parse_mixed_values(self):
        self.assertEqual(
            NameValuePairListSemicolonSeparated.parse_exact_size(self._EMPTY_BYTES),
            self._EMPTY
        )
        self.assertEqual(
            NameValuePairListSemicolonSeparated.parse_exact_size(self._OPTION_BYTES),
            self._OPTION
        )
        self.assertEqual(
            NameValuePairListSemicolonSeparated.parse_exact_size(self._KEY_VALUE_BYTES),
            self._KEY_VALUE
        )
        self.assertEqual(
            NameValuePairListSemicolonSeparated.parse_exact_size(self._KEY_VALUE_OPTION_BYTES),
            self._KEY_VALUE_OPTION
        )
        self.assertEqual(
            NameValuePairListSemicolonSeparated.parse_exact_size(self._OPTION_KEY_VALUE_BYTES),
            self._OPTION_KEY_VALUE
        )

    def test_compose_mixed_values(self):
        self.assertEqual(self._EMPTY.compose(), self._EMPTY_BYTES)
        self.assertEqual(self._OPTION.compose(), self._OPTION_BYTES)
        self.assertEqual(self._KEY_VALUE.compose(), self._KEY_VALUE_BYTES)
        self.assertEqual(self._KEY_VALUE_OPTION.compose(), self._KEY_VALUE_OPTION_BYTES)
        self.assertEqual(self._OPTION_KEY_VALUE.compose(), self._OPTION_KEY_VALUE_BYTES)

    def test_parse_single_option(self):
        header_field_value = NameValuePairListSemicolonSeparated.parse_exact_size(b'option')
        self.assertEqual(header_field_value.value, OrderedDict([('option', None), ]))

    def test_parse_muliple_options(self):
        header_field_value = NameValuePairListSemicolonSeparated.parse_exact_size(b'option1;option2;option3')
        self.assertEqual(
            header_field_value.value,
            OrderedDict([('option1', None), ('option2', None), ('option3', None), ])
        )

        header_field_value = NameValuePairListSemicolonSeparated.parse_exact_size(
            b' option1; \toption2;\t \toption3'
        )
        self.assertEqual(
            header_field_value.value,
            OrderedDict([('option1', None), ('option2', None), ('option3', None), ])
        )

    def test_compose_options(self):
        self.assertEqual(
            NameValuePairListSemicolonSeparated(OrderedDict([])).compose(),
            b''
        )
        self.assertEqual(self._OPTION.compose(), self._OPTION_BYTES)
        self.assertEqual(
            NameValuePairListSemicolonSeparated(
                OrderedDict([('option1', None), ('option2', None), ('option3', None), ])
            ).compose(),
            b'option1; option2; option3'
        )
