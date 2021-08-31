#!/usr/bin/env python
# -*- coding: utf-8 -*-

import unittest

import datetime

from collections import OrderedDict

import attr
import dateutil

from cryptoparser.common.exception import InvalidValue, InvalidType

from cryptoparser.httpx.parse import (
    HttpHeaderFieldValueString,
    HttpHeaderFieldValueListSemicolonSeparated,
    HttpHeaderFieldValueComponent,
    HttpHeaderFieldValueDateTime,
)

from .classes import (
    HttpHeaderFieldValueMultipleTest,
    HttpHeaderFieldValueEnumTest,
    HttpHeaderFieldValueStringEnumTest,
    HttpHeaderFieldValueComponentNumberTest,
    HttpHeaderFieldValueComponentOptionTest,
    HttpHeaderFieldValueComponentStringTest,
    HttpHeaderFieldValueComponentTimeDeltaTest,
    HttpHeaderFieldValueComponentQuotedStringTest,
    HttpHeaderFieldValueTimeDeltaTest,
)


class TestHttpHeaderFieldValueString(unittest.TestCase):
    def test_parse(self):
        self.assertEqual(HttpHeaderFieldValueString.parse_exact_size(b'value').value, 'value')

    def test_compose(self):
        self.assertEqual(HttpHeaderFieldValueString('value').compose(), b'value')

    def test_markdown(self):
        self.assertEqual(HttpHeaderFieldValueString('value').as_markdown(), 'value')


class TestHttpHeaderFieldValueStringEnum(unittest.TestCase):
    def test_error(self):
        with self.assertRaises(InvalidValue) as context_manager:
            HttpHeaderFieldValueStringEnumTest('value not in enum')
        self.assertEqual(context_manager.exception.value, 'value not in enum')

        with self.assertRaises(InvalidValue) as context_manager:
            HttpHeaderFieldValueStringEnumTest.parse_exact_size(b'value not in enum')
        self.assertEqual(context_manager.exception.value, 'value not in enum')

    def test_parse(self):
        self.assertEqual(
            HttpHeaderFieldValueStringEnumTest.parse_exact_size(b'first'),
            HttpHeaderFieldValueStringEnumTest(HttpHeaderFieldValueEnumTest.FIRST)
        )
        self.assertEqual(
            HttpHeaderFieldValueStringEnumTest.parse_exact_size(b'FIRST'),
            HttpHeaderFieldValueStringEnumTest(HttpHeaderFieldValueEnumTest.FIRST)
        )

    def test_compose(self):
        self.assertEqual(
            HttpHeaderFieldValueStringEnumTest(HttpHeaderFieldValueEnumTest.SECOND).compose(),
            b'second'
        )

    def test_markdown(self):
        self.assertEqual(
            HttpHeaderFieldValueStringEnumTest(HttpHeaderFieldValueEnumTest.SECOND).as_markdown(),
            'second'
        )


class TestHttpHeaderFieldValueComponentOption(unittest.TestCase):
    def test_parse(self):
        component, _ = HttpHeaderFieldValueComponentOptionTest.parse_immutable(b'option')
        self.assertEqual(component.value, False)

        component, _ = HttpHeaderFieldValueComponentOptionTest.parse_immutable(b'testOption')
        self.assertEqual(component.value, True)

    def test_compose(self):
        self.assertEqual(HttpHeaderFieldValueComponentOptionTest(False).compose(), b'')
        self.assertEqual(HttpHeaderFieldValueComponentOptionTest(True).compose(), b'testOption')


class TestHttpHeaderFieldValueComponentString(unittest.TestCase):
    def test_error(self):
        with self.assertRaises(InvalidType):
            HttpHeaderFieldValueComponentStringTest.parse_exact_size(b'shortNam')

        with self.assertRaises(InvalidType):
            HttpHeaderFieldValueComponentStringTest.parse_exact_size(b'wrongName=value')

    def test_parse(self):
        component = HttpHeaderFieldValueComponentStringTest.parse_exact_size(b'testString=value')
        self.assertEqual(component.value, 'value')

    def test_compose(self):
        self.assertEqual(HttpHeaderFieldValueComponentStringTest('value').compose(), b'testString=value')


class TestHttpHeaderFieldValueComponentQuotedString(unittest.TestCase):
    def test_error(self):
        component = HttpHeaderFieldValueComponentQuotedStringTest.parse_exact_size(b'testQuotedString="value')
        self.assertEqual(component.value, 'value')

        component = HttpHeaderFieldValueComponentQuotedStringTest.parse_exact_size(b'testQuotedString=value"')
        self.assertEqual(component.value, 'value')

        component = HttpHeaderFieldValueComponentQuotedStringTest.parse_exact_size(b'testQuotedString=""value"')
        self.assertEqual(component.value, 'value')

        component = HttpHeaderFieldValueComponentQuotedStringTest.parse_exact_size(b'testQuotedString="value""')
        self.assertEqual(component.value, 'value')

    def test_parse(self):
        component = HttpHeaderFieldValueComponentQuotedStringTest.parse_exact_size(b'testQuotedString=value')
        self.assertEqual(component.value, 'value')

        component = HttpHeaderFieldValueComponentQuotedStringTest.parse_exact_size(b'testQuotedString="value"')
        self.assertEqual(component.value, 'value')

    def test_compose(self):
        self.assertEqual(HttpHeaderFieldValueComponentQuotedStringTest('value').compose(), b'testQuotedString="value"')


class TestHttpHeaderFieldValueComponentNumber(unittest.TestCase):
    def test_error(self):
        with self.assertRaises(InvalidValue) as context_manager:
            HttpHeaderFieldValueComponentNumberTest.parse_exact_size(b'testNumber=notnumeric')
        self.assertEqual(context_manager.exception.value, b'notnumeric')

    def test_parse(self):
        component = HttpHeaderFieldValueComponentNumberTest.parse_exact_size(b'testNumber=1234')
        self.assertEqual(component.value, 1234)

    def test_compose(self):
        self.assertEqual(HttpHeaderFieldValueComponentNumberTest(1234).compose(), b'testNumber=1234')


class TestHttpHeaderFieldValueComponentTimeDelta(unittest.TestCase):
    def test_error(self):
        with self.assertRaises(InvalidValue) as context_manager:
            HttpHeaderFieldValueComponentTimeDeltaTest.parse_exact_size(b'testTimeDelta=notnumeric')
        self.assertEqual(context_manager.exception.value, b'notnumeric')

        with self.assertRaises(InvalidValue) as context_manager:
            HttpHeaderFieldValueComponentTimeDeltaTest.parse_exact_size(
                b'testTimeDelta=' + str(2 ** 48).encode('ascii')
            )
        self.assertEqual(context_manager.exception.value, 2 ** 48)

    def test_parse(self):
        component = HttpHeaderFieldValueComponentTimeDeltaTest.parse_exact_size(b'testTimeDelta=86401')
        self.assertEqual(component.value, datetime.timedelta(days=1, seconds=1))

    def test_compose(self):
        self.assertEqual(
            HttpHeaderFieldValueComponentTimeDeltaTest(datetime.timedelta(days=1, seconds=1)).compose(),
            b'testTimeDelta=86401'
        )


class TestHttpHeaderFieldValueMultiple(unittest.TestCase):
    def test_error(self):
        with self.assertRaises(InvalidValue) as context_manager:
            HttpHeaderFieldValueMultipleTest.parse_exact_size(b'')
        self.assertEqual(context_manager.exception.value, None)

    def test_init_param_default(self):
        header_field = HttpHeaderFieldValueMultipleTest(datetime.timedelta(1))
        self.assertEqual(header_field.option.value, False)
        self.assertEqual(header_field.number.value, 0)
        self.assertEqual(header_field.string.value, 'default')

    def test_init_param_convert(self):
        header_field_from_value = HttpHeaderFieldValueMultipleTest(
            time_delta=datetime.timedelta(1),
        )
        header_field_from_component = HttpHeaderFieldValueMultipleTest(
            time_delta=HttpHeaderFieldValueComponentTimeDeltaTest(datetime.timedelta(1))
        )
        self.assertEqual(header_field_from_value, header_field_from_component)

    def test_parse(self):
        header_field = HttpHeaderFieldValueMultipleTest.parse_exact_size(b'testTimeDelta=1')
        self.assertEqual(
            header_field,
            HttpHeaderFieldValueMultipleTest(datetime.timedelta(seconds=1))
        )
        self.assertEqual(
            header_field.option.value,  # pylint: disable=no-member
            attr.fields_dict(HttpHeaderFieldValueMultipleTest)['option'].default
        )
        self.assertEqual(
            header_field.string.value,  # pylint: disable=no-member
            attr.fields_dict(HttpHeaderFieldValueMultipleTest)['string'].default
        )
        self.assertEqual(
            header_field.number.value,  # pylint: disable=no-member
            attr.fields_dict(HttpHeaderFieldValueMultipleTest)['number'].default
        )

        parsed_header_field = HttpHeaderFieldValueMultipleTest.parse_exact_size(
            b'testTimeDelta=1; testOption; testString=string; testNumber=1'
        )
        header_field = HttpHeaderFieldValueMultipleTest(
            time_delta=datetime.timedelta(seconds=1),
            option=True,
            string='string',
            number=1
        )
        self.assertEqual(parsed_header_field, header_field)

        parsed_header_field = HttpHeaderFieldValueMultipleTest.parse_exact_size(
            b'testTimeDelta=1; testOption; testString=string; testOptionalString=optional_string; testNumber=1'
        )
        header_field = HttpHeaderFieldValueMultipleTest(
            time_delta=datetime.timedelta(seconds=1),
            option=True,
            string='string',
            optional_string='optional_string',
            number=1
        )
        self.assertEqual(parsed_header_field, header_field)

    def test_compose(self):
        header_field = HttpHeaderFieldValueMultipleTest(datetime.timedelta(seconds=1))
        self.assertEqual(header_field.compose(), b'testTimeDelta=1; testString=default; testNumber=0')

        header_field.option.value = True
        self.assertEqual(header_field.compose(), b'testTimeDelta=1; testOption; testString=default; testNumber=0')


class TestHttpHeaderFieldValueComponentKeyValue(unittest.TestCase):
    def test_parse_error(self):
        component = HttpHeaderFieldValueComponent.parse_exact_size(b'name="')
        self.assertEqual(component.name, 'name')
        self.assertEqual(component.value, '')

        component = HttpHeaderFieldValueComponent.parse_exact_size(b'name="value')
        self.assertEqual(component.name, 'name')
        self.assertEqual(component.value, 'value')

    def test_parse(self):
        component = HttpHeaderFieldValueComponent.parse_exact_size(b'name=value')
        self.assertEqual(component.name, 'name')
        self.assertEqual(component.value, 'value')

        component = HttpHeaderFieldValueComponent.parse_exact_size(b'name=')
        self.assertEqual(component.name, 'name')
        self.assertEqual(component.value, '')

    def test_parse_quoted(self):
        component = HttpHeaderFieldValueComponent.parse_exact_size(b'name=""')
        self.assertEqual(component.name, 'name')
        self.assertEqual(component.value, '')

        component = HttpHeaderFieldValueComponent.parse_exact_size(b'name="value"')
        self.assertEqual(component.name, 'name')
        self.assertEqual(component.value, 'value')

    def test_compose(self):
        self.assertEqual(HttpHeaderFieldValueComponent('name', 'value').compose(), b'name=value')

    def test_compose_quoted(self):
        self.assertEqual(HttpHeaderFieldValueComponent('name', 'value', quoted=True).compose(), b'name="value"')


class TestHttpHeaderFieldValue(unittest.TestCase):
    def test_error(self):
        self.assertEqual(
            HttpHeaderFieldValueListSemicolonSeparated.parse_exact_size(b';;;option').components,
            OrderedDict([('option', None)])
        )
        self.assertEqual(
            HttpHeaderFieldValueListSemicolonSeparated.parse_exact_size(b'option;;;').components,
            OrderedDict([('option', None)])
        )

    def test_parse_mixed_values(self):
        self.assertEqual(
            HttpHeaderFieldValueListSemicolonSeparated.parse_exact_size(b'').components,
            {}
        )
        self.assertEqual(
            HttpHeaderFieldValueListSemicolonSeparated.parse_exact_size(b'option').components,
            {'option': None}
        )
        self.assertEqual(
            HttpHeaderFieldValueListSemicolonSeparated.parse_exact_size(b'key=value').components,
            {'key': 'value'}
        )
        self.assertEqual(
            HttpHeaderFieldValueListSemicolonSeparated.parse_exact_size(b'key=value;option').components,
            OrderedDict([('key', 'value'), ('option', None)])
        )
        self.assertEqual(
            HttpHeaderFieldValueListSemicolonSeparated.parse_exact_size(b'option;key=value').components,
            OrderedDict([('option', None), ('key', 'value')])
        )

    def test_compose_mixed_values(self):
        self.assertEqual(
            HttpHeaderFieldValueListSemicolonSeparated(OrderedDict([])).compose(),
            b''
        )
        self.assertEqual(
            HttpHeaderFieldValueListSemicolonSeparated(OrderedDict([('option', None)])).compose(),
            b'option'
        )
        self.assertEqual(
            HttpHeaderFieldValueListSemicolonSeparated(OrderedDict([('key', 'value')])).compose(),
            b'key=value'
        )
        self.assertEqual(
            HttpHeaderFieldValueListSemicolonSeparated(OrderedDict([('key1', 'value1'), ('option', None)])).compose(),
            b'key1=value1; option'
        )
        self.assertEqual(
            HttpHeaderFieldValueListSemicolonSeparated(OrderedDict([('option', None), ('key1', 'value1')])).compose(),
            b'option; key1=value1'
        )

    def test_parse_single_option(self):
        header_field_value = HttpHeaderFieldValueListSemicolonSeparated.parse_exact_size(b'option')
        self.assertEqual(header_field_value.components, OrderedDict([('option', None), ]))

    def test_parse_muliple_options(self):
        header_field_value = HttpHeaderFieldValueListSemicolonSeparated.parse_exact_size(b'option1;option2;option3')
        self.assertEqual(
            header_field_value.components,
            OrderedDict([('option1', None), ('option2', None), ('option3', None), ])
        )

        header_field_value = HttpHeaderFieldValueListSemicolonSeparated.parse_exact_size(
            b' option1; \toption2;\t \toption3'
        )
        self.assertEqual(
            header_field_value.components,
            OrderedDict([('option1', None), ('option2', None), ('option3', None), ])
        )

    def test_compose_options(self):
        self.assertEqual(
            HttpHeaderFieldValueListSemicolonSeparated(OrderedDict([])).compose(),
            b''
        )
        self.assertEqual(
            HttpHeaderFieldValueListSemicolonSeparated(OrderedDict([('option', None)])).compose(),
            b'option'
        )
        self.assertEqual(
            HttpHeaderFieldValueListSemicolonSeparated(
                OrderedDict([('option1', None), ('option2', None), ('option3', None), ])
            ).compose(),
            b'option1; option2; option3'
        )


class TestHttpHeaderFieldValueDateTime(unittest.TestCase):
    def test_parse(self):
        http_header_field = HttpHeaderFieldValueDateTime.parse_exact_size(b'Wed, 21 Oct 2015 07:28:00 GMT')
        self.assertEqual(
            http_header_field.value,
            datetime.datetime(2015, 10, 21, 7, 28, tzinfo=dateutil.tz.tzoffset(None, 0))
        )

        http_header_field = HttpHeaderFieldValueDateTime.parse_exact_size(b'Wed, 21 Oct 2015 07:28:00 +01:00')
        self.assertEqual(
            http_header_field.value,
            datetime.datetime(2015, 10, 21, 7, 28, tzinfo=dateutil.tz.tzoffset(None, 3600))
        )

    def test_compose(self):
        self.assertEqual(
            HttpHeaderFieldValueDateTime(
                datetime.datetime(2015, 10, 21, 7, 28, tzinfo=dateutil.tz.tzoffset(None, 0))
            ).compose(),
            b'Wed, 21 Oct 2015 07:28:00 GMT'
        )


class TestHttpHeaderFieldValueTimeDelta(unittest.TestCase):
    def test_parse(self):
        http_header_field = HttpHeaderFieldValueTimeDeltaTest.parse_exact_size(b'86401')
        self.assertEqual(http_header_field.value, datetime.timedelta(days=1, seconds=1))

    def test_compose(self):
        self.assertEqual(
            HttpHeaderFieldValueTimeDeltaTest(datetime.timedelta(days=1, seconds=1)).compose(),
            b'86401'
        )
