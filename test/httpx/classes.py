# -*- coding: utf-8 -*-

import enum
import unittest

import attr

from cryptoparser.common.base import StringEnumParsable

from cryptoparser.httpx.parse import (
    HttpHeaderFieldValueMultiple,
    HttpHeaderFieldValueStringEnum,
    HttpHeaderFieldValueStringEnumParams,
    HttpHeaderFieldValueComponentNumber,
    HttpHeaderFieldValueComponentOption,
    HttpHeaderFieldValueComponentString,
    HttpHeaderFieldValueComponentQuotedString,
    HttpHeaderFieldValueComponentTimeDelta,
)


class TestCasesBasesHttpHeader:
    class MinimalHeader(unittest.TestCase):
        _header_minimal = None
        _header_minimal_bytes = None

        def test_parse_minimal(self):
            parsed_header = self._header_minimal.parse_exact_size(self._header_minimal_bytes)
            self.assertEqual(parsed_header, self._header_minimal)

        def test_compose_minimal(self):
            self.assertEqual(self._header_minimal.compose(), self._header_minimal_bytes)

    class FullHeaderBase(unittest.TestCase):
        _header_full = None
        _header_full_bytes = None

    class FullHeader(FullHeaderBase):
        def test_parse_full(self):
            parsed_header = self._header_full.parse_exact_size(self._header_full_bytes)
            self.assertEqual(parsed_header, self._header_full)

        def test_compose_full(self):
            self.assertEqual(self._header_full.compose(), self._header_full_bytes)

    class CaseInsensitiveHeader(FullHeaderBase):
        _header_full_upper_case_bytes = None
        _header_full_lower_case_bytes = None

        def test_parse_upper_case(self):
            parsed_header = self._header_full.parse_exact_size(self._header_full_upper_case_bytes)
            self.assertEqual(parsed_header, self._header_full)

        def test_parse_lower_case(self):
            parsed_header = self._header_full.parse_exact_size(self._header_full_lower_case_bytes)
            self.assertEqual(parsed_header, self._header_full)


class HttpHeaderFieldValueEnumTest(StringEnumParsable, enum.Enum):
    FIRST = HttpHeaderFieldValueStringEnumParams(code='first')
    SECOND = HttpHeaderFieldValueStringEnumParams(code='second')


class HttpHeaderFieldValueStringEnumTest(HttpHeaderFieldValueStringEnum):
    @classmethod
    def _get_value_type(cls):
        return HttpHeaderFieldValueEnumTest


class HttpHeaderFieldValueComponentOptionTest(HttpHeaderFieldValueComponentOption):
    @classmethod
    def get_canonical_name(cls):
        return 'testOption'


class HttpHeaderFieldValueComponentStringTest(HttpHeaderFieldValueComponentString):
    @classmethod
    def get_canonical_name(cls):
        return 'testString'


class HttpHeaderFieldValueComponentOptionalStringTest(HttpHeaderFieldValueComponentQuotedString):
    @classmethod
    def get_canonical_name(cls):
        return 'testOptionalString'


class HttpHeaderFieldValueComponentQuotedStringTest(HttpHeaderFieldValueComponentQuotedString):
    @classmethod
    def get_canonical_name(cls):
        return 'testQuotedString'


class HttpHeaderFieldValueComponentNumberTest(HttpHeaderFieldValueComponentNumber):
    @classmethod
    def get_canonical_name(cls):
        return 'testNumber'


class HttpHeaderFieldValueComponentTimeDeltaTest(HttpHeaderFieldValueComponentTimeDelta):
    @classmethod
    def get_canonical_name(cls):
        return 'testTimeDelta'


@attr.s
class HttpHeaderFieldValueMultipleTest(HttpHeaderFieldValueMultiple):
    time_delta = attr.ib(
        converter=HttpHeaderFieldValueComponentTimeDeltaTest.convert,
        validator=attr.validators.instance_of(HttpHeaderFieldValueComponentTimeDeltaTest)
    )
    option = attr.ib(
        converter=HttpHeaderFieldValueComponentOptionTest.convert,
        validator=attr.validators.instance_of(HttpHeaderFieldValueComponentOptionTest),
        default=False
    )
    string = attr.ib(
        converter=HttpHeaderFieldValueComponentStringTest.convert,
        validator=attr.validators.instance_of(HttpHeaderFieldValueComponentStringTest),
        default='default'
    )
    optional_string = attr.ib(
        converter=attr.converters.optional(HttpHeaderFieldValueComponentOptionalStringTest.convert),
        validator=attr.validators.optional(
            attr.validators.instance_of(HttpHeaderFieldValueComponentOptionalStringTest)
        ),
        default=None
    )
    number = attr.ib(
        converter=HttpHeaderFieldValueComponentNumberTest.convert,
        validator=attr.validators.instance_of(HttpHeaderFieldValueComponentNumberTest),
        default=0
    )
