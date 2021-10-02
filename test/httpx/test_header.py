#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os

import unittest

import datetime
import dateutil

from cryptoparser.httpx.header import (
    HttpHeaderFields,
    HttpHeaderFieldAge,
    HttpHeaderFieldContentType,
    HttpHeaderFieldCacheControlResponse,
    HttpHeaderFieldDate,
    HttpHeaderFieldETag,
    HttpHeaderFieldExpectCT,
    HttpHeaderFieldExpectStaple,
    HttpHeaderFieldExpires,
    HttpHeaderFieldLastModified,
    HttpHeaderFieldName,
    HttpHeaderFieldPragma,
    HttpHeaderFieldReferrerPolicy,
    HttpHeaderFieldServer,
    HttpHeaderFieldSTS,
    HttpHeaderFieldUnparsed,
    HttpHeaderFieldValueCacheControlResponse,
    HttpHeaderFieldValueExpectCT,
    HttpHeaderFieldValueExpectStaple,
    HttpHeaderFieldValuePragma,
    HttpHeaderFieldValueReferrerPolicy,
    HttpHeaderFieldValueSTS,
    HttpHeaderFieldValueXContentTypeOptions,
    HttpHeaderFieldValueXFrameOptions,
    HttpHeaderFieldXContentTypeOptions,
    HttpHeaderFieldXFrameOptions,
    HttpHeaderReferrerPolicy,
    HttpHeaderPragma,
    HttpHeaderXContentTypeOptions,
    HttpHeaderXFrameOptions,
)

from cryptoparser.common.exception import InvalidValue

from .classes import TestCasesBasesHttpHeader


class TestHttpHeaderFieldValueCacheControlResponse(
        TestCasesBasesHttpHeader.MinimalHeader,
        TestCasesBasesHttpHeader.FullHeader,
        TestCasesBasesHttpHeader.CaseInsensitiveHeader):

    _header_minimal = HttpHeaderFieldValueCacheControlResponse()
    _header_minimal_bytes = b''
    _header_minimal_markdown = ''

    _header_full = HttpHeaderFieldValueCacheControlResponse(
        max_age=datetime.timedelta(seconds=1),
        s_maxage=datetime.timedelta(seconds=2),
        must_revalidate=True,
        no_cache=True,
        no_store=True,
        public=True,
        private=True,
        no_transform=True,
    )
    _header_full_bytes = b'max-age=1, s-maxage=2, must-revalidate, no-cache, no-store, public, private, no-transform'
    _header_full_upper_case_bytes = b', '.join([
        b'MAX-AGE=1',
        b'S-MAXAGE=2',
        b'MUST-REVALIDATE',
        b'NO-CACHE',
        b'NO-STORE',
        b'PUBLIC',
        b'PRIVATE',
        b'NO-TRANSFORM',
    ])
    _header_full_lower_case_bytes = b', '.join([
        b'max-age=1',
        b's-maxage=2',
        b'must-revalidate',
        b'no-cache',
        b'no-store',
        b'public',
        b'private',
        b'no-transform',
    ])
    _header_minimal_markdown = os.linesep.join([
        '* Max Age: n/a',
        '* S Maxage: n/a',
        '* Must Revalidate:',
        '    * Value: no',
        '* Proxy Revalidate:',
        '    * Value: no',
        '* No Cache:',
        '    * Value: no',
        '* No Store:',
        '    * Value: no',
        '* Public:',
        '    * Value: no',
        '* Private:',
        '    * Value: no',
        '* No Transform:',
        '    * Value: no',
        '',
    ])


class TestHttpHeaderFieldValuePragma(
        TestCasesBasesHttpHeader.FullHeader,
        TestCasesBasesHttpHeader.CaseInsensitiveHeader):
    _header_full = HttpHeaderFieldValuePragma(HttpHeaderPragma.NO_CACHE)
    _header_full_bytes = b'no-cache'
    _header_full_upper_case_bytes = b'NO-CACHE'
    _header_full_lower_case_bytes = b'no-cache'


class TestHttpHeaderFieldValueSTS(
        TestCasesBasesHttpHeader.MinimalHeader,
        TestCasesBasesHttpHeader.FullHeader,
        TestCasesBasesHttpHeader.CaseInsensitiveHeader):
    _header_minimal = HttpHeaderFieldValueSTS(max_age=datetime.timedelta(seconds=1))
    _header_minimal_bytes = b'max-age=1'
    _header_minimal_markdown = os.linesep.join([
        '* Max Age:',
        '    * Value: 0:00:01',
        '* Include Subdomains:',
        '    * Value: no',
        '* Preload:',
        '    * Value: no',
        '',
    ])

    _header_full = HttpHeaderFieldValueSTS(max_age=datetime.timedelta(seconds=1), include_subdomains=True, preload=True)
    _header_full_bytes = b'max-age=1; includeSubDomains; preload'
    _header_full_upper_case_bytes = b'MAX-AGE=1; INCLUDESUBDOMAINS; PRELOAD'
    _header_full_lower_case_bytes = b'max-age=1; includesubdomains; preload'


class TestHttpHeaderFieldValueExpectStaple(
        TestCasesBasesHttpHeader.MinimalHeader,
        TestCasesBasesHttpHeader.FullHeader,
        TestCasesBasesHttpHeader.CaseInsensitiveHeader):
    _header_minimal = HttpHeaderFieldValueExpectStaple(max_age=datetime.timedelta(seconds=1))
    _header_minimal_bytes = b'max-age=1'
    _header_minimal_markdown = os.linesep.join([
        '* Max Age:',
        '    * Value: 0:00:01',
        '* Include Subdomains:',
        '    * Value: no',
        '* Preload:',
        '    * Value: no',
        '* Report Uri: n/a',
        '',
    ])

    _header_full = HttpHeaderFieldValueExpectStaple(
        max_age=datetime.timedelta(seconds=1),
        include_subdomains=True,
        preload=True,
        report_uri="http://example.com"
    )
    _header_full_bytes = b'max-age=1; includeSubDomains; preload; report-uri="http://example.com"'
    _header_full_upper_case_bytes = b'MAX-AGE=1; INCLUDESUBDOMAINS; PRELOAD; REPORT-URI="http://example.com"'
    _header_full_lower_case_bytes = b'max-age=1; includesubdomains; preload; report-uri="http://example.com"'


class TestHttpHeaderFieldValueExpectCT(
        TestCasesBasesHttpHeader.MinimalHeader,
        TestCasesBasesHttpHeader.FullHeader,
        TestCasesBasesHttpHeader.CaseInsensitiveHeader):
    _header_minimal = HttpHeaderFieldValueExpectCT(max_age=datetime.timedelta(seconds=1))
    _header_minimal_bytes = b'max-age=1'
    _header_minimal_markdown = os.linesep.join([
        '* Max Age:',
        '    * Value: 0:00:01',
        '* Enforce:',
        '    * Value: no',
        '* Report Uri: n/a',
        '',
    ])

    _header_full = HttpHeaderFieldValueExpectCT(
        max_age=datetime.timedelta(seconds=1),
        enforce=True,
        report_uri='http://example.com'
    )
    _header_full_bytes = b'max-age=1, enforce, report-uri="http://example.com"'
    _header_full_upper_case_bytes = b'MAX-AGE=1, ENFORCE, REPORT-URI="http://example.com"'
    _header_full_lower_case_bytes = b'max-age=1, enforce, report-uri="http://example.com"'


class TestHttpHeaderFieldValueXContentTypeOptions(TestCasesBasesHttpHeader.FullHeader):
    _header_full = HttpHeaderFieldValueXContentTypeOptions(HttpHeaderXContentTypeOptions.NOSNIFF)
    _header_full_bytes = b'nosniff'


class TestHttpHeaderFieldValueXFrameOptions(TestCasesBasesHttpHeader.FullHeader):
    _header_full = HttpHeaderFieldValueXFrameOptions(HttpHeaderXFrameOptions.SAMEORIGIN)
    _header_full_bytes = b'SAMEORIGIN'


class TestHttpHeaderFieldValueReferrerPolicy(TestCasesBasesHttpHeader.FullHeader):
    _header_full = HttpHeaderFieldValueReferrerPolicy(HttpHeaderReferrerPolicy.SAME_ORIGIN)
    _header_full_bytes = b'same-origin'


class TestHttpHeaderFieldName(unittest.TestCase):
    def test_markdown(self):
        self.assertEqual(
            HttpHeaderFieldName.STRICT_TRANSPORT_SECURITY.value.as_markdown(),
            'Strict-Transport-Security',
        )

    def test_from_name(self):
        with self.assertRaises(InvalidValue) as context_manager:
            HttpHeaderFieldName.from_name('non-existing-name')
        self.assertEqual(context_manager.exception.value, 'non-existing-name')

        self.assertEqual(
            HttpHeaderFieldName.from_name('strict-transport-security'),
            HttpHeaderFieldName.STRICT_TRANSPORT_SECURITY
        )
        self.assertEqual(
            HttpHeaderFieldName.from_name('STRICT-TRANSPORT-SECURITY'),
            HttpHeaderFieldName.STRICT_TRANSPORT_SECURITY
        )
        self.assertEqual(
            HttpHeaderFieldName.from_name('Strict-Transport-Security'),
            HttpHeaderFieldName.STRICT_TRANSPORT_SECURITY
        )


class TestHttpHeaderFields(unittest.TestCase):
    def setUp(self):
        self.headers_bytes = b'\r\n'.join([
            b'Age: 1',
            b'Cache-Control: no-cache',
            b'Content-Type: text/html',
            b'Date: Thu, 01 Jan 1970 00:00:00 GMT',
            b'ETag: 12345678',
            b'Expect-CT: max-age=1',
            b'Expect-Staple: max-age=1',
            b'Expires: Thu, 01 Jan 1970 00:00:00 GMT',
            b'Last-Modified: Thu, 01 Jan 1970 00:00:00 GMT',
            b'Pragma: no-cache',
            b'Referrer-Policy: origin',
            b'Server: server',
            b'Strict-Transport-Security: max-age=1',
            b'X-Unparsed: Value',
            b'X-Content-Type-Options: nosniff',
            b'X-Frame-Options: SAMEORIGIN',
            b'',
            b'',
        ])
        self.headers = HttpHeaderFields([
            HttpHeaderFieldAge(datetime.timedelta(seconds=1)),
            HttpHeaderFieldCacheControlResponse(HttpHeaderFieldValueCacheControlResponse(no_cache=True)),
            HttpHeaderFieldContentType('text/html'),
            HttpHeaderFieldDate(datetime.datetime.fromtimestamp(0, tz=dateutil.tz.UTC)),
            HttpHeaderFieldETag('12345678'),
            HttpHeaderFieldExpectCT(HttpHeaderFieldValueExpectCT(datetime.timedelta(seconds=1))),
            HttpHeaderFieldExpectStaple(HttpHeaderFieldValueExpectStaple(datetime.timedelta(seconds=1))),
            HttpHeaderFieldExpires(datetime.datetime.fromtimestamp(0, tz=dateutil.tz.UTC)),
            HttpHeaderFieldLastModified(datetime.datetime.fromtimestamp(0, tz=dateutil.tz.UTC)),
            HttpHeaderFieldPragma(HttpHeaderPragma.NO_CACHE),
            HttpHeaderFieldReferrerPolicy(HttpHeaderReferrerPolicy.ORIGIN),
            HttpHeaderFieldServer('server'),
            HttpHeaderFieldSTS(HttpHeaderFieldValueSTS(datetime.timedelta(seconds=1))),
            HttpHeaderFieldUnparsed('X-Unparsed', 'Value'),
            HttpHeaderFieldXContentTypeOptions(HttpHeaderXContentTypeOptions.NOSNIFF),
            HttpHeaderFieldXFrameOptions(HttpHeaderXFrameOptions.SAMEORIGIN),
        ])

    def test_parse(self):
        self.assertEqual(
            HttpHeaderFields.parse_exact_size(self.headers_bytes),
            self.headers
        )

    def test_compose(self):
        self.assertEqual(self.headers.compose(), self.headers_bytes)

    def test_markdown(self):
        self.assertEqual(self.headers.as_markdown(), os.linesep.join([
            '1.',
            '    * Name: Age',
            '    * Value: 1',
            '2.',
            '    * Name: Cache-Control',
            '    * Value:',
            '        * Max Age: n/a',
            '        * S Maxage: n/a',
            '        * Must Revalidate:',
            '            * Value: no',
            '        * Proxy Revalidate:',
            '            * Value: no',
            '        * No Cache:',
            '            * Value: yes',
            '        * No Store:',
            '            * Value: no',
            '        * Public:',
            '            * Value: no',
            '        * Private:',
            '            * Value: no',
            '        * No Transform:',
            '            * Value: no',
            '3.',
            '    * Name: Content-Type',
            '    * Value: text/html',
            '4.',
            '    * Name: Date',
            '    * Value: Thu, 01 Jan 1970 00:00:00 GMT',
            '5.',
            '    * Name: ETag',
            '    * Value: 12345678',
            '6.',
            '    * Name: Expect-CT',
            '    * Value:',
            '        * Max Age:',
            '            * Value: 0:00:01',
            '        * Enforce:',
            '            * Value: no',
            '        * Report Uri: n/a',
            '7.',
            '    * Name: Expect-Staple',
            '    * Value:',
            '        * Max Age:',
            '            * Value: 0:00:01',
            '        * Include Subdomains:',
            '            * Value: no',
            '        * Preload:',
            '            * Value: no',
            '        * Report Uri: n/a',
            '8.',
            '    * Name: Expires',
            '    * Value: Thu, 01 Jan 1970 00:00:00 GMT',
            '9.',
            '    * Name: Last-Modified',
            '    * Value: Thu, 01 Jan 1970 00:00:00 GMT',
            '10.',
            '    * Name: Pragma',
            '    * Value: no-cache',
            '11.',
            '    * Name: Referrer-Policy',
            '    * Value: origin',
            '12.',
            '    * Name: Server',
            '    * Value: server',
            '13.',
            '    * Name: Strict-Transport-Security',
            '    * Value:',
            '        * Max Age:',
            '            * Value: 0:00:01',
            '        * Include Subdomains:',
            '            * Value: no',
            '        * Preload:',
            '            * Value: no',
            '14.',
            '    * Name: X-Unparsed',
            '    * Value: Value',
            '15.',
            '    * Name: X-Content-Type-Options',
            '    * Value: nosniff',
            '16.',
            '    * Name: X-Frame-Options',
            '    * Value: SAMEORIGIN',
            '',
        ]))


class TestHttpHeaderFieldUnparsed(unittest.TestCase):
    def test_error(self):
        with self.assertRaises(InvalidValue) as context_manager:
            HttpHeaderFieldUnparsed.parse_immutable(b'name: value')
        self.assertEqual(context_manager.exception.value, b'value')

        with self.assertRaises(InvalidValue) as context_manager:
            HttpHeaderFieldUnparsed.parse_immutable(b'name value')
        self.assertEqual(context_manager.exception.value, b'name value')

    def test_parse(self):
        parsable = b'name: value\r\n'
        header, parsed_length = HttpHeaderFieldUnparsed.parse_immutable(parsable)
        self.assertEqual(header.name, 'name')
        self.assertEqual(header.value, 'value')
        self.assertEqual(parsable[parsed_length:], b'\r\n')

        parsable = b'name:  value\r\n'
        header, parsed_length = HttpHeaderFieldUnparsed.parse_immutable(parsable)
        self.assertEqual(header.name, 'name')
        self.assertEqual(header.value, 'value')
        self.assertEqual(parsable[parsed_length:], b'\r\n')

    def test_compose(self):
        header = HttpHeaderFieldUnparsed('name', 'value')
        self.assertEqual(header.compose(), b'name: value')

    def test_markdown(self):
        header = HttpHeaderFieldUnparsed('name', 'value')
        self.assertEqual(header.as_markdown(), os.linesep.join([
            '* Name: name',
            '* Value: value',
            ''
        ]))