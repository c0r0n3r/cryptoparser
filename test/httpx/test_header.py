#!/usr/bin/env python
# -*- coding: utf-8 -*-

import datetime

from cryptoparser.httpx.header import (
    HttpHeaderFieldValueCacheControlResponse,
    HttpHeaderFieldValueExpectCT,
    HttpHeaderFieldValueExpectStaple,
    HttpHeaderFieldValuePragma,
    HttpHeaderFieldValueReferrerPolicy,
    HttpHeaderFieldValueSTS,
    HttpHeaderFieldValueXContentTypeOptions,
    HttpHeaderFieldValueXFrameOptions,
    HttpHeaderReferrerPolicy,
    HttpHeaderPragma,
    HttpHeaderXContentTypeOptions,
    HttpHeaderXFrameOptions,
)

from .classes import TestCasesBasesHttpHeader


class TestHttpHeaderFieldValueCacheControlResponse(
        TestCasesBasesHttpHeader.MinimalHeader,
        TestCasesBasesHttpHeader.FullHeader,
        TestCasesBasesHttpHeader.CaseInsensitiveHeader):

    _header_minimal = HttpHeaderFieldValueCacheControlResponse()
    _header_minimal_bytes = b''

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
