#!/usr/bin/env python
# -*- coding: utf-8 -*-

import datetime

from cryptoparser.httpx.header import (
    HttpHeaderFieldValueExpectCT,
    HttpHeaderFieldValueExpectStaple,
    HttpHeaderFieldValueSTS,
    HttpHeaderFieldValueXContentTypeOptions,
    HttpHeaderXContentTypeOptions,
    HttpHeaderFieldValueReferrerPolicy,
    HttpHeaderReferrerPolicy,
    HttpHeaderFieldValueXFrameOptions,
    HttpHeaderXFrameOptions,
)

from .classes import TestCasesBasesHttpHeader


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
    _header_full_bytes = b'max-age=1; enforce; report-uri="http://example.com"'
    _header_full_upper_case_bytes = b'MAX-AGE=1; ENFORCE; REPORT-URI="http://example.com"'
    _header_full_lower_case_bytes = b'max-age=1; enforce; report-uri="http://example.com"'


class TestHttpHeaderFieldValueXContentTypeOption(TestCasesBasesHttpHeader.FullHeader):
    _header_full = HttpHeaderFieldValueXContentTypeOptions(HttpHeaderXContentTypeOptions.NOSNIFF)
    _header_full_bytes = b'nosniff'


class TestHttpHeaderFieldValueXFrameOptions(TestCasesBasesHttpHeader.FullHeader):
    _header_full = HttpHeaderFieldValueXFrameOptions(HttpHeaderXFrameOptions.SAMEORIGIN)
    _header_full_bytes = b'SAMEORIGIN'


class TestHttpHeaderFieldValueReferrerPolicy(TestCasesBasesHttpHeader.FullHeader):
    _header_full = HttpHeaderFieldValueReferrerPolicy(HttpHeaderReferrerPolicy.SAME_ORIGIN)
    _header_full_bytes = b'same-origin'
