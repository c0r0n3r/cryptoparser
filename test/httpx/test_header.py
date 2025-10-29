#!/usr/bin/env python
# pylint: disable=too-many-lines
# -*- coding: utf-8 -*-

import os

import unittest

import datetime

from cryptodatahub.common.algorithm import Hash
from cryptodatahub.common.exception import InvalidValue

from cryptoparser.common.exception import InvalidType
from cryptoparser.httpx.header import (
    ContentSecurityPolicyDirectiveBaseUri,
    ContentSecurityPolicyDirectiveBlockAllMixedContent,
    ContentSecurityPolicyDirectiveChildSrc,
    ContentSecurityPolicyDirectiveConnectSrc,
    ContentSecurityPolicyDirectiveDefaultSrc,
    ContentSecurityPolicyDirectiveFontSrc,
    ContentSecurityPolicyDirectiveFormAction,
    ContentSecurityPolicyDirectiveFrameAncestors,
    ContentSecurityPolicyDirectiveFrameSrc,
    ContentSecurityPolicyDirectiveImgSrc,
    ContentSecurityPolicyDirectiveManifestSrc,
    ContentSecurityPolicyDirectiveMediaSrc,
    ContentSecurityPolicyDirectiveObjectSrc,
    ContentSecurityPolicyDirectivePluginTypes,
    ContentSecurityPolicyDirectivePrefetchSrc,
    ContentSecurityPolicyDirectiveReferrer,
    ContentSecurityPolicyDirectiveReportTo,
    ContentSecurityPolicyDirectiveReportUri,
    ContentSecurityPolicyDirectiveRequireTrustedTypesFor,
    ContentSecurityPolicyDirectiveSandbox,
    ContentSecurityPolicyDirectiveScriptSrc,
    ContentSecurityPolicyDirectiveScriptSrcAttr,
    ContentSecurityPolicyDirectiveScriptSrcElem,
    ContentSecurityPolicyDirectiveStyleSrc,
    ContentSecurityPolicyDirectiveStyleSrcAttr,
    ContentSecurityPolicyDirectiveStyleSrcElem,
    ContentSecurityPolicyDirectiveUpgradeInsecureRequests,
    ContentSecurityPolicyDirectiveWebrtc,
    ContentSecurityPolicyDirectiveWorkerSrc,
    ContentSecurityPolicyReferrerPolicy,
    ContentSecurityPolicySourceHash,
    ContentSecurityPolicySourceHost,
    ContentSecurityPolicySourceKeyword,
    ContentSecurityPolicySourceNonce,
    ContentSecurityPolicySourceScheme,
    ContentSecurityPolicyTrustedTypeSinkGroup,
    ContentSecurityPolicyWebRtcType,
    FieldValueMimeType,
    HttpHeaderFields,
    HttpHeaderFieldAge,
    HttpHeaderFieldCacheControlResponse,
    HttpHeaderFieldContentType,
    HttpHeaderFieldContentSecurityPolicy,
    HttpHeaderFieldContentSecurityPolicyReportOnly,
    HttpHeaderFieldDate,
    HttpHeaderFieldETag,
    HttpHeaderFieldExpectCT,
    HttpHeaderFieldExpectStaple,
    HttpHeaderFieldExpires,
    HttpHeaderFieldLastModified,
    HttpHeaderFieldName,
    HttpHeaderFieldNetworkErrorLogging,
    HttpHeaderFieldPragma,
    HttpHeaderFieldPublicKeyPinning,
    HttpHeaderFieldReferrerPolicy,
    HttpHeaderFieldServer,
    HttpHeaderFieldSetCookie,
    HttpHeaderFieldSTS,
    HttpHeaderFieldUnparsed,
    HttpHeaderFieldValueCacheControlResponse,
    HttpHeaderFieldValueContentSecurityPolicy,
    HttpHeaderFieldValueContentType,
    HttpHeaderFieldValueExpectCT,
    HttpHeaderFieldValueExpectStaple,
    HttpHeaderFieldValueNetworkErrorLogging,
    HttpHeaderFieldValuePragma,
    HttpHeaderFieldValuePublicKeyPinning,
    HttpHeaderFieldValueReferrerPolicy,
    HttpHeaderFieldValueSetCookie,
    HttpHeaderFieldValueSTS,
    HttpHeaderFieldValueXContentTypeOptions,
    HttpHeaderFieldValueXFrameOptions,
    HttpHeaderFieldValueXXSSProtection,
    HttpHeaderFieldXContentSecurityPolicy,
    HttpHeaderFieldXContentTypeOptions,
    HttpHeaderFieldXFrameOptions,
    HttpHeaderFieldXXSSProtection,
    HttpHeaderReferrerPolicy,
    HttpHeaderPragma,
    HttpHeaderSetCookieComponentSameSite,
    HttpHeaderXContentTypeOptions,
    HttpHeaderXFrameOptions,
    HttpHeaderXXSSProtectionMode,
    HttpHeaderXXSSProtectionState,
    MimeTypeRegistry,
)

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
        '* Must Revalidate: no',
        '* Proxy Revalidate: no',
        '* No Cache: no',
        '* No Store: no',
        '* Public: no',
        '* Private: no',
        '* No Transform: no',
        '',
    ])


class TestContentSecurityPolicySourceHash(unittest.TestCase):
    def test_error_wrong_prefix(self):
        with self.assertRaises(InvalidType):
            ContentSecurityPolicySourceHash.parse_exact_size(b'notavalidhashalgorithm')

    def test_parse(self):
        self.assertEqual(
            ContentSecurityPolicySourceHash.parse_exact_size(b'sha256-bGlnaHQgd29yay4='),
            ContentSecurityPolicySourceHash(Hash.SHA2_256, bytearray(b'light work.'))
        )

    def test_compose(self):
        self.assertEqual(
            ContentSecurityPolicySourceHash(Hash.SHA2_256, bytearray(b'light work.')).compose(),
            b'sha256-bGlnaHQgd29yay4='
        )


class TestContentSecurityPolicySourceHost(unittest.TestCase):
    def test_parse(self):
        self.assertEqual(
            ContentSecurityPolicySourceHost.parse_exact_size(b'http://example.com'),
            ContentSecurityPolicySourceHost('http://example.com')
        )

    def test_compose(self):
        self.assertEqual(
            ContentSecurityPolicySourceHost('http://example.com').compose(),
            b'http://example.com'
        )


class TestContentSecurityPolicySourceNonce(unittest.TestCase):
    def test_error_wrong_prefix(self):
        with self.assertRaises(InvalidType):
            ContentSecurityPolicySourceNonce.parse_exact_size(b'bGlnaHQgd29yay4=')

    def test_parse(self):
        self.assertEqual(
            ContentSecurityPolicySourceNonce.parse_exact_size(b'nonce-bGlnaHQgd29yay4='),
            ContentSecurityPolicySourceNonce(bytearray(b'light work.'))
        )

    def test_compose(self):
        self.assertEqual(
            ContentSecurityPolicySourceNonce(bytearray(b'light work.')).compose(),
            b'nonce-bGlnaHQgd29yay4='
        )


class TestContentSecurityPolicySourceScheme(unittest.TestCase):
    def test_parse(self):
        self.assertEqual(
            ContentSecurityPolicySourceScheme.parse_exact_size(b'http:'),
            ContentSecurityPolicySourceScheme('http')
        )

    def test_compose(self):
        self.assertEqual(
            ContentSecurityPolicySourceScheme('http').compose(),
            b'http:'
        )


class TestContentSecurityPolicyDirectivesFetch(
        TestCasesBasesHttpHeader.MinimalHeader,
        TestCasesBasesHttpHeader.FullHeader):

    _header_minimal = ContentSecurityPolicyDirectiveDefaultSrc([ContentSecurityPolicySourceKeyword.SELF])
    _header_minimal_bytes = ' '.join([
        'default-src',
        '\'self\'',
    ]).encode('ascii')
    _header_minimal_markdown = os.linesep.join([
        '* Type: default-src',
        '* Value:',
        '    1.',
        '        * Type: KEYWORD',
        '        * Value: \'self\'',
        '',
    ])
    _header_full = ContentSecurityPolicyDirectiveDefaultSrc([
        ContentSecurityPolicySourceKeyword.SELF,
        ContentSecurityPolicySourceScheme('http'),
        ContentSecurityPolicySourceHost('https://example.com'),
        ContentSecurityPolicySourceNonce(bytearray(b'light work.')),
        ContentSecurityPolicySourceHash(Hash.SHA2_256, bytearray(b'light work.')),
    ])
    _header_full_bytes = ' '.join([
        'default-src',
        '\'self\'',
        'http:',
        'https://example.com',
        'nonce-bGlnaHQgd29yay4=',
        'sha256-bGlnaHQgd29yay4=',
    ]).encode('ascii')

    def test_min_source_length(self):
        with self.assertRaises(InvalidValue) as context_manager:
            ContentSecurityPolicyDirectiveDefaultSrc.parse_exact_size(b'default-src')
        self.assertEqual(context_manager.exception.value, b'')

    def test_error_invalid_value_type(self):
        with self.assertRaises(InvalidValue):
            ContentSecurityPolicyDirectiveDefaultSrc([None])


class TestContentSecurityPolicyDirectiveFrameAncestors(
        TestCasesBasesHttpHeader.MinimalHeader,
        TestCasesBasesHttpHeader.FullHeader):

    _header_minimal = ContentSecurityPolicyDirectiveFrameAncestors([ContentSecurityPolicySourceKeyword.SELF])
    _header_minimal_bytes = ' '.join([
        'frame-ancestors',
        '\'self\'',
    ]).encode('ascii')
    _header_minimal_markdown = os.linesep.join([
        '* Type: frame-ancestors',
        '* Value:',
        '    1.',
        '        * Type: KEYWORD',
        '        * Value: \'self\'',
        '',
    ])
    _header_full = ContentSecurityPolicyDirectiveFrameAncestors([
        ContentSecurityPolicySourceKeyword.SELF,
        ContentSecurityPolicySourceScheme('http'),
        ContentSecurityPolicySourceHost('https://example.com'),
    ])
    _header_full_bytes = ' '.join([
        'frame-ancestors',
        '\'self\'',
        'http:',
        'https://example.com',
    ]).encode('ascii')

    def test_error_invalid_value_type(self):
        with self.assertRaises(InvalidValue):
            ContentSecurityPolicyDirectiveFrameAncestors([
                ContentSecurityPolicySourceKeyword(ContentSecurityPolicySourceKeyword.REPORT_SAMPLE)
            ])

        with self.assertRaises(InvalidValue):
            ContentSecurityPolicyDirectiveFrameAncestors([
                ContentSecurityPolicySourceNonce(bytearray(b'light work.'))
            ])

        with self.assertRaises(InvalidValue):
            ContentSecurityPolicyDirectiveFrameAncestors([
                ContentSecurityPolicySourceHash(Hash.SHA2_256, bytearray(b'light work.'))
            ])


class TestContentSecurityPolicyDirectiveWebrtc(
        TestCasesBasesHttpHeader.MinimalHeader):

    _header_minimal = ContentSecurityPolicyDirectiveWebrtc(ContentSecurityPolicyWebRtcType.ALLOW)
    _header_minimal_bytes = ' '.join([
        'webrtc',
        '\'allow\'',
    ]).encode('ascii')
    _header_minimal_markdown = '\'allow\''

    def test_error_invalid_value_type(self):
        with self.assertRaises(InvalidValue) as context_manager:
            ContentSecurityPolicyDirectiveWebrtc('not-a-webrtc-type')
        self.assertEqual(context_manager.exception.value, 'not-a-webrtc-type')


class TestContentSecurityPolicyDirectiveRequireTrustedTypesFor(
        TestCasesBasesHttpHeader.MinimalHeader):

    _header_minimal = ContentSecurityPolicyDirectiveRequireTrustedTypesFor([
        ContentSecurityPolicyTrustedTypeSinkGroup.SCRIPT
    ])
    _header_minimal_bytes = ' '.join([
        'require-trusted-types-for',
        '\'script\'',
    ]).encode('ascii')
    _header_minimal_markdown = os.linesep.join([
        '* Type: require-trusted-types-for',
        '* Sink Groups:',
        '    1. \'script\'',
        '',
    ])


class TestContentSecurityPolicyDirectiveReportUri(
        TestCasesBasesHttpHeader.MinimalHeader,
        TestCasesBasesHttpHeader.FullHeader):

    _header_minimal = ContentSecurityPolicyDirectiveReportUri(['http://example.com'])
    _header_minimal_bytes = ' '.join([
        'report-uri',
        'http://example.com',
    ]).encode('ascii')
    _header_minimal_markdown = os.linesep.join([
        '* Type: report-uri',
        '* URI references:',
        '    1. http://example.com',
        '',
    ])
    _header_full = ContentSecurityPolicyDirectiveReportUri(['http://example.com/1', 'http://example.com/2'])
    _header_full_bytes = ' '.join([
        'report-uri',
        'http://example.com/1',
        'http://example.com/2',
    ]).encode('ascii')

    def test_min_reference_length(self):
        with self.assertRaises(InvalidValue) as context_manager:
            ContentSecurityPolicyDirectiveReportUri.parse_exact_size(b'report-uri')
        self.assertEqual(context_manager.exception.value, b'')


class TestContentSecurityPolicyDirectiveReportTo(
        TestCasesBasesHttpHeader.MinimalHeader):

    _header_minimal = ContentSecurityPolicyDirectiveReportTo('token')
    _header_minimal_bytes = ' '.join([
        'report-to',
        'token',
    ]).encode('ascii')
    _header_minimal_markdown = os.linesep.join([
        '* Token: token',
        '',
    ])


class TestContentSecurityPolicyDirectiveSandbox(
        TestCasesBasesHttpHeader.MinimalHeader,
        TestCasesBasesHttpHeader.FullHeader):

    _header_minimal = ContentSecurityPolicyDirectiveSandbox(['token'])
    _header_minimal_bytes = ' '.join([
        'sandbox',
        'token',
    ]).encode('ascii')
    _header_minimal_markdown = os.linesep.join([
        '* Type: sandbox',
        '* Tokens:',
        '    1. token',
        '',
    ])
    _header_full = ContentSecurityPolicyDirectiveSandbox(['token1', 'token2'])
    _header_full_bytes = ' '.join([
        'sandbox',
        'token1',
        'token2',
    ]).encode('ascii')


class TestContentSecurityPolicyDirectivePluginTypes(
        TestCasesBasesHttpHeader.MinimalHeader,
        TestCasesBasesHttpHeader.FullHeader):

    _header_minimal = ContentSecurityPolicyDirectivePluginTypes([
        FieldValueMimeType('html', MimeTypeRegistry.TEXT)
    ])
    _header_minimal_bytes = ' '.join([
        'plugin-types',
        'text/html',
    ]).encode('ascii')
    _header_minimal_markdown = os.linesep.join([
        '* Type: plugin-types',
        '* MIME Types:',
        '    1.',
        '        * Type: html',
        '        * Registry: TEXT',
        '',
    ])
    _header_full = ContentSecurityPolicyDirectivePluginTypes([
        FieldValueMimeType('html', MimeTypeRegistry.TEXT),
        FieldValueMimeType('csv', MimeTypeRegistry.TEXT),
    ])
    _header_full_bytes = ' '.join([
        'plugin-types',
        'text/html',
        'text/csv',
    ]).encode('ascii')


class TestContentSecurityPolicyDirectiveNoValue(
        TestCasesBasesHttpHeader.MinimalHeader):

    _header_minimal = ContentSecurityPolicyDirectiveBlockAllMixedContent()
    _header_minimal_bytes = b'block-all-mixed-content'
    _header_minimal_markdown = os.linesep.join([
        '* Type: block-all-mixed-content',
        '* Value: n/a',
        '',
    ])


class TestHttpHeaderFieldValueContentSecurityPolicy(
        TestCasesBasesHttpHeader.MinimalHeader,
        TestCasesBasesHttpHeader.FullHeader):

    _header_minimal = HttpHeaderFieldValueContentSecurityPolicy([
        ContentSecurityPolicyDirectiveDefaultSrc([
            ContentSecurityPolicySourceKeyword.SELF,
            ContentSecurityPolicySourceHash(Hash.SHA2_256, bytearray(b'light work.')),
            ContentSecurityPolicySourceNonce(bytearray(b'light work.')),
            ContentSecurityPolicySourceScheme('http'),
            ContentSecurityPolicySourceHost('http://example.com'),
        ])
    ])
    _header_minimal_bytes = ' '.join([
        'default-src',
        '\'self\'',
        'sha256-bGlnaHQgd29yay4=',
        'nonce-bGlnaHQgd29yay4=',
        'http:',
        'http://example.com',
    ]).encode('ascii')
    _header_minimal_markdown = os.linesep.join([
        '* Directives:',
        '    1.',
        '        * Type: default-src',
        '        * Value:',
        '            1.',
        '                * Type: KEYWORD',
        '                * Value: \'self\'',
        '            2.',
        '                * Type: HASH',
        '                * Value:',
        '                    * Hash Algorithm: SHA-256',
        '                    * Hash Value: bGlnaHQgd29yay4=',
        '            3.',
        '                * Type: NONCE',
        '                * Value: bGlnaHQgd29yay4=',
        '            4.',
        '                * Type: SCHEME',
        '                * Value: http',
        '            5.',
        '                * Type: HOST',
        '                * Value: http://example.com',
        '',
    ])
    _header_full = HttpHeaderFieldValueContentSecurityPolicy([
        ContentSecurityPolicyDirectiveChildSrc([
            ContentSecurityPolicySourceKeyword.SELF,
        ]),
        ContentSecurityPolicyDirectiveConnectSrc([
            ContentSecurityPolicySourceKeyword.SELF,
        ]),
        ContentSecurityPolicyDirectiveDefaultSrc([
            ContentSecurityPolicySourceKeyword.SELF,
        ]),
        ContentSecurityPolicyDirectiveFontSrc([
            ContentSecurityPolicySourceKeyword.SELF,
        ]),
        ContentSecurityPolicyDirectiveFrameSrc([
            ContentSecurityPolicySourceKeyword.SELF,
        ]),
        ContentSecurityPolicyDirectiveImgSrc([
            ContentSecurityPolicySourceKeyword.SELF,
        ]),
        ContentSecurityPolicyDirectiveManifestSrc([
            ContentSecurityPolicySourceKeyword.SELF,
        ]),
        ContentSecurityPolicyDirectiveMediaSrc([
            ContentSecurityPolicySourceKeyword.SELF,
        ]),
        ContentSecurityPolicyDirectiveObjectSrc([
            ContentSecurityPolicySourceKeyword.SELF,
        ]),
        ContentSecurityPolicyDirectivePrefetchSrc([
            ContentSecurityPolicySourceKeyword.SELF,
        ]),
        ContentSecurityPolicyDirectiveScriptSrc([
            ContentSecurityPolicySourceKeyword.SELF,
        ]),
        ContentSecurityPolicyDirectiveScriptSrcElem([
            ContentSecurityPolicySourceKeyword.SELF,
        ]),
        ContentSecurityPolicyDirectiveScriptSrcAttr([
            ContentSecurityPolicySourceKeyword.SELF,
        ]),
        ContentSecurityPolicyDirectiveStyleSrc([
            ContentSecurityPolicySourceKeyword.SELF,
        ]),
        ContentSecurityPolicyDirectiveStyleSrcElem([
            ContentSecurityPolicySourceKeyword.SELF,
        ]),
        ContentSecurityPolicyDirectiveStyleSrcAttr([
            ContentSecurityPolicySourceKeyword.SELF,
        ]),
        ContentSecurityPolicyDirectiveWebrtc(
            ContentSecurityPolicyWebRtcType.ALLOW,
        ),
        ContentSecurityPolicyDirectiveWorkerSrc([
            ContentSecurityPolicySourceKeyword.SELF,
        ]),
        ContentSecurityPolicyDirectiveBaseUri([
            ContentSecurityPolicySourceKeyword.SELF,
        ]),
        ContentSecurityPolicyDirectiveSandbox([
            'token'
        ]),
        ContentSecurityPolicyDirectiveFormAction([
            ContentSecurityPolicySourceKeyword.SELF,
        ]),
        ContentSecurityPolicyDirectiveFrameAncestors([
            ContentSecurityPolicySourceKeyword.SELF,
        ]),
        ContentSecurityPolicyDirectiveReportUri([
            'http://example.com'
        ]),
        ContentSecurityPolicyDirectiveReportTo(
            'token'
        ),
        ContentSecurityPolicyDirectiveBlockAllMixedContent(),
        ContentSecurityPolicyDirectiveUpgradeInsecureRequests(),
        ContentSecurityPolicyDirectiveReferrer(
            ContentSecurityPolicyReferrerPolicy.NO_REFERRER,
        ),
        ContentSecurityPolicyDirectivePluginTypes([
            FieldValueMimeType('html', MimeTypeRegistry.TEXT)
        ]),
    ])
    _header_full_bytes = '; '.join([
        'child-src \'self\'',
        'connect-src \'self\'',
        'default-src \'self\'',
        'font-src \'self\'',
        'frame-src \'self\'',
        'img-src \'self\'',
        'manifest-src \'self\'',
        'media-src \'self\'',
        'object-src \'self\'',
        'prefetch-src \'self\'',
        'script-src \'self\'',
        'script-src-elem \'self\'',
        'script-src-attr \'self\'',
        'style-src \'self\'',
        'style-src-elem \'self\'',
        'style-src-attr \'self\'',
        'webrtc \'allow\'',
        'worker-src \'self\'',
        'base-uri \'self\'',
        'sandbox token',
        'form-action \'self\'',
        'frame-ancestors \'self\'',
        'report-uri http://example.com',
        'report-to token',
        'block-all-mixed-content',
        'upgrade-insecure-requests',
        'referrer "no-referrer"',
        'plugin-types text/html',
    ]).encode('ascii')


class TestHttpHeaderFieldValueContentType(
        TestCasesBasesHttpHeader.MinimalHeader,
        TestCasesBasesHttpHeader.FullHeader):

    _header_minimal = HttpHeaderFieldValueContentType(
        FieldValueMimeType('html', MimeTypeRegistry.TEXT)
     )
    _header_minimal_bytes = b'text/html'
    _header_minimal_markdown = os.linesep.join([
        '* MIME type:',
        '    * Type: html',
        '    * Registry: TEXT',
        '* Charset: n/a',
        '* Boundary: n/a',
        '',
    ])

    _header_full = HttpHeaderFieldValueContentType(
        FieldValueMimeType('bhttp', MimeTypeRegistry.MESSAGE),
        charset='utf-8',
        boundary='boundary_pattern',
    )
    _header_full_bytes = b'message/bhttp; charset=utf-8; boundary=boundary_pattern'

    def test_error_invalid_parameter(self):
        with self.assertRaises(InvalidValue) as context_manager:
            HttpHeaderFieldValueContentType(
                FieldValueMimeType('html', MimeTypeRegistry.TEXT),
                boundary='pattern',
            )
        self.assertEqual(context_manager.exception.value, 'pattern')

        with self.assertRaises(InvalidValue) as context_manager:
            HttpHeaderFieldValueContentType(
                FieldValueMimeType('bhttp', MimeTypeRegistry.MESSAGE),
            )
        self.assertEqual(context_manager.exception.value, None)


class TestHttpHeaderFieldValueNetworkErrorLogging(
        TestCasesBasesHttpHeader.MinimalHeader,
        TestCasesBasesHttpHeader.FullHeader):
    _header_minimal = HttpHeaderFieldValueNetworkErrorLogging(
        report_to="network-errors",
        max_age=1,
    )
    _header_minimal_bytes = b'{"report_to": "network-errors", "max_age": 1}'
    _header_minimal_markdown = os.linesep.join([
        '* Report To: network-errors',
        '* Max Age: 0:00:01',
        '* Include Subdomains: n/a',
        '* Success Fraction: n/a',
        '* Failure Fraction: n/a',
        '',
    ])

    _header_full = HttpHeaderFieldValueNetworkErrorLogging(
        report_to="network-errors",
        max_age=datetime.timedelta(1),
        include_subdomains=True,
        success_fraction=0.1,
        failure_fraction=0.9,
    )
    _header_full_bytes = b''.join([
        b'{',
        b'"report_to": "network-errors", ',
        b'"max_age": 86400, ',
        b'"include_subdomains": true, ',
        b'"success_fraction": 0.1, ',
        b'"failure_fraction": 0.9',
        b'}',
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
        '* Max Age: 0:00:01',
        '* Include Subdomains: no',
        '* Preload: no',
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
        '* Max Age: 0:00:01',
        '* Include Subdomains: no',
        '* Preload: no',
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
        '* Max Age: 0:00:01',
        '* Enforce: no',
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


class TestHttpHeaderFieldValuePublicKeyPinning(
        TestCasesBasesHttpHeader.MinimalHeader,
        TestCasesBasesHttpHeader.FullHeader,
        TestCasesBasesHttpHeader.CaseInsensitiveHeader):
    _header_minimal = HttpHeaderFieldValuePublicKeyPinning(
        pin_sha256='cGluLXNoYTI1Ng==',
        max_age=datetime.timedelta(seconds=1),
    )
    _header_minimal_bytes = b'pin-sha256="cGluLXNoYTI1Ng=="; max-age=1'
    _header_minimal_markdown = os.linesep.join([
        '* Pin (SHA-256): cGluLXNoYTI1Ng==',
        '* Max Age: 0:00:01',
        '* Include Subdomains: no',
        '* Report Uri: n/a',
        '',
    ])

    _header_full = HttpHeaderFieldValuePublicKeyPinning(
        pin_sha256='cGluLXNoYTI1Ng==',
        max_age=datetime.timedelta(seconds=1),
        include_subdomains=True,
        report_uri='http://example.com'
    )
    _header_full_bytes = b'; '.join([
        b'pin-sha256="cGluLXNoYTI1Ng=="',
        b'max-age=1',
        b'includeSubDomains',
        b'report-uri="http://example.com"',
    ])
    _header_full_upper_case_bytes = b'; '.join([
        b'PIN-SHA256="cGluLXNoYTI1Ng=="',
        b'MAX-AGE=1',
        b'INCLUDESUBDOMAINS',
        b'REPORT-URI="http://example.com"',
    ])
    _header_full_lower_case_bytes = b'; '.join([
        b'pin-sha256="cGluLXNoYTI1Ng=="',
        b'max-age=1',
        b'includesubdomains',
        b'report-uri="http://example.com"',
    ])


class TestHttpHeaderFieldValueSetCookie(TestCasesBasesHttpHeader.MinimalHeader, TestCasesBasesHttpHeader.FullHeader):
    _header_minimal = HttpHeaderFieldValueSetCookie('name', 'value')
    _header_minimal_bytes = b'name=value'
    _header_minimal_markdown = os.linesep.join([
        '* Name: name',
        '* Value: value',
        '* Expires: n/a',
        '* Max Age: n/a',
        '* Domain: n/a',
        '* Path: n/a',
        '* Secure: no',
        '* Http Only: no',
        '* Same Site: n/a',
        ''
    ])

    _header_full = HttpHeaderFieldValueSetCookie(
        name='name', value='value',
        expires=datetime.datetime.fromtimestamp(0, datetime.timezone.utc),
        max_age=datetime.timedelta(seconds=1),
        domain='example.com',
        path='/',
        secure=True,
        http_only=True,
        same_site=HttpHeaderSetCookieComponentSameSite.LAX,
    )
    _header_full_bytes = b'; '.join([
        b'name=value',
        b'expires=Thu, 01 Jan 1970 00:00:00 GMT',
        b'max-age=1',
        b'Domain=example.com',
        b'Path=/',
        b'Secure',
        b'HttpOnly',
        b'SameSite=Lax',
    ])


class TestHttpHeaderFieldValueXContentTypeOptions(TestCasesBasesHttpHeader.FullHeader):
    _header_full = HttpHeaderFieldValueXContentTypeOptions(HttpHeaderXContentTypeOptions.NOSNIFF)
    _header_full_bytes = b'nosniff'


class TestHttpHeaderFieldValueXFrameOptions(TestCasesBasesHttpHeader.FullHeader):
    _header_full = HttpHeaderFieldValueXFrameOptions(HttpHeaderXFrameOptions.SAMEORIGIN)
    _header_full_bytes = b'SAMEORIGIN'


class TestHttpHeaderFieldValueXXSSProtection(TestCasesBasesHttpHeader.FullHeader):
    _header_full = HttpHeaderFieldValueXXSSProtection(
        HttpHeaderXXSSProtectionState.ENABLED,
        HttpHeaderXXSSProtectionMode.BLOCK,
        'http://example.com'
    )
    _header_full_bytes = b'1; mode=block; report=http://example.com'


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
            b'NEL: {"report_to": "network-errors", "max_age": 1}',
            b'Pragma: no-cache',
            b'Public-Key-Pinning: pin-sha256="cGluLXNoYTI1Ng=="; max-age=1',
            b'Referrer-Policy: origin',
            b'Server: server',
            b'Set-Cookie: name=value',
            b'Strict-Transport-Security: max-age=1',
            b'X-Unparsed: Value',
            b'X-Content-Type-Options: nosniff',
            b'X-Frame-Options: SAMEORIGIN',
            b'X-XSS-Protection: 1',
            b'Content-Security-Policy: default-src \'self\'',
            b'Content-Security-Policy-Report-Only: default-src \'self\'',
            b'X-Content-Security-Policy: default-src \'self\'',
            b'',
            b'',
        ])
        self.headers = HttpHeaderFields([
            HttpHeaderFieldAge(datetime.timedelta(seconds=1)),
            HttpHeaderFieldCacheControlResponse(HttpHeaderFieldValueCacheControlResponse(no_cache=True)),
            HttpHeaderFieldContentType(FieldValueMimeType('html', MimeTypeRegistry.TEXT)),
            HttpHeaderFieldDate(datetime.datetime.fromtimestamp(0, datetime.timezone.utc)),
            HttpHeaderFieldETag('12345678'),
            HttpHeaderFieldExpectCT(HttpHeaderFieldValueExpectCT(datetime.timedelta(seconds=1))),
            HttpHeaderFieldExpectStaple(HttpHeaderFieldValueExpectStaple(datetime.timedelta(seconds=1))),
            HttpHeaderFieldExpires(datetime.datetime.fromtimestamp(0, datetime.timezone.utc)),
            HttpHeaderFieldLastModified(datetime.datetime.fromtimestamp(0, datetime.timezone.utc)),
            HttpHeaderFieldNetworkErrorLogging(HttpHeaderFieldValueNetworkErrorLogging(
                report_to="network-errors", max_age=1
            )),
            HttpHeaderFieldPragma(HttpHeaderPragma.NO_CACHE),
            HttpHeaderFieldPublicKeyPinning(HttpHeaderFieldValuePublicKeyPinning(
                pin_sha256='cGluLXNoYTI1Ng==',
                max_age=datetime.timedelta(seconds=1),
            )),
            HttpHeaderFieldReferrerPolicy(HttpHeaderReferrerPolicy.ORIGIN),
            HttpHeaderFieldServer('server'),
            HttpHeaderFieldSetCookie(HttpHeaderFieldValueSetCookie('name', 'value')),
            HttpHeaderFieldSTS(HttpHeaderFieldValueSTS(datetime.timedelta(seconds=1))),
            HttpHeaderFieldUnparsed('X-Unparsed', 'Value'),
            HttpHeaderFieldXContentTypeOptions(HttpHeaderXContentTypeOptions.NOSNIFF),
            HttpHeaderFieldXFrameOptions(HttpHeaderXFrameOptions.SAMEORIGIN),
            HttpHeaderFieldXXSSProtection(HttpHeaderXXSSProtectionState.ENABLED),
            HttpHeaderFieldContentSecurityPolicy([
                ContentSecurityPolicyDirectiveDefaultSrc([ContentSecurityPolicySourceKeyword.SELF])
            ]),
            HttpHeaderFieldContentSecurityPolicyReportOnly([
                ContentSecurityPolicyDirectiveDefaultSrc([ContentSecurityPolicySourceKeyword.SELF])
            ]),
            HttpHeaderFieldXContentSecurityPolicy([
                ContentSecurityPolicyDirectiveDefaultSrc([ContentSecurityPolicySourceKeyword.SELF])
            ]),
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
            '        * Must Revalidate: no',
            '        * Proxy Revalidate: no',
            '        * No Cache: yes',
            '        * No Store: no',
            '        * Public: no',
            '        * Private: no',
            '        * No Transform: no',
            '3.',
            '    * Name: Content-Type',
            '    * Value:',
            '        * MIME type:',
            '            * Type: html',
            '            * Registry: TEXT',
            '        * Charset: n/a',
            '        * Boundary: n/a',
            '4.',
            '    * Name: Date',
            '    * Value: 1970-01-01 00:00:00+00:00',
            '5.',
            '    * Name: ETag',
            '    * Value: 12345678',
            '6.',
            '    * Name: Expect-CT',
            '    * Value:',
            '        * Max Age: 0:00:01',
            '        * Enforce: no',
            '        * Report Uri: n/a',
            '7.',
            '    * Name: Expect-Staple',
            '    * Value:',
            '        * Max Age: 0:00:01',
            '        * Include Subdomains: no',
            '        * Preload: no',
            '        * Report Uri: n/a',
            '8.',
            '    * Name: Expires',
            '    * Value: 1970-01-01 00:00:00+00:00',
            '9.',
            '    * Name: Last-Modified',
            '    * Value: 1970-01-01 00:00:00+00:00',
            '10.',
            '    * Name: NEL',
            '    * Value:',
            '        * Report To: network-errors',
            '        * Max Age: 0:00:01',
            '        * Include Subdomains: n/a',
            '        * Success Fraction: n/a',
            '        * Failure Fraction: n/a',
            '11.',
            '    * Name: Pragma',
            '    * Value: no-cache',
            '12.',
            '    * Name: Public-Key-Pinning',
            '    * Value:',
            '        * Pin (SHA-256): cGluLXNoYTI1Ng==',
            '        * Max Age: 0:00:01',
            '        * Include Subdomains: no',
            '        * Report Uri: n/a',
            '13.',
            '    * Name: Referrer-Policy',
            '    * Value: origin',
            '14.',
            '    * Name: Server',
            '    * Value: server',
            '15.',
            '    * Name: Set-Cookie',
            '    * Value:',
            '        * Name: name',
            '        * Value: value',
            '        * Expires: n/a',
            '        * Max Age: n/a',
            '        * Domain: n/a',
            '        * Path: n/a',
            '        * Secure: no',
            '        * Http Only: no',
            '        * Same Site: n/a',
            '16.',
            '    * Name: Strict-Transport-Security',
            '    * Value:',
            '        * Max Age: 0:00:01',
            '        * Include Subdomains: no',
            '        * Preload: no',
            '17.',
            '    * Name: X-Unparsed',
            '    * Value: Value',
            '18.',
            '    * Name: X-Content-Type-Options',
            '    * Value: nosniff',
            '19.',
            '    * Name: X-Frame-Options',
            '    * Value: SAMEORIGIN',
            '20.',
            '    * Name: X-XSS-Protection',
            '    * Value:',
            '        * State: enabled',
            '        * Mode: n/a',
            '        * Report: n/a',
            '21.',
            '    * Name: Content-Security-Policy',
            '    * Value:',
            '        * Directives:',
            '            1.',
            '                * Type: default-src',
            '                * Value:',
            '                    1.',
            '                        * Type: KEYWORD',
            '                        * Value: \'self\'',
            '22.',
            '    * Name: Content-Security-Policy-Report-Only',
            '    * Value:',
            '        * Directives:',
            '            1.',
            '                * Type: default-src',
            '                * Value:',
            '                    1.',
            '                        * Type: KEYWORD',
            '                        * Value: \'self\'',
            '23.',
            '    * Name: X-Content-Security-Policy',
            '    * Value:',
            '        * Directives:',
            '            1.',
            '                * Type: default-src',
            '                * Value:',
            '                    1.',
            '                        * Type: KEYWORD',
            '                        * Value: \'self\'',
            '',
        ]))


class TestHttpHeaderFieldUnparsed(unittest.TestCase):
    def test_error(self):
        with self.assertRaises(InvalidValue) as context_manager:
            HttpHeaderFieldUnparsed.parse_immutable(b'name: value')
        self.assertEqual(context_manager.exception.value, b'value')

        with self.assertRaises(InvalidValue) as context_manager:
            HttpHeaderFieldUnparsed.parse_immutable(b'name value')
        self.assertEqual(context_manager.exception.value, b'')

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
